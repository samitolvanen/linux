// SPDX-License-Identifier: GPL-2.0 or MIT

//! PWR_CONTROL block management.
//!
//! On architecture 14 the host drives resets and power domain
//! transitions through the PWR_CONTROL block. The L2 domain stays under
//! host control, while the shader and tiler domains are delegated to
//! the MCU once the L2 is up, and retracted into host control when they
//! need to be powered down in sequence.

use kernel::{
    device::{
        Bound,
        Device, //
    },
    devres::Devres,
    io::{
        poll,
        Io, //
    },
    irq::ThreadedRegistration,
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    },
    time::Delta, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice, //
    },
    irq::{
        TyrIrq,
        TyrIrqTrait, //
    },
    regs::{
        join_u64,
        pwr_control::*, //
    },
};

/// Timeout for a power domain transition to complete.
const TRANSITION_TIMEOUT: Delta = Delta::from_secs(2);

/// Timeout for a pending retract operation to clear.
const RETRACT_TIMEOUT: Delta = Delta::from_millis(2);

/// Timeout for a reset command to complete.
const RESET_TIMEOUT: Delta = Delta::from_millis(500);

/// Returns the bitmask for the PWR interrupts the driver actively handles.
pub(crate) fn pwr_interrupts_mask() -> u32 {
    PWR_INT_MASK::zeroed()
        .with_power_changed_single(true)
        .with_power_changed_all(true)
        .with_delegation_changed(true)
        .with_retract_completed(true)
        .with_inspect_completed(true)
        .with_command_not_allowed(true)
        .with_command_invalid(true)
        .into_raw()
}

pub(crate) struct PwrIrq {
    iomem: Arc<Devres<IoMem>>,
    /// Cached value of `pwr_interrupts_mask`.
    mask: u32,
}

/// Clears latched PWR IRQs and unmasks the sources the driver handles.
pub(crate) fn pwr_irq_enable(io: &IoMem) {
    io.write_reg(PWR_INT_CLEAR::from_raw(u32::MAX));
    io.write_reg(PWR_INT_MASK::from_raw(pwr_interrupts_mask()));
}

/// Masks all PWR IRQ sources.
pub(crate) fn pwr_irq_disable(io: &IoMem) {
    io.write_reg(PWR_INT_MASK::from_raw(0));
}

/// Registers the PWR IRQ handler.
///
/// The PWR block raises its interrupts on the same line as the GPU
/// block, so this is a second shared registration on the "gpu"
/// interrupt.
pub(crate) fn pwr_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<Bound>,
    iomem: Arc<Devres<IoMem>>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<PwrIrq>>, Error> + 'a> {
    let mask = pwr_interrupts_mask();
    let io = iomem.access(pdev.as_ref())?;
    // Drop any latched IRQs from a previous probe.
    pwr_irq_enable(io);

    let irq_type = PwrIrq {
        iomem: iomem.clone(),
        mask,
    };

    TyrIrq::request(pdev, tdev, c"gpu", c"pwr", irq_type)
}

impl TyrIrqTrait for PwrIrq {
    fn read_status(&self, dev: &Device<Bound>) -> u32 {
        self.iomem
            .access(dev)
            .map(|io| io.read(PWR_INT_STAT).into_raw())
            .unwrap_or_default()
    }

    fn disable_all(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(PWR_INT_MASK::from_raw(0));
        }
    }

    fn reenable(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(PWR_INT_MASK::from_raw(self.mask));
        }
    }

    fn read_raw_status(&self, dev: &Device<Bound>) -> u32 {
        self.iomem
            .access(dev)
            .map(|io| io.read(PWR_INT_RAWSTAT).into_raw())
            .unwrap_or_default()
    }

    fn clear_status(&self, dev: &Device<Bound>, status: u32) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(PWR_INT_CLEAR::from_raw(status));
        }
    }

    fn mask(&self) -> u32 {
        self.mask
    }

    fn handle(&self, tdev: &TyrDrmDevice, status: u32) {
        let status = PWR_INT_STAT::from_raw(status);

        if status.command_not_allowed() {
            dev_err!(tdev.pdev.as_ref(), "PWR_IRQ: COMMAND_NOT_ALLOWED\n");
        }

        if status.command_invalid() {
            dev_err!(tdev.pdev.as_ref(), "PWR_IRQ: COMMAND_INVALID\n");
        }
    }
}

fn pwr_status(io: &IoMem) -> PWR_STATUS {
    PWR_STATUS::from_raw(join_u64(
        io.read(PWR_STATUS_LO).into_raw(),
        io.read(PWR_STATUS_HI).into_raw(),
    ))
}

fn domain_name(domain: PwrDomain) -> &'static str {
    match domain {
        PwrDomain::L2 => "L2",
        PwrDomain::Tiler => "Tiler",
        PwrDomain::Shader => "Shader",
        PwrDomain::Base => "Base",
        PwrDomain::Stack => "Stack",
    }
}

fn domain_ready(io: &IoMem, domain: PwrDomain) -> u64 {
    match domain {
        PwrDomain::L2 => join_u64(
            io.read(PWR_L2_READY_LO).into_raw(),
            io.read(PWR_L2_READY_HI).into_raw(),
        ),
        PwrDomain::Tiler => join_u64(
            io.read(PWR_TILER_READY_LO).into_raw(),
            io.read(PWR_TILER_READY_HI).into_raw(),
        ),
        PwrDomain::Shader => join_u64(
            io.read(PWR_SHADER_READY_LO).into_raw(),
            io.read(PWR_SHADER_READY_HI).into_raw(),
        ),
        PwrDomain::Base => join_u64(
            io.read(PWR_BASE_READY_LO).into_raw(),
            io.read(PWR_BASE_READY_HI).into_raw(),
        ),
        PwrDomain::Stack => join_u64(
            io.read(PWR_STACK_READY_LO).into_raw(),
            io.read(PWR_STACK_READY_HI).into_raw(),
        ),
    }
}

fn domain_pwrtrans(io: &IoMem, domain: PwrDomain) -> u64 {
    match domain {
        PwrDomain::L2 => join_u64(
            io.read(PWR_L2_PWRTRANS_LO).into_raw(),
            io.read(PWR_L2_PWRTRANS_HI).into_raw(),
        ),
        PwrDomain::Tiler => join_u64(
            io.read(PWR_TILER_PWRTRANS_LO).into_raw(),
            io.read(PWR_TILER_PWRTRANS_HI).into_raw(),
        ),
        PwrDomain::Shader => join_u64(
            io.read(PWR_SHADER_PWRTRANS_LO).into_raw(),
            io.read(PWR_SHADER_PWRTRANS_HI).into_raw(),
        ),
        PwrDomain::Base => join_u64(
            io.read(PWR_BASE_PWRTRANS_LO).into_raw(),
            io.read(PWR_BASE_PWRTRANS_HI).into_raw(),
        ),
        PwrDomain::Stack => join_u64(
            io.read(PWR_STACK_PWRTRANS_LO).into_raw(),
            io.read(PWR_STACK_PWRTRANS_HI).into_raw(),
        ),
    }
}

fn domain_allowed(status: PWR_STATUS, domain: PwrDomain) -> bool {
    match domain {
        PwrDomain::L2 => status.allow_l2(),
        PwrDomain::Tiler => status.allow_tiler(),
        PwrDomain::Shader => status.allow_shader(),
        PwrDomain::Base => status.allow_base(),
        PwrDomain::Stack => status.allow_stack(),
    }
}

fn domain_delegated(status: PWR_STATUS, domain: PwrDomain) -> bool {
    match domain {
        PwrDomain::L2 => status.delegated_l2(),
        PwrDomain::Tiler => status.delegated_tiler(),
        PwrDomain::Shader => status.delegated_shader(),
        PwrDomain::Base => status.delegated_base(),
        PwrDomain::Stack => status.delegated_stack(),
    }
}

/// Returns the subdomain bits for a power transition command.
///
/// The shader domain carries the ray traversal unit as a subdomain, so
/// it is included whenever the GPU has one.
fn domain_subdomain(domain: PwrDomain, has_rtu: bool) -> u8 {
    if domain == PwrDomain::Shader && has_rtu {
        PWR_SUBDOMAIN_RTU
    } else {
        0
    }
}

/// Writes a PWR command, with its 64-bit argument when non-zero.
fn write_command(io: &IoMem, command: PWR_COMMAND, args: u64) {
    if args != 0 {
        io.write_reg(PWR_CMDARG_LO::from_raw(args as u32));
        io.write_reg(PWR_CMDARG_HI::from_raw((args >> 32) as u32));
    }

    io.write_reg(command);
}

/// Logs the PWR block state after a failed domain transition.
fn log_pwr_state(dev: &Device, iomem: &Devres<IoMem>) {
    use crate::regs::gpu_control::{
        GPU_FEATURES_HI,
        GPU_FEATURES_LO, //
    };

    let Some(io) = iomem.try_access() else {
        return;
    };

    dev_info!(
        dev,
        "GPU_FEATURES:    0x{:016x}\n",
        join_u64(
            io.read(GPU_FEATURES_LO).into_raw(),
            io.read(GPU_FEATURES_HI).into_raw()
        )
    );
    dev_info!(
        dev,
        "PWR_STATUS:      0x{:016x}\n",
        pwr_status(&io).into_raw()
    );
    dev_info!(
        dev,
        "L2_PRESENT:      0x{:016x}\n",
        join_u64(
            io.read(PWR_L2_PRESENT_LO).into_raw(),
            io.read(PWR_L2_PRESENT_HI).into_raw()
        )
    );
    dev_info!(
        dev,
        "L2_PWRTRANS:     0x{:016x}\n",
        domain_pwrtrans(&io, PwrDomain::L2)
    );
    dev_info!(
        dev,
        "L2_READY:        0x{:016x}\n",
        domain_ready(&io, PwrDomain::L2)
    );
    dev_info!(
        dev,
        "TILER_PRESENT:   0x{:016x}\n",
        join_u64(
            io.read(PWR_TILER_PRESENT_LO).into_raw(),
            io.read(PWR_TILER_PRESENT_HI).into_raw()
        )
    );
    dev_info!(
        dev,
        "TILER_PWRTRANS:  0x{:016x}\n",
        domain_pwrtrans(&io, PwrDomain::Tiler)
    );
    dev_info!(
        dev,
        "TILER_READY:     0x{:016x}\n",
        domain_ready(&io, PwrDomain::Tiler)
    );
    dev_info!(
        dev,
        "SHADER_PRESENT:  0x{:016x}\n",
        join_u64(
            io.read(PWR_SHADER_PRESENT_LO).into_raw(),
            io.read(PWR_SHADER_PRESENT_HI).into_raw()
        )
    );
    dev_info!(
        dev,
        "SHADER_PWRTRANS: 0x{:016x}\n",
        domain_pwrtrans(&io, PwrDomain::Shader)
    );
    dev_info!(
        dev,
        "SHADER_READY:    0x{:016x}\n",
        domain_ready(&io, PwrDomain::Shader)
    );
}

/// Issues a PWR reset command and waits for completion.
///
/// Completion is polled from `PWR_INT_RAWSTAT`, which latches the bit
/// regardless of `PWR_INT_MASK`, so `reset_completed` stays masked.
fn reset(dev: &Device, iomem: &Devres<IoMem>, command: PwrCommand) -> Result {
    {
        let io = iomem.try_access().ok_or(ENODEV)?;

        // Clear any stale reset-completed state before issuing a new reset.
        io.write_reg(PWR_INT_CLEAR::zeroed().with_reset_completed(true));

        write_command(&io, PWR_COMMAND::zeroed().with_command(command), 0);
    }

    poll::read_poll_timeout(
        || {
            let io = iomem.try_access().ok_or(ENODEV)?;
            Ok(io.read(PWR_INT_RAWSTAT))
        },
        |status| status.reset_completed(),
        Delta::from_millis(1),
        RESET_TIMEOUT,
    )
    .inspect_err(|_| dev_err!(dev, "RESET timed out (0x{:x})\n", command as u32))?;

    Ok(())
}

/// Issues a soft reset through PWR_CONTROL.
///
/// Runs on the reset-worker path, so access goes through the revocable guard.
pub(crate) fn reset_soft(dev: &Device, iomem: &Devres<IoMem>) -> Result {
    {
        let io = iomem.try_access().ok_or(ENODEV)?;
        if !pwr_status(&io).allow_soft_reset() {
            dev_err!(dev, "RESET_SOFT not allowed\n");
            return Err(EOPNOTSUPP);
        }
    }

    reset(dev, iomem, PwrCommand::ResetSoft)
}

fn wait_domain_transition(
    dev: &Device,
    iomem: &Devres<IoMem>,
    domain: PwrDomain,
    timeout: Delta,
) -> Result {
    poll::read_poll_timeout(
        || {
            let io = iomem.try_access().ok_or(ENODEV)?;
            Ok(domain_pwrtrans(&io, domain))
        },
        |val| *val == 0,
        Delta::from_micros(100),
        timeout,
    )
    .inspect_err(|_| dev_err!(dev, "{} domain power in transition\n", domain_name(domain)))?;

    Ok(())
}

/// Direction of a host-driven domain transition.
#[derive(Copy, Clone)]
enum Transition {
    Up,
    Down,
}

fn domain_transition(
    dev: &Device,
    iomem: &Devres<IoMem>,
    transition: Transition,
    domain: PwrDomain,
    mask: u64,
    has_rtu: bool,
    timeout: Delta,
) -> Result {
    let (command, expected) = match transition {
        Transition::Up => (PwrCommand::PowerUp, mask),
        Transition::Down => (PwrCommand::PowerDown, 0),
    };
    let pwr_cmd = PWR_COMMAND::zeroed()
        .with_command(command)
        .with_domain(domain)
        .with_subdomain(domain_subdomain(domain, has_rtu));

    wait_domain_transition(dev, iomem, domain, timeout)?;

    {
        let io = iomem.try_access().ok_or(ENODEV)?;

        if domain_ready(&io, domain) & mask == expected {
            return Ok(());
        }

        write_command(&io, pwr_cmd, mask);
    }

    poll::read_poll_timeout(
        || {
            let io = iomem.try_access().ok_or(ENODEV)?;
            Ok(domain_ready(&io, domain))
        },
        |val| *val & mask == expected,
        Delta::from_micros(100),
        timeout,
    )
    .inspect_err(|_| {
        dev_err!(
            dev,
            "timeout waiting on {} power domain transition, cmd(0x{:x}), arg(0x{:x})\n",
            domain_name(domain),
            pwr_cmd.into_raw(),
            mask
        );
        log_pwr_state(dev, iomem);
    })?;

    Ok(())
}

/// Retracts control of a domain from the MCU.
///
/// The L2 domain is never delegated, so retracting it is rejected.
fn retract_domain(dev: &Device, iomem: &Devres<IoMem>, domain: PwrDomain) -> Result {
    if domain == PwrDomain::L2 {
        return Err(EPERM);
    }

    let status = {
        let io = iomem.try_access().ok_or(ENODEV)?;
        pwr_status(&io)
    };

    poll::read_poll_timeout(
        || {
            let io = iomem.try_access().ok_or(ENODEV)?;
            Ok(pwr_status(&io))
        },
        |status| !status.retract_pending(),
        Delta::from_micros(0),
        RETRACT_TIMEOUT,
    )
    .inspect_err(|_| dev_err!(dev, "{} domain retract pending\n", domain_name(domain)))?;

    if !domain_delegated(status, domain) {
        dev_dbg!(dev, "{} domain already retracted\n", domain_name(domain));
        return Ok(());
    }

    {
        let io = iomem.try_access().ok_or(ENODEV)?;
        write_command(
            &io,
            PWR_COMMAND::zeroed()
                .with_command(PwrCommand::Retract)
                .with_domain(domain),
            0,
        );
    }

    poll::read_poll_timeout(
        || {
            let io = iomem.try_access().ok_or(ENODEV)?;
            Ok(pwr_status(&io))
        },
        |status| domain_allowed(*status, domain) && !domain_delegated(*status, domain),
        Delta::from_micros(10),
        TRANSITION_TIMEOUT,
    )
    .inspect_err(|_| dev_err!(dev, "Retracting {} domain timeout\n", domain_name(domain)))?;

    Ok(())
}

/// Delegates control of a domain to the MCU.
///
/// Delegating the L2 domain is prohibited.
fn delegate_domain(dev: &Device, iomem: &Devres<IoMem>, domain: PwrDomain) -> Result {
    if domain == PwrDomain::L2 {
        return Err(EPERM);
    }

    let status = {
        let io = iomem.try_access().ok_or(ENODEV)?;
        pwr_status(&io)
    };

    if domain_delegated(status, domain) {
        return Ok(());
    }

    if !domain_allowed(status, domain) {
        dev_warn!(
            dev,
            "Delegating {} domain not allowed\n",
            domain_name(domain)
        );
        return Err(EPERM);
    }

    wait_domain_transition(dev, iomem, domain, TRANSITION_TIMEOUT)?;

    {
        let io = iomem.try_access().ok_or(ENODEV)?;
        write_command(
            &io,
            PWR_COMMAND::zeroed()
                .with_command(PwrCommand::Delegate)
                .with_domain(domain),
            0,
        );
    }

    poll::read_poll_timeout(
        || {
            let io = iomem.try_access().ok_or(ENODEV)?;
            Ok(pwr_status(&io))
        },
        |status| domain_delegated(*status, domain) && !domain_allowed(*status, domain),
        Delta::from_micros(10),
        TRANSITION_TIMEOUT,
    )
    .inspect_err(|_| dev_err!(dev, "Delegating {} domain timeout\n", domain_name(domain)))?;

    Ok(())
}

/// Delegates the shader and tiler power domains to the MCU, which can
/// better manage which cores need to be powered based on the running
/// jobs.
fn delegate_domains(dev: &Device, iomem: &Devres<IoMem>) -> Result {
    delegate_domain(dev, iomem, PwrDomain::Shader)?;

    if let Err(e) = delegate_domain(dev, iomem, PwrDomain::Tiler) {
        let _ = retract_domain(dev, iomem, PwrDomain::Shader);
        return Err(e);
    }

    Ok(())
}

/// Forcefully powers down a domain.
///
/// If the power off fails, the domain stays retracted under host control.
fn domain_force_off(
    dev: &Device,
    iomem: &Devres<IoMem>,
    domain: PwrDomain,
    has_rtu: bool,
) -> Result {
    let ready = {
        let io = iomem.try_access().ok_or(ENODEV)?;
        domain_ready(&io, domain)
    };

    if ready == 0 {
        return Ok(());
    }

    // The domain has to be under host control to issue a power off command.
    retract_domain(dev, iomem, domain)?;

    domain_transition(
        dev,
        iomem,
        Transition::Down,
        domain,
        ready,
        has_rtu,
        TRANSITION_TIMEOUT,
    )
}

/// Powers off the L2 domain.
///
/// A halted MCU is expected to power down its delegated domains, but a
/// hung MCU may not, so the tiler and shader domains are retracted back
/// into host control and powered down in order first.
pub(crate) fn l2_power_off(
    dev: &Device<Bound>,
    iomem: &Devres<IoMem>,
    l2_present: u64,
    has_rtu: bool,
) -> Result {
    {
        let io = iomem.access(dev)?;
        if !pwr_status(io).allow_l2() {
            dev_warn!(dev, "Power off L2 domain not allowed\n");
            return Err(EPERM);
        }
    }

    domain_force_off(dev, iomem, PwrDomain::Tiler, has_rtu)?;
    domain_force_off(dev, iomem, PwrDomain::Shader, has_rtu)?;

    domain_transition(
        dev,
        iomem,
        Transition::Down,
        PwrDomain::L2,
        l2_present,
        has_rtu,
        TRANSITION_TIMEOUT,
    )
}

/// Powers on the L2 domain and delegates the shader and tiler domains
/// to the MCU.
///
/// Runs on the reset-worker path, so access goes through the revocable guard.
pub(crate) fn l2_power_on(
    dev: &Device,
    iomem: &Devres<IoMem>,
    l2_present: u64,
    has_rtu: bool,
) -> Result {
    {
        let io = iomem.try_access().ok_or(ENODEV)?;
        if !pwr_status(&io).allow_l2() {
            dev_warn!(dev, "Power on L2 domain not allowed\n");
            return Err(EPERM);
        }
    }

    domain_transition(
        dev,
        iomem,
        Transition::Up,
        PwrDomain::L2,
        l2_present,
        has_rtu,
        TRANSITION_TIMEOUT,
    )?;

    delegate_domains(dev, iomem)
}
