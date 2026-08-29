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
    io::{
        mem::DevresIoMem,
        poll,
        Io, //
    },
    irq::ThreadedRegistration,
    platform,
    prelude::*,
    sizes::SZ_2M,
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
        gpu_control::{
            GPU_FEATURES_HI,
            GPU_FEATURES_LO, //
        },
        join_u64,
        pwr_control::*, //
    }, //
};

/// Timeout for a power domain transition to complete.
const TRANSITION_TIMEOUT: Delta = Delta::from_secs(2);

/// Timeout for a pending retract operation to clear.
const RETRACT_TIMEOUT: Delta = Delta::from_millis(2);

/// Timeout for a reset command to complete.
const RESET_TIMEOUT: Delta = Delta::from_millis(500);

/// Returns the PWR IRQ sources the driver services.
fn pwr_irq_sources() -> PWR_IRQ_MASK {
    PWR_IRQ_MASK::zeroed()
        .with_power_changed_single(true)
        .with_power_changed_all(true)
        .with_delegation_changed(true)
        .with_retract_completed(true)
        .with_inspect_completed(true)
        .with_command_not_allowed(true)
        .with_command_invalid(true)
}

pub(crate) struct PwrIrq;

/// Clears the latched PWR IRQs the driver services and unmasks them.
pub(crate) fn pwr_irq_enable(io: &IoMem<'_>) {
    let sources = pwr_irq_sources();

    io.write_reg(PWR_IRQ_CLEAR::from_raw(sources.into_raw()));
    io.write_reg(sources);
}

/// Masks all PWR IRQ sources.
pub(crate) fn pwr_irq_disable(io: &IoMem<'_>) {
    io.write_reg(PWR_IRQ_MASK::from_raw(0));
}

/// Registers the PWR IRQ handler with the sources masked.
///
/// The PWR block raises its interrupts on the same line as the GPU
/// block, so this is a second shared registration on the "gpu"
/// interrupt.
///
/// # Safety
///
/// Callers must not `mem::forget()` the resulting registration or otherwise prevent its
/// `Drop` implementation from running.
pub(crate) unsafe fn pwr_irq_init<'drm>(
    pdev: &'drm platform::Device<Bound>,
    tdev: ARef<TyrDrmDevice>,
    iomem: Arc<DevresIoMem<SZ_2M>>,
) -> Result<impl PinInit<ThreadedRegistration<'drm, TyrIrq<'drm, PwrIrq>>, Error> + 'drm> {
    // The caller unmasks the sources once the handler is registered.
    iomem
        .access(pdev.as_ref())?
        .write_reg(PWR_IRQ_MASK::zeroed());

    // SAFETY: The caller guarantees that the registration is not leaked.
    Ok(unsafe { TyrIrq::request(pdev, tdev, c"gpu", c"pwr", iomem, PwrIrq) })
}

impl TyrIrqTrait for PwrIrq {
    fn read_status(&self, io: &IoMem<'_>) -> u32 {
        io.read(PWR_IRQ_STATUS).into_raw()
    }

    fn disable_all(&self, io: &IoMem<'_>) {
        io.write_reg(PWR_IRQ_MASK::from_raw(0));
    }

    fn reenable(&self, io: &IoMem<'_>) {
        io.write_reg(PWR_IRQ_MASK::from_raw(self.mask()));
    }

    fn read_raw_status(&self, io: &IoMem<'_>) -> u32 {
        io.read(PWR_IRQ_RAWSTAT).into_raw()
    }

    fn clear_status(&self, io: &IoMem<'_>, status: u32) {
        io.write_reg(PWR_IRQ_CLEAR::from_raw(status));
    }

    fn mask(&self) -> u32 {
        pwr_irq_sources().into_raw()
    }

    fn handle(&self, tdev: &TyrDrmDevice, _io: &IoMem<'_>, status: u32) {
        let status = PWR_IRQ_STATUS::from_raw(status);

        if status.command_not_allowed() {
            dev_err!(tdev.as_ref(), "PWR_IRQ: COMMAND_NOT_ALLOWED\n");
        }

        if status.command_invalid() {
            dev_err!(tdev.as_ref(), "PWR_IRQ: COMMAND_INVALID\n");
        }
    }
}

fn pwr_status(io: &IoMem<'_>) -> PWR_STATUS {
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

fn domain_ready(io: &IoMem<'_>, domain: PwrDomain) -> u64 {
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

fn domain_pwrtrans(io: &IoMem<'_>, domain: PwrDomain) -> u64 {
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
fn write_command(io: &IoMem<'_>, command: PWR_COMMAND, args: u64) {
    if args != 0 {
        io.write_reg(PWR_CMDARG_LO::from_raw(args as u32));
        io.write_reg(PWR_CMDARG_HI::from_raw((args >> 32) as u32));
    }

    io.write_reg(command);
}

/// Logs the PWR block state after a failed domain transition.
fn log_pwr_state(dev: &Device, io: &IoMem<'_>) {
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
        pwr_status(io).into_raw()
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
        domain_pwrtrans(io, PwrDomain::L2)
    );
    dev_info!(
        dev,
        "L2_READY:        0x{:016x}\n",
        domain_ready(io, PwrDomain::L2)
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
        domain_pwrtrans(io, PwrDomain::Tiler)
    );
    dev_info!(
        dev,
        "TILER_READY:     0x{:016x}\n",
        domain_ready(io, PwrDomain::Tiler)
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
        domain_pwrtrans(io, PwrDomain::Shader)
    );
    dev_info!(
        dev,
        "SHADER_READY:    0x{:016x}\n",
        domain_ready(io, PwrDomain::Shader)
    );
}

/// Issues a PWR reset command and waits for completion.
///
/// Completion is polled from `PWR_IRQ_RAWSTAT`, which latches the bit
/// regardless of `PWR_IRQ_MASK`, so `reset_completed` stays masked.
fn reset(dev: &Device, io: &IoMem<'_>, command: PwrCommand) -> Result {
    // Clear any stale reset-completed state before issuing a new reset.
    io.write_reg(PWR_IRQ_CLEAR::zeroed().with_reset_completed(true));

    write_command(io, PWR_COMMAND::zeroed().with_command(command), 0);

    poll::read_poll_timeout(
        || Ok(io.read(PWR_IRQ_RAWSTAT)),
        |status| status.reset_completed(),
        Delta::from_millis(1),
        RESET_TIMEOUT,
    )
    .inspect_err(|_| dev_err!(dev, "RESET timed out (0x{:x})\n", command as u32))?;

    Ok(())
}

/// Issues a soft reset through PWR_CONTROL.
pub(crate) fn reset_soft(dev: &Device, io: &IoMem<'_>) -> Result {
    if !pwr_status(io).allow_soft_reset() {
        dev_err!(dev, "RESET_SOFT not allowed\n");
        return Err(EOPNOTSUPP);
    }

    reset(dev, io, PwrCommand::ResetSoft)
}

fn wait_domain_transition(
    dev: &Device,
    io: &IoMem<'_>,
    domain: PwrDomain,
    timeout: Delta,
) -> Result {
    poll::read_poll_timeout(
        || Ok(domain_pwrtrans(io, domain)),
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
    io: &IoMem<'_>,
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

    wait_domain_transition(dev, io, domain, timeout)?;

    if domain_ready(io, domain) & mask == expected {
        return Ok(());
    }

    write_command(io, pwr_cmd, mask);

    poll::read_poll_timeout(
        || Ok(domain_ready(io, domain)),
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
        log_pwr_state(dev, io);
    })?;

    Ok(())
}

/// Retracts control of a domain from the MCU.
///
/// The L2 domain is never delegated, so retracting it is rejected.
fn retract_domain(dev: &Device, io: &IoMem<'_>, domain: PwrDomain) -> Result {
    if domain == PwrDomain::L2 {
        return Err(EPERM);
    }

    let status = pwr_status(io);

    poll::read_poll_timeout(
        || Ok(pwr_status(io)),
        |status| !status.retract_pending(),
        Delta::from_micros(0),
        RETRACT_TIMEOUT,
    )
    .inspect_err(|_| dev_err!(dev, "{} domain retract pending\n", domain_name(domain)))?;

    if !domain_delegated(status, domain) {
        dev_dbg!(dev, "{} domain already retracted\n", domain_name(domain));
        return Ok(());
    }

    write_command(
        io,
        PWR_COMMAND::zeroed()
            .with_command(PwrCommand::Retract)
            .with_domain(domain),
        0,
    );

    poll::read_poll_timeout(
        || Ok(pwr_status(io)),
        |status| domain_allowed(*status, domain) && !domain_delegated(*status, domain),
        Delta::from_micros(10),
        TRANSITION_TIMEOUT,
    )
    .inspect_err(|_| dev_err!(dev, "Retracting {} domain timeout\n", domain_name(domain)))?;

    Ok(())
}

/// Delegates control of a domain to the MCU.
///
/// The L2 domain stays under host control, so delegating it is rejected.
fn delegate_domain(dev: &Device, io: &IoMem<'_>, domain: PwrDomain) -> Result {
    if domain == PwrDomain::L2 {
        return Err(EPERM);
    }

    let status = pwr_status(io);

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

    wait_domain_transition(dev, io, domain, TRANSITION_TIMEOUT)?;

    write_command(
        io,
        PWR_COMMAND::zeroed()
            .with_command(PwrCommand::Delegate)
            .with_domain(domain),
        0,
    );

    poll::read_poll_timeout(
        || Ok(pwr_status(io)),
        |status| domain_delegated(*status, domain) && !domain_allowed(*status, domain),
        Delta::from_micros(10),
        TRANSITION_TIMEOUT,
    )
    .inspect_err(|_| dev_err!(dev, "Delegating {} domain timeout\n", domain_name(domain)))?;

    Ok(())
}

/// Delegates the shader and tiler power domains to the MCU. The MCU
/// tracks the running jobs, so it powers only the cores they need.
fn delegate_domains(dev: &Device, io: &IoMem<'_>) -> Result {
    delegate_domain(dev, io, PwrDomain::Shader)?;

    if let Err(e) = delegate_domain(dev, io, PwrDomain::Tiler) {
        let _ = retract_domain(dev, io, PwrDomain::Shader);
        return Err(e);
    }

    Ok(())
}

/// Forcefully powers down a domain.
///
/// If the power off fails, the domain stays retracted under host control.
fn domain_force_off(dev: &Device, io: &IoMem<'_>, domain: PwrDomain, has_rtu: bool) -> Result {
    let ready = domain_ready(io, domain);

    if ready == 0 {
        return Ok(());
    }

    // The domain has to be under host control to issue a power off command.
    retract_domain(dev, io, domain)?;

    domain_transition(
        dev,
        io,
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
pub(crate) fn l2_power_off(dev: &Device, io: &IoMem<'_>, l2_present: u64, has_rtu: bool) -> Result {
    if !pwr_status(io).allow_l2() {
        dev_warn!(dev, "Power off L2 domain not allowed\n");
        return Err(EPERM);
    }

    domain_force_off(dev, io, PwrDomain::Tiler, has_rtu)?;
    domain_force_off(dev, io, PwrDomain::Shader, has_rtu)?;

    domain_transition(
        dev,
        io,
        Transition::Down,
        PwrDomain::L2,
        l2_present,
        has_rtu,
        TRANSITION_TIMEOUT,
    )
}

/// Powers on the L2 domain and delegates the shader and tiler domains
/// to the MCU.
pub(crate) fn l2_power_on(dev: &Device, io: &IoMem<'_>, l2_present: u64, has_rtu: bool) -> Result {
    if !pwr_status(io).allow_l2() {
        dev_warn!(dev, "Power on L2 domain not allowed\n");
        return Err(EPERM);
    }

    domain_transition(
        dev,
        io,
        Transition::Up,
        PwrDomain::L2,
        l2_present,
        has_rtu,
        TRANSITION_TIMEOUT,
    )?;

    delegate_domains(dev, io)
}
