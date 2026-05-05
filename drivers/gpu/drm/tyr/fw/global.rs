// SPDX-License-Identifier: GPL-2.0 or MIT

//! Global CSF firmware interface implementation.
//!
//! This module owns the GLB-side firmware runtime state and configuration
//! path. It keeps the global request/ack protocol and CSG discovery together,
//! while leaving shared register definitions and low-level interface helpers in
//! fw/interfaces.rs.

mod cs;
mod csg;

use kernel::{
    clk::Clk,
    device::Device,
    io::{
        register::Array,
        Io,
        Region, //
    },
    new_mutex,
    num::Bounded,
    prelude::*,
    sizes::SizeConstants,
    sync::{
        Arc,
        Mutex, //
    },
    time::arch_timer_get_rate, //
};

use crate::{
    driver::IoMem,
    fw::{
        interfaces::{
            FwInterface,
            CSG_CONTROL_BLOCK_SIZE,
            GLB_ACK,
            GLB_ACK_IRQ_MASK,
            GLB_ALLOC_EN,
            GLB_CONTROL_BLOCK_SIZE,
            GLB_GROUP_NUM,
            GLB_GROUP_STRIDE,
            GLB_IDLE_TIMER,
            GLB_INPUT_BLOCK_SIZE,
            GLB_INPUT_VA,
            GLB_OUTPUT_BLOCK_SIZE,
            GLB_OUTPUT_VA,
            GLB_PROGRESS_TIMER,
            GLB_PWROFF_TIMER,
            GLB_REQ,
            GLB_VERSION, //
        },
        region::FwRegion,
        Section, //
    },
    gpu::GpuInfo,
    regs::doorbell_block::DOORBELL,
    wait::{
        Wait,
        WaitResult, //
    }, //
};

pub(super) use self::csg::CsgInterface;

/// Encodes a GLB timer timeout and selects the backing time source.
pub(super) fn conv_timeout(core_clk: &Clk, timeout_us: u32) -> Result<(u32, Bounded<u32, 1>)> {
    // The max timeout is determined by the 31 bit size of the timeout field.
    let max_timeout = (1u32 << 31) - 1;
    let core_rate = core_clk.rate().as_hz() as u64;

    let (timer_rate, timer_source) = match arch_timer_get_rate() {
        Some(rate) => (u64::from(rate), Bounded::try_new(0).unwrap()),
        _ if core_rate != 0 => (core_rate, Bounded::try_new(1).unwrap()),
        _ => return Err(EINVAL),
    };

    let timeout_in_cycles = u64::from(timeout_us) * timer_rate;

    // The hardware stores the represented timeout value with a shr(10) to save space.
    let timeout_shift = u64::SZ_1K;
    let us_per_second = 1_000_000u64;

    let timeout_val = timeout_in_cycles.div_ceil(us_per_second * timeout_shift);
    let timeout_val = timeout_val.min(u64::from(max_timeout)) as u32;

    Ok((timeout_val, timer_source))
}

/// Request/acknowledge communication between Tyr and CSF.
struct GlobalInterfaceRequests<'a> {
    /// Global input block where driver writes requests.
    input: &'a FwInterface<FwRegion<GLB_INPUT_BLOCK_SIZE>>,
    /// Global output block where firmware writes acknowledgements.
    output: &'a FwInterface<Region<GLB_OUTPUT_BLOCK_SIZE>>,
}

impl<'a> GlobalInterfaceRequests<'a> {
    fn new(
        input: &'a FwInterface<FwRegion<GLB_INPUT_BLOCK_SIZE>>,
        output: &'a FwInterface<Region<GLB_OUTPUT_BLOCK_SIZE>>,
    ) -> Self {
        Self { input, output }
    }

    /// Waits for the firmware to acknowledge the given request bits.
    ///
    /// The ack condition is `(GLB_ACK & mask) == (GLB_REQ & mask)`.
    fn wait_acks(&self, reqs_mask: GLB_REQ, event_wait: &Wait, timeout_ms: u32) -> Result {
        let mask = reqs_mask.into_raw();

        event_wait.wait_interruptible_timeout(timeout_ms, || {
            let req = self.input.read(GLB_REQ).into_raw() & mask;
            let ack = self.output.read(GLB_ACK).into_raw() & mask;
            if req == ack {
                Ok(WaitResult::Done)
            } else {
                Ok(WaitResult::Retry)
            }
        })
    }

    /// Use to make requests, where simply changing the bit value is
    /// sufficient to make a request; the bit value has no meaning in itself.
    fn toggle_requests(&self, reqs_mask: GLB_REQ) -> Result {
        let reqs_mask_val = reqs_mask.into_raw();

        let cur_ack_val = self.output.read(GLB_ACK).into_raw();

        // Calculate which bits to toggle based on ACK state
        let toggled_bits = (cur_ack_val ^ reqs_mask_val) & reqs_mask_val;

        let cur_req_val = self.input.read(GLB_REQ).into_raw();
        let preserved_bits = cur_req_val & !reqs_mask_val;
        let new_val = toggled_bits | preserved_bits;

        self.input.write(GLB_REQ, GLB_REQ::from_raw(new_val));
        Ok(())
    }
}

/// State of the global interface.
enum GlobalInterfaceState {
    /// Interface is not yet initialized.
    Disabled,
    /// Interface is initialized and operational.
    Enabled(EnabledGlobalInterface),
}

/// When enabled, the Global Interface has control,
/// input, and output system memory interfaces, as well as
/// the discovered CSG interfaces.
#[expect(dead_code)]
struct EnabledGlobalInterface {
    /// Control block interface - provides version, features, and CSG discovery.
    glb_control: FwInterface<Region<GLB_CONTROL_BLOCK_SIZE>>,
    /// Input block interface - driver writes requests here.
    glb_input: FwInterface<FwRegion<GLB_INPUT_BLOCK_SIZE>>,
    /// Output block interface - firmware writes acknowledgements here.
    glb_output: FwInterface<Region<GLB_OUTPUT_BLOCK_SIZE>>,
    /// Runtime stride between CSG control blocks (read from GLB_GROUP_STRIDE).
    csg_stride: usize,
    /// Number of CSG interfaces reported by hardware.
    csg_num: usize,
    /// Discovered CSG interfaces.
    csg: KVec<CsgInterface>,
}

/// Global CSF Interface state, protected by the interface mutex.
struct InnerGlobalInterface {
    /// Current interface state (Disabled or Enabled).
    state: GlobalInterfaceState,
}

/// Global CSF Interface
///
/// The CSF controls operations that are common to all CSs.
#[pin_data]
pub(crate) struct GlobalInterface {
    #[pin]
    inner: Mutex<InnerGlobalInterface>,
}

impl GlobalInterface {
    /// Creates a new CSF global interface, initially disabled.
    pub(crate) fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            inner <- new_mutex!(InnerGlobalInterface::new()),
        })
    }

    pub(crate) fn enable(
        &self,
        dev: &Device,
        iomem: &IoMem<'_>,
        shared_section: &Section,
        gpu_info: &GpuInfo,
        core_clk: &Clk,
        event_wait: &Wait,
    ) -> Result {
        let mut inner = self.inner.lock();
        inner.enable(dev, iomem, shared_section, gpu_info, core_clk, event_wait)
    }

    pub(crate) fn csif_info_counts(&self) -> Result<(u32, u32, u32, u32)> {
        let inner = self.inner.lock();
        inner.csif_info_counts()
    }

    pub(crate) fn group_suspend_buf_sizes(&self) -> Result<(u32, u32)> {
        let inner = self.inner.lock();
        inner.group_suspend_buf_sizes()
    }
}

impl InnerGlobalInterface {
    /// Creates the interface state, initially disabled.
    fn new() -> Self {
        Self {
            state: GlobalInterfaceState::Disabled,
        }
    }

    /// Enables the global interface and discovers the CSG interfaces.
    ///
    /// This reads the firmware's control block to set up the global input/output
    /// interfaces; it configures timers and shader core allocation; and it discovers
    /// available CSG interfaces.
    fn enable(
        &mut self,
        dev: &Device,
        iomem: &IoMem<'_>,
        shared_section: &Section,
        gpu_info: &GpuInfo,
        core_clk: &Clk,
        event_wait: &Wait,
    ) -> Result {
        let vmap = Arc::new(shared_section.mem.bo().owned_vmap::<0>()?, GFP_KERNEL)?;
        let va_range = shared_section.mem.va_range();

        let glb_control = FwInterface::<Region<GLB_CONTROL_BLOCK_SIZE>>::new(
            dev,
            &vmap,
            va_range,
            va_range.start,
        )?;

        let version = glb_control.read(GLB_VERSION);
        if version.major().get() == 0 {
            dev_err!(
                dev,
                "CSF interface version is 0. Firmware may have failed to boot."
            );
            return Err(EINVAL);
        }
        dev_info!(
            dev,
            "CSF interface version: {}.{}.{}",
            version.major().get(),
            version.minor().get(),
            version.patch().get()
        );

        let input_va = glb_control.read(GLB_INPUT_VA);
        let glb_input = FwInterface::<FwRegion<GLB_INPUT_BLOCK_SIZE>>::new(
            dev,
            &vmap,
            va_range,
            input_va.value().get().into(),
        )?;

        let output_va = glb_control.read(GLB_OUTPUT_VA);
        let glb_output = FwInterface::<Region<GLB_OUTPUT_BLOCK_SIZE>>::new(
            dev,
            &vmap,
            va_range,
            output_va.value().get().into(),
        )?;

        Self::configure_glb_input(&glb_input, gpu_info, core_clk)?;
        let ack_mask = Self::configure_glb_requests(&glb_input, &glb_output)?;

        // Ring the global doorbell to notify the MCU.
        iomem.write(DOORBELL::at(0), DOORBELL::zeroed().with_ring(true));

        // Wait for the firmware to acknowledge the initial global configuration.
        let request_field = GlobalInterfaceRequests::new(&glb_input, &glb_output);

        if let Err(e) = request_field.wait_acks(ack_mask, event_wait, 1000) {
            dev_err!(dev, "CSF firmware failed to ACK initial GLB config");
            return Err(e);
        }

        // Read how many CSG interfaces exist.
        let csg_num = glb_control.read(GLB_GROUP_NUM).value().get();

        // Read the stride between CSG control blocks.
        let csg_stride = glb_control.read(GLB_GROUP_STRIDE).value().get() as usize;

        if csg_stride < CSG_CONTROL_BLOCK_SIZE {
            dev_err!(
                dev,
                "CSG stride {} is smaller than control block size {}",
                csg_stride,
                CSG_CONTROL_BLOCK_SIZE
            );
            return Err(EINVAL);
        }

        // Validate the CSG number reported.
        if csg_num as usize > super::MAX_CSG {
            dev_err!(
                dev,
                "Too many CSGs: hardware reports {}, max supported {}",
                csg_num,
                super::MAX_CSG
            );
            return Err(EINVAL);
        }

        let enabled = EnabledGlobalInterface {
            glb_control,
            glb_input,
            glb_output,
            csg_stride,
            csg_num: csg_num as usize,
            csg: KVec::with_capacity(csg_num as usize, GFP_KERNEL)?,
        };

        self.state = GlobalInterfaceState::Enabled(enabled);
        self.init_csg(dev, shared_section)?;
        Ok(())
    }

    /// Programs GLB input-block configuration registers.
    ///
    /// Writes shader core allocation and timer values. These settings are applied
    /// by firmware only after the corresponding GLB_REQ bits are updated.
    fn configure_glb_input(
        glb_input: &FwInterface<FwRegion<GLB_INPUT_BLOCK_SIZE>>,
        gpu_info: &GpuInfo,
        core_clk: &Clk,
    ) -> Result {
        // Make all present shader cores available for endpoint allocation.
        glb_input.write(
            GLB_ALLOC_EN,
            GLB_ALLOC_EN::zeroed().with_mask(gpu_info.shader_present),
        );

        // Configure power-down delay for shader and tiler domains.
        // The firmware powers down a domain after it has been idle for this duration,
        // and cancels the timeout if work arrives before expiry.

        // Power-down delay after idle, in microseconds.
        const PWROFF_HYSTERESIS_US: u32 = 10_000;
        let (pwroff_timeout, pwroff_source) = conv_timeout(core_clk, PWROFF_HYSTERESIS_US)?;
        let pwroff_source = pwroff_source.into();
        let pwroff_timeout = Bounded::<u32, 31>::try_new(pwroff_timeout).ok_or(EINVAL)?;
        glb_input.write(
            GLB_PWROFF_TIMER,
            GLB_PWROFF_TIMER::zeroed()
                .with_timeout(pwroff_timeout)
                .with_timer_source(pwroff_source),
        );

        // Configure forward progress timeout.
        //
        // Keep this aligned with panthor, which programs a fixed GPU-cycle timeout.
        // The real-time duration therefore varies with the GPU clock rate (e.g. ~5.24 s
        // at 500 MHz, longer at lower frequencies).
        //
        // The hardware stores the timeout in units of 1024 cycles, so encode the raw
        // cycle count by shifting right by 10.
        const PROGRESS_TIMEOUT_CYCLES: u32 = 5 * 500 * 1024 * 1024;
        const PROGRESS_TIMEOUT_SCALE_SHIFT: u32 = 10;
        let progress_timeout = PROGRESS_TIMEOUT_CYCLES >> PROGRESS_TIMEOUT_SCALE_SHIFT;
        glb_input.write(
            GLB_PROGRESS_TIMER,
            GLB_PROGRESS_TIMER::zeroed().with_timeout(progress_timeout),
        );

        // Configure the delay before reporting the GPU as idle.
        const IDLE_HYSTERESIS_US: u32 = 800;
        let (idle_timeout, idle_source) = conv_timeout(core_clk, IDLE_HYSTERESIS_US)?;
        let idle_source = idle_source.into();
        let idle_timeout = Bounded::<u32, 31>::try_new(idle_timeout).ok_or(EINVAL)?;
        glb_input.write(
            GLB_IDLE_TIMER,
            GLB_IDLE_TIMER::zeroed()
                .with_timeout(idle_timeout)
                .with_timer_source(idle_source),
        );

        Ok(())
    }

    /// Programs GLB_REQ and ACK IRQ mask after GLB input registers are configured.
    ///
    /// This sets desired persistent states, toggles configuration-update requests,
    /// and returns the GLB_REQ bits that must be acknowledged by firmware.
    fn configure_glb_requests(
        glb_input: &FwInterface<FwRegion<GLB_INPUT_BLOCK_SIZE>>,
        glb_output: &FwInterface<Region<GLB_OUTPUT_BLOCK_SIZE>>,
    ) -> Result<GLB_REQ> {
        // Firmware updates GLB_ACK (output block) in response to GLB_REQ.
        // GLB_ACK_IRQ_MASK selects which of these updates trigger a host interrupt.
        glb_input.write(
            GLB_ACK_IRQ_MASK,
            GLB_ACK_IRQ_MASK::zeroed()
                .with_cfg_progress_timer(true)
                .with_cfg_alloc_en(true)
                .with_cfg_pwroff_timer(true)
                .with_idle_enable(true)
                .with_idle_event(true)
                .with_counter_enable(true),
        );

        // Requests whose value represents the desired persistent state.
        let cur_req = glb_input.read(GLB_REQ);
        glb_input.write(
            GLB_REQ,
            cur_req.with_idle_enable(true).with_counter_enable(true),
        );

        let request_field = GlobalInterfaceRequests::new(glb_input, glb_output);

        // Fields that require toggle semantics.
        let toggle_mask = GLB_REQ::zeroed()
            .with_cfg_progress_timer(true)
            .with_cfg_alloc_en(true)
            .with_cfg_pwroff_timer(true);

        request_field.toggle_requests(toggle_mask)?;

        // All fields we want to wait for completion on (REQ == ACK).
        let ack_mask = GLB_REQ::zeroed()
            .with_cfg_progress_timer(true)
            .with_cfg_alloc_en(true)
            .with_cfg_pwroff_timer(true)
            .with_idle_enable(true)
            .with_counter_enable(true);

        Ok(ack_mask)
    }

    /// Initialize CSG interfaces.
    ///
    /// This uses the previously read CSG count to create and enable each CSG interface.
    fn init_csg(&mut self, dev: &Device, shared_section: &Section) -> Result {
        let enabled = match &mut self.state {
            GlobalInterfaceState::Enabled(e) => e,
            GlobalInterfaceState::Disabled => return Err(EINVAL),
        };

        for csg_idx in 0..enabled.csg_num {
            // Create and enable the CSG interface.
            let mut csg = CsgInterface::new(csg_idx)?;
            csg.enable(dev, shared_section, csg_idx, enabled.csg_stride)?;

            enabled.csg.push(csg, GFP_KERNEL)?;
        }

        Ok(())
    }

    fn csg(&self, index: usize) -> Option<&CsgInterface> {
        let enabled = match &self.state {
            GlobalInterfaceState::Enabled(e) => e,
            GlobalInterfaceState::Disabled => return None,
        };

        enabled.csg.get(index)
    }

    fn csg_slot_count(&self) -> Result<u32> {
        let enabled = match &self.state {
            GlobalInterfaceState::Enabled(e) => e,
            GlobalInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_num as u32)
    }

    fn csif_info_counts(&self) -> Result<(u32, u32, u32, u32)> {
        let csg = self.csg(0).ok_or(EINVAL)?;
        let cs = csg.cs(0).ok_or(EINVAL)?;

        Ok((
            self.csg_slot_count()?,
            csg.cs_slot_count()?,
            cs.work_regs()?,
            cs.scoreboards()?,
        ))
    }

    fn group_suspend_buf_sizes(&self) -> Result<(u32, u32)> {
        let csg = self.csg(0).ok_or(EINVAL)?;

        csg.suspend_buf_sizes()
    }
}
