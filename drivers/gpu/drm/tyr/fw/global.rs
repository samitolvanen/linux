// SPDX-License-Identifier: GPL-2.0 or MIT

//! Code to control the global interface of the CSF firmware.

use core::ops::Deref;

use csg::CommandStreamGroup;
use kernel::bits::genmask_u32;
use kernel::clk::Clk;
use kernel::devres::Devres;
use kernel::impl_has_delayed_work;
use kernel::io;
use kernel::io::mem::IoMem;
use kernel::kvec;
use kernel::new_mutex;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::time;
#[allow(unused)]
use kernel::workqueue;
use kernel::workqueue::WorkItem;

use crate::driver::TyrData;
use crate::driver::TyrDevice;
use crate::fw::impl_shared_section_read;
use crate::fw::impl_shared_section_rw;
use crate::fw::RequestField;
use crate::fw::SharedSectionEntry;
use crate::gpu::GpuInfo;
use crate::regs::Doorbell;
use crate::regs::CSF_GLB_DOORBELL_ID;
use crate::wait::Wait;

use super::{Section, SharedSectionRange};

pub(crate) mod cs;
pub(crate) mod csg;

#[allow(dead_code)]
mod constants {
    use kernel::bits::{bit_u32, genmask_u32};

    pub(super) const GLB_TIMER_SOURCE_GPU_COUNTER: u32 = bit_u32(31);
    pub(super) const PROGRESS_TIMEOUT_CYCLES: u32 = 5 * 500 * 1024 * 1024;
    pub(super) const PROGRESS_TIMEOUT_SCALE_SHIFT: u32 = 10;
    pub(super) const IDLE_HYSTERESIS_US: u32 = 800;
    pub(super) const PWROFF_HYSTERESIS_US: u32 = 10000;
    pub(super) const GLB_HALT: u32 = bit_u32(0);
    pub(super) const GLB_CFG_PROGRESS_TIMER: u32 = bit_u32(1);
    pub(super) const GLB_CFG_ALLOC_EN: u32 = bit_u32(2);
    pub(super) const GLB_CFG_POWEROFF_TIMER: u32 = bit_u32(3);
    pub(super) const GLB_PROTM_ENTER: u32 = bit_u32(4);
    pub(super) const GLB_PERFCNT_EN: u32 = bit_u32(5);
    pub(super) const GLB_PERFCNT_SAMPLE: u32 = bit_u32(6);
    pub(super) const GLB_COUNTER_EN: u32 = bit_u32(7);
    pub(super) const GLB_PING: u32 = bit_u32(8);
    pub(super) const GLB_FWCFG_UPDATE: u32 = bit_u32(9);
    pub(super) const GLB_IDLE_EN: u32 = bit_u32(10);
    pub(super) const GLB_SLEEP: u32 = bit_u32(12);
    pub(super) const GLB_INACTIVE_COMPUTE: u32 = bit_u32(20);
    pub(super) const GLB_INACTIVE_FRAGMENT: u32 = bit_u32(21);
    pub(super) const GLB_INACTIVE_TILER: u32 = bit_u32(22);
    pub(super) const GLB_PROTM_EXIT: u32 = bit_u32(23);
    pub(super) const GLB_PERFCNT_THRESHOLD: u32 = bit_u32(24);
    pub(super) const GLB_PERFCNT_OVERFLOW: u32 = bit_u32(25);
    pub(super) const GLB_IDLE: u32 = bit_u32(26);
    pub(super) const GLB_DBG_CSF: u32 = bit_u32(30);
    pub(super) const GLB_DBG_HOST: u32 = bit_u32(31);
    pub(super) const GLB_REQ_MASK: u32 = genmask_u32(0..=10);
    pub(super) const GLB_EVT_MASK: u32 = genmask_u32(20..=26);

    pub(super) const PING_INTERVAL_MS: i64 = 12000;
}

use constants::*;

fn glb_timer_val(val: u32) -> u32 {
    val & genmask_u32(0..=30)
}

#[repr(transparent)]
/// A value that is valid to pass for timeout fields in the global interface.
struct TimeoutCycles(u32);

impl TimeoutCycles {
    fn from_micro(core_clk: &Clk, timeout_us: u32) -> Result<Self> {
        let timer_rate = core_clk.rate().as_hz() as u64;

        if timer_rate == 0 {
            return Err(EINVAL);
        }

        let mut mod_cycles =
            (u64::from(timeout_us) * timer_rate).div_ceil(1000000 << 10);

        if mod_cycles > glb_timer_val(u32::MAX).into() {
            pr_err!("Invalid timeout computed\n");
            mod_cycles = glb_timer_val(u32::MAX).into();
        }

        let mod_cycles = u32::try_from(mod_cycles)?;
        Ok(Self(
            glb_timer_val(mod_cycles) | GLB_TIMER_SOURCE_GPU_COUNTER,
        ))
    }
}

impl From<TimeoutCycles> for u32 {
    fn from(value: TimeoutCycles) -> Self {
        value.0
    }
}

/// The global control interface.
#[repr(C)]
pub(crate) struct Control {
    pub(crate) version: u32,
    pub(crate) features: u32,
    pub(crate) input_va: u32,
    pub(crate) output_va: u32,
    pub(crate) group_num: u32,
    pub(crate) group_stride: u32,
    pub(crate) perfcnt_size: u32,
    pub(crate) instr_features: u32,
}

impl Control {
    /// CSF major version.
    pub(crate) fn version_major(&self) -> u32 {
        self.version >> 24
    }

    /// CSF minor version.
    pub(crate) fn version_minor(&self) -> u32 {
        (self.version >> 16) & 0xff
    }

    /// CSF patch version.
    pub(crate) fn version_patch(&self) -> u32 {
        self.version & 0xffff
    }
}

#[repr(C)]
#[derive(Debug)]
/// The input area for the global interface
pub(crate) struct Input {
    pub(crate) req: u32,
    pub(crate) ack_irq_mask: u32,
    pub(crate) doorbell_req: u32,
    pub(crate) reserved1: u32,
    pub(crate) progress_timer: u32,
    pub(crate) poweroff_timer: u32,
    pub(crate) core_en_mask: u32,
    pub(crate) reserved2: u32,
    pub(crate) perfcnt_as: u32,
    pub(crate) perfcnt_base: u64,
    pub(crate) perfcnt_extratct: u32,
    pub(crate) reserved3: [u32; 3],
    pub(crate) percnt_config: u32,
    pub(crate) percnt_csg_select: u32,
    pub(crate) perfcnt_fw_enable: u32,
    pub(crate) perfcnt_csg_enable: u32,
    pub(crate) perfcnt_csf_enable: u32,
    pub(crate) perfcnt_shader_enable: u32,
    pub(crate) perfcnt_tiler_enable: u32,
    pub(crate) perfcnt_mmu_l2_enable: u32,
    pub(crate) reserved4: [u32; 8],
    pub(crate) idle_timer: u32,
}

#[repr(C)]
#[derive(Debug)]
/// The output area for the global interface
pub(crate) struct Output {
    pub(crate) ack: u32,
    pub(crate) reserved1: u32,
    pub(crate) doorbell_ack: u32,
    pub(crate) reserved2: u32,
    pub(crate) halt_status: u32,
    pub(crate) perfcnt_status: u32,
    pub(crate) perfcnt_insert: u32,
}

impl_shared_section_rw!(Control);
impl_shared_section_rw!(Input);
impl_shared_section_read!(Output);

pub(crate) enum GlobalInterfaceState {
    Disabled,
    Enabled(EnabledGlobalInterface),
}

impl GlobalInterfaceState {
    fn enabled(&self) -> Result<&EnabledGlobalInterface> {
        match self {
            GlobalInterfaceState::Enabled(enabled) => Ok(enabled),
            GlobalInterfaceState::Disabled => Err(EINVAL),
        }
    }

    fn enabled_mut(&mut self) -> Result<&mut EnabledGlobalInterface> {
        match self {
            GlobalInterfaceState::Enabled(enabled) => Ok(enabled),
            GlobalInterfaceState::Disabled => Err(EINVAL),
        }
    }
}

struct EnabledGlobalInterface {
    control_area: SharedSectionRange,
    input_area: SharedSectionRange,
    output_area: SharedSectionRange,

    csgs: KVec<CommandStreamGroup>,
}

/// The global interface.
pub(crate) struct GlobalInterface {
    state: GlobalInterfaceState,

    iomem: Arc<Devres<IoMem>>,

    shared_section: Arc<Mutex<KBox<Section>>>,

    event_wait: Arc<Wait>,

    /// Whether the MCU has booted.
    pub(super) booted: bool,
}

impl GlobalInterface {
    pub(super) fn new(
        shared_section: KBox<Section>,
        iomem: Arc<Devres<IoMem>>,
        req_wait: Arc<Wait>,
    ) -> Result<Self> {
        let shared_section =
            Arc::pin_init(new_mutex!(shared_section), GFP_KERNEL)?;

        Ok(Self {
            state: GlobalInterfaceState::Disabled,
            iomem,
            shared_section,
            event_wait: req_wait,
            booted: false,
        })
    }

    pub(crate) fn enable(
        &mut self,
        tdev: &TyrDevice,
        gpu_info: &GpuInfo,
        core_clk: &Clk,
    ) -> Result {
        // This takes a mutex internally in clk_prepare().
        let poweroff_timer =
            TimeoutCycles::from_micro(core_clk, PWROFF_HYSTERESIS_US)?.into();

        let control_area = SharedSectionRange {
            shared_section: self.shared_section.clone(),
            start: 0,
            end: core::mem::size_of::<Control>(),
        };

        let op = || Control::read(&control_area);
        let cond = |control: &Control| -> bool { control.version != 0 };
        let _ = io::poll::read_poll_timeout(
            op,
            cond,
            time::Delta::from_millis(0),
            time::Delta::from_millis(200),
        );

        let control = Control::read(&control_area)?;
        if control.version == 0 {
            pr_err!(
                "MCU firmware version is 0. Firmware may have failed to boot\n"
            );
            return Err(EINVAL);
        }

        let mut input_area = self.shared_range(
            control.input_va.into(),
            core::mem::size_of::<Input>(),
        )?;

        let output_area = self.shared_range(
            control.output_va.into(),
            core::mem::size_of::<Output>(),
        )?;

        /// The start of the CSG control area for the first CSG.
        const CSF_GROUP_CONTROL_OFFSET: u32 = 0x1000;

        let mut csgs: KVec<CommandStreamGroup> = kvec![];
        for csg_idx in 0..control.group_num {
            let iface_offset =
                CSF_GROUP_CONTROL_OFFSET + (csg_idx * control.group_stride);

            let csg =
                CommandStreamGroup::init(self, iface_offset, csg_idx as usize)?;

            if let Some(first) = csgs.first() {
                if !first.is_identical(&csg)? {
                    pr_err!("Expecting identical CSG slots\n");
                    return Err(EINVAL);
                }
            }

            csgs.push(csg, GFP_KERNEL)?;
        }

        pr_info!(
            "CSF FW using interface v.{}.{}.{}, Features {} Instrumentation features {}\n",
            control.version_major(),
            control.version_minor(),
            control.version_patch(),
            control.features,
            control.instr_features
        );

        let mut input = Input::read(&input_area)?;

        // Enable all shader cores.
        input.core_en_mask = gpu_info.shader_present as u32;

        // Setup timers.
        input.poweroff_timer = poweroff_timer;
        input.progress_timer =
            PROGRESS_TIMEOUT_CYCLES >> PROGRESS_TIMEOUT_SCALE_SHIFT;
        input.idle_timer = IDLE_HYSTERESIS_US;

        // Enable the interrupts we care about.
        input.ack_irq_mask = GLB_CFG_ALLOC_EN
            | GLB_PING
            | GLB_CFG_POWEROFF_TIMER
            | GLB_CFG_POWEROFF_TIMER
            | GLB_IDLE_EN
            | GLB_IDLE;

        input.write(&mut input_area)?;

        let req = RequestField::new(
            &input_area,
            core::mem::offset_of!(Input, req),
            core::mem::offset_of!(Output, ack),
        );
        req.update_reqs(GLB_IDLE_EN, GLB_IDLE_EN)?;

        let reqs =
            GLB_CFG_ALLOC_EN | GLB_CFG_POWEROFF_TIMER | GLB_CFG_PROGRESS_TIMER;
        req.toggle_reqs(reqs)?;

        self.ring_glb_doorbell()?;

        let enabled = EnabledGlobalInterface {
            control_area,
            input_area,
            output_area,
            csgs,
        };

        self.state = GlobalInterfaceState::Enabled(enabled);
        self.arm_watchdog(tdev)
    }

    /// Ring the global interface doorbell.
    pub(crate) fn ring_glb_doorbell(&self) -> Result {
        // Make sure that all previous writes are visible to the CSF before it
        // can be awaken.
        kernel::sync::barrier::smp_mb();
        Doorbell::new(CSF_GLB_DOORBELL_ID).write(&self.iomem, 1)
    }

    pub(crate) fn csg(
        &mut self,
        csg_idx: usize,
    ) -> Option<&CommandStreamGroup> {
        match &self.state {
            GlobalInterfaceState::Disabled => None,
            GlobalInterfaceState::Enabled(EnabledGlobalInterface {
                csgs,
                ..
            }) => csgs.get(csg_idx),
        }
    }

    pub(crate) fn csg_mut(
        &mut self,
        csg_idx: usize,
    ) -> Option<&mut CommandStreamGroup> {
        match &mut self.state {
            GlobalInterfaceState::Disabled => None,
            GlobalInterfaceState::Enabled(EnabledGlobalInterface {
                csgs,
                ..
            }) => csgs.get_mut(csg_idx),
        }
    }

    pub(crate) fn arm_watchdog(&self, tdev: &TyrDevice) -> Result {
        tdev.reset_wq
            .enqueue_delayed::<_, 0>(
                tdev.deref().clone(),
                PING_INTERVAL_MS as usize,
            )
            .map_err(|_| EINVAL)
    }

    pub(crate) fn ping(&mut self) -> Result {
        let glb_iface = match self.state {
            GlobalInterfaceState::Enabled(ref enabled) => enabled,
            GlobalInterfaceState::Disabled => {
                pr_err!(
                    "Trying to ping CSF but the global interface is down\n"
                );
                return Ok(());
            }
        };

        let req = RequestField::new(
            &glb_iface.input_area,
            core::mem::offset_of!(Input, req),
            core::mem::offset_of!(Output, ack),
        );

        req.toggle_reqs(GLB_PING)?;

        self.ring_glb_doorbell()?;

        if let Err(ETIMEDOUT) = req.wait_acks(GLB_PING, &self.event_wait, 100) {
            pr_err!("CSF has not responded to a ping request\n");
            pr_err!("The firmware probably crashed\n");
        }

        Ok(())
    }

    /// Computes a range into the shared section for a given VA in the shared
    /// area.
    ///
    /// The result is an offset that can be safely dereferenced by the CPU.
    pub(super) fn shared_range(
        &mut self,
        mcu_va: u64,
        size: usize,
    ) -> Result<SharedSectionRange> {
        let shared_mem_start = u64::from(self.shared_section.lock().va.start);
        let shared_mem_end = u64::from(self.shared_section.lock().va.end);

        if mcu_va < shared_mem_start || mcu_va >= shared_mem_end {
            Err(EINVAL)
        } else {
            let offset = (mcu_va - shared_mem_start) as usize;
            Ok(SharedSectionRange {
                shared_section: self.shared_section.clone(),
                start: offset,
                end: offset + size,
            })
        }
    }

    /// Set the CSG state.
    pub(crate) fn set_csg_state(
        &mut self,
        csg_idx: usize,
        state: csg::GroupState,
    ) -> Result {
        let glb = self.state.enabled_mut()?;
        let csg_iface = glb.csgs.get_mut(csg_idx).ok_or(EINVAL)?;

        csg_iface.set_group_state(state)
    }

    /// Ring the CSG doorbell, thereby instructing CSF to process the requests
    /// made on this CSG.
    pub(crate) fn ring_csg_doorbell(&mut self, csg_idx: usize) -> Result {
        self.doorbell_request()?.toggle_reqs(1 << csg_idx)?;

        self.ring_glb_doorbell()?;

        let op = || self.read_output();
        let cond = |output: &Output| -> bool { output.doorbell_ack == 1 };
        let _ = io::poll::read_poll_timeout(
            op,
            cond,
            time::Delta::from_millis(0),
            time::Delta::from_millis(100),
        );

        Ok(())
    }

    fn shared_section_size(&self) -> usize {
        let shared_section = self.shared_section.lock();
        shared_section.mem.size()
    }

    /// Whether the firmware has booted or not.
    pub(crate) fn booted(&self) -> bool {
        self.booted
    }
}

impl_has_delayed_work! {
    impl HasDelayedWork<Self, 0> for TyrData {
        self.ping_work
    }
}

impl WorkItem<0> for TyrData {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        let res = this.fw.with_locked_global_iface(|glb| {
            glb.ping()?;
            this.reset_wq
                .enqueue_delayed::<_, 0>(
                    this.clone(),
                    PING_INTERVAL_MS as usize,
                )
                .map_err(|_| EINVAL)
        });

        if let Err(err) = res {
            pr_err!(
                "Ping failed: {}, the firmware probably crashed\n",
                err.to_errno()
            );

            if let Ok(mcu_status) = crate::regs::MCU_STATUS.read(&this.iomem) {
                pr_err!("MCU_STATUS is {}\n", mcu_status);
            }
        }
    }
}

impl SharedSectionEntry for GlobalInterface {
    type Control = Control;
    type Input = Input;
    type Output = Output;

    fn read_control(&self) -> Result<Self::Control> {
        let glb = self.state.enabled()?;
        Control::read(&glb.control_area)
    }

    fn write_control(&mut self, control: Self::Control) -> Result {
        let glb = self.state.enabled_mut()?;
        control.write(&mut glb.control_area)
    }

    fn read_input(&self) -> Result<Self::Input> {
        let glb = self.state.enabled()?;
        Input::read(&glb.input_area)
    }

    fn write_input(&mut self, input: Self::Input) -> Result {
        let glb = self.state.enabled_mut()?;
        input.write(&mut glb.input_area)
    }

    fn read_output(&self) -> Result<Self::Output> {
        let glb = self.state.enabled()?;
        Output::read(&glb.output_area)
    }

    fn input_request(&self) -> Result<RequestField> {
        let glb = self.state.enabled()?;

        Ok(RequestField::new(
            &glb.input_area,
            core::mem::offset_of!(Input, req),
            core::mem::offset_of!(Output, ack),
        ))
    }

    fn doorbell_request(&self) -> Result<RequestField> {
        let glb = self.state.enabled()?;

        Ok(RequestField::new(
            &glb.input_area,
            core::mem::offset_of!(Input, doorbell_req),
            core::mem::offset_of!(Output, doorbell_ack),
        ))
    }
}
