// SPDX-License-Identifier: GPL-2.0 or MIT

//! Firmware Job IRQ handling and readiness state.
//!
//! This module owns the Job IRQ registration plus the wait state used for
//! firmware events and initial GLB readiness.

use kernel::{
    device::Bound,
    io::{
        mem::DevresIoMem,
        Io, //
    },
    irq::ThreadedRegistration,
    new_mutex,
    platform,
    prelude::*,
    sizes::SZ_2M,
    sync::{
        aref::ARef,
        atomic::{
            Acquire,
            Atomic,
            Release, //
        },
        Arc, //
    }, //
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
    new_wait,
    regs::job_control::{
        JOB_IRQ_CLEAR,
        JOB_IRQ_MASK,
        JOB_IRQ_RAWSTAT,
        JOB_IRQ_STATUS, //
    },
    wait::{
        Wait,
        WaitResult, //
    }, //
};

const CSG_IRQ_MASK: u32 = (1u32 << super::MAX_CSG) - 1;

/// Returns the Job IRQ sources the driver services.
fn job_irq_sources() -> JOB_IRQ_MASK {
    JOB_IRQ_MASK::zeroed()
        .with_const_csg::<CSG_IRQ_MASK>()
        .with_glb(true)
}

/// Wait state shared between the Job IRQ handler and the firmware.
#[derive(Clone)]
pub(crate) struct JobIrqState {
    /// A condvar representing a wait on a firmware event.
    event_wait: Arc<Wait>,

    /// A condvar representing a wait for MCU boot readiness.
    boot_wait: Arc<Wait>,

    /// Latched to `true` by the IRQ handler when the firmware signals readiness via the GLB bit.
    fw_ready: Arc<Atomic<bool>>,
}

impl JobIrqState {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            event_wait: new_wait!()?,
            boot_wait: new_wait!()?,
            fw_ready: Arc::new(Atomic::new(false), GFP_KERNEL)?,
        })
    }

    pub(crate) fn event_wait_arc(&self) -> Arc<Wait> {
        self.event_wait.clone()
    }

    /// Waits until the firmware signals readiness via the GLB IRQ bit.
    pub(crate) fn wait_ready(&self, timeout_ms: u32) -> Result {
        self.boot_wait.wait_interruptible_timeout(timeout_ms, || {
            if self.fw_ready.load(Acquire) {
                Ok(WaitResult::Done)
            } else {
                Ok(WaitResult::Retry)
            }
        })
    }

    pub(crate) fn handle(&self, status: u32) {
        self.event_wait.notify_all();

        if JOB_IRQ_RAWSTAT::from_raw(status).glb() {
            self.fw_ready.store(true, Release);
            self.boot_wait.notify_all();
        }
    }
}

pub(crate) struct JobIrq {
    state: JobIrqState,
}

/// Unmasks the Job IRQ sources and registers the handler.
///
/// # Safety
///
/// Callers must not `mem::forget()` the resulting registration or otherwise prevent its
/// `Drop` implementation from running.
pub(crate) unsafe fn job_irq_init<'drm>(
    pdev: &'drm platform::Device<Bound>,
    tdev: ARef<TyrDrmDevice>,
    iomem: Arc<DevresIoMem<SZ_2M>>,
    state: JobIrqState,
) -> Result<impl PinInit<ThreadedRegistration<'drm, TyrIrq<'drm, JobIrq>>, Error> + 'drm> {
    let mask = job_irq_sources();

    let io = iomem.access(pdev.as_ref())?;
    io.write_reg(JOB_IRQ_CLEAR::from_raw(mask.into_raw()));
    io.write_reg(mask);

    let job_irq = JobIrq { state };

    // SAFETY: The caller guarantees that the registration is not leaked.
    Ok(unsafe { TyrIrq::request(pdev, tdev, c"job", iomem, job_irq) })
}

impl TyrIrqTrait for JobIrq {
    fn read_status(&self, io: &IoMem<'_>) -> u32 {
        io.read(JOB_IRQ_STATUS).into_raw()
    }

    fn disable_all(&self, io: &IoMem<'_>) {
        io.write_reg(JOB_IRQ_MASK::zeroed());
    }

    fn reenable(&self, io: &IoMem<'_>) {
        io.write_reg(job_irq_sources());
    }

    fn read_raw_status(&self, io: &IoMem<'_>) -> u32 {
        io.read(JOB_IRQ_RAWSTAT).into_raw()
    }

    fn clear_status(&self, io: &IoMem<'_>, status: u32) {
        io.write_reg(JOB_IRQ_CLEAR::from_raw(status));
    }

    fn mask(&self) -> u32 {
        job_irq_sources().into_raw()
    }

    fn handle(&self, _tdev: &TyrDrmDevice, _io: &IoMem<'_>, status: u32) {
        self.state.handle(status);
    }
}
