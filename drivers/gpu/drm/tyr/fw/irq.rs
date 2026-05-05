// SPDX-License-Identifier: GPL-2.0 or MIT

//! Firmware Job IRQ handling and readiness state.
//!
//! This module owns the Job IRQ registration plus the wait state used for
//! firmware events and initial GLB readiness.

use core::sync::atomic::{
    AtomicBool,
    Ordering,
};

use kernel::{
    c_str,
    device::{
        Bound,
        Device, //
    },
    devres::Devres,
    io::Io,
    irq::ThreadedRegistration,
    new_mutex,
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    },
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice, //
    },
    irq::{
        TyrIrq,
        TyrIrqTrait,
    },
    regs::job_control::{
        JOB_IRQ_CLEAR,
        JOB_IRQ_MASK,
        JOB_IRQ_RAWSTAT,
        JOB_IRQ_STATUS, //
    },
    new_wait,
    wait::{
        Wait,
        WaitResult,
    },
};

const CSG_IRQ_MASK: u32 = (1u32 << super::MAX_CSG) - 1;

#[derive(Clone)]
pub(crate) struct JobIrqState {
    event_wait: Arc<Wait>,
    boot_wait: Arc<Wait>,
    fw_ready: Arc<AtomicBool>,
}

impl JobIrqState {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            event_wait: new_wait!()?,
            boot_wait: new_wait!()?,
            fw_ready: Arc::new(AtomicBool::new(false), GFP_KERNEL)?,
        })
    }

    pub(crate) fn event_wait_arc(&self) -> Arc<Wait> {
        self.event_wait.clone()
    }

    pub(crate) fn wait_ready(&self, timeout_ms: u32) -> Result {
        self.boot_wait.wait_interruptible_timeout(timeout_ms, || {
            if self.fw_ready.load(Ordering::Acquire) {
                Ok(WaitResult::Done)
            } else {
                Ok(WaitResult::Retry)
            }
        })
    }

    pub(crate) fn handle(&self, status: u32) {
        self.event_wait.notify_all();

        if JOB_IRQ_RAWSTAT::from_raw(status).glb() {
            self.fw_ready.store(true, Ordering::Release);
            self.boot_wait.notify_all();
        }
    }
}

pub(crate) struct JobIrq {
    iomem: Arc<Devres<IoMem>>,
    state: JobIrqState,
}

pub(crate) fn job_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<Bound>,
    iomem: Arc<Devres<IoMem>>,
    state: JobIrqState,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<JobIrq>>, Error> + 'a> {
    let io = iomem.access(pdev.as_ref())?;
    io.write_reg(
        JOB_IRQ_MASK::zeroed()
            .with_const_csg::<CSG_IRQ_MASK>()
            .with_glb(true),
    );
    let job_irq = JobIrq {
        iomem: iomem.clone(),
        state,
    };

    TyrIrq::request(pdev, tdev, c_str!("job"), job_irq)
}

impl TyrIrqTrait for JobIrq {
    fn read_status(&self, dev: &Device<Bound>) -> u32 {
        match self.iomem.access(dev) {
            Ok(io) => io.read(JOB_IRQ_STATUS).into_raw(),
            Err(_) => 0,
        }
    }

    fn disable_all(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(JOB_IRQ_MASK::zeroed());
        }
    }

    fn reenable(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(
                JOB_IRQ_MASK::zeroed()
                    .with_const_csg::<CSG_IRQ_MASK>()
                    .with_glb(true),
            );
        }
    }

    fn read_raw_status(&self, dev: &Device<Bound>) -> u32 {
        match self.iomem.access(dev) {
            Ok(io) => io.read(JOB_IRQ_RAWSTAT).into_raw(),
            Err(_) => 0,
        }
    }

    fn clear_status(&self, dev: &Device<Bound>, status: u32) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(JOB_IRQ_CLEAR::from_raw(status));
        }
    }

    fn mask(&self) -> u32 {
        JOB_IRQ_MASK::zeroed()
            .with_const_csg::<CSG_IRQ_MASK>()
            .with_glb(true)
            .into_raw()
    }

    fn handle(&self, tdev: &TyrDrmDevice, status: u32) {
        let _ = tdev;
        self.state.handle(status);
    }
}
