// SPDX-License-Identifier: GPL-2.0 or MIT

//! IRQ handling for the Job IRQ.
//!
//! The Job IRQ signals events from the MCU, including global interface acknowledgements.
#![allow(dead_code)]

use kernel::{
    device::Bound,
    io::Io,
    irq::ThreadedRegistration,
    platform,
    prelude::*,
    sync::{
        atomic::{
            Atomic,
            Release, //
        },
        Arc, //
    }, //
};

use crate::{
    driver::{
        IoMem,
        TyrIrq,
        TyrIrqTrait, //
    },
    regs::job_control::{
        JOB_IRQ_CLEAR,
        JOB_IRQ_MASK,
        JOB_IRQ_RAWSTAT,
        JOB_IRQ_STATUS, //
    },
    wait::Wait, //
};

const CSG_IRQ_MASK: u32 = (1u32 << super::MAX_CSG) - 1;

pub(crate) struct JobIrq<'drm> {
    iomem: Arc<IoMem<'drm>>,
    fw_ready: Arc<Atomic<bool>>,
    ready_wait: Arc<Wait>,
}

/// Unmasks the Job IRQ sources and registers the handler.
///
/// # Safety
///
/// Callers must not `mem::forget()` the resulting registration or otherwise prevent its
/// `Drop` implementation from running.
pub(crate) unsafe fn job_irq_init<'drm>(
    pdev: &'drm platform::Device<Bound>,
    iomem: Arc<IoMem<'drm>>,
    fw_ready: Arc<Atomic<bool>>,
    ready_wait: Arc<Wait>,
) -> impl PinInit<ThreadedRegistration<'drm, TyrIrq<JobIrq<'drm>>>, Error> + 'drm {
    iomem.write_reg(
        JOB_IRQ_MASK::zeroed()
            .with_const_csg::<CSG_IRQ_MASK>()
            .with_glb(true),
    );
    let job_irq = JobIrq {
        iomem: iomem.clone(),
        fw_ready,
        ready_wait,
    };

    // SAFETY: The caller guarantees that the registration is not leaked.
    unsafe { TyrIrq::request(pdev, c"job", job_irq) }
}

impl TyrIrqTrait for JobIrq<'_> {
    fn read_status(&self) -> u32 {
        self.iomem.read(JOB_IRQ_STATUS).into_raw()
    }

    fn clear_mask(&self) {
        self.iomem.write_reg(JOB_IRQ_MASK::zeroed());
    }

    fn reenable_mask(&self) {
        self.iomem.write_reg(
            JOB_IRQ_MASK::zeroed()
                .with_const_csg::<CSG_IRQ_MASK>()
                .with_glb(true),
        );
    }

    fn read_raw_status(&self) -> u32 {
        self.iomem.read(JOB_IRQ_RAWSTAT).into_raw()
    }

    fn clear_status(&self, status: u32) {
        self.iomem.write_reg(JOB_IRQ_CLEAR::from_raw(status));
    }

    fn mask(&self) -> u32 {
        JOB_IRQ_MASK::zeroed()
            .with_const_csg::<CSG_IRQ_MASK>()
            .with_glb(true)
            .into_raw()
    }

    fn handle(&self, status: u32) {
        if JOB_IRQ_RAWSTAT::from_raw(status).glb() {
            self.fw_ready.store(true, Release);
            self.ready_wait.notify_all();
        }
    }
}
