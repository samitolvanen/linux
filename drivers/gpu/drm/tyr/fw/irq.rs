// SPDX-License-Identifier: GPL-2.0 or MIT

//! IRQ handling for the Job IRQ.
//!
//! The Job IRQ signals events from the MCU, including global interface acknowledgements.

use kernel::{
    device::Bound,
    io::{
        mem::DevresIoMem,
        Io, //
    },
    irq::ThreadedRegistration,
    platform,
    prelude::*,
    sizes::SZ_2M,
    sync::{
        aref::ARef,
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
        TyrDrmDevice,
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

pub(crate) struct JobIrq {
    fw_ready: Arc<Atomic<bool>>,
    event_wait: Arc<Wait>,
    boot_wait: Arc<Wait>,
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
    fw_ready: Arc<Atomic<bool>>,
    event_wait: Arc<Wait>,
    boot_wait: Arc<Wait>,
) -> Result<impl PinInit<ThreadedRegistration<'drm, TyrIrq<'drm, JobIrq>>, Error> + 'drm> {
    let mask = JOB_IRQ_MASK::zeroed()
        .with_const_csg::<CSG_IRQ_MASK>()
        .with_glb(true);

    let io = iomem.access(pdev.as_ref())?;
    io.write_reg(JOB_IRQ_CLEAR::from_raw(mask.into_raw()));
    io.write_reg(mask);

    let job_irq = JobIrq {
        fw_ready,
        event_wait,
        boot_wait,
    };

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
        io.write_reg(
            JOB_IRQ_MASK::zeroed()
                .with_const_csg::<CSG_IRQ_MASK>()
                .with_glb(true),
        );
    }

    fn read_raw_status(&self, io: &IoMem<'_>) -> u32 {
        io.read(JOB_IRQ_RAWSTAT).into_raw()
    }

    fn clear_status(&self, io: &IoMem<'_>, status: u32) {
        io.write_reg(JOB_IRQ_CLEAR::from_raw(status));
    }

    fn mask(&self) -> u32 {
        JOB_IRQ_MASK::zeroed()
            .with_const_csg::<CSG_IRQ_MASK>()
            .with_glb(true)
            .into_raw()
    }

    fn handle(&self, _tdev: &TyrDrmDevice, status: u32) {
        self.event_wait.notify_all();

        if JOB_IRQ_RAWSTAT::from_raw(status).glb() {
            self.fw_ready.store(true, Release);
            self.boot_wait.notify_all();
        }
    }
}
