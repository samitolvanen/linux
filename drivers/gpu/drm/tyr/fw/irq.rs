// SPDX-License-Identifier: GPL-2.0 or MIT

//! The IRQ handling for the Job IRQs.
//!
//! The Job IRQ controls our interactions with the MCU.

use kernel::{
    c_str,
    device::{
        Bound,
        Device, //
    },
    devres::Devres,
    io::Io,
    irq::ThreadedRegistration,
    platform,
    prelude::*,
    sync::Arc,
    types::ARef, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice,
        TyrIrq,
        TyrIrqTrait, //
    },
    regs::{
        job_control,
        JOB_IRQ_GLOBAL_IF, //
    },
    wait::Wait, //
};

pub(crate) struct JobIrq {
    iomem: Arc<Devres<IoMem>>,
    event_wait: Arc<Wait>,
    boot_wait: Arc<Wait>,
}

pub(crate) fn job_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<kernel::device::Bound>,
    iomem: Arc<Devres<IoMem>>,
    event_wait: Arc<Wait>,
    boot_wait: Arc<Wait>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<JobIrq>>, Error> + 'a> {
    // SAFETY: pdev is a bound device.
    let dev = unsafe { pdev.as_ref().as_bound() };
    let io = iomem.access(dev)?;
    io.write_reg(job_control::JOB_IRQ_MASK::from_raw(u32::MAX));

    let irq_type = JobIrq {
        iomem: iomem.clone(),
        event_wait,
        boot_wait,
    };

    TyrIrq::request(pdev, tdev, c_str!("job"), irq_type)
}

impl TyrIrqTrait for JobIrq {
    fn read_status(&self, dev: &Device<Bound>) -> u32 {
        self.iomem
            .access(dev)
            .map(|io| io.read(job_control::JOB_IRQ_STATUS).into_raw())
            .unwrap_or_default()
    }

    fn disable_all(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(job_control::JOB_IRQ_MASK::from_raw(0));
        }
    }

    fn reenable(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(job_control::JOB_IRQ_MASK::from_raw(self.mask()));
        }
    }

    fn read_raw_status(&self, dev: &Device<Bound>) -> u32 {
        self.iomem
            .access(dev)
            .map(|io| io.read(job_control::JOB_IRQ_RAWSTAT).into_raw())
            .unwrap_or_default()
    }

    fn clear_status(&self, dev: &Device<Bound>, status: u32) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(job_control::JOB_IRQ_CLEAR::from_raw(status));
        }
    }

    fn mask(&self) -> u32 {
        u32::MAX // for now.
    }

    fn handle(&self, tdev: &TyrDrmDevice, status: u32) {
        self.event_wait.notify_all();

        let _ = tdev.fw.with_locked_global_iface(|glb| {
            if status & JOB_IRQ_GLOBAL_IF != 0 && !glb.booted {
                glb.booted = true;
            }
            Ok(())
        });

        self.boot_wait.notify_all();

        let _ = tdev.with_locked_scheduler(|sched| {
            sched.set_events(tdev, status);
            Ok(())
        });
    }
}
