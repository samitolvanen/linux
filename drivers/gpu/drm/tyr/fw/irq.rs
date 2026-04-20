// SPDX-License-Identifier: GPL-2.0 or MIT

//! The IRQ handling for the Job IRQs.
//!
//! The Job IRQ controls our interactions with the MCU.

use kernel::c_str;
use kernel::device::{Bound, Device};
use kernel::devres::Devres;
use kernel::irq::ThreadedRegistration;
use kernel::platform;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::types::ARef;

use crate::driver::IoMem;
use crate::driver::TyrDevice;
use crate::driver::TyrIrq;
use crate::driver::TyrIrqTrait;
use crate::regs;
use crate::wait::Wait;

pub(crate) struct JobIrq {
    iomem: Arc<Devres<IoMem>>,
    event_wait: Arc<Wait>,
    boot_wait: Arc<Wait>,
}

pub(crate) fn job_irq_init<'a>(
    tdev: ARef<TyrDevice>,
    pdev: &'a platform::Device<kernel::device::Bound>,
    iomem: Arc<Devres<IoMem>>,
    event_wait: Arc<Wait>,
    boot_wait: Arc<Wait>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<JobIrq>>, Error> + 'a> {
    crate::regs::JOB_IRQ_MASK.write(pdev.as_ref(), &iomem, u32::MAX)?;

    let irq_type = JobIrq {
        iomem: iomem.clone(),
        event_wait,
        boot_wait,
    };

    TyrIrq::request(pdev, tdev, c_str!("job"), irq_type)
}

impl TyrIrqTrait for JobIrq {
    fn read_status(&self, dev: &Device<Bound>) -> u32 {
        regs::JOB_IRQ_STAT
            .read(dev, &self.iomem)
            .unwrap_or_default()
    }

    fn disable_all(&self, dev: &Device<Bound>) {
        let _ = regs::JOB_IRQ_MASK.write(dev, &self.iomem, 0);
    }

    fn reenable(&self, dev: &Device<Bound>, _tdev: &TyrDevice) {
        let _ = regs::JOB_IRQ_MASK.write(dev, &self.iomem, self.mask());
    }

    fn read_raw_status(&self, dev: &Device<Bound>) -> u32 {
        regs::JOB_IRQ_RAWSTAT
            .read(dev, &self.iomem)
            .unwrap_or_default()
    }

    fn clear_status(&self, dev: &Device<Bound>, status: u32) {
        let _ = regs::JOB_IRQ_CLEAR.write(dev, &self.iomem, status);
    }

    fn mask(&self) -> u32 {
        u32::MAX // for now.
    }

    fn handle(&self, tdev: &TyrDevice, status: u32) {
        self.event_wait.notify_all();

        if status & regs::JOB_IRQ_GLOBAL_IF != 0 {
            let _ = tdev.fw.with_locked_global_iface(|glb| {
                if !glb.booted {
                    glb.booted = true;
                }
                Ok(())
            });
        }

        self.boot_wait.notify_all();
    }
}
