// SPDX-License-Identifier: GPL-2.0 or MIT

//! IRQ handling for the Job IRQ.
//!
//! The Job IRQ signals events from the MCU, including global interface acknowledgements.

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
    sync::{
        aref::ARef,
        Arc, //
    },
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
};

const CSG_IRQ_MASK: u32 = (1u32 << super::MAX_CSG) - 1;

pub(crate) struct JobIrq {
    iomem: Arc<Devres<IoMem>>,
}

pub(crate) fn job_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<Bound>,
    iomem: Arc<Devres<IoMem>>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<JobIrq>>, Error> + 'a> {
    let io = iomem.access(pdev.as_ref())?;
    io.write_reg(
        JOB_IRQ_MASK::zeroed()
            .with_const_csg::<CSG_IRQ_MASK>()
            .with_glb(true),
    );
    let job_irq = JobIrq { iomem: iomem.clone() };

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
        tdev.fw.notify_event();

        if JOB_IRQ_RAWSTAT::from_raw(status).glb() {
            tdev.fw.notify_ready();
        }
    }
}
