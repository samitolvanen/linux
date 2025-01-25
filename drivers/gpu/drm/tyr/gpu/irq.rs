// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU IRQ handler.

use kernel::c_str;
use kernel::devres::Devres;
use kernel::io::mem::IoMem;
use kernel::irq::ThreadedRegistration;
use kernel::platform;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::types::ARef;

use crate::driver::TyrDevice;
use crate::driver::TyrIrq;
use crate::driver::TyrIrqTrait;
use crate::regs;
use crate::wait::Wait;

pub(crate) struct GpuIrq {
    iomem: Arc<Devres<IoMem>>,
    power_on_wait: Arc<Wait<bool>>,
}

pub(crate) fn gpu_irq_init<'a>(
    tdev: ARef<TyrDevice>,
    pdev: &'a platform::Device<kernel::device::Bound>,
    iomem: Arc<Devres<IoMem>>,
    power_on_wait: Arc<Wait<bool>>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<GpuIrq>>, Error> + 'a> {
    crate::regs::GPU_INT_MASK.write(&iomem, u32::MAX)?;

    let irq_type = GpuIrq {
        iomem: iomem.clone(),
        power_on_wait,
    };

    TyrIrq::request(pdev, tdev, c_str!("gpu"), irq_type)
}

impl TyrIrqTrait for GpuIrq {
    fn read_status(&self) -> u32 {
        regs::GPU_INT_STAT.read(&self.iomem).unwrap_or_default()
    }

    fn disable_all(&self) {
        let _ = regs::GPU_INT_MASK.write(&self.iomem, 0);
    }

    fn reenable(&self) {
        let _ = regs::GPU_INT_MASK.write(&self.iomem, self.mask());
    }

    fn read_raw_status(&self) -> u32 {
        regs::GPU_INT_RAWSTAT.read(&self.iomem).unwrap_or_default()
    }

    fn clear_status(&self, status: u32) {
        let _ = regs::GPU_INT_CLEAR.write(&self.iomem, status);
    }

    fn mask(&self) -> u32 {
        u32::MAX
    }

    fn handle(&self, _: &TyrDevice, status: u32) {
        if status
            == regs::GPU_INT_RAWSTAT_RESET_COMPLETED
                | regs::GPU_INT_RAWSTAT_POWER_CHANGED_SINGLE
                | regs::GPU_INT_RAWSTAT_POWER_CHANGED_ALL
        {
            let _ = self.power_on_wait.with_locked_data(|powered_on| {
                *powered_on = true;
                Ok(())
            });

            self.power_on_wait.notify_all();
        }
    }
}
