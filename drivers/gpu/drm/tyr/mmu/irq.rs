// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU IRQ handler.
//!
//! The interrupts return, among many other things, information about faulting
//! addresses.

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
use crate::mmu::decode_faults;
use crate::regs;

pub(crate) struct MmuIrq {
    iomem: Arc<Devres<IoMem>>,
}

pub(crate) fn mmu_irq_init<'a>(
    tdev: ARef<TyrDevice>,
    pdev: &'a platform::Device<kernel::device::Bound>,
    iomem: Arc<Devres<IoMem>>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<MmuIrq>>, Error> + 'a> {
    crate::regs::MMU_IRQ_MASK.write(pdev.as_ref(), &iomem, u32::MAX)?;

    let irq_type = MmuIrq {
        iomem: iomem.clone(),
    };

    TyrIrq::request(pdev, tdev, c_str!("mmu"), irq_type)
}

impl TyrIrqTrait for MmuIrq {
    fn read_status(&self, dev: &Device<Bound>) -> u32 {
        regs::MMU_IRQ_STAT
            .read(dev, &self.iomem)
            .unwrap_or_default()
    }

    fn disable_all(&self, dev: &Device<Bound>) {
        let _ = regs::MMU_IRQ_MASK.write(dev, &self.iomem, 0);
    }

    fn reenable(&self, dev: &Device<Bound>, tdev: &TyrDevice) {
        let faulty_mask = tdev.with_locked_mmu(|mmu| Ok(mmu.faulty_mask)).unwrap_or(0);
        let _ = regs::MMU_IRQ_MASK.write(dev, &self.iomem, self.mask() & !faulty_mask);
    }

    fn read_raw_status(&self, dev: &Device<Bound>) -> u32 {
        regs::MMU_IRQ_RAWSTAT
            .read(dev, &self.iomem)
            .unwrap_or_default()
    }

    fn clear_status(&self, dev: &Device<Bound>, status: u32) {
        let _ = regs::MMU_IRQ_CLEAR.write(dev, &self.iomem, status);
    }

    fn mask(&self) -> u32 {
        u32::MAX // for now.
    }

    fn handle(&self, tdev: &TyrDevice, status: u32) {
        let status = status & kernel::bits::genmask_u32(0..=15);
        let _ = decode_faults(tdev, status, &self.iomem);

        if status != 0 {}
    }
}
