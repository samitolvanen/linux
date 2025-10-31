// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU IRQ handler.
//!
//! The interrupts return, among many other things, information about faulting
//! addresses.

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
    crate::regs::MMU_INT_MASK.write(&iomem, u32::MAX)?;

    let irq_type = MmuIrq {
        iomem: iomem.clone(),
    };

    TyrIrq::request(pdev, tdev, c_str!("mmu"), irq_type)
}

impl TyrIrqTrait for MmuIrq {
    fn read_status(&self) -> u32 {
        regs::MMU_INT_STAT.read(&self.iomem).unwrap_or_default()
    }

    fn disable_all(&self) {
        let _ = regs::MMU_INT_MASK.write(&self.iomem, 0);
    }

    fn reenable(&self) {
        let _ = regs::MMU_INT_MASK.write(&self.iomem, self.mask());
    }

    fn read_raw_status(&self) -> u32 {
        regs::MMU_INT_RAWSTAT.read(&self.iomem).unwrap_or_default()
    }

    fn clear_status(&self, status: u32) {
        let _ = regs::MMU_INT_CLEAR.write(&self.iomem, status);
    }

    fn mask(&self) -> u32 {
        u32::MAX // for now.
    }

    fn handle(&self, _: &TyrDevice, status: u32) {
        let status = status & kernel::bits::genmask_u32(0..=15);
        let _ = decode_faults(status, &self.iomem);
    }
}
