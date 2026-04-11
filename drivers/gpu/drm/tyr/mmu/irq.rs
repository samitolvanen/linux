// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU IRQ handler.
//!
//! The interrupts return, among many other things, information about faulting
//! addresses.

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
    mmu::decode_faults,
    regs::mmu_control, //
};

pub(crate) struct MmuIrq {
    iomem: Arc<Devres<IoMem>>,
}

pub(crate) fn mmu_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<kernel::device::Bound>,
    iomem: Arc<Devres<IoMem>>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<MmuIrq>>, Error> + 'a> {
    // SAFETY: pdev is a bound device.
    let dev = unsafe { pdev.as_ref().as_bound() };
    let io = iomem.access(dev)?;
    io.write_reg(mmu_control::IRQ_MASK::from_raw(u32::MAX));

    let irq_type = MmuIrq {
        iomem: iomem.clone(),
    };

    TyrIrq::request(pdev, tdev, c_str!("mmu"), irq_type)
}

impl TyrIrqTrait for MmuIrq {
    fn read_status(&self, dev: &Device<Bound>) -> u32 {
        self.iomem
            .access(dev)
            .map(|io| io.read(mmu_control::IRQ_STATUS).into_raw())
            .unwrap_or_default()
    }

    fn disable_all(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(mmu_control::IRQ_MASK::from_raw(0));
        }
    }

    fn reenable(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(mmu_control::IRQ_MASK::from_raw(self.mask()));
        }
    }

    fn read_raw_status(&self, dev: &Device<Bound>) -> u32 {
        self.iomem
            .access(dev)
            .map(|io| io.read(mmu_control::IRQ_RAWSTAT).into_raw())
            .unwrap_or_default()
    }

    fn clear_status(&self, dev: &Device<Bound>, status: u32) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(mmu_control::IRQ_CLEAR::from_raw(status));
        }
    }

    fn mask(&self) -> u32 {
        u32::MAX // for now.
    }

    fn handle(&self, _: &TyrDrmDevice, status: u32) {
        let fault_bits = status & kernel::bits::genmask_u32(0..=15);
        if fault_bits != 0 {
            let _ = decode_faults(fault_bits, &self.iomem);
        }
    }
}
