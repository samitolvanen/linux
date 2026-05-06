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
        TyrDrmDeviceData,
        TyrIrq,
        TyrIrqTrait, //
    },
    mmu::decode_faults,
    regs::{
        mmu_control,
        MAX_AS, //
    },
};

/// Bit mask covering the per-AS PAGE_FAULT bits (one per address space).
const PAGE_FAULT_BITS: u16 = ((1u32 << MAX_AS) - 1) as u16;

/// Returns the bitmask for the MMU interrupts the driver actively handles.
///
/// Currently this enables the per-AS page-fault bits (one per address
/// space, up to [`MAX_AS`]) so [`decode_faults`] can identify and process
/// faulting transactions; other MMU events stay masked.
pub(crate) fn mmu_interrupts_mask() -> u32 {
    mmu_control::IRQ_MASK::zeroed()
        .with_page_fault(PAGE_FAULT_BITS)
        .into_raw()
}

/// MMU interrupt handler data.
pub(crate) struct MmuIrq {
    iomem: Arc<Devres<IoMem>>,
    /// Cached value of [`mmu_interrupts_mask`] so the per-interrupt
    /// `mask()` does not rebuild it on every call.
    mask: u32,
}

pub(crate) fn mmu_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<kernel::device::Bound>,
    iomem: Arc<Devres<IoMem>>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<MmuIrq>>, Error> + 'a> {
    let irq_type = MmuIrq {
        iomem: iomem.clone(),
        mask: mmu_interrupts_mask(),
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
        self.mask
    }

    fn handle(&self, tdev: &TyrDrmDevice, status: u32) {
        let fault_bits = status & u32::from(PAGE_FAULT_BITS);
        if fault_bits != 0 {
            let _ = decode_faults(fault_bits, &self.iomem);
            // schedule_tick coalesces redundant requests via the workqueue.
            TyrDrmDeviceData::schedule_tick(&ARef::from(tdev));
        }
    }
}

impl MmuIrq {
    /// Enables the MMU interrupts in hardware.
    ///
    /// Clears any latched bits in `IRQ_RAWSTAT` left over from a previous
    /// probe before unmasking, then writes [`mmu_interrupts_mask`] to
    /// `IRQ_MASK`.
    pub(crate) fn enable_hardware(dev: &Device<Bound>, iomem: &Devres<IoMem>) -> Result {
        let io = iomem.access(dev)?;
        // Drop any latched IRQs from a previous probe.
        io.write_reg(mmu_control::IRQ_CLEAR::from_raw(u32::MAX));
        io.write_reg(mmu_control::IRQ_MASK::from_raw(mmu_interrupts_mask()));
        Ok(())
    }
}
