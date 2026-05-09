// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU IRQ handler.
//!
//! The MMU interrupt line reports per-address-space page faults. This module
//! wires the generic Tyr IRQ wrapper to the MMU IRQ registers and delegates the
//! human-readable fault reporting to `faults.rs`.

use core::sync::atomic::Ordering;
use kernel::{
    c_str,
    device::{Bound, Device},
    devres::Devres,
    io::Io,
    irq::ThreadedRegistration,
    platform,
    prelude::*,
    sync::{aref::ARef, Arc},
};

use crate::{
    driver::{IoMem, TyrDrmDevice, TyrDrmDeviceData},
    irq::{TyrIrq, TyrIrqTrait},
    mmu::faults::decode_faults,
    regs::{
        mmu_control,
        MAX_AS, //
    },
};

/// Bit mask covering the per-AS PAGE_FAULT bits (one per address space).
const PAGE_FAULT_BITS: u16 = ((1u32 << MAX_AS) - 1) as u16;

/// Per-AS PAGE_FAULT bits, one bit per address space.
pub(crate) fn mmu_interrupts_mask() -> u32 {
    mmu_control::IRQ_MASK::zeroed()
        .with_page_fault(PAGE_FAULT_BITS)
        .into_raw()
}

pub(crate) struct MmuIrq {
    iomem: Arc<Devres<IoMem>>,
    /// Cached value of [`mmu_interrupts_mask`] so the per-interrupt
    /// `mask()` does not rebuild it on every call.
    mask: u32,
}

pub(crate) fn mmu_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<Bound>,
    iomem: Arc<Devres<IoMem>>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<MmuIrq>>, Error> + 'a> {
    let mask = mmu_interrupts_mask();
    let io = iomem.access(pdev.as_ref())?;
    // Drop any latched IRQs from a previous probe.
    io.write_reg(mmu_control::IRQ_CLEAR::from_raw(u32::MAX));
    io.write_reg(mmu_control::IRQ_MASK::from_raw(mask));

    let irq_type = MmuIrq { iomem, mask };
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

            let as_manager = tdev.mmu.as_manager.lock();
            for as_idx in 0..MAX_AS {
                if (fault_bits & (1 << as_idx)) != 0 {
                    if let Some(vm_as_data) = as_manager.slot_data(as_idx) {
                        vm_as_data.unhandled_fault.store(true, Ordering::Relaxed);
                    }
                }
            }

            TyrDrmDeviceData::schedule_tick(&ARef::from(tdev));
        }
    }
}
