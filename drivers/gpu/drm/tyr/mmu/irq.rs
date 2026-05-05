// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU IRQ handler.
//!
//! The MMU interrupt line reports per-address-space page faults. This module
//! wires the generic Tyr IRQ wrapper to the MMU IRQ registers and delegates the
//! human-readable fault reporting to `faults.rs`.

use kernel::{
    bits::genmask_u32,
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
    mmu::faults::decode_faults,
    regs::mmu_control, //
};

pub(crate) struct MmuIrq;

/// Unmasks the MMU IRQ sources and registers the handler.
///
/// # Safety
///
/// Callers must not `mem::forget()` the resulting registration or otherwise prevent its
/// `Drop` implementation from running.
pub(crate) unsafe fn mmu_irq_init<'drm>(
    pdev: &'drm platform::Device<Bound>,
    tdev: ARef<TyrDrmDevice>,
    iomem: Arc<DevresIoMem<SZ_2M>>,
) -> Result<impl PinInit<ThreadedRegistration<'drm, TyrIrq<'drm, MmuIrq>>, Error> + 'drm> {
    iomem
        .access(pdev.as_ref())?
        .write_reg(mmu_control::IRQ_MASK::from_raw(u32::MAX));

    // SAFETY: The caller guarantees that the registration is not leaked.
    Ok(unsafe { TyrIrq::request(pdev, tdev, c"mmu", iomem, MmuIrq) })
}

impl TyrIrqTrait for MmuIrq {
    fn read_status(&self, io: &IoMem<'_>) -> u32 {
        io.read(mmu_control::IRQ_STATUS).into_raw()
    }

    fn disable_all(&self, io: &IoMem<'_>) {
        io.write_reg(mmu_control::IRQ_MASK::from_raw(0));
    }

    fn reenable(&self, io: &IoMem<'_>) {
        io.write_reg(mmu_control::IRQ_MASK::from_raw(self.mask()));
    }

    fn read_raw_status(&self, io: &IoMem<'_>) -> u32 {
        io.read(mmu_control::IRQ_RAWSTAT).into_raw()
    }

    fn clear_status(&self, io: &IoMem<'_>, status: u32) {
        io.write_reg(mmu_control::IRQ_CLEAR::from_raw(status));
    }

    fn mask(&self) -> u32 {
        u32::MAX
    }

    fn handle(&self, tdev: &TyrDrmDevice, io: &IoMem<'_>, status: u32) {
        let fault_bits = status & genmask_u32(0..=15);
        if fault_bits != 0 {
            let _ = decode_faults(tdev, fault_bits, io);
        }
    }
}
