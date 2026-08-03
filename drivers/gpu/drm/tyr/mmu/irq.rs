// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU IRQ handler.
//!
//! The MMU interrupt line reports per-address-space page faults. This module
//! wires the generic Tyr IRQ wrapper to the MMU IRQ registers and delegates the
//! human-readable fault reporting to `faults.rs`.

use kernel::{
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
        atomic::Relaxed,
        Arc, //
    }, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    irq::{
        TyrIrq,
        TyrIrqTrait, //
    },
    mmu::faults::decode_faults,
    regs::{
        mmu_control,
        MAX_AS, //
    }, //
};

const PAGE_FAULT_BITS: u16 = ((1u32 << MAX_AS) - 1) as u16;

/// Returns the MMU IRQ sources the driver services.
fn mmu_irq_sources() -> mmu_control::IRQ_MASK {
    mmu_control::IRQ_MASK::zeroed().with_page_fault(PAGE_FAULT_BITS)
}

pub(crate) struct MmuIrq;

/// Clears the latched MMU IRQs the driver services and unmasks them.
pub(crate) fn mmu_irq_enable(io: &IoMem<'_>) {
    let sources = mmu_irq_sources();

    io.write_reg(mmu_control::IRQ_CLEAR::from_raw(sources.into_raw()));
    io.write_reg(sources);
}

/// Registers the MMU IRQ handler with the sources masked.
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
    // The caller unmasks the sources once the handler is registered.
    iomem
        .access(pdev.as_ref())?
        .write_reg(mmu_control::IRQ_MASK::from_raw(0));

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
        mmu_irq_sources().into_raw()
    }

    fn handle(&self, tdev: &TyrDrmDevice, io: &IoMem<'_>, status: u32) {
        let fault_bits = status & u32::from(PAGE_FAULT_BITS);
        if fault_bits == 0 {
            return;
        }

        let _ = decode_faults(tdev, fault_bits, io);

        // Flag the faulting AS slots and tear their MMU programming
        // down before the scheduler tick runs, so any further GPU
        // accesses to those VMs fault immediately instead of generating
        // a fault storm while the scheduler evicts the owning groups.
        if let Some(guard) = tdev.registration_guard() {
            guard.registration_data_with(|reg_data| {
                let mut as_manager = reg_data.mmu.as_manager.lock();
                for as_idx in 0..MAX_AS {
                    if fault_bits & (1u32 << as_idx) == 0 {
                        continue;
                    }
                    // Clone, because slot_data borrows as_manager and
                    // deactivate_vm takes &mut self.
                    let Some(vm_as_data) = as_manager.slot_data(as_idx).cloned() else {
                        continue;
                    };
                    vm_as_data.unhandled_fault.store(true, Relaxed);
                    if let Err(e) = as_manager.deactivate_vm(&vm_as_data) {
                        dev_err!(
                            tdev.as_ref(),
                            "mmu_irq: deactivate_vm({}) failed: {:?}\n",
                            as_idx,
                            e
                        );
                    }
                }
            });
        }

        TyrDrmDeviceData::schedule_tick(&ARef::from(tdev));
    }
}
