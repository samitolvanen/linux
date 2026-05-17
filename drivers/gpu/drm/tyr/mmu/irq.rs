// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU IRQ handler.
//!
//! The MMU interrupt line reports per-address-space page faults. This module
//! wires the generic Tyr IRQ wrapper to the MMU IRQ registers and delegates the
//! human-readable fault reporting to `faults.rs`.

use kernel::{
    c_str,
    device::{Bound, Device},
    devres::Devres,
    io::Io,
    irq::ThreadedRegistration,
    new_spinlock,
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::Relaxed,
        Arc,
        SpinLock, //
    }, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    irq::{TyrIrq, TyrIrqTrait},
    mmu::faults::decode_faults,
    regs::{
        mmu_control,
        MAX_AS, //
    },
};

const PAGE_FAULT_BITS: u16 = ((1u32 << MAX_AS) - 1) as u16;

/// Live `IRQ_MASK` value for the page-fault sources, one bit per hardware
/// AS slot.
///
/// The lock covers the `IRQ_MASK` write and the value. The hard handler
/// never takes the lock, and `mmu_irq_disable` writes `IRQ_MASK` without
/// it, so a quiesced window must run no AS programming.
#[pin_data]
pub(crate) struct PageFaultMask {
    #[pin]
    mask: SpinLock<u32>,
}

impl PageFaultMask {
    /// Creates a mask with every slot masked.
    pub(super) fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            mask <- new_spinlock!(0),
        })
    }

    /// Returns the mask, for filtering `IRQ_RAWSTAT`.
    fn get(&self) -> u32 {
        *self.mask.lock()
    }

    /// Masks every slot, for a reset that left them all unprogrammed.
    pub(super) fn mask_all(&self, io: &IoMem) {
        let mut mask = self.mask.lock();

        *mask = 0;
        io.write_reg(mmu_control::IRQ_MASK::from_raw(*mask));
    }

    /// Unmasks AS slot `as_nr`, dropping the faults it latched while masked.
    ///
    /// The caller passes a present slot and holds the AS slot manager lock.
    pub(super) fn unmask_slot(&self, io: &IoMem, as_nr: usize) {
        let bit = 1u32 << as_nr;
        let mut mask = self.mask.lock();

        *mask |= bit;
        io.write_reg(mmu_control::IRQ_CLEAR::from_raw(bit));
        io.write_reg(mmu_control::IRQ_MASK::from_raw(*mask));
    }

    /// Masks AS slot `as_nr`.
    ///
    /// The caller requirements of `unmask_slot` apply.
    pub(super) fn mask_slot(&self, io: &IoMem, as_nr: usize) {
        let mut mask = self.mask.lock();

        *mask &= !(1u32 << as_nr);
        io.write_reg(mmu_control::IRQ_MASK::from_raw(*mask));
    }

    /// Clears the latched faults of the slots in the mask and unmasks them.
    pub(super) fn enable(&self, io: &IoMem) {
        let mask = self.mask.lock();

        io.write_reg(mmu_control::IRQ_CLEAR::from_raw(*mask));
        io.write_reg(mmu_control::IRQ_MASK::from_raw(*mask));
    }

    /// Writes the mask back to `IRQ_MASK`.
    fn restore(&self, io: &IoMem) {
        let mask = self.mask.lock();

        io.write_reg(mmu_control::IRQ_MASK::from_raw(*mask));
    }
}

pub(crate) struct MmuIrq {
    iomem: Arc<Devres<IoMem>>,
    /// Live page-fault IRQ mask, shared with the AS manager.
    fault_mask: Arc<PageFaultMask>,
}

/// Masks all MMU IRQ sources.
pub(crate) fn mmu_irq_disable(io: &IoMem) {
    io.write_reg(mmu_control::IRQ_MASK::from_raw(0));
}

pub(crate) fn mmu_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<Bound>,
    iomem: Arc<Devres<IoMem>>,
    fault_mask: Arc<PageFaultMask>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<MmuIrq>>, Error> + 'a> {
    let io = iomem.access(pdev.as_ref())?;
    // The caller unmasks the sources once the handler is registered.
    io.write_reg(mmu_control::IRQ_MASK::from_raw(0));

    let irq_type = MmuIrq { iomem, fault_mask };
    TyrIrq::request(pdev, tdev, c_str!("mmu"), c_str!("mmu"), irq_type)
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
            self.fault_mask.restore(io);
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
        self.fault_mask.get()
    }

    fn handle(&self, tdev: &TyrDrmDevice, status: u32) {
        let fault_bits = status & u32::from(PAGE_FAULT_BITS);
        if fault_bits == 0 {
            return;
        }

        let _ = decode_faults(fault_bits, &self.iomem, tdev);

        // Flag the faulting AS slots and tear their MMU programming
        // down before the scheduler tick runs, so any further GPU
        // accesses to those VMs fault immediately instead of generating
        // a fault storm while the scheduler evicts the owning groups.
        let mut as_manager = tdev.mmu.as_manager.lock();
        for as_idx in 0..MAX_AS {
            if fault_bits & (1u32 << as_idx) == 0 {
                continue;
            }
            // Clone so the slot_data borrow of as_manager ends before
            // disable_vm takes &mut self.
            let Some(vm_as_data) = as_manager.slot_data(as_idx).cloned() else {
                continue;
            };
            vm_as_data.unhandled_fault.store(true, Relaxed);
            if let Err(e) = as_manager.disable_vm(&vm_as_data) {
                pr_err!("mmu_irq: disable_vm({}) failed: {:?}\n", as_idx, e);
            }
        }
        drop(as_manager);

        TyrDrmDeviceData::schedule_tick(&ARef::from(tdev));
    }
}
