// SPDX-License-Identifier: GPL-2.0 or MIT

//! Memory Management Unit (MMU) driver for the Tyr GPU.
//!
//! This module manages GPU address spaces and virtual memory (VM) operations through
//! hardware MMU slots. It provides functionality for flushing page tables and
//! managing VM updates for active address spaces.
//!
//! The MMU coordinates with the [`AddressSpaceManager`] to handle hardware
//! address space allocation and page table operations, using [`SlotManager`]
//! to track which address spaces are currently active in hardware slots.
//!
//! [`AddressSpaceManager`]: address_space::AddressSpaceManager
//! [`SlotManager`]: crate::slot::SlotManager

use core::ops::Range;

use kernel::{
    devres::Devres,
    io::Io,
    new_mutex,
    platform,
    prelude::*,
    sync::{
        Arc,
        ArcBorrow,
        Mutex, //
    }, //
};

use crate::{
    driver::IoMem,
    mmu::address_space::{
        AddressSpaceManager,
        VmAsData, //
    },
    regs::{
        gpu_control::AS_PRESENT,
        MAX_AS, //
    },
    slot::SlotManager, //
};

pub(crate) mod address_space;

pub(crate) type AsSlotManager = SlotManager<AddressSpaceManager, MAX_AS>;

/// MMU component of the GPU.
///
/// This is used to bind VM objects to an AS (Address Space) slot
/// and make the VM active on the GPU.
///
/// All operations acquire an internal lock, allowing concurrent access from multiple
/// threads. Methods may block if another thread holds the lock.
#[pin_data]
pub(crate) struct Mmu {
    /// Manages the allocation of hardware MMU slots to GPU address spaces.
    ///
    /// Tracks which address spaces are currently active in hardware slots and
    /// coordinates address space operations like flushing and VM updates.
    ///
    /// This mutex also protects individual [`Seat`]s that are wrapped with
    /// `LockedBy<Seat, SlotManager<...>>` to share the same lock protection.
    ///
    /// [`Seat`]: crate::slot::Seat
    #[pin]
    pub(crate) as_manager: Mutex<AsSlotManager>,
}

impl Mmu {
    /// Create an MMU component for this device.
    pub(crate) fn new(
        pdev: &platform::Device,
        iomem: ArcBorrow<'_, Devres<IoMem>>,
    ) -> Result<Arc<Mmu>> {
        // SAFETY: pdev is a bound device.
        let dev = unsafe { pdev.as_ref().as_bound() };
        let io = (*iomem).access(dev)?;
        let present = io.read(AS_PRESENT).present().get();
        let slot_count = present.count_ones().try_into()?;

        let as_manager = AddressSpaceManager::new(pdev, iomem, present)?;
        let mmu_init = try_pin_init!(Self{
            as_manager <- new_mutex!(SlotManager::new(as_manager, slot_count)?),
        });
        Arc::pin_init(mmu_init, GFP_KERNEL)
    }

    /// Make a VM active.
    ///
    /// This implies assigning the VM to an AS slot through the slot manager.
    pub(crate) fn activate_vm(&self, vm: ArcBorrow<'_, VmAsData>) -> Result {
        self.as_manager.lock().activate_vm(vm)
    }

    /// Make the VM inactive.
    ///
    /// Evicts the VM from its AS slot through the slot manager.
    pub(crate) fn deactivate_vm(&self, vm: &VmAsData) -> Result {
        self.as_manager.lock().deactivate_vm(vm)
    }

    /// Flush caches after a VM update.
    ///
    /// If the VM is no longer resident, this is a NOP, otherwise, the
    /// AS manager will flush the GPU and MMU Translation Lookaside Buffer (TLB) caches.
    pub(crate) fn flush_vm(&self, vm: &VmAsData) -> Result {
        self.as_manager.lock().flush_vm(vm)
    }

    /// Flags the start of a VM update.
    ///
    /// If the VM is resident, any GPU access on the memory range being
    /// updated will be blocked until `Mmu::end_vm_update()` is called.
    /// This guarantees the atomicity of a VM update.
    /// If the VM is not resident, this is a NOP.
    pub(crate) fn start_vm_update(&self, vm: &VmAsData, region: &Range<u64>) -> Result {
        self.as_manager.lock().start_vm_update(vm, region)
    }

    /// Flags the end of a VM update.
    ///
    /// If the VM is resident, this will let GPU accesses on the updated
    /// range go through, in case any of them were blocked.
    /// If the VM is not resident, this is a NOP.
    pub(crate) fn end_vm_update(&self, vm: &VmAsData) -> Result {
        self.as_manager.lock().end_vm_update(vm)
    }
}
