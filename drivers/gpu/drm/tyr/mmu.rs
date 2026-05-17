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
    device::Bound,
    devres::Devres,
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
    driver::{
        IoMem,
        TyrDrmDeviceData,
        TyrPlatformDriverData, //
    },
    gpu::GpuInfo,
    mmu::address_space::{
        AddressSpaceManager,
        VmAsData, //
    },
    regs::{
        gpu_control::{
            FlushMode,
            AS_PRESENT, //
        },
        MAX_AS, //
    },
    reset::{
        hw_gate::{
            HwGate,
            HwReadGuard, //
        },
        ResetHandle, //
    },
    slot::SlotManager, //
};

pub(crate) mod address_space;
mod faults;
pub(crate) mod irq;

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
    /// Total number of hardware AS slots reported by the GPU.
    as_slot_count: usize,

    /// Gate serializing reset-sensitive AS operations against the reset
    /// worker. Shared with the reset controller that closes it.
    hw_gate: Arc<HwGate>,

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
        gpu_info: &GpuInfo,
        reset: ResetHandle,
    ) -> Result<Arc<Mmu>> {
        let present = AS_PRESENT::from_raw(gpu_info.as_present).present().get();
        let slot_count: usize = present.count_ones().try_into()?;

        let hw_gate = reset.hw_gate();
        let as_manager = AddressSpaceManager::new(pdev, iomem, present, reset)?;
        let mmu_init = try_pin_init!(Self{
            as_slot_count: slot_count,
            hw_gate,
            as_manager <- new_mutex!(SlotManager::new(as_manager, slot_count)?),
        });
        Arc::pin_init(mmu_init, GFP_KERNEL)
    }

    /// Returns the total number of hardware AS slots present on the GPU.
    ///
    /// AS slot 0 is permanently reserved for the firmware MCU VM, so the
    /// count of slots available to user VMs is `as_slot_count() - 1`.
    pub(crate) fn as_slot_count(&self) -> usize {
        self.as_slot_count
    }

    /// Enters a read section on the reset hardware-access gate.
    ///
    /// Held across reset-sensitive AS MMIO so the reset worker drains it
    /// before wiping the hardware. Acquired outside the AS manager lock, so a
    /// caller parked on a closed gate never holds it.
    pub(crate) fn begin_hw_access(&self) -> HwReadGuard<'_> {
        self.hw_gate.read()
    }

    /// Make a VM active.
    ///
    /// This implies assigning the VM to an AS slot through the slot manager.
    /// An extra user on an already-resident VM only bumps the count under the
    /// AS slot manager lock, keeping it off any in-flight page-table update.
    /// Binding a not-resident VM takes the op lock first.
    pub(crate) fn activate_vm(&self, vm: ArcBorrow<'_, VmAsData>) -> Result {
        // The `.lock()` guard is a condition temporary, so it drops before
        // the path below can take the op lock.
        if self.as_manager.lock().bump_resident_vm_users(&vm) {
            return Ok(());
        }
        let _op = vm.lock_ops();
        let _hw = self.begin_hw_access();
        self.as_manager.lock().activate_vm(vm)
    }

    /// Flag the VM idle.
    ///
    /// Keeps the VM on its AS slot through the slot manager, leaving it
    /// reclaimable under pressure.
    pub(crate) fn idle_vm(&self, vm: &VmAsData) -> Result {
        self.as_manager.lock().idle_vm(vm)
    }

    /// Make the VM inactive.
    ///
    /// Evicts the VM from its AS slot through the slot manager.
    /// The per-VM op lock is taken first so a residency change cannot overlap
    /// an in-flight page-table update on the same VM.
    pub(crate) fn deactivate_vm(&self, vm: &VmAsData) -> Result {
        let _op = vm.lock_ops();
        let _hw = self.begin_hw_access();
        self.as_manager.lock().deactivate_vm(vm)
    }

    /// Releases every resident VM's hardware AS slot for runtime suspend.
    ///
    /// Runs with the GPU still clocked and the MCU halted, so the eviction
    /// MMIO completes and no AS slot is programmed when the clocks gate.
    /// Takes no VM op lock.
    pub(crate) fn suspend(&self) {
        self.as_manager.lock().suspend()
    }

    /// Returns the AS slot index `vm` is currently bound to, or `None`
    /// if it is not resident.
    ///
    /// The returned value is a snapshot taken under the AS slot manager
    /// mutex. Callers that act on the slot id must serialise their use
    /// against `Mmu::deactivate_vm`; otherwise the AS slot manager
    /// may evict the VM in between.
    pub(crate) fn vm_as_slot(&self, vm: &VmAsData) -> Option<u8> {
        self.as_manager.lock().vm_as_slot(vm)
    }

    /// Cleans the L2 and LSC caches and waits for completion.
    ///
    /// Used on suspend so that firmware-written state (CSG suspend
    /// buffers) is in memory before the GPU loses power.
    pub(crate) fn flush_caches(&self) -> Result {
        self.as_manager.lock().gpu_flush_caches(
            MAX_AS,
            FlushMode::Clean,
            FlushMode::Clean,
            FlushMode::None,
        )
    }

    /// Flags the start of a VM update.
    ///
    /// If the VM is resident, any GPU access on the memory range being
    /// updated will be blocked until `Mmu::end_vm_update()` is called.
    /// This guarantees the atomicity of a VM update.
    /// If the region is empty or the VM is not resident, this is a NOP.
    pub(crate) fn start_vm_update(&self, vm: &VmAsData, region: &Range<u64>) -> Result {
        self.as_manager.lock().start_vm_update(vm, region)
    }

    /// Widens the active lock to cover a larger region.
    ///
    /// `region` must contain the currently locked range so the GPU stays
    /// stalled over it while the update completes. If the region is empty or
    /// the VM is not resident, this is a NOP.
    pub(crate) fn extend_vm_update(&self, vm: &VmAsData, region: &Range<u64>) -> Result {
        self.as_manager.lock().extend_vm_update(vm, region)
    }

    /// Flags the end of a VM update.
    ///
    /// If the VM is resident, this will let GPU accesses on the updated
    /// range go through, in case any of them were blocked.
    /// If the region is empty or the VM is not resident, this is a NOP.
    pub(crate) fn end_vm_update(&self, vm: &VmAsData, region: &Range<u64>) -> Result {
        self.as_manager.lock().end_vm_update(vm, region)
    }

    /// Reads the `(group_id, group_uid, csg_id)` back-pointer recorded on
    /// the VM resident in AS slot `as_slot`. Returns
    /// `(u64::MAX, u64::MAX, u32::MAX)` when no VM is bound there or no
    /// group is currently bound to the VM's CSG slot.
    pub(crate) fn bound_group_for_as_slot(&self, as_slot: usize) -> (u64, u64, u32) {
        let as_manager = self.as_manager.lock();
        match as_manager.slot_data(as_slot) {
            Some(vm_as_data) => vm_as_data.bound_group(),
            None => (u64::MAX, u64::MAX, u32::MAX),
        }
    }
}

/// Stops the MMU for a GPU reset.
///
/// Only the MMU IRQ is suspended. No AS commands are issued. The reset
/// may have been scheduled because an AS command or cache flush is
/// stuck.
pub(crate) fn pre_reset(tdev: &TyrDrmDeviceData, iomem: &Devres<IoMem>) {
    tdev.mmu_irq.reset_suspend(iomem, irq::mmu_irq_disable);
}

/// Restores the MMU after a GPU reset.
///
/// The reset left every AS slot unprogrammed, so every recorded
/// binding is released and the next activation reprograms the slot.
/// The MMU IRQ is then re-enabled with a full mask rewrite.
pub(crate) fn post_reset(tdev: &TyrDrmDeviceData, iomem: &Devres<IoMem>) {
    {
        // The reset worker holds the closed gate here, so eviction must not
        // take a VM op lock and goes through the AS slot manager directly. A
        // span parked on the closed gate re-checks residency when it resumes,
        // so releasing the binding is enough.
        let mut as_manager = tdev.mmu.as_manager.lock();
        for as_idx in 0..tdev.mmu.as_slot_count {
            // Clone the VM here because slot_data borrows as_manager and
            // deactivate_vm takes &mut self.
            let Some(vm) = as_manager.slot_data(as_idx).cloned() else {
                continue;
            };
            if let Err(e) = as_manager.deactivate_vm(&vm) {
                pr_err!("post_reset: releasing AS slot {} failed: {:?}\n", as_idx, e);
            }
        }
    }

    tdev.mmu_irq.reset_resume(iomem, irq::mmu_irq_enable);
}

/// Releases the resident AS slots and stops the MMU IRQ for runtime
/// suspend.
pub(crate) fn suspend(dev: &platform::Device<Bound>, data: Pin<&TyrPlatformDriverData>) {
    let bound = dev.as_ref();
    let tdev = &data.device;
    tdev.mmu.suspend();
    tdev.mmu_irq
        .quiesce(bound, &tdev.iomem, irq::mmu_irq_disable);
}

/// Re-enables the MMU IRQ for runtime resume.
pub(crate) fn resume(dev: &platform::Device<Bound>, data: Pin<&TyrPlatformDriverData>) -> Result {
    let io = data.device.iomem.access(dev.as_ref())?;
    data.device.mmu_irq.clear_suspended();
    irq::mmu_irq_enable(io);
    Ok(())
}
