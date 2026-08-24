// SPDX-License-Identifier: GPL-2.0 or MIT

//! Memory Management Unit (MMU) module.
//!
//! The GPU MMU provides a limited number of memory address spaces for use by command streams.
//! The MMU translates virtual addresses to physical addresses and manages memory configuration
//! and access permissions.
//!
//! This MMU module is essentially a locked wrapper around a [`SlotManager`] instance.
//! The [`SlotManager`] manages the assignment of virtual address spaces to hardware address-space
//! (AS) slots. MMU commands such as updates and flushes are carried out by the
//! [`AddressSpaceManager`] which actually writes to the MMU registers.

use core::ops::Range;

use kernel::{
    device::Bound,
    io::mem::DevresIoMem,
    new_mutex,
    platform,
    prelude::*,
    sizes::SZ_2M,
    sync::{
        Arc,
        ArcBorrow,
        Mutex, //
    }, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmRegistrationData, //
    },
    gpu::GpuInfo,
    irq::{
        clear_suspended,
        quiesce, //
    },
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
    slot::SlotManager, //
};

pub(crate) mod address_space;
mod faults;
pub(crate) mod irq;

pub(crate) type AsSlotManager = SlotManager<AddressSpaceManager, MAX_AS>;

/// Locked wrapper for carrying out virtual memory (VM) operations on the MMU.
#[pin_data]
pub(crate) struct Mmu {
    /// Total number of hardware AS slots reported by the GPU.
    as_slot_count: usize,

    /// Slot Manager instance used to allocate hardware slots and write to MMU registers.
    #[pin]
    pub(crate) as_manager: Mutex<AsSlotManager>,
}

impl Mmu {
    /// Create an MMU component for this device.
    pub(crate) fn new(
        pdev: &platform::Device<Bound>,
        iomem: Arc<DevresIoMem<SZ_2M>>,
        gpu_info: &GpuInfo,
    ) -> Result<Arc<Mmu>> {
        let present = AS_PRESENT::from_raw(gpu_info.as_present).present().get();
        let slot_count: usize = present.count_ones().try_into()?;

        let address_space_manager = AddressSpaceManager::new(pdev, iomem, present)?;
        let as_slot_manager =
            SlotManager::new(address_space_manager, slot_count).inspect_err(|e| {
                dev_err!(
                    pdev,
                    "Failed to initialize MMU slot manager with {} slots: {:?}",
                    slot_count,
                    e
                );
            })?;
        let mmu_init = try_pin_init!(Self{
            as_slot_count: slot_count,
            as_manager <- new_mutex!(as_slot_manager),
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

    /// Assign a VM to an AS slot, provide a translation table,
    /// and update the MMU to make the VM resident.
    ///
    /// An extra user on an already-resident VM only bumps the count under the
    /// AS slot manager lock, keeping it off any in-flight page-table update.
    /// Binding a not-resident VM takes the op lock first.
    pub(crate) fn activate_vm(&self, vm_as_data: ArcBorrow<'_, VmAsData>) -> Result {
        // The `.lock()` guard is a condition temporary, so it drops before
        // the path below can take the op lock.
        if self.as_manager.lock().bump_resident_vm_users(&vm_as_data) {
            return Ok(());
        }
        let _op = vm_as_data.lock_ops();
        self.as_manager.lock().activate_vm(vm_as_data)
    }

    /// Flag the VM idle.
    ///
    /// Keeps the VM on its AS slot through the slot manager, leaving it
    /// reclaimable under pressure.
    pub(crate) fn idle_vm(&self, vm_as_data: &VmAsData) -> Result {
        self.as_manager.lock().idle_vm(vm_as_data)
    }

    /// Evict a VM from its AS slot and flush the MMU.
    ///
    /// The per-VM op lock is taken first so a residency change cannot overlap
    /// an in-flight page-table update on the same VM.
    pub(crate) fn deactivate_vm(&self, vm_as_data: &VmAsData) -> Result {
        let _op = vm_as_data.lock_ops();
        self.as_manager.lock().deactivate_vm(vm_as_data)
    }

    /// Releases every resident VM's hardware AS slot for runtime suspend.
    ///
    /// Runs with the GPU still clocked and the MCU halted, so the eviction
    /// MMIO completes and no AS slot is programmed when the clocks gate.
    /// Takes no VM op lock.
    pub(crate) fn suspend(&self) {
        self.as_manager.lock().suspend()
    }

    /// Returns the AS slot index the VM is currently bound to, or `None`
    /// if it is not resident.
    ///
    /// The returned value is a snapshot taken under the AS slot manager
    /// mutex. Callers that act on the slot id must serialize their use
    /// against `Mmu::deactivate_vm`. Otherwise the AS slot manager
    /// may evict the VM in between.
    pub(crate) fn vm_as_slot(&self, vm_as_data: &VmAsData) -> Option<u8> {
        self.as_manager.lock().vm_as_slot(vm_as_data)
    }

    /// Cleans the L2 and LSC caches and waits for completion.
    ///
    /// Used on suspend so that firmware-written state (CSG suspend
    /// buffers) is in memory before the GPU loses power.
    pub(crate) fn flush_caches(&self) -> Result {
        self.as_manager
            .lock()
            .gpu_flush_caches(FlushMode::Clean, FlushMode::Clean, FlushMode::None)
    }

    /// Flags the start of a VM update.
    ///
    /// If the VM is resident, any GPU access on the memory range being
    /// updated will be blocked until `Mmu::end_vm_update()` is called.
    /// This guarantees the atomicity of a VM update.
    /// If the region is empty or the VM is not resident, this is a NOP.
    pub(crate) fn start_vm_update(&self, vm_as_data: &VmAsData, region: &Range<u64>) -> Result {
        self.as_manager.lock().start_vm_update(vm_as_data, region)
    }

    /// Widens the active lock to cover a larger region.
    ///
    /// `region` must contain the currently locked range so the GPU stays
    /// stalled over it while the update completes. If the region is empty or
    /// the VM is not resident, this is a NOP.
    pub(crate) fn extend_vm_update(&self, vm_as_data: &VmAsData, region: &Range<u64>) -> Result {
        self.as_manager.lock().extend_vm_update(vm_as_data, region)
    }

    /// Flags the end of a VM update.
    ///
    /// If the VM is resident, this will let GPU accesses on the updated
    /// range go through, in case any of them were blocked.
    /// If the region is empty or the VM is not resident, this is a NOP.
    pub(crate) fn end_vm_update(&self, vm_as_data: &VmAsData, region: &Range<u64>) -> Result {
        self.as_manager.lock().end_vm_update(vm_as_data, region)
    }
}

/// Releases the resident AS slots and stops the MMU IRQ for runtime
/// suspend.
pub(crate) fn suspend(reg_data: &TyrDrmRegistrationData<'_>, io: &IoMem<'_>) {
    reg_data.mmu.suspend();
    quiesce(&reg_data.mmu_irq, io, irq::mmu_irq_disable);
}

/// Re-enables the MMU IRQ for runtime resume.
pub(crate) fn resume(reg_data: &TyrDrmRegistrationData<'_>, io: &IoMem<'_>) {
    clear_suspended(&reg_data.mmu_irq);
    irq::mmu_irq_enable(io);
}
