// SPDX-License-Identifier: GPL-2.0 or MIT

//! All VMs have to be placed on a physical slot to become active. This file
//! implements an allocator to track which slots are active, and later to evict
//! the least recently used one if needed.
//!
//! Implementing this allocator is a TODO. For now, we just return EBUSY when
//! all slots are taken, and slots are never freed once inactive.

// /// Alocates HW AS slots, which represent a physical slot where a VM can be
// /// placed in.
// ///
// /// Panthor keeps a LRU list for the purposes of evicting VMs when a slot is
// /// requested but no one is free. We defer this to a future implementation.
// ///
// /// Note that this is still TODO: this type doesn't yet track any VMs.
// struct SlotAllocator {
//     /// How many slots are free.
//     free_mask: u32,
// }

// impl SlotAllocator {
//     fn alloc_slot(allocator: Arc<Mutex<Self>>, vm: &mut Vm) {
//         let mut alloc = allocator.lock();
//         let slot = alloc.free_mask.trailing_zeros();

//         if slot < 32 {
//             alloc.free_mask |= 1 << slot;
//             let slot_allocation = SlotAllocation {
//                 allocator: allocator.clone(),
//                 slot: slot as u8,
//             };
//             vm.binding = Some(slot_allocation);
//         }
//     }

//     fn free_slot(vm: &mut Vm) {
//         vm.binding = None;
//     }
// }

// /// Represents a slot allocation.
// ///
// /// This type returns the slot to the allocator once it is dropped.
// ///
// ///
// /// Note that this is still TODO: this type doesn't yet track any VMs.
// struct SlotAllocation {
//     /// The allocator that allocated this slot.
//     allocator: Arc<Mutex<SlotAllocator>>,
//     /// The actual slot value.
//     slot: u8,
// }

// impl Drop for SlotAllocation {
//     fn drop(&mut self) {
//         self.allocator.lock().free_mask &= !(1 << self.slot);
//     }
// }
