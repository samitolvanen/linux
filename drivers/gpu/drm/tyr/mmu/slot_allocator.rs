// SPDX-License-Identifier: GPL-2.0 or MIT

//! All VMs have to be placed on a physical slot to become active. This file
//! implements an allocator to track which slots are active, and later to evict
//! the least recently used one if needed.

use kernel::{bits::bit_u32, prelude::*};

fn as_nr_mask(as_nr: usize) -> u32 {
    bit_u32(as_nr as u32)
}

/// Alocates HW AS slots, which represent a physical slot where a VM can be
/// placed in.
///
/// Panthor keeps a LRU list for the purposes of evicting VMs when a slot is
/// requested but no one is free. We defer this to a future implementation.
pub(crate) struct SlotAllocator {
    /// Which AS slots are free.
    occupied_mask: u32,
}

impl SlotAllocator {
    pub(crate) fn new() -> Self {
        Self { occupied_mask: 0 }
    }

    pub(crate) fn find_slot(&mut self, for_mcu: bool) -> Result<usize> {
        if for_mcu {
            self.find_slot_zero()
        } else {
            self.find_slot_inner()
        }
    }

    fn find_slot_zero(&mut self) -> Result<usize> {
        if self.occupied_mask & 1 == 0 {
            Ok(0)
        } else {
            Err(EBUSY)
        }
    }

    fn find_slot_inner(&mut self) -> Result<usize> {
        let as_nr = (self.occupied_mask | 1).trailing_ones();

        if as_nr < 32 {
            Ok(as_nr as usize)
        } else {
            Err(EBUSY)
        }
    }

    pub(crate) fn alloc_slot(&mut self, as_nr: usize) {
        let mask = as_nr_mask(as_nr);
        if self.occupied_mask & mask != 0 {
            pr_err!("AS slot {as_nr} already allocated.\n");
        }
        self.occupied_mask |= mask;
    }

    pub(crate) fn free_slot(&mut self, as_nr: usize) {
        let mask = as_nr_mask(as_nr);
        if self.occupied_mask & mask == 0 {
            pr_err!("AS slot {as_nr} already free.\n");
        }
        self.occupied_mask &= !mask;
    }
}
