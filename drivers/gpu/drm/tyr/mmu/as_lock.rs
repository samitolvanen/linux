// SPDX-License-Identifier: GPL-2.0 or MIT

//! Address space locking.

use core::ops::Range;

use kernel::bits::genmask_checked_u64;
use kernel::devres::Devres;
use kernel::prelude::*;

use crate::driver::IoMem;
use crate::mmu::Mmu;
use crate::regs::*;

/// A token type that represents a lock on a region of a given address space.
pub(super) struct AsLockToken<'a> {
    iomem: &'a Devres<IoMem>,
    as_nr: usize,
}

impl<'a> AsLockToken<'a> {
    /// Lock a `region` of `as_nr`.
    pub(super) fn lock_region(
        iomem: &'a Devres<IoMem>,
        as_nr: usize,
        region: Range<u64>,
    ) -> Result<Self> {
        if region.end - region.start == 0 {
            return Err(EINVAL);
        }

        // The locked region is a naturally aligned power of 2 block encoded as
        // log2 minus(1).
        //
        // Calculate the desired start/end and look for the highest bit which
        // differs. The smallest naturally aligned block must include this bit
        // change, the desired region starts with this bit (and subsequent bits)
        // zeroed and ends with the bit (and subsequent bits) set to one.
        let diff = region.start ^ (region.end - 1);
        let fls = if diff == 0 {
            0
        } else {
            64 - diff.leading_zeros() as u8
        };

        let region_width = core::cmp::max(fls, AS_LOCK_REGION_MIN_SIZE.trailing_zeros() as u8) - 1;

        // Mask off the low bits of region.start, which would be ignored by the
        // hardware anyways.
        let region_start =
            region.start & genmask_checked_u64(region_width as u32..=63).ok_or(EINVAL)?;

        let region_val = (region_width as u64) | region_start;

        // Lock the region that needs to be updated.
        as_lockaddr_lo(as_nr)?.write(iomem, (region_val & 0xffffffff) as u32)?;
        as_lockaddr_hi(as_nr)?.write(iomem, (region_val >> 32) as u32)?;

        Mmu::write_cmd(iomem, as_nr, AS_COMMAND_LOCK)?;

        Ok(Self { iomem, as_nr })
    }
}

impl Drop for AsLockToken<'_> {
    fn drop(&mut self) {
        if let Err(err) = Mmu::write_cmd(self.iomem, self.as_nr, AS_COMMAND_UNLOCK) {
            pr_err!("Failed to unlock AS{}: {:?}\n", self.as_nr, err);
            return;
        }
        if let Err(err) = Mmu::wait_ready(self.iomem, self.as_nr) {
            pr_err!("MMU is busy for AS{}: {:?}\n", self.as_nr, err);
        }
    }
}
