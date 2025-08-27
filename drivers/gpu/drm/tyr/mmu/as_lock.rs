// SPDX-License-Identifier: GPL-2.0 or MIT

//! Address space locking.

use core::ops::Range;

use kernel::bits::{genmask_checked_u64, genmask_u64};
use kernel::devres::Devres;
use kernel::io::mem::IoMem;
use kernel::prelude::*;

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
        let region_width = core::cmp::max(
            (region.start ^ (region.end - 1)).leading_zeros() as u8,
            64 - AS_LOCK_REGION_MIN_SIZE.trailing_zeros() as u8,
        ) - 1;

        // Mask off the low bits of region.start, which would be ignored by the
        // hardware anyways.
        let region_start = region.start
            & genmask_checked_u64(region_width as u32..=63).ok_or(EINVAL)?;

        let region = (region_width as u64) | region_start;

        let region_lo = (region & 0xffffffff) as u32;
        let region_hi = (region >> 32) as u32;

        // Lock the region that needs to be updated.
        as_lockaddr_lo(as_nr)?.write(iomem, region_lo)?;
        as_lockaddr_hi(as_nr)?.write(iomem, region_hi)?;
        as_command(as_nr)?.write(iomem, AS_COMMAND_LOCK)?;

        Ok(Self { iomem, as_nr })
    }
}

impl Drop for AsLockToken<'_> {
    fn drop(&mut self) {
        let as_cmd = as_command(self.as_nr);
        match as_cmd {
            Ok(as_cmd) => {
                if let Err(err) = Mmu::wait_ready(self.iomem, self.as_nr) {
                    pr_err!("MMU is busy for AS{}: {:?}\n", self.as_nr, err);
                    return;
                }
                if let Err(err) = as_cmd.write(self.iomem, AS_COMMAND_FLUSH_PT)
                {
                    pr_err!(
                        "Failed to flush page tables for AS{}: {:?}\n",
                        self.as_nr,
                        err
                    );
                    return;
                }
                if let Err(err) = Mmu::wait_ready(self.iomem, self.as_nr) {
                    pr_err!("MMU is busy for AS{}: {:?}\n", self.as_nr, err);
                }
            }

            Err(err) => {
                pr_err!("Failed to unlock AS{}: {:?}\n", self.as_nr, err);
            }
        }
    }
}
