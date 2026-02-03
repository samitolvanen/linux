// SPDX-License-Identifier: GPL-2.0 or MIT

//! The GPUVM driver implementation.
//!
//! GPUVM will split a given sm_map/sm_unmap request into a series of map, unmap
//! and remap operations in order to manage the VA range.
//!
//! This file contains the driver-specific implementation, which includes the
//! map, unmap and remap driver callbacks.

use core::ops::Range;

use kernel::devres::Devres;
use kernel::drm::gpuvm::{self};
use kernel::io_pgtable::IoPageTable;
use kernel::io_pgtable::ARM64LPAES1;
use kernel::prelude::*;
use kernel::sizes::{SZ_1G, SZ_2M, SZ_4K};
use kernel::sync::Arc;

use crate::driver;
use crate::driver::IoMem;
use crate::mmu::vm;
use crate::mmu::Mmu;

/// Data associated with a VM mapping.
#[pin_data]
pub(crate) struct TyrVaData {}

impl TyrVaData {
    pub(crate) fn new() -> impl PinInit<Self> {
        pin_init!(Self {})
    }
}

/// Data associated with a VM <=> BO pairing.
#[pin_data]
pub(crate) struct TyrVmBoData {}

impl TyrVmBoData {
    pub(crate) fn new() -> impl PinInit<Self> {
        pin_init!(Self {})
    }
}

/// A convenience so that we do not have to spell this whole thing out every
/// time.
type PinnedVa = gpuvm::GpuVaAlloc<LockedVm>;

/// A context that is passed throughout the map/unmap/remap steps.
pub(crate) struct StepContext {
    /// The used when mapping the VM that we are doing the steps on.
    pub(super) vm_map_flags: Option<vm::map_flags::Flags>,

    /// The address space number for the VM we are executing the operations on.
    pub(super) vm_as_nr: Option<usize>,

    /// We may need to access the MMIO region when performing the steps.
    pub(super) iomem: Arc<Devres<IoMem>>,

    /// This handles the remap case.
    ///
    /// Partial unmap requests or map requests overlapping existing mappings
    /// will trigger a remap call, which needs to register up to three VA
    /// objects (one for the new mapping, and two for the previous and next
    /// mappings).
    pub(super) preallocated_vas: [Option<PinnedVa>; 3],
}

impl StepContext {
    /// Finds one of our pre-allocated VAs.
    ///
    /// It is a logic error to call this more than three times for a given
    /// StepContext.
    fn preallocated_va(&mut self) -> Result<PinnedVa> {
        self.preallocated_vas
            .iter_mut()
            .find_map(|f| f.take())
            .ok_or(EINVAL)
    }

    pub(super) fn preallocate_vas() -> Result<[Option<PinnedVa>; 3]> {
        Ok([
            Some(gpuvm::GpuVaAlloc::<LockedVm>::new(GFP_KERNEL)?),
            Some(gpuvm::GpuVaAlloc::<LockedVm>::new(GFP_KERNEL)?),
            Some(gpuvm::GpuVaAlloc::<LockedVm>::new(GFP_KERNEL)?),
        ])
    }
}

/// A state that can only be accessed when the GPUVM is locked.
pub(crate) struct LockedVm {
    /// The page table for this VM.
    pub(in crate::mmu) page_table: ARM64LPAES1<Mmu>,
    /// The allocator keeping track of what ranges are in use for the kernel VA
    /// range.
    pub(super) kernel_mm: vm::range::RangeAlloc,
}

impl LockedVm {
    pub(super) fn new(page_table: ARM64LPAES1<Mmu>, kernel_mm: vm::range::RangeAlloc) -> Self {
        LockedVm {
            page_table,
            kernel_mm,
        }
    }

    fn get_pgsize(addr: u64, size: u64) -> (u64, u64) {
        // io-pgtable only operates on multiple pages within a single table
        // entry, so we need to split at boundaries of the table size, i.e.
        // the next block size up. The distance from address A to the next
        // boundary of block size B is logically B - A % B, but in unsigned
        // two's complement where B is a power of two we get the equivalence
        // B - A % B == (B - A) % B == (n * B - A) % B, and choose n = 0 :)
        let blk_offset_2m = addr.wrapping_neg() % (SZ_2M as u64);

        if blk_offset_2m != 0 || size < SZ_2M as u64 {
            let count = if blk_offset_2m == 0 {
                size / SZ_4K as u64
            } else {
                blk_offset_2m.min(size) / SZ_4K as u64
            };
            return (SZ_4K as u64, count);
        }

        let blk_offset_1g = addr.wrapping_neg() % (SZ_1G as u64);
        let blk_offset = if blk_offset_1g == 0 {
            SZ_1G as u64
        } else {
            blk_offset_1g
        };
        let count = blk_offset.min(size) / SZ_2M as u64;
        (SZ_2M as u64, count)
    }

    fn unmap_pages(
        &mut self,
        iomem: &Devres<IoMem>,
        as_nr: Option<usize>,
        iova: Range<u64>,
    ) -> Result {
        let start_iova = iova.start;
        let size = iova.end - iova.start;
        let mut offset = 0u64;

        pr_info!(
            "Unmapping range {:#x} - {:#x}\n",
            start_iova,
            start_iova + size
        );

        while offset < size {
            let remaining = size - offset;
            let curr_iova = start_iova + offset;

            let (pgsize, pgcount) = Self::get_pgsize(curr_iova, remaining);

            let unmapped_sz =
                self.page_table
                    .unmap_pages(curr_iova as usize, pgsize as usize, pgcount as usize);

            if unmapped_sz as u64 != pgsize * pgcount {
                pr_err!(
                    "AS ({:#?}): failed to unmap range {:#x}-{:#x} (requested range {:#x}-{:#x}), unmapped only {:#x} bytes\n",
                    as_nr,
                    curr_iova + unmapped_sz as u64,
                    curr_iova + pgsize * pgcount,
                    start_iova,
                    start_iova + size,
                    unmapped_sz,
                );

                if let Some(as_nr) = as_nr {
                    let _ =
                        Mmu::flush_range(iomem, as_nr, start_iova..curr_iova + unmapped_sz as u64);
                }

                return Err(EINVAL);
            }

            pr_info!(
                "AS ({:#?}): unmapped {} bytes, iova: {:#x}, pgsize: {}, pgcount: {}, len: {}\n",
                as_nr,
                unmapped_sz,
                curr_iova,
                pgsize,
                pgcount,
                remaining
            );

            offset += unmapped_sz as u64;
        }

        // Flush the entire unmapped range
        if let Some(as_nr) = as_nr {
            Mmu::flush_range(iomem, as_nr, start_iova..start_iova + size)?;
        }

        Ok(())
    }
}

impl gpuvm::DriverGpuVm for LockedVm {
    type Driver = driver::TyrDriver;
    type Object = crate::gem::Object;
    type VaData = TyrVaData;
    type VmBoData = TyrVmBoData;
    type SmContext<'ctx> = StepContext;

    fn sm_step_map<'op, 'ctx>(
        &mut self,
        op: gpuvm::OpMap<'op, Self>,
        ctx: &mut Self::SmContext<'ctx>,
    ) -> Result<gpuvm::OpMapped<'op, Self>, Error> {
        let start_iova = op.addr();
        let mut iova = start_iova;
        let mut left = op.length();
        let mut offset = op.gem_offset();
        let gpuva = ctx.preallocated_va()?;

        let vm_bo = op.vm_bo();
        let sgt = vm_bo.obj().sg_table();
        let prot = ctx.vm_map_flags.ok_or(EINVAL)?.to_prot();

        pr_info!("mapping {} bytes, iova: {:#x}, prot {}\n", left, iova, prot);

        for range in sgt
            .as_ref()
            .expect("SGT should be set before step_map")
            .iter()
        {
            let mut paddr = range.dma_address();
            let mut len = u64::from(range.dma_len());

            if left == 0 {
                break;
            }

            if offset > 0 {
                let skip = len.min(offset);
                paddr += skip;
                len -= skip;
                offset -= skip;
            }

            if len == 0 {
                continue;
            }

            assert!(offset == 0);

            len = len.min(left);

            let mut segment_mapped = 0u64;
            while segment_mapped < len {
                let remaining = len - segment_mapped;
                let curr_iova = iova + segment_mapped;
                let curr_paddr = paddr + segment_mapped;

                let (pgsize, pgcount) = Self::get_pgsize(curr_iova | curr_paddr, remaining);

                let mapped = self.page_table.map_pages(
                    curr_iova as usize,
                    curr_paddr as usize,
                    pgsize as usize,
                    pgcount as usize,
                    prot,
                )?;

                if mapped == 0 {
                    pr_err!(
                        "map_pages returned 0 bytes mapped (iova: {:#x}, paddr: {:#x}, pgsize: {:#x}, pgcount: {})\n",
                        curr_iova, curr_paddr, pgsize, pgcount
                    );
                    // Unmap what we've mapped so far
                    if segment_mapped > 0 || iova > start_iova {
                        let _ = self.unmap_pages(
                            &ctx.iomem,
                            ctx.vm_as_nr,
                            start_iova..iova + segment_mapped,
                        );
                    }
                    return Err(ENOMEM);
                }

                segment_mapped += mapped as u64;
            }

            left -= len;
            iova += len;
        }

        let op = op.insert(gpuva, TyrVaData::new());

        if let Some(as_nr) = ctx.vm_as_nr {
            let range = start_iova..iova;
            Mmu::flush_range(&ctx.iomem, as_nr, range)?;
        }

        Ok(op)
    }

    fn sm_step_unmap<'op, 'ctx>(
        &mut self,
        op: gpuvm::OpUnmap<'op, Self>,
        ctx: &mut Self::SmContext<'ctx>,
    ) -> Result<gpuvm::OpUnmapped<'op, Self>, Error> {
        let va = op.va();
        let iova = va.range();

        pr_info!("Unmapping range {:#x} - {:#x}\n", iova.start, iova.end);
        self.unmap_pages(&ctx.iomem, ctx.vm_as_nr, iova)?;

        let (unmapped, _) = op.remove();
        Ok(unmapped)
    }

    fn sm_step_remap<'op, 'ctx>(
        &mut self,
        op: gpuvm::OpRemap<'op, Self>,
        ctx: &mut Self::SmContext<'ctx>,
    ) -> Result<gpuvm::OpRemapped<'op, Self>, Error> {
        pr_info!(
            "Remapping range {:#x} - {:#x}\n",
            op.va_to_unmap().addr(),
            op.va_to_unmap().addr() + op.va_to_unmap().length()
        );
        let prev_va = ctx.preallocated_va()?;
        let next_va = ctx.preallocated_va()?;

        let va = op.va_to_unmap();
        let orig_addr = va.addr();
        let orig_range: u64 = va.length();

        // Only unmap the hole between prev/next, if they exist
        let unmap_start = if let Some(op) = op.prev() {
            op.addr() + op.length()
        } else {
            orig_addr
        };

        let unmap_end = if let Some(op) = op.next() {
            op.addr()
        } else {
            orig_addr + orig_range
        };

        let unmap_range = unmap_start..unmap_end;

        self.unmap_pages(&ctx.iomem, ctx.vm_as_nr, unmap_range)?;

        let (remapped, _) = op.remap([prev_va, next_va], TyrVaData::new(), TyrVaData::new());
        Ok(remapped)
    }
}
