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
use kernel::drm::gpuvm::DriverGpuVa;
use kernel::drm::gpuvm::{self};
use kernel::io::mem::IoMem;
use kernel::io_pgtable::IoPageTable;
use kernel::io_pgtable::ARM64LPAES1;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::types::ARef;

use crate::driver;
use crate::mmu::vm;
use crate::mmu::Mmu;

/// A convenience so that we do not have to spell this whole thing out every
/// time.
type PinnedVa = Pin<KBox<gpuvm::GpuVa<LockedVm>>>;

/// A context that is passed throughout the map/unmap/remap steps.
pub(in crate::mmu) struct StepContext {
    /// The Vm <=> BO connection,
    pub(super) vm_bo: Option<ARef<gpuvm::GpuVmBo<LockedVm>>>,

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
            Some(gpuvm::GpuVa::<LockedVm>::new(pin_init::init_zeroed())?),
            Some(gpuvm::GpuVa::<LockedVm>::new(pin_init::init_zeroed())?),
            Some(gpuvm::GpuVa::<LockedVm>::new(pin_init::init_zeroed())?),
        ])
    }
}

pub(crate) struct GpuVa {/* TODO */}
unsafe impl pin_init::Zeroable for GpuVa {}

impl DriverGpuVa for GpuVa {}

/// A state that can only be accessed when the GPUVM is locked.
pub(in crate::mmu) struct LockedVm {
    /// The page table for this VM.
    pub(in crate::mmu) page_table: ARM64LPAES1<Mmu>,
    /// The allocator keeping track of what ranges are in use for the kernel VA
    /// range.
    pub(super) kernel_mm: vm::range::RangeAlloc,
}

impl LockedVm {
    pub(super) fn new(
        page_table: ARM64LPAES1<Mmu>,
        kernel_mm: vm::range::RangeAlloc,
    ) -> impl Init<Self> {
        init!(LockedVm {
            page_table,
            kernel_mm,
        })
    }

    fn unmap_pages(
        &mut self,
        iomem: &Devres<IoMem>,
        as_nr: Option<usize>,
        iova: Range<u64>,
    ) -> Result {
        let mut total_unmapped = 0;
        let size = iova.end - iova.start;

        while total_unmapped < size {
            let pgsize = 4096;
            let pgcount = (size - total_unmapped).div_ceil(pgsize);

            let unmapped_sz = self.page_table.unmap_pages(
                iova.start as usize,
                pgsize as usize,
                pgcount as usize,
            );

            if unmapped_sz as u64 != pgsize * pgcount {
                let range = iova.start
                    ..iova.start + total_unmapped + unmapped_sz as u64;

                pr_err!(
                    "AS ({:#?}): failed to unmap range {:#x} - {:#x}, unmapped only {:#x} bytes\n",
                    as_nr,
                    iova.start,
                    iova.start + size,
                    unmapped_sz,
                );

                if let Some(as_nr) = as_nr {
                    Mmu::flush_range(iomem, as_nr, range)?;
                }

                return Err(EINVAL);
            }

            pr_info!(
                "AS ({:#?}): unmapped {} bytes, iova: {:#x}, pgsize: {}, pgcount: {}, len: {}\n",
                as_nr,
                unmapped_sz,
                iova.start,
                pgsize,
                pgcount,
                size
            );

            total_unmapped += unmapped_sz as u64;
        }

        if let Some(as_nr) = as_nr {
            Mmu::flush_range(iomem, as_nr, iova)?;
        }

        Ok(())
    }
}

impl gpuvm::DriverGpuVm for LockedVm {
    type Driver = driver::TyrDriver;
    type GpuVmBo = VmBo;
    type StepContext = StepContext;

    type GpuVa = GpuVa;

    fn step_map(
        gpuvm: &mut gpuvm::GpuVm<Self>,
        op: &mut gpuvm::OpMap<Self>,
        ctx: &mut Self::StepContext,
    ) -> Result {
        // This is the mapping algorithm from Asahi.

        let mut iova = op.addr();
        let mut left = op.length();
        let mut offset = op.gem_offset();
        let gpuva = ctx.preallocated_va()?;

        let vm_bo = ctx.vm_bo.as_ref().ok_or(EINVAL)?;
        let sgt = vm_bo.gem().sg_table();
        let prot = ctx.vm_map_flags.ok_or(EINVAL)?.to_prot();

        pr_info!("mapping {} bytes, iova: {:#x}, prot {}\n", left, iova, prot);

        for range in sgt
            .as_ref()
            .expect("SGT should be set before step_map")
            .iter()
        {
            let mut addr = range.dma_address();
            let mut len = u64::from(range.dma_len());

            if left == 0 {
                break;
            }

            if offset > 0 {
                let skip = len.min(offset);
                addr += skip;
                len -= skip;
                offset -= skip;
            }

            if len == 0 {
                continue;
            }

            assert!(offset == 0);

            len = len.min(left);

            let pgsize = 4096;
            let pgcount = len.div_ceil(pgsize);

            let _ = gpuvm.page_table.map_pages(
                iova as usize,
                addr as usize,
                pgsize as usize,
                pgcount as usize,
                prot,
            )?;

            left -= len;
            iova += len;
        }

        gpuvm.insert_va(op, gpuva).map_err(|_| EINVAL)?;
        gpuvm.find_va(op.range(), |gpuvm, gpuva| {
            let gpuva = gpuva.ok_or(EINVAL)?;
            gpuvm.link_va(
                gpuva,
                ctx.vm_bo.as_ref().expect("step_map with no BO"),
            )?;
            Ok(())
        })?;

        Ok(())
    }

    fn step_unmap(
        gpuvm: &mut gpuvm::GpuVm<Self>,
        op: &mut gpuvm::OpUnMap<Self>,
        ctx: &mut Self::StepContext,
    ) -> Result {
        // This is always set by drm_gpuvm.c:op_unmap_cb(), not sure why it's an
        // Option.
        //
        // XXX: discuss this with everybody else
        let va = op.va().expect("This is always set by GPUVM");
        let iova = va.range();

        gpuvm.unmap_pages(&ctx.iomem, ctx.vm_as_nr, iova)?;

        gpuvm.find_va(va.range(), |gpuvm, gpuva| {
            let removed =
                gpuvm.remove_va(gpuva.unwrap()).map_err(|_| EINVAL)?;
            gpuvm.unlink_va(&removed);
            Ok(())
        })?;

        Ok(())
    }

    fn step_remap(
        gpuvm: &mut gpuvm::GpuVm<Self>,
        op: &mut gpuvm::OpReMap<Self>,
        _vm_bo: &gpuvm::GpuVmBo<Self>,
        ctx: &mut Self::StepContext,
    ) -> Result {
        let prev_va = ctx.preallocated_va()?;
        let next_va = ctx.preallocated_va()?;
        let vm_bo = ctx.vm_bo.as_ref().ok_or(EINVAL)?;

        let va = op.unmap().va().ok_or(EINVAL)?;
        let orig_addr = va.addr();
        let orig_range: u64 = va.length();

        // Only unmap the hole between prev/next, if they exist
        let unmap_start = if let Some(op) = op.prev_map() {
            op.addr() + op.length()
        } else {
            orig_addr
        };

        let unmap_end = if let Some(op) = op.next_map() {
            op.addr()
        } else {
            orig_addr + orig_range
        };

        let unmap_range = unmap_start..unmap_end;

        gpuvm.unmap_pages(&ctx.iomem, ctx.vm_as_nr, unmap_range)?;
        gpuvm.find_va(op.unmap().va().unwrap().range(), |gpuvm, gpuva| {
            let removed_va =
                gpuvm.remove_va(gpuva.unwrap()).map_err(|_| EINVAL)?;
            gpuvm.unlink_va(&removed_va);
            Ok(())
        })?;

        if let Some(prev_op) = op.prev_map() {
            gpuvm.insert_va(prev_op, prev_va).map_err(|_| EINVAL)?;
            gpuvm.find_va(prev_op.range(), |gpuvm, gpuva| {
                let gpuva = gpuva.ok_or(EINVAL)?;
                gpuvm.link_va(gpuva, vm_bo)?;
                Ok(())
            })?;
        }

        if let Some(next_op) = op.next_map() {
            gpuvm.insert_va(next_op, next_va).map_err(|_| EINVAL)?;
            gpuvm.find_va(next_op.range(), |gpuvm, gpuva| {
                let gpuva = gpuva.ok_or(EINVAL)?;
                gpuvm.link_va(gpuva, vm_bo)?;
                Ok(())
            })?;
        }

        Ok(())
    }
}

/// Data associated with a VM <=> BO pairing
#[pin_data]
pub(in crate::mmu) struct VmBo {}

impl gpuvm::DriverGpuVmBo for VmBo {
    fn new() -> impl PinInit<Self> {
        pin_init!(VmBo {})
    }
}
