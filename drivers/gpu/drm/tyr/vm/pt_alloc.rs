// SPDX-License-Identifier: GPL-2.0 or MIT

//! Page table memory for GPU virtual address spaces.
//!
//! An asynchronous VM_BIND updates the page table inside the dma-fence
//! signalling section. That section must not make allocations that can wait
//! for reclaim. Every update therefore reserves the page tables it can need
//! before it starts. `PtAllocator` hands those page tables out for as long as
//! the update runs.

use core::{
    alloc::Layout,
    mem::ManuallyDrop,
    ptr::NonNull, //
};

use kernel::{
    alloc::{
        allocator::Kmalloc,
        Allocator,
        Flags,
        NumaNode, //
    },
    iommu::pgtable::{
        IoPageTable,
        PageTableAlloc,
        ARM64LPAES1, //
    },
    new_spinlock,
    prelude::*,
    ptr::{
        Alignable,
        Alignment, //
    },
    sizes::{
        SZ_2M,
        SZ_4K, //
    },
    sync::SpinLock,
    warn_on, //
};

/// The page table format and allocator used by GPU address spaces.
pub(crate) type PageTable = IoPageTable<ARM64LPAES1, PtAllocator>;

/// Size of every page table below the top level, fixed by the 4KB granule.
const PT_SIZE: usize = SZ_4K;

/// Level 1 shift in a four-level ARM64 LPAE stage 1 walk with a 4KB granule.
///
/// Covers 512GB per table.
const PT_LVL1_SHIFT: u32 = 39;

/// Level 2 shift in a four-level ARM64 LPAE stage 1 walk with a 4KB granule.
///
/// Covers 1GB per table.
const PT_LVL2_SHIFT: u32 = 30;

/// Level 3 shift in a four-level ARM64 LPAE stage 1 walk with a 4KB granule.
///
/// Covers 2MB per table, which is also the smallest block mapping size.
const PT_LVL3_SHIFT: u32 = 21;

/// The smallest block mapping size (2MB) for a four-level ARM64 LPAE stage 1
/// walk with a 4KB granule.
///
/// This is also the region covered by a single level-3 page table.
pub(crate) const PT_MIN_BLOCK_SIZE: usize = SZ_2M;

/// Sizes, in address bits, of the regions one page table covers at each level
/// of a four-level ARM64 LPAE stage 1 walk with a 4KB granule, apart from the
/// top-level table.
///
/// An update can need one new table per region it spans at each of these
/// levels.
const PT_LEVEL_SHIFTS: [u32; 3] = [PT_LVL1_SHIFT, PT_LVL2_SHIFT, PT_LVL3_SHIFT];

/// Smallest page table this allocator hands out. The hardware needs at least
/// this much alignment for a page table. The `PageTableAlloc` contract does
/// not promise a minimum size, so a smaller request is rounded up here.
const PT_MIN_SIZE: usize = 64;

/// Returns the layout of a page table of `size` bytes.
///
/// A page table must be aligned to its own size. Returns `None` if the rounded
/// size is not a power of two.
fn pt_layout(size: usize) -> Option<Layout> {
    let size = size.max(PT_MIN_SIZE);

    Layout::from_size_align(size, size).ok()
}

/// Returns how many regions of `1 << shift` bytes `start..end` spans.
fn regions_spanned(start: u64, end: u64, shift: u32) -> u64 {
    ((end - 1) >> shift) - (start >> shift) + 1
}

/// A page table, owned until it is handed to the io-pgtable core.
struct PtPage {
    ptr: NonNull<u8>,
    size: usize,
}

// SAFETY: A `PtPage` owns its allocation, which has no affinity to the thread
// that allocated it.
unsafe impl Send for PtPage {}

impl PtPage {
    /// Allocates a zeroed page table of `size` bytes.
    fn new(size: usize, flags: Flags) -> Option<Self> {
        let ptr = Kmalloc::alloc(pt_layout(size)?, flags | __GFP_ZERO, NumaNode::NO_NODE).ok()?;

        Some(Self {
            ptr: ptr.cast(),
            size,
        })
    }

    /// Gives up ownership of the page table.
    fn into_raw(self) -> NonNull<u8> {
        ManuallyDrop::new(self).ptr
    }

    /// Takes back ownership of a page table from `PtPage::into_raw`.
    ///
    /// # Safety
    ///
    /// `ptr` must have come from `PtPage::into_raw` for the same `size`, and
    /// must not have been freed since.
    unsafe fn from_raw(ptr: NonNull<u8>, size: usize) -> Self {
        Self { ptr, size }
    }
}

impl Drop for PtPage {
    fn drop(&mut self) {
        let Some(layout) = pt_layout(self.size) else {
            // Every page table was allocated with a layout from `pt_layout`,
            // so it cannot fail here. Leak the page table rather than free it
            // with a layout it was not allocated with.
            warn_on!(true);
            return;
        };

        // SAFETY: The layout is the one the page table was allocated with, and
        // nothing accesses the page table after this.
        unsafe { Kmalloc::free(self.ptr, layout) };
    }
}

/// Page tables reserved for one page table update.
#[derive(Default)]
pub(crate) struct PtReserve {
    pages: KVec<PtPage>,
}

impl PtReserve {
    /// Reserves the page tables that mapping `size` bytes at `va` can need.
    pub(crate) fn for_map(va: u64, size: u64) -> Result<Self> {
        let end = va.checked_add(size).ok_or(EINVAL)?;
        if size == 0 {
            return Ok(Self::default());
        }

        // The map may have to build a table at every level it spans. Counting
        // the table for each region is an overestimate, because the map can
        // find one already built or cover a whole region with one block entry.
        //
        // A map that overlaps an existing mapping splits that mapping. The
        // split leaves a fragment only where an end of the map is not aligned
        // to a `PT_MIN_BLOCK_SIZE` block. That fragment lies in the block the
        // misaligned end falls in. The count below already covers that block,
        // so rebuilding the fragment needs no further table.
        let count = PT_LEVEL_SHIFTS
            .iter()
            .map(|&shift| regions_spanned(va, end, shift))
            .sum();

        Self::with_count(count)
    }

    /// Reserves the page tables that unmapping `size` bytes at `va` can need.
    pub(crate) fn for_unmap(va: u64, size: u64) -> Result<Self> {
        let end = va.checked_add(size).ok_or(EINVAL)?;
        if size == 0 {
            return Ok(Self::default());
        }

        // An unmap whose start or end falls inside a `PT_MIN_BLOCK_SIZE`
        // block tears the whole block down. It then rebuilds the part of the
        // block that survives. That rebuild needs a level-3 table. One table
        // serves both ends when they fall in the same block.
        let block = Alignment::new::<{ PT_MIN_BLOCK_SIZE }>();
        let head = va != va.align_down(block);
        let tail = end != end.align_down(block);
        let same_block = va.align_down(block) == end.align_down(block);

        let mut count = 0;
        if head {
            count += 1;
        }
        if tail && !(head && same_block) {
            count += 1;
        }

        Self::with_count(count)
    }

    /// Allocates `count` page tables.
    fn with_count(count: u64) -> Result<Self> {
        let count = usize::try_from(count).map_err(|_| EINVAL)?;
        let mut pages = KVec::with_capacity(count, GFP_KERNEL)?;

        for _ in 0..count {
            let page = PtPage::new(PT_SIZE, GFP_KERNEL).ok_or(ENOMEM)?;
            pages.push(page, GFP_KERNEL)?;
        }

        Ok(Self { pages })
    }
}

/// Provides the memory backing the page tables of one VM.
#[pin_data]
pub(crate) struct PtAllocator {
    #[pin]
    pool: SpinLock<PtPool>,
}

/// The state `PtAllocator` hands page tables out from.
struct PtPool {
    /// Page tables reserved for the update in progress, `None` outside one.
    reserve: Option<PtReserve>,
    /// Whether a reserve has already failed to serve a request, so that only
    /// the first failure warns.
    warned: bool,
}

impl PtAllocator {
    /// Creates an allocator with no reserve.
    pub(crate) fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            pool <- new_spinlock!(PtPool {
                reserve: None,
                warned: false,
            }),
        })
    }

    /// Makes `reserve` available to the page table update that is starting.
    pub(crate) fn set_reserve(&self, reserve: PtReserve) {
        self.pool.lock().reserve = Some(reserve);
    }

    /// Takes back what is left of the reserve of a finished update.
    pub(crate) fn take_reserve(&self) -> PtReserve {
        self.pool.lock().reserve.take().unwrap_or_default()
    }
}

// SAFETY: `PtPage::new` allocates zeroed, physically contiguous memory from
// the slab allocator, in a layout whose size and alignment are both at least
// the requested size. Handing a page table out removes it from the reserve,
// so no page table is handed out twice. A page table is only freed once it
// comes back through `free`.
unsafe impl PageTableAlloc for PtAllocator {
    fn alloc(&self, size: usize, flags: Flags) -> Option<NonNull<u8>> {
        let first_failure = {
            let mut pool = self.pool.lock();

            match pool.reserve.as_mut() {
                None => false,
                Some(reserve) => {
                    if size == PT_SIZE {
                        if let Some(page) = reserve.pages.pop() {
                            return Some(page.into_raw());
                        }
                    }

                    let first_failure = !pool.warned;
                    pool.warned = true;
                    first_failure
                }
            }
        };

        // The reserve holds a page table for everything an update can ask for,
        // so a request it cannot serve means the estimate is wrong.
        warn_on!(first_failure);

        // Reached for the top-level table, which is allocated before any
        // update starts, and for a request the reserve could not serve.
        Some(PtPage::new(size, flags)?.into_raw())
    }

    unsafe fn free(&self, pages: NonNull<u8>, size: usize) {
        // A freed page table goes back to the slab allocator and never to a
        // reserve, so every page table a reserve hands out is still zeroed.
        //
        // SAFETY: The caller guarantees that `pages` came from `alloc` for
        // `size` and has not been freed since.
        drop(unsafe { PtPage::from_raw(pages, size) });
    }
}
