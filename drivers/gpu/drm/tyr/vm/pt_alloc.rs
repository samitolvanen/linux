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
    bindings,
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
    /// Allocates a page table of `size` bytes with `flags`.
    fn new(size: usize, flags: Flags) -> Option<Self> {
        let ptr = Kmalloc::alloc(pt_layout(size)?, flags, NumaNode::NO_NODE).ok()?;

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

/// An unzeroed `PT_SIZE` page table held by a `PtReserve` or a `PtPool`.
///
/// # Invariants
///
/// The pointer came from `PtPage::into_raw` for `PT_SIZE`, and this
/// `ReservedPt` owns the page table.
struct ReservedPt(NonNull<u8>);

// SAFETY: A `ReservedPt` owns its page table, which has no affinity to the
// thread that allocated it.
unsafe impl Send for ReservedPt {}

impl ReservedPt {
    /// Allocates a `PT_SIZE` page table.
    fn new(flags: Flags) -> Option<Self> {
        // INVARIANT: The pointer comes from `PtPage::into_raw` for `PT_SIZE`.
        Some(Self(PtPage::new(PT_SIZE, flags)?.into_raw()))
    }

    /// Zeroes the page table and gives up ownership of it.
    fn into_zeroed_raw(self) -> NonNull<u8> {
        // SAFETY: By the type invariant, `self` owns a `PT_SIZE` page table, so
        // it is valid for writes of `PT_SIZE` bytes.
        unsafe { self.0.as_ptr().write_bytes(0, PT_SIZE) };
        ManuallyDrop::new(self).0
    }
}

impl TryFrom<PtPage> for ReservedPt {
    type Error = PtPage;

    fn try_from(page: PtPage) -> Result<Self, PtPage> {
        if page.size != PT_SIZE {
            return Err(page);
        }

        // INVARIANT: The pointer comes from `PtPage::into_raw` for `PT_SIZE`.
        Ok(Self(page.into_raw()))
    }
}

impl Drop for ReservedPt {
    fn drop(&mut self) {
        // SAFETY: By the type invariant, the pointer came from
        // `PtPage::into_raw` for `PT_SIZE` and is owned by `self`.
        drop(unsafe { PtPage::from_raw(self.0, PT_SIZE) });
    }
}

/// Largest number of page tables one `PtReserve` can hold, so that its
/// array fits in one kmalloc() allocation.
const PT_RESERVE_MAX: usize = bindings::KMALLOC_MAX_SIZE as usize / size_of::<ReservedPt>();

/// Page tables reserved for one page table update.
#[derive(Default)]
pub(crate) struct PtReserve {
    pages: KVec<ReservedPt>,
}

impl PtReserve {
    /// Reserves the page tables that mapping `size` bytes at `va` can need.
    pub(crate) fn for_map(
        allocator: &PtAllocator,
        va: u64,
        size: u64,
        flags: Flags,
    ) -> Result<Self> {
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

        Self::with_count(allocator, count, flags)
    }

    /// Reserves the page tables that unmapping `size` bytes at `va` can need.
    pub(crate) fn for_unmap(
        allocator: &PtAllocator,
        va: u64,
        size: u64,
        flags: Flags,
    ) -> Result<Self> {
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

        Self::with_count(allocator, count, flags)
    }

    /// Reserves `count` page tables, taking the ones `allocator` caches before
    /// allocating with `flags`.
    fn with_count(allocator: &PtAllocator, count: u64, flags: Flags) -> Result<Self> {
        let count = usize::try_from(count)
            .ok()
            .filter(|&count| count <= PT_RESERVE_MAX)
            .ok_or(ENOMEM)?;
        if count == 0 {
            return Ok(Self::default());
        }

        let mut pages = KVec::with_capacity(count, flags)?;
        allocator.take_cached(&mut pages);

        while pages.len() < count {
            let page = ReservedPt::new(flags).ok_or(ENOMEM)?;
            pages.push(page, flags)?;
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

/// Largest number of page tables a `PtPool` caches, enough for the reserve of
/// a map within one `PT_MIN_BLOCK_SIZE` block.
const PT_POOL_CACHE_CAP: usize = PT_LEVEL_SHIFTS.len();

/// The state `PtAllocator` hands page tables out from.
struct PtPool {
    /// Page tables reserved for the update in progress, `None` outside one.
    reserve: Option<PtReserve>,
    /// Page tables freed or left unused by an update, kept for later reserves.
    cache: [Option<ReservedPt>; PT_POOL_CACHE_CAP],
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
                cache: [const { None }; PT_POOL_CACHE_CAP],
                warned: false,
            }),
        })
    }

    /// Makes `reserve` available to the page table update that is starting.
    pub(crate) fn set_reserve(&self, reserve: PtReserve) {
        self.pool.lock().reserve = Some(reserve);
    }

    /// Takes back the reserve of a finished update after moving its spare
    /// page tables into the cache.
    #[inline(never)]
    pub(crate) fn take_reserve(&self) -> PtReserve {
        let mut pool = self.pool.lock();
        let mut reserve = pool.reserve.take().unwrap_or_default();

        for slot in pool.cache.iter_mut().filter(|slot| slot.is_none()) {
            *slot = reserve.pages.pop();
        }

        reserve
    }

    /// Moves cached page tables into `pages`, up to its capacity.
    fn take_cached(&self, pages: &mut KVec<ReservedPt>) {
        let mut pool = self.pool.lock();

        for slot in pool.cache.iter_mut() {
            let Some(page) = slot.take() else {
                continue;
            };

            if let Err(err) = pages.push_within_capacity(page) {
                *slot = Some(err.0);
                break;
            }
        }
    }

    /// Caches `page` if the cache has room, and frees it otherwise.
    fn cache_or_free(&self, page: ReservedPt) {
        let mut pool = self.pool.lock();

        if let Some(slot) = pool.cache.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(page);
        }
    }
}

// SAFETY: Every page table is physically contiguous memory from the slab
// allocator, in a layout whose size and alignment are both at least the
// requested size, and is zeroed when it is handed out. Handing a page table
// out removes it from the reserve, and only `free` caches or frees it, so it
// is never handed out again or freed while io-pgtable owns it.
unsafe impl PageTableAlloc for PtAllocator {
    fn alloc(&self, size: usize, flags: Flags) -> Option<NonNull<u8>> {
        let first_failure = {
            let mut pool = self.pool.lock();

            match pool.reserve.as_mut() {
                None => false,
                Some(reserve) => {
                    if size == PT_SIZE {
                        if let Some(page) = reserve.pages.pop() {
                            drop(pool);
                            return Some(page.into_zeroed_raw());
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
        Some(PtPage::new(size, flags | __GFP_ZERO)?.into_raw())
    }

    #[inline]
    unsafe fn free(&self, pages: NonNull<u8>, size: usize) {
        // SAFETY: The caller guarantees that `pages` came from `alloc` for
        // `size` and has not been freed since.
        let page = unsafe { PtPage::from_raw(pages, size) };

        match ReservedPt::try_from(page) {
            Ok(page) => self.cache_or_free(page),
            Err(page) => drop(page),
        }
    }
}
