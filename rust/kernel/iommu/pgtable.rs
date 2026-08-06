// SPDX-License-Identifier: GPL-2.0

//! IOMMU page table management.
//!
//! C header: [`include/linux/io-pgtable.h`](srctree/include/linux/io-pgtable.h)

use core::{
    marker::PhantomData,
    ptr::NonNull, //
};

use crate::{
    alloc,
    bindings,
    device::{
        Bound,
        Device, //
    },
    devres::Devres,
    error::to_result,
    io::PhysAddr,
    prelude::*,
    sync::Arc, //
};

use bindings::io_pgtable_fmt;

/// Protection flags used with IOMMU mappings.
pub mod prot {
    /// Read access.
    pub const READ: u32 = bindings::IOMMU_READ;
    /// Write access.
    pub const WRITE: u32 = bindings::IOMMU_WRITE;
    /// Request cache coherency.
    pub const CACHE: u32 = bindings::IOMMU_CACHE;
    /// Request no-execute permission.
    pub const NOEXEC: u32 = bindings::IOMMU_NOEXEC;
    /// MMIO peripheral mapping.
    pub const MMIO: u32 = bindings::IOMMU_MMIO;
    /// Privileged mapping.
    pub const PRIVILEGED: u32 = bindings::IOMMU_PRIV;
}

/// Represents a requested `io_pgtable` configuration.
pub struct Config {
    /// Quirk bitmask (type-specific).
    pub quirks: usize,
    /// Valid page sizes, as a bitmask of powers of two.
    pub pgsize_bitmap: usize,
    /// Input address space size in bits.
    pub ias: u32,
    /// Output address space size in bits.
    pub oas: u32,
    /// IOMMU uses coherent accesses for page table walks.
    pub coherent_walk: bool,
}

/// An io page table using a specific format.
///
/// `A` is the allocator that provides the memory backing the page tables. By default the
/// io-pgtable core allocates that memory itself.
///
/// # Invariants
///
/// The pointer references a valid io page table.
pub struct IoPageTable<F: IoPageTableFmt, A = CoreAlloc> {
    ptr: NonNull<bindings::io_pgtable_ops>,
    /// The custom allocator, if any.
    _allocator: Option<Arc<A>>,
    _marker: PhantomData<F>,
}

// SAFETY: `struct io_pgtable_ops` is not restricted to a single thread, and it is safe to drop the
// allocator on another thread because `A: Send + Sync`.
unsafe impl<F: IoPageTableFmt, A: Send + Sync> Send for IoPageTable<F, A> {}
// SAFETY: `struct io_pgtable_ops` may be accessed concurrently, and the page table operations only
// take a shared reference to the allocator, which is safe from any thread because `A: Sync`.
unsafe impl<F: IoPageTableFmt, A: Send + Sync> Sync for IoPageTable<F, A> {}

/// The format used by this page table.
pub trait IoPageTableFmt: 'static {
    /// The value representing this format.
    const FORMAT: io_pgtable_fmt;
}

/// Smallest page table an [`IoPageTable`] asks a [`PageTableAlloc`] for.
///
/// A page table can be smaller than the alignment the hardware needs for it, so both hooks round
/// the size up to this value.
const MIN_PAGE_TABLE_SIZE: usize = 64;

/// The allocator that provides the memory backing the page tables of an [`IoPageTable`].
///
/// [`alloc`] may sleep only when the flags passed to it allow sleeping. [`free`] can run in a
/// context that cannot sleep, so it must never block.
///
/// Both hooks can be called at any time while the [`IoPageTable`] exists. Dropping the
/// [`IoPageTable`] frees the page tables that are still live, so [`free`] runs during that drop
/// as well.
///
/// # Safety
///
/// Memory returned by [`alloc`] is programmed into a page table walked by hardware, so
/// implementers must return memory that is
///
/// * zeroed, because the hardware and the io-pgtable core both read it as page table entries
///   before anything writes them,
/// * suitable for `dma_map_single()` and `virt_to_phys()`, so it must not come from `vmalloc`,
/// * at least `size` bytes long and aligned to `size`,
/// * owned by the page table until it is passed back to [`free`], so [`alloc`] must not return
///   memory it has already returned, and must not free it in the meantime.
///
/// [`alloc`]: PageTableAlloc::alloc
/// [`free`]: PageTableAlloc::free
pub unsafe trait PageTableAlloc: Send + Sync + 'static {
    /// Allocates one page table of `size` bytes.
    ///
    /// `size` is fixed by the granule the [`IoPageTable`] was created with, except for the
    /// top-level table, which is allocated while the [`IoPageTable`] itself is created. [`free`]
    /// is called with the same `size` for the same page table.
    ///
    /// Returns [`None`] if no memory is available.
    ///
    /// [`free`]: PageTableAlloc::free
    fn alloc(&self, size: usize, flags: alloc::Flags) -> Option<NonNull<u8>>;

    /// Frees a page table obtained from [`PageTableAlloc::alloc`].
    ///
    /// # Safety
    ///
    /// `pages` must have been returned by [`PageTableAlloc::alloc`] on `self` for the same `size`,
    /// and must not have been freed since.
    unsafe fn free(&self, pages: NonNull<u8>, size: usize);
}

/// The io-pgtable core's own page allocator, which is the default for [`IoPageTable`].
///
/// This type has no values. It only implements [`PageTableAlloc`] so that it can be used as the
/// default type parameter.
pub enum CoreAlloc {}

// SAFETY: This type has no values, so neither method can be called.
unsafe impl PageTableAlloc for CoreAlloc {
    fn alloc(&self, _size: usize, _flags: alloc::Flags) -> Option<NonNull<u8>> {
        match *self {}
    }

    unsafe fn free(&self, _pages: NonNull<u8>, _size: usize) {
        match *self {}
    }
}

/// # Safety
///
/// `cookie` must point to a valid `A` that outlives this call.
unsafe extern "C" fn alloc_callback<A: PageTableAlloc>(
    cookie: *mut c_void,
    size: usize,
    gfp: bindings::gfp_t,
) -> *mut c_void {
    // SAFETY: The caller guarantees that `cookie` points to a valid `A`.
    let allocator = unsafe { &*cookie.cast::<A>() };

    match allocator.alloc(size.max(MIN_PAGE_TABLE_SIZE), alloc::Flags::from_raw(gfp)) {
        Some(pages) => pages.as_ptr().cast(),
        None => core::ptr::null_mut(),
    }
}

/// # Safety
///
/// * `cookie` must point to a valid `A` that outlives this call.
/// * `pages` must have been returned by `alloc_callback::<A>` for the same `cookie` and must not
///   have been freed since. `size` rounded up to `MIN_PAGE_TABLE_SIZE` must be the size that call
///   was made for.
unsafe extern "C" fn free_callback<A: PageTableAlloc>(
    cookie: *mut c_void,
    pages: *mut c_void,
    size: usize,
) {
    let Some(pages) = NonNull::new(pages.cast::<u8>()) else {
        return;
    };

    // SAFETY: The caller guarantees that `cookie` points to a valid `A`.
    let allocator = unsafe { &*cookie.cast::<A>() };

    // SAFETY: The caller guarantees that `pages` came from `A::alloc` and has not been freed
    // since. The io-pgtable core passes the size of the page table, not the size the core asked
    // for. Rounding that size the same way `alloc_callback` does gives back the size of the
    // allocation.
    unsafe { allocator.free(pages, size.max(MIN_PAGE_TABLE_SIZE)) };
}

impl<F: IoPageTableFmt> IoPageTable<F> {
    /// Create a new `IoPageTable` as a device resource.
    #[inline]
    pub fn new(
        dev: &Device<Bound>,
        config: Config,
    ) -> impl PinInit<Devres<IoPageTable<F>>, Error> + '_ {
        // SAFETY: Devres ensures that the value is dropped during device unbind.
        Devres::new(dev, unsafe { Self::new_raw(dev, config) })
    }

    /// Create a new `IoPageTable`.
    ///
    /// # Safety
    ///
    /// If successful, then the returned `IoPageTable` must be dropped before the device is
    /// unbound.
    #[inline]
    pub unsafe fn new_raw(dev: &Device<Bound>, config: Config) -> Result<IoPageTable<F>> {
        // SAFETY: The caller ensures that the io pgtable does not outlive the device.
        unsafe { Self::create(dev, config, None) }
    }
}

impl<F: IoPageTableFmt, A: PageTableAlloc> IoPageTable<F, A> {
    /// Create a new `IoPageTable` with a custom allocator, as a device resource.
    ///
    /// `F` must be a format that supports a custom allocator, i.e. one that advertises
    /// `IO_PGTABLE_CAP_CUSTOM_ALLOCATOR`. Any other format fails with [`ENOMEM`].
    #[inline]
    pub fn new_with_alloc(
        dev: &Device<Bound>,
        config: Config,
        allocator: Arc<A>,
    ) -> impl PinInit<Devres<IoPageTable<F, A>>, Error> + '_ {
        // SAFETY: Devres ensures that the value is dropped during device unbind.
        Devres::new(dev, unsafe {
            Self::new_raw_with_alloc(dev, config, allocator)
        })
    }

    /// Create a new `IoPageTable` with a custom allocator.
    ///
    /// `allocator` provides the memory backing the page tables, including the top-level table
    /// this call allocates. The allocator is released once the page table has been freed.
    ///
    /// `F` must be a format that supports a custom allocator, i.e. one that advertises
    /// `IO_PGTABLE_CAP_CUSTOM_ALLOCATOR`. Any other format fails with [`ENOMEM`].
    ///
    /// # Safety
    ///
    /// If successful, then the returned `IoPageTable` must be dropped before the device is
    /// unbound.
    #[inline]
    pub unsafe fn new_raw_with_alloc(
        dev: &Device<Bound>,
        config: Config,
        allocator: Arc<A>,
    ) -> Result<IoPageTable<F, A>> {
        // SAFETY: The caller ensures that the io pgtable does not outlive the device.
        unsafe { Self::create(dev, config, Some(allocator)) }
    }

    /// # Safety
    ///
    /// If successful, then the returned `IoPageTable` must be dropped before the device is
    /// unbound.
    unsafe fn create(
        dev: &Device<Bound>,
        config: Config,
        allocator: Option<Arc<A>>,
    ) -> Result<Self> {
        let mut raw_cfg = bindings::io_pgtable_cfg {
            quirks: config.quirks,
            pgsize_bitmap: config.pgsize_bitmap,
            ias: config.ias,
            oas: config.oas,
            coherent_walk: config.coherent_walk,
            tlb: &raw const NOOP_FLUSH_OPS,
            iommu_dev: dev.as_raw(),
            // SAFETY: All zeroes is a valid value for `struct io_pgtable_cfg`.
            ..unsafe { core::mem::zeroed() }
        };

        let cookie = match &allocator {
            Some(allocator) => {
                raw_cfg.alloc = Some(alloc_callback::<A>);
                raw_cfg.free = Some(free_callback::<A>);
                // The `Arc` keeps the allocator at this address until the returned page table
                // drops it.
                Arc::as_ptr(allocator).cast_mut().cast()
            }
            None => core::ptr::null_mut(),
        };

        // SAFETY:
        // * The raw_cfg pointer is valid for the duration of this call.
        // * The provided `FLUSH_OPS` contains valid function pointers that ignore the cookie.
        // * The allocator callbacks accept `cookie`, which the returned page table keeps alive.
        // * The caller ensures that the io pgtable does not outlive the device.
        let ops = unsafe { bindings::alloc_io_pgtable_ops(F::FORMAT, &mut raw_cfg, cookie) };

        // INVARIANT: We successfully created a valid page table.
        Ok(IoPageTable {
            ptr: NonNull::new(ops).ok_or(ENOMEM)?,
            _allocator: allocator,
            _marker: PhantomData,
        })
    }
}

impl<F: IoPageTableFmt, A> IoPageTable<F, A> {
    /// Obtain a raw pointer to the underlying `struct io_pgtable_ops`.
    #[inline]
    pub fn raw_ops(&self) -> *mut bindings::io_pgtable_ops {
        self.ptr.as_ptr()
    }

    /// Obtain a raw pointer to the underlying `struct io_pgtable`.
    #[inline]
    pub fn raw_pgtable(&self) -> *mut bindings::io_pgtable {
        // SAFETY: The io_pgtable_ops of an io-pgtable is always the ops field of a io_pgtable.
        unsafe { kernel::container_of!(self.raw_ops(), bindings::io_pgtable, ops) }
    }

    /// Obtain a raw pointer to the underlying `struct io_pgtable_cfg`.
    #[inline]
    pub fn raw_cfg(&self) -> *mut bindings::io_pgtable_cfg {
        // SAFETY: The `raw_pgtable()` method returns a valid pointer.
        unsafe { &raw mut (*self.raw_pgtable()).cfg }
    }

    /// Map a physically contiguous range of pages of the same size.
    ///
    /// Even if successful, this operation may not map the entire range. In that case, only a
    /// prefix of the range is mapped, and the returned integer indicates its length in bytes. In
    /// this case, the caller will usually call `map_pages` again for the remaining range.
    ///
    /// The returned [`Result`] indicates whether an error was encountered while mapping pages.
    /// Note that this may return a non-zero length even if an error was encountered. The caller
    /// will usually [unmap the relevant pages](Self::unmap_pages) on error.
    ///
    /// The caller must flush the TLB before using the pgtable to access the newly created mapping.
    ///
    /// # Safety
    ///
    /// * No other io-pgtable operation may access the range `iova .. iova+pgsize*pgcount` while
    ///   this `map_pages` operation executes.
    /// * This page table must not contain any mapping that overlaps with the mapping created by
    ///   this call.
    /// * If this page table is live, then the caller must ensure that it's okay to access the
    ///   physical address being mapped for the duration in which it is mapped.
    #[inline]
    pub unsafe fn map_pages(
        &self,
        iova: usize,
        paddr: PhysAddr,
        pgsize: usize,
        pgcount: usize,
        prot: u32,
        flags: alloc::Flags,
    ) -> (usize, Result) {
        let mut mapped: usize = 0;

        // SAFETY: The `map_pages` function in `io_pgtable_ops` is never null.
        let map_pages = unsafe { (*self.raw_ops()).map_pages.unwrap_unchecked() };

        // SAFETY: The safety requirements of this method are sufficient to call `map_pages`.
        let ret = to_result(unsafe {
            (map_pages)(
                self.raw_ops(),
                iova,
                paddr,
                pgsize,
                pgcount,
                prot as i32,
                flags.as_raw(),
                &mut mapped,
            )
        });

        (mapped, ret)
    }

    /// Unmap a range of virtually contiguous pages of the same size.
    ///
    /// This may not unmap the entire range, and returns the length of the unmapped prefix in
    /// bytes.
    ///
    /// # Safety
    ///
    /// * No other io-pgtable operation may access the range `iova .. iova+pgsize*pgcount` while
    ///   this `unmap_pages` operation executes.
    /// * This page table must contain one or more consecutive mappings starting at `iova` whose
    ///   total size is `pgcount * pgsize`.
    #[inline]
    #[must_use]
    pub unsafe fn unmap_pages(&self, iova: usize, pgsize: usize, pgcount: usize) -> usize {
        // SAFETY: The `unmap_pages` function in `io_pgtable_ops` is never null.
        let unmap_pages = unsafe { (*self.raw_ops()).unmap_pages.unwrap_unchecked() };

        // SAFETY: The safety requirements of this method are sufficient to call `unmap_pages`.
        unsafe { (unmap_pages)(self.raw_ops(), iova, pgsize, pgcount, core::ptr::null_mut()) }
    }

    /// Translate an `iova` to the physical address it maps to.
    ///
    /// Returns [`None`] if `iova` is not mapped. As in the underlying C op, a mapping to physical
    /// address 0 is indistinguishable from unmapped and also reports [`None`]. The returned address
    /// includes the offset of `iova` within the mapping block, so it is exact for any `iova`, not
    /// just block-aligned ones. This walk is lock-free and does not allocate.
    ///
    /// # Safety
    ///
    /// No other io-pgtable operation may modify the entry covering `iova` while this walk
    /// executes.
    #[inline]
    pub unsafe fn iova_to_phys(&self, iova: usize) -> Option<PhysAddr> {
        // SAFETY: The `iova_to_phys` function in `io_pgtable_ops` is never null.
        let iova_to_phys = unsafe { (*self.raw_ops()).iova_to_phys.unwrap_unchecked() };

        // SAFETY: The safety requirements of this method are sufficient to call `iova_to_phys`.
        let paddr = unsafe { (iova_to_phys)(self.raw_ops(), iova) };

        // A zero return means `iova` is not mapped.
        (paddr != 0).then_some(paddr)
    }
}

// For the initial users of these rust bindings, the GPU FW is managing the IOTLB and performs all
// required invalidations using a range. There is no need for it get ARM style invalidation
// instructions from the page table code.
//
// Support for flushing the TLB with ARM style invalidation instructions may be added in the
// future.
static NOOP_FLUSH_OPS: bindings::iommu_flush_ops = bindings::iommu_flush_ops {
    tlb_flush_all: Some(rust_tlb_flush_all_noop),
    tlb_flush_walk: Some(rust_tlb_flush_walk_noop),
    tlb_add_page: None,
};

#[no_mangle]
extern "C" fn rust_tlb_flush_all_noop(_cookie: *mut core::ffi::c_void) {}

#[no_mangle]
extern "C" fn rust_tlb_flush_walk_noop(
    _iova: usize,
    _size: usize,
    _granule: usize,
    _cookie: *mut core::ffi::c_void,
) {
}

impl<F: IoPageTableFmt, A> Drop for IoPageTable<F, A> {
    fn drop(&mut self) {
        // Freeing the remaining page tables calls back into the allocator, which is only dropped
        // once this function returns.
        //
        // SAFETY: The caller of `Self::ttbr()` promised that the page table is not live when this
        // destructor runs.
        unsafe { bindings::free_io_pgtable_ops(self.raw_ops()) };
    }
}

/// The `ARM_64_LPAE_S1` page table format.
pub enum ARM64LPAES1 {}

impl IoPageTableFmt for ARM64LPAES1 {
    const FORMAT: io_pgtable_fmt = bindings::io_pgtable_fmt_ARM_64_LPAE_S1 as io_pgtable_fmt;
}

impl<A> IoPageTable<ARM64LPAES1, A> {
    /// Access the `ttbr` field of the configuration.
    ///
    /// This is the physical address of the page table, which may be passed to the device that
    /// needs to use it.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the device stops using the page table before dropping it.
    #[inline]
    pub unsafe fn ttbr(&self) -> u64 {
        // SAFETY: `arm_lpae_s1_cfg` is the right cfg type for `ARM64LPAES1`.
        unsafe { (*self.raw_cfg()).__bindgen_anon_1.arm_lpae_s1_cfg.ttbr }
    }

    /// Access the `mair` field of the configuration.
    #[inline]
    pub fn mair(&self) -> u64 {
        // SAFETY: `arm_lpae_s1_cfg` is the right cfg type for `ARM64LPAES1`.
        unsafe { (*self.raw_cfg()).__bindgen_anon_1.arm_lpae_s1_cfg.mair }
    }
}
