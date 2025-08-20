// SPDX-License-Identifier: GPL-2.0

//! Allocator support.
//!
//! Documentation for the kernel's memory allocators can found in the "Memory Allocation Guide"
//! linked below. For instance, this includes the concept of "get free page" (GFP) flags and the
//! typical application of the different kernel allocators.
//!
//! Reference: <https://docs.kernel.org/core-api/memory-allocation.html>

use super::Flags;
use core::alloc::Layout;
use core::marker::PhantomData;
use core::ptr;
use core::ptr::NonNull;

use crate::alloc::{AllocError, Allocator};
use crate::bindings;
use crate::page;
use crate::pr_warn;

/// The contiguous kernel allocator.
///
/// `Kmalloc` is typically used for physically contiguous allocations up to page size, but also
/// supports larger allocations up to `bindings::KMALLOC_MAX_SIZE`, which is hardware specific.
///
/// For more details see [self].
pub struct Kmalloc;

/// The virtually contiguous kernel allocator.
///
/// `Vmalloc` allocates pages from the page level allocator and maps them into the contiguous kernel
/// virtual space. It is typically used for large allocations. The memory allocated with this
/// allocator is not physically contiguous.
///
/// For more details see [self].
pub struct Vmalloc;

/// The kvmalloc kernel allocator.
///
/// `KVmalloc` attempts to allocate memory with `Kmalloc` first, but falls back to `Vmalloc` upon
/// failure. This allocator is typically used when the size for the requested allocation is not
/// known and may exceed the capabilities of `Kmalloc`.
///
/// For more details see [self].
pub struct KVmalloc;

/// # Invariants
///
/// One of the following: `krealloc`, `vrealloc`, `kvrealloc`.
struct ReallocFunc(
    unsafe extern "C" fn(*const crate::ffi::c_void, usize, u32) -> *mut crate::ffi::c_void,
);

impl ReallocFunc {
    // INVARIANT: `krealloc` satisfies the type invariants.
    const KREALLOC: Self = Self(bindings::krealloc);

    // INVARIANT: `vrealloc` satisfies the type invariants.
    const VREALLOC: Self = Self(bindings::vrealloc);

    // INVARIANT: `kvrealloc` satisfies the type invariants.
    const KVREALLOC: Self = Self(bindings::kvrealloc);

    /// # Safety
    ///
    /// This method has the same safety requirements as [`Allocator::realloc`].
    ///
    /// # Guarantees
    ///
    /// This method has the same guarantees as `Allocator::realloc`. Additionally
    /// - it accepts any pointer to a valid memory allocation allocated by this function.
    /// - memory allocated by this function remains valid until it is passed to this function.
    #[inline]
    unsafe fn call(
        &self,
        ptr: Option<NonNull<u8>>,
        layout: Layout,
        old_layout: Layout,
        flags: Flags,
    ) -> Result<NonNull<[u8]>, AllocError> {
        let size = layout.size();
        let ptr = match ptr {
            Some(ptr) => {
                if old_layout.size() == 0 {
                    ptr::null()
                } else {
                    ptr.as_ptr()
                }
            }
            None => ptr::null(),
        };

        // SAFETY:
        // - `self.0` is one of `krealloc`, `vrealloc`, `kvrealloc` and thus only requires that
        //   `ptr` is NULL or valid.
        // - `ptr` is either NULL or valid by the safety requirements of this function.
        //
        // GUARANTEE:
        // - `self.0` is one of `krealloc`, `vrealloc`, `kvrealloc`.
        // - Those functions provide the guarantees of this function.
        let raw_ptr = unsafe {
            // If `size == 0` and `ptr != NULL` the memory behind the pointer is freed.
            self.0(ptr.cast(), size, flags.0).cast()
        };

        let ptr = if size == 0 {
            crate::alloc::dangling_from_layout(layout)
        } else {
            NonNull::new(raw_ptr).ok_or(AllocError)?
        };

        Ok(NonNull::slice_from_raw_parts(ptr, size))
    }
}

impl Kmalloc {
    /// Returns a [`Layout`] that makes [`Kmalloc`] fulfill the requested size and alignment of
    /// `layout`.
    pub fn aligned_layout(layout: Layout) -> Layout {
        // Note that `layout.size()` (after padding) is guaranteed to be a multiple of
        // `layout.align()` which together with the slab guarantees means that `Kmalloc` will return
        // a properly aligned object (see comments in `kmalloc()` for more information).
        layout.pad_to_align()
    }
}

// SAFETY: `realloc` delegates to `ReallocFunc::call`, which guarantees that
// - memory remains valid until it is explicitly freed,
// - passing a pointer to a valid memory allocation is OK,
// - `realloc` satisfies the guarantees, since `ReallocFunc::call` has the same.
unsafe impl Allocator for Kmalloc {
    #[inline]
    unsafe fn realloc(
        ptr: Option<NonNull<u8>>,
        layout: Layout,
        old_layout: Layout,
        flags: Flags,
    ) -> Result<NonNull<[u8]>, AllocError> {
        let layout = Kmalloc::aligned_layout(layout);

        // SAFETY: `ReallocFunc::call` has the same safety requirements as `Allocator::realloc`.
        unsafe { ReallocFunc::KREALLOC.call(ptr, layout, old_layout, flags) }
    }
}

impl Vmalloc {
    /// Convert a pointer to a [`Vmalloc`] allocation to a [`page::BorrowedPage`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use core::ptr::{NonNull, from_mut};
    /// # use kernel::{page, prelude::*};
    /// use kernel::alloc::allocator::Vmalloc;
    ///
    /// let mut vbox = VBox::<[u8; page::PAGE_SIZE]>::new_uninit(GFP_KERNEL)?;
    ///
    /// {
    ///     // SAFETY: By the type invariant of `Box` the inner pointer of `vbox` is non-null.
    ///     let ptr = unsafe { NonNull::new_unchecked(from_mut(&mut *vbox)) };
    ///
    ///     // SAFETY:
    ///     // `ptr` is a valid pointer to a `Vmalloc` allocation.
    ///     // `ptr` is valid for the entire lifetime of `page`.
    ///     let page = unsafe { Vmalloc::to_page(ptr.cast()) };
    ///
    ///     // SAFETY: There is no concurrent read or write to the same page.
    ///     unsafe { page.fill_zero_raw(0, page::PAGE_SIZE)? };
    /// }
    /// # Ok::<(), Error>(())
    /// ```
    ///
    /// # Safety
    ///
    /// - `ptr` must be a valid pointer to a [`Vmalloc`] allocation.
    /// - `ptr` must remain valid for the entire duration of `'a`.
    pub unsafe fn to_page<'a>(ptr: NonNull<u8>) -> page::BorrowedPage<'a> {
        // SAFETY: `ptr` is a valid pointer to `Vmalloc` memory.
        let page = unsafe { bindings::vmalloc_to_page(ptr.as_ptr().cast()) };

        // SAFETY: `vmalloc_to_page` returns a valid pointer to a `struct page` for a valid pointer
        // to `Vmalloc` memory.
        let page = unsafe { NonNull::new_unchecked(page) };

        // SAFETY:
        // - `page` is a valid pointer to a `struct page`, given that by the safety requirements of
        //   this function `ptr` is a valid pointer to a `Vmalloc` allocation.
        // - By the safety requirements of this function `ptr` is valid for the entire lifetime of
        //   `'a`.
        unsafe { page::BorrowedPage::from_raw(page) }
    }
}

// SAFETY: `realloc` delegates to `ReallocFunc::call`, which guarantees that
// - memory remains valid until it is explicitly freed,
// - passing a pointer to a valid memory allocation is OK,
// - `realloc` satisfies the guarantees, since `ReallocFunc::call` has the same.
unsafe impl Allocator for Vmalloc {
    #[inline]
    unsafe fn realloc(
        ptr: Option<NonNull<u8>>,
        layout: Layout,
        old_layout: Layout,
        flags: Flags,
    ) -> Result<NonNull<[u8]>, AllocError> {
        // TODO: Support alignments larger than PAGE_SIZE.
        if layout.align() > bindings::PAGE_SIZE {
            pr_warn!("Vmalloc does not support alignments larger than PAGE_SIZE yet.\n");
            return Err(AllocError);
        }

        // SAFETY: If not `None`, `ptr` is guaranteed to point to valid memory, which was previously
        // allocated with this `Allocator`.
        unsafe { ReallocFunc::VREALLOC.call(ptr, layout, old_layout, flags) }
    }
}

// SAFETY: `realloc` delegates to `ReallocFunc::call`, which guarantees that
// - memory remains valid until it is explicitly freed,
// - passing a pointer to a valid memory allocation is OK,
// - `realloc` satisfies the guarantees, since `ReallocFunc::call` has the same.
unsafe impl Allocator for KVmalloc {
    #[inline]
    unsafe fn realloc(
        ptr: Option<NonNull<u8>>,
        layout: Layout,
        old_layout: Layout,
        flags: Flags,
    ) -> Result<NonNull<[u8]>, AllocError> {
        // `KVmalloc` may use the `Kmalloc` backend, hence we have to enforce a `Kmalloc`
        // compatible layout.
        let layout = Kmalloc::aligned_layout(layout);

        // TODO: Support alignments larger than PAGE_SIZE.
        if layout.align() > bindings::PAGE_SIZE {
            pr_warn!("KVmalloc does not support alignments larger than PAGE_SIZE yet.\n");
            return Err(AllocError);
        }

        // SAFETY: If not `None`, `ptr` is guaranteed to point to valid memory, which was previously
        // allocated with this `Allocator`.
        unsafe { ReallocFunc::KVREALLOC.call(ptr, layout, old_layout, flags) }
    }
}

/// An [`Iterator`] of [`page::BorrowedPage`] items owned by a [`Vmalloc`] allocation.
///
/// # Guarantees
///
/// The pages iterated by the [`Iterator`] appear in the order as they are mapped in the CPU's
/// virtual address space ascendingly.
///
/// # Invariants
///
/// - `buf` is a valid and [`page::PAGE_SIZE`] aligned pointer into a [`Vmalloc`] allocation.
/// - `size` is the number of bytes from `buf` until the end of the [`Vmalloc`] allocation `buf`
///   points to.
pub struct VmallocPageIter<'a> {
    /// The base address of the [`Vmalloc`] buffer.
    buf: NonNull<u8>,
    /// The size of the buffer pointed to by `buf` in bytes.
    size: usize,
    /// The current page index of the [`Iterator`].
    index: usize,
    _p: PhantomData<page::BorrowedPage<'a>>,
}

impl<'a> Iterator for VmallocPageIter<'a> {
    type Item = page::BorrowedPage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.index.checked_mul(page::PAGE_SIZE)?;

        // Even though `self.size()` may be smaller than `Self::page_count() * page::PAGE_SIZE`, it
        // is always a number between `(Self::page_count() - 1) * page::PAGE_SIZE` and
        // `Self::page_count() * page::PAGE_SIZE`, hence the check below is sufficient.
        if offset < self.size() {
            self.index += 1;
        } else {
            return None;
        }

        // TODO: Use `NonNull::add()` instead, once the minimum supported compiler version is
        // bumped to 1.80 or later.
        //
        // SAFETY: `offset` is in the interval `[0, (self.page_count() - 1) * page::PAGE_SIZE]`,
        // hence the resulting pointer is guaranteed to be within the same allocation.
        let ptr = unsafe { self.buf.as_ptr().add(offset) };

        // SAFETY: `ptr` is guaranteed to be non-null given that it is derived from `self.buf`.
        let ptr = unsafe { NonNull::new_unchecked(ptr) };

        // SAFETY:
        // - `ptr` is a valid pointer to a `Vmalloc` allocation.
        // - `ptr` is valid for the duration of `'a`.
        Some(unsafe { Vmalloc::to_page(ptr) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.page_count().saturating_sub(self.index);

        (remaining, Some(remaining))
    }
}

impl<'a> VmallocPageIter<'a> {
    /// Creates a new [`VmallocPageIter`] instance.
    ///
    /// # Safety
    ///
    /// - `buf` must be a [`page::PAGE_SIZE`] aligned pointer into a [`Vmalloc`] allocation.
    /// - `buf` must be valid for at least the lifetime of `'a`.
    /// - `size` must be the number of bytes from `buf` until the end of the [`Vmalloc`] allocation
    ///   `buf` points to.
    pub unsafe fn new(buf: NonNull<u8>, size: usize) -> Self {
        // INVARIANT: By the safety requirements, `buf` is a valid and `page::PAGE_SIZE` aligned
        // pointer into a [`Vmalloc`] allocation.
        Self {
            buf,
            size,
            index: 0,
            _p: PhantomData,
        }
    }

    /// Returns the base address of the backing [`Vmalloc`] allocation.
    #[inline]
    pub fn base_address(&self) -> NonNull<u8> {
        self.buf
    }

    /// Returns the size of the backing [`Vmalloc`] allocation in bytes.
    ///
    /// Note that this is the size the [`Vmalloc`] allocation has been allocated with. Hence, this
    /// number may be smaller than `[`Self::page_count`] * [`page::PAGE_SIZE`]`.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the number of pages owned by the backing [`Vmalloc`] allocation.
    #[inline]
    pub fn page_count(&self) -> usize {
        self.size().div_ceil(page::PAGE_SIZE)
    }
}
