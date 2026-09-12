// SPDX-License-Identifier: GPL-2.0 or MIT

//! Base types for firmware interface blocks.

use kernel::{
    io::Region,
    ptr::{
        Alignment,
        KnownSize, //
    }, //
};

/// Untyped region of a firmware interface block that has 64-bit fields.
///
/// The infallible accessors refuse an access that needs a stronger alignment than the base type
/// promises through `KnownSize::MIN_ALIGN`, so reaching a 64-bit field needs a `MIN_ALIGN` of 8.
/// Raising the layout alignment instead would round `size_of_val()` up to a multiple of 8, past
/// the end of a block whose size is 4 mod 8. The layout alignment therefore stays at 4, and the
/// stronger alignment is a type invariant.
///
/// # Invariants
///
/// - The base address of the region is 8-byte aligned.
/// - The size of the region is at least `SIZE` and a multiple of 4.
#[repr(C, align(4))]
pub(in crate::fw) struct FwRegion<const SIZE: usize> {
    inner: [u8],
}

impl<const SIZE: usize> KnownSize for FwRegion<SIZE> {
    const MIN_SIZE: usize = SIZE;
    const MIN_ALIGN: Alignment = Alignment::new::<8>();

    #[inline(always)]
    fn size(p: *const Self) -> usize {
        (p as *const [u8]).len()
    }
}

/// Base type of a firmware interface block.
///
/// # Safety
///
/// `ptr_from_parts()` must return a pointer with the address and the provenance of `base`, and a
/// `KnownSize::size()` of `size`.
pub(in crate::fw) unsafe trait FwBase: KnownSize {
    /// Creates a raw mutable pointer to the `size` bytes at `base`.
    ///
    /// Just like other methods on raw pointers, it is not unsafe to create a raw pointer that
    /// does not uphold the type invariants of `Self`. However such pointers are not valid.
    fn ptr_from_parts(base: *mut u8, size: usize) -> *mut Self;
}

// SAFETY: `Region::ptr_from_raw_parts_mut()` returns a slice pointer built from `base` and `size`.
unsafe impl<const SIZE: usize> FwBase for Region<SIZE> {
    #[inline]
    fn ptr_from_parts(base: *mut u8, size: usize) -> *mut Self {
        Region::ptr_from_raw_parts_mut(base, size)
    }
}

// SAFETY: The slice pointer keeps `base` and has length `size`, and the cast to a `repr(C)` type
// whose only field is `[u8]` keeps both.
unsafe impl<const SIZE: usize> FwBase for FwRegion<SIZE> {
    #[inline]
    fn ptr_from_parts(base: *mut u8, size: usize) -> *mut Self {
        core::ptr::slice_from_raw_parts_mut(base, size) as *mut Self
    }
}
