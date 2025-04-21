// SPDX-License-Identifier: GPL-2.0

//! Atomic primitives.
//!
//! These primitives have the same semantics as their C counterparts: and the precise definitions of
//! semantics can be found at [`LKMM`]. Note that Linux Kernel Memory (Consistency) Model is the
//! only model for Rust code in kernel, and Rust's own atomics should be avoided.
//!
//! # Data races
//!
//! [`LKMM`] atomics have different rules regarding data races:
//!
//! - A normal write from C side is treated as an atomic write if
//!   CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=y.
//! - Mixed-size atomic accesses don't cause data races.
//!
//! [`LKMM`]: srctree/tools/memory-mode/

pub mod generic;
pub mod ops;
pub mod ordering;

pub use generic::Atomic;
pub use ordering::{Acquire, Full, Relaxed, Release};

/// ```rust
/// use kernel::sync::atomic::{Atomic, Relaxed};
///
/// let x = Atomic::new(42u64);
///
/// assert_eq!(42, x.load(Relaxed));
/// ```
// SAFETY: `u64` and `i64` has the same size and alignment.
unsafe impl generic::AllowAtomic for u64 {
    type Repr = i64;

    fn into_repr(self) -> Self::Repr {
        self as _
    }

    fn from_repr(repr: Self::Repr) -> Self {
        repr as _
    }
}

/// ```rust
/// use kernel::sync::atomic::{Atomic, Full, Relaxed};
///
/// let x = Atomic::new(42u64);
///
/// assert_eq!(42, x.fetch_add(12, Full));
/// assert_eq!(54, x.load(Relaxed));
///
/// x.add(13, Relaxed);
///
/// assert_eq!(67, x.load(Relaxed));
/// ```
impl generic::AllowAtomicArithmetic for u64 {
    type Delta = u64;

    fn delta_into_repr(d: Self::Delta) -> Self::Repr {
        d as _
    }
}

/// ```rust
/// use kernel::sync::atomic::{Atomic, Relaxed};
///
/// let x = Atomic::new(42u32);
///
/// assert_eq!(42, x.load(Relaxed));
/// ```
// SAFETY: `u32` and `i32` has the same size and alignment.
unsafe impl generic::AllowAtomic for u32 {
    type Repr = i32;

    fn into_repr(self) -> Self::Repr {
        self as _
    }

    fn from_repr(repr: Self::Repr) -> Self {
        repr as _
    }
}

/// ```rust
/// use kernel::sync::atomic::{Atomic, Full, Relaxed};
///
/// let x = Atomic::new(42u32);
///
/// assert_eq!(42, x.fetch_add(12, Full));
/// assert_eq!(54, x.load(Relaxed));
///
/// x.add(13, Relaxed);
///
/// assert_eq!(67, x.load(Relaxed));
/// ```
impl generic::AllowAtomicArithmetic for u32 {
    type Delta = u32;

    fn delta_into_repr(d: Self::Delta) -> Self::Repr {
        d as _
    }
}

// SAFETY: `usize` has the same size and the alignment as `i64` for 64bit and the same as `i32` for
// 32bit.
unsafe impl generic::AllowAtomic for usize {
    #[cfg(CONFIG_64BIT)]
    type Repr = i64;
    #[cfg(not(CONFIG_64BIT))]
    type Repr = i32;

    fn into_repr(self) -> Self::Repr {
        self as _
    }

    fn from_repr(repr: Self::Repr) -> Self {
        repr as _
    }
}

/// ```rust
/// use kernel::sync::atomic::{Atomic, Full, Relaxed};
///
/// let x = Atomic::new(42usize);
///
/// assert_eq!(42, x.fetch_add(12, Full));
/// assert_eq!(54, x.load(Relaxed));
///
/// x.add(13, Relaxed);
///
/// assert_eq!(67, x.load(Relaxed));
/// ```
impl generic::AllowAtomicArithmetic for usize {
    type Delta = usize;

    fn delta_into_repr(d: Self::Delta) -> Self::Repr {
        d as _
    }
}

// SAFETY: `isize` has the same size and the alignment as `i64` for 64bit and the same as `i32` for
// 32bit.
unsafe impl generic::AllowAtomic for isize {
    type Repr = i64;

    fn into_repr(self) -> Self::Repr {
        self as _
    }

    fn from_repr(repr: Self::Repr) -> Self {
        repr as _
    }
}

/// ```rust
/// use kernel::sync::atomic::{Atomic, Full, Relaxed};
///
/// let x = Atomic::new(42isize);
///
/// assert_eq!(42, x.fetch_add(12, Full));
/// assert_eq!(54, x.load(Relaxed));
///
/// x.add(13, Relaxed);
///
/// assert_eq!(67, x.load(Relaxed));
/// ```
impl generic::AllowAtomicArithmetic for isize {
    type Delta = isize;

    fn delta_into_repr(d: Self::Delta) -> Self::Repr {
        d as _
    }
}

/// ```rust
/// use kernel::sync::atomic::{Atomic, Relaxed};
///
/// let x = Atomic::new(core::ptr::null_mut::<i32>());
///
/// assert!(x.load(Relaxed).is_null());
/// ```
// SAFETY: A `*mut T` has the same size and the alignment as `i64` for 64bit and the same as `i32`
// for 32bit. And it's safe to transfer the ownership of a pointer value to another thread.
unsafe impl<T> generic::AllowAtomic for *mut T {
    #[cfg(CONFIG_64BIT)]
    type Repr = i64;
    #[cfg(not(CONFIG_64BIT))]
    type Repr = i32;

    fn into_repr(self) -> Self::Repr {
        self as _
    }

    fn from_repr(repr: Self::Repr) -> Self {
        repr as _
    }
}

/// ```rust
/// use kernel::sync::atomic::{Atomic, Relaxed};
///
/// let s: &mut [i32] = &mut [1, 3, 2, 4];
///
/// let x = Atomic::new(s.as_mut_ptr());
///
/// x.add(1, Relaxed);
///
/// let ptr = x.fetch_add(1, Relaxed); // points to the 2nd element.
/// let ptr2 = x.load(Relaxed); // points to the 3rd element.
///
/// // SAFETY: `ptr` and `ptr2` are valid pointers to the 2nd and 3rd elements of `s` with writing
/// // provenance, and no other thread is accessing these elements.
/// unsafe { core::ptr::swap(ptr, ptr2); }
///
/// assert_eq!(s, &mut [1, 2, 3, 4]);
/// ```
impl<T> generic::AllowAtomicArithmetic for *mut T {
    type Delta = isize;

    /// The behavior of arithmetic operations
    fn delta_into_repr(d: Self::Delta) -> Self::Repr {
        // Since atomic arithmetic operations are wrapping, so a wrapping_mul() here suffices even
        // if overflow may happen.
        d.wrapping_mul(core::mem::size_of::<T>() as _) as _
    }
}
