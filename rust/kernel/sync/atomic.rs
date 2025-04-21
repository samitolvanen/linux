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
