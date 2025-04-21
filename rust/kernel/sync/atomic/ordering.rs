// SPDX-License-Identifier: GPL-2.0

//! Memory orderings.
//!
//! The semantics of these orderings follows the [`LKMM`] definitions and rules.
//!
//! - [`Acquire`] and [`Release`] are similar to their counterpart in Rust memory model.
//! - [`Full`] means "fully-ordered", that is:
//!   - It provides ordering between all the preceding memory accesses and the annotated operation.
//!   - It provides ordering between the annotated operation and all the following memory accesses.
//!   - It provides ordering between all the preceding memory accesses and all the fllowing memory
//!     accesses.
//!   - All the orderings are the same strong as a full memory barrier (i.e. `smp_mb()`).
//! - [`Relaxed`] is similar to the counterpart in Rust memory model, except that dependency
//!   orderings are also honored in [`LKMM`]. Dependency orderings are described in "DEPENDENCY
//!   RELATIONS" in [`LKMM`]'s [`explanation`].
//!
//! [`LKMM`]: srctree/tools/memory-model/
//! [`explanation`]: srctree/tools/memory-model/Documentation/explanation.txt

/// The annotation type for relaxed memory ordering.
pub struct Relaxed;

/// The annotation type for acquire memory ordering.
pub struct Acquire;

/// The annotation type for release memory ordering.
pub struct Release;

/// The annotation type for fully-order memory ordering.
pub struct Full;

/// The trait bound for operations that only support relaxed ordering.
pub trait RelaxedOnly {}

impl RelaxedOnly for Relaxed {}

/// The trait bound for operations that only support acquire or relaxed ordering.
pub trait AcquireOrRelaxed {
    /// Describes whether an ordering is relaxed or not.
    const IS_RELAXED: bool = false;
}

impl AcquireOrRelaxed for Acquire {}

impl AcquireOrRelaxed for Relaxed {
    const IS_RELAXED: bool = true;
}

/// The trait bound for operations that only support release or relaxed ordering.
pub trait ReleaseOrRelaxed {
    /// Describes whether an ordering is relaxed or not.
    const IS_RELAXED: bool = false;
}

impl ReleaseOrRelaxed for Release {}

impl ReleaseOrRelaxed for Relaxed {
    const IS_RELAXED: bool = true;
}

/// Describes the exact memory ordering of an `impl` [`All`].
pub enum OrderingDesc {
    /// Relaxed ordering.
    Relaxed,
    /// Acquire ordering.
    Acquire,
    /// Release ordering.
    Release,
    /// Fully-ordered.
    Full,
}

/// The trait bound for annotating operations that should support all orderings.
pub trait All {
    /// Describes the exact memory ordering.
    const ORDER: OrderingDesc;
}

impl All for Relaxed {
    const ORDER: OrderingDesc = OrderingDesc::Relaxed;
}

impl All for Acquire {
    const ORDER: OrderingDesc = OrderingDesc::Acquire;
}

impl All for Release {
    const ORDER: OrderingDesc = OrderingDesc::Release;
}

impl All for Full {
    const ORDER: OrderingDesc = OrderingDesc::Full;
}
