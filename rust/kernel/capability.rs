// SPDX-License-Identifier: GPL-2.0

//! Capability checks.
//!
//! C header: [`include/linux/capability.h`](srctree/include/linux/capability.h).

use crate::bindings;

/// A POSIX capability that can be checked against the current task.
///
/// The numeric value matches the `CAP_*` constants from
/// [`include/uapi/linux/capability.h`](srctree/include/uapi/linux/capability.h).
///
/// # Invariants
///
/// The value is a valid capability number, i.e. one of the `CAP_*` constants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Capability(i32);

impl Capability {
    /// `CAP_SYS_NICE`: allow raising priority and setting priority on
    /// other processes, among other scheduling-related privileges.
    // INVARIANT: `CAP_SYS_NICE` is one of the `CAP_*` constants.
    pub const SYS_NICE: Capability = Capability(bindings::CAP_SYS_NICE as i32);
}

/// Returns whether the current task has the given capability.
///
/// Wraps the kernel's `capable()` function, which checks the effective
/// credentials of the current task against `cap`.
///
/// When `CONFIG_MULTIUSER=n` this always returns `true`, matching the C
/// `capable()` stub.
#[inline]
pub fn capable(cap: Capability) -> bool {
    // SAFETY: under `CONFIG_MULTIUSER=y`, `capable()` BUG()s on an invalid
    // capability number, and by the type invariant `cap.0` is a valid one.
    unsafe { bindings::capable(cap.0) }
}
