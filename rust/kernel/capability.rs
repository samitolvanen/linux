// SPDX-License-Identifier: GPL-2.0

//! Capability checks.
//!
//! C header: [`include/linux/capability.h`](srctree/include/linux/capability.h).

use crate::bindings;

/// A POSIX capability that can be checked against the current task.
///
/// The numeric value matches the `CAP_*` constants from
/// [`include/uapi/linux/capability.h`](srctree/include/uapi/linux/capability.h).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Capability(i32);

impl Capability {
    /// `CAP_SYS_NICE`: allow raising priority and setting priority on
    /// other processes, among other scheduling-related privileges.
    pub const SYS_NICE: Capability = Capability(bindings::CAP_SYS_NICE as i32);
}

/// Returns whether the current task has the given capability.
///
/// Wraps the kernel's `capable()` helper, which checks the effective
/// credentials of the current task against `cap`.
#[inline]
pub fn capable(cap: Capability) -> bool {
    // SAFETY: `capable()` only reads the current task's effective
    // credentials and the supplied capability value; it has no
    // preconditions on the caller.
    unsafe { bindings::capable(cap.0) }
}
