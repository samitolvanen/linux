// SPDX-License-Identifier: GPL-2.0

//! Debug tracepoints for the [`crate::drm::syncobj`] abstraction.
//!
//! Downstream-only instrumentation, not intended for upstream submission.
//! Used to correlate fence stores and loads on a sync object across
//! independent DRM files. The `syncobj_ptr` argument is the kernel
//! `struct drm_syncobj *` address, a file-independent identity for a shared
//! object (e.g. one imported across VkInstances via OPAQUE_FD), so a
//! producer's fence store and a consumer's fence load on the same object can
//! be matched even though their per-file handles differ. It is a debug
//! correlation key only and is never dereferenced.

// Each `declare_trace!` expansion contains an `unsafe { ... }` block whose
// argument list comes from macro metavariables. Clippy reports this at the
// macro definition site (`rust/kernel/tracepoint.rs`); the safety of each
// call is already documented by the generated `# Safety` rustdoc and the
// `unsafe` blocks in the wrappers below, so silence the lint here.
#![allow(clippy::macro_metavars_in_unsafe)]

use crate::tracepoint::declare_trace;

declare_trace! {
    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_syncobj_replace_fence(syncobj_ptr: u64, fence_ctx: u64, fence_seqno: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_syncobj_add_point(
        syncobj_ptr: u64,
        point: u64,
        fence_ctx: u64,
        fence_seqno: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_syncobj_find_fence(
        syncobj_ptr: u64,
        point: u64,
        fence_ctx: u64,
        fence_seqno: u64,
        signaled: u8,
    );
}

/// Emit on a binary fence store via
/// [`SyncObj::replace_fence`](crate::drm::syncobj::SyncObj::replace_fence).
/// A clear (`fence` is `None`) reports `fence_ctx = 0`, `fence_seqno = 0`.
pub(crate) fn replace_fence(syncobj_ptr: u64, fence_ctx: u64, fence_seqno: u64) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context.
    unsafe { rust_syncobj_replace_fence(syncobj_ptr, fence_ctx, fence_seqno) }
}

/// Emit on a timeline fence store via
/// [`SyncObj::add_point`](crate::drm::syncobj::SyncObj::add_point).
pub(crate) fn add_point(syncobj_ptr: u64, point: u64, fence_ctx: u64, fence_seqno: u64) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context.
    unsafe { rust_syncobj_add_point(syncobj_ptr, point, fence_ctx, fence_seqno) }
}

/// Emit on a fence load via
/// [`SyncObj::find_fence`](crate::drm::syncobj::SyncObj::find_fence). A miss
/// (no fence resolved) reports `fence_ctx = 0`, `fence_seqno = 0`.
pub(crate) fn find_fence(
    syncobj_ptr: u64,
    point: u64,
    fence_ctx: u64,
    fence_seqno: u64,
    signaled: bool,
) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context.
    unsafe {
        rust_syncobj_find_fence(
            syncobj_ptr,
            point,
            fence_ctx,
            fence_seqno,
            u8::from(signaled),
        )
    }
}
