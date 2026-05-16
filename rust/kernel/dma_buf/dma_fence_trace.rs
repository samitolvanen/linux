// SPDX-License-Identifier: GPL-2.0

//! Debug tracepoints for the [`crate::dma_buf::dma_fence`] abstraction.
//!
//! Downstream-only instrumentation, not intended for upstream submission.
//! Emits one event when a published [`DriverDmaFence`] is signaled and
//! one event from the C-side trampoline that dispatches registered
//! [`FenceCallback`]s, so the [`crate::drm::job_queue`] tracepoints can
//! be correlated against the dma_fence machinery via `(ctx, seqno)`.

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
    unsafe fn rust_dmaf_signal(fence_ctx: u64, fence_seqno: u64, errno: i32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_dmaf_callback_fire(fence_ctx: u64, fence_seqno: u64);
}

/// Emit on every published-fence signal.
pub(crate) fn signal(fence_ctx: u64, fence_seqno: u64, errno: i32) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context, including the dma_fence signalling section.
    unsafe { rust_dmaf_signal(fence_ctx, fence_seqno, errno) }
}

/// Emit at the top of the C callback trampoline that dispatches
/// [`FenceCallback`](crate::dma_buf::dma_fence::FenceCallback)s registered
/// via [`FenceCallbackRegistration`](crate::dma_buf::dma_fence::FenceCallbackRegistration).
pub(crate) fn callback_fire(fence_ctx: u64, fence_seqno: u64) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context, including the dma_fence signalling section.
    unsafe { rust_dmaf_callback_fire(fence_ctx, fence_seqno) }
}
