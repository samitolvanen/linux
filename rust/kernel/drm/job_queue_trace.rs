// SPDX-License-Identifier: GPL-2.0

//! Debug tracepoints for the [`crate::drm::job_queue`] pipeline.
//!
//! Downstream-only instrumentation, not intended for upstream submission.
//! Used to correlate pipeline state transitions, fence-callback
//! registrations, and callback invocations with `dma_fence` signalling
//! events when chasing scheduler stalls.
//!
//! The numeric kind encodings below are decoded symbolically by the C
//! header `include/trace/events/rust_jq_debug.h`. Keep both sides in sync.

// Each `declare_trace!` expansion contains an `unsafe { ... }` block whose
// argument list comes from macro metavariables. Clippy reports this at the
// macro definition site (`rust/kernel/tracepoint.rs`); the safety of each
// call is already documented by the generated `# Safety` rustdoc and the
// `unsafe` blocks in the wrappers below, so silence the lint here.
#![allow(clippy::macro_metavars_in_unsafe)]

use crate::dma_buf::dma_fence::PublicDmaFence;
use crate::sync::aref::ARef;
use crate::tracepoint::declare_trace;

/// Stage kind discriminant for [`rust_jq_process_stage_enter`].
pub(crate) const STAGE_KIND_WAITING_FOR_DEPS: u32 = 0;
/// Stage kind discriminant for [`rust_jq_process_stage_enter`].
pub(crate) const STAGE_KIND_WAITING_FOR_EXEC: u32 = 1;
/// Stage kind discriminant for [`rust_jq_process_stage_enter`].
pub(crate) const STAGE_KIND_EXECUTING: u32 = 2;
/// Stage kind discriminant for [`rust_jq_process_stage_enter`].
pub(crate) const STAGE_KIND_DRIVER: u32 = 3;

/// Advance kind discriminant for [`rust_jq_stage_advance`].
pub(crate) const ADVANCE_KIND_ADVANCE: u32 = 0;
/// Advance kind discriminant for [`rust_jq_stage_advance`].
pub(crate) const ADVANCE_KIND_WAIT_ON: u32 = 1;
/// Advance kind discriminant for [`rust_jq_stage_advance`].
pub(crate) const ADVANCE_KIND_WAIT_FOR: u32 = 2;
/// Advance kind discriminant for [`rust_jq_stage_advance`].
pub(crate) const ADVANCE_KIND_WAIT: u32 = 3;
/// Advance kind discriminant for [`rust_jq_stage_advance`].
pub(crate) const ADVANCE_KIND_TIMED_OUT: u32 = 4;

/// Callback kind discriminant for [`rust_jq_register_cb`] and
/// [`rust_jq_cb_fire`].
pub(crate) const CB_KIND_STAGE: u32 = 0;
/// Callback kind discriminant for [`rust_jq_register_cb`] and
/// [`rust_jq_cb_fire`].
pub(crate) const CB_KIND_DEP: u32 = 1;
/// Callback kind discriminant for [`rust_jq_register_cb`] and
/// [`rust_jq_cb_fire`].
pub(crate) const CB_KIND_PROGRESS: u32 = 2;

/// Reason placeholder for [`rust_jq_check_progress`] when the caller did
/// not propagate a more specific reason.
pub(crate) const CHECK_REASON_UNKNOWN: u32 = 0;

declare_trace! {
    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_process_stage_enter(entry_idx: u32, stage_i: u32, stage_kind: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_stage_advance(
        entry_idx: u32,
        stage_i: u32,
        advance_kind: u32,
        wait_ms_or_errno: i64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_register_cb(
        entry_idx: u32,
        cb_kind: u32,
        fence_ctx: u64,
        fence_seqno: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_cb_fire(cb_kind: u32, fence_ctx: u64, fence_seqno: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_fence_state(
        entry_idx: u32,
        fence_ctx: u64,
        fence_seqno: u64,
        signaled: u8,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_check_progress(reason: u32);
}

/// Emit on entry to `process_stage`.
pub(crate) fn process_stage_enter(entry_idx: u32, stage_i: u32, stage_kind: u32) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context.
    unsafe { rust_jq_process_stage_enter(entry_idx, stage_i, stage_kind) }
}

/// Emit at every `StageAdvance::*` return site in `process_stage`.
pub(crate) fn stage_advance(
    entry_idx: u32,
    stage_i: u32,
    advance_kind: u32,
    wait_ms_or_errno: i64,
) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context.
    unsafe { rust_jq_stage_advance(entry_idx, stage_i, advance_kind, wait_ms_or_errno) }
}

/// Emit on successful [`FenceCallbackRegistration`](crate::dma_buf::dma_fence::FenceCallbackRegistration)
/// creation.
pub(crate) fn register_cb(entry_idx: u32, cb_kind: u32, fence_ctx: u64, fence_seqno: u64) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context.
    unsafe { rust_jq_register_cb(entry_idx, cb_kind, fence_ctx, fence_seqno) }
}

/// Emit at the top of every `FenceCallback::signaled` implementation in
/// `job_queue`.
pub(crate) fn cb_fire(cb_kind: u32, fence_ctx: u64, fence_seqno: u64) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context, including the dma_fence signalling path.
    unsafe { rust_jq_cb_fire(cb_kind, fence_ctx, fence_seqno) }
}

/// Emit immediately before delegating to a driver stage's `process()`,
/// reporting the live submit-fence state.
pub(crate) fn fence_state(entry_idx: u32, fence_ctx: u64, fence_seqno: u64, signaled: bool) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context.
    unsafe { rust_jq_fence_state(entry_idx, fence_ctx, fence_seqno, u8::from(signaled)) }
}

/// Emit on entry to `check_progress`.
pub(crate) fn check_progress(reason: u32) {
    // SAFETY: The C tracepoint takes plain scalars and is safe to call from
    // any context.
    unsafe { rust_jq_check_progress(reason) }
}

/// Return `(context, seqno)` for `fence`, the correlation key used across
/// the `rust_jq_*` and `rust_dmaf_*` tracepoints.
pub(crate) fn fence_key(fence: &ARef<PublicDmaFence>) -> (u64, u64) {
    let raw = fence.raw();
    // SAFETY: `raw` is a valid `dma_fence` pointer obtained from a live
    // `ARef<PublicDmaFence>` reference held by the caller; the `context`
    // and `seqno` fields are immutable for the lifetime of the fence.
    let ctx = unsafe { (*raw).context };
    (ctx, fence.seqno())
}
