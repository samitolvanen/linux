/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Debug tracepoints for the Rust DRM job_queue abstraction.
 *
 * Downstream-only instrumentation; not intended for upstream.
 *
 * Copyright (C) 2026 Google LLC.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM rust_jq_debug

#if !defined(_RUST_JQ_DEBUG_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _RUST_JQ_DEBUG_TRACE_H

#include <linux/tracepoint.h>
#include <linux/types.h>

/*
 * Numeric encodings mirror the Rust-side discriminants in
 * rust/kernel/drm/job_queue_trace.rs. Keep them in sync.
 */

#define RUST_JQ_STAGE_KIND				\
	{ 0, "WaitingForDeps" },			\
	{ 1, "WaitingForExec" },			\
	{ 2, "Executing" },				\
	{ 3, "Driver" }

#define RUST_JQ_ADVANCE_KIND				\
	{ 0, "Advance" },				\
	{ 1, "WaitOn" },				\
	{ 2, "WaitFor" },				\
	{ 3, "Wait" },					\
	{ 4, "TimedOut" }

#define RUST_JQ_CB_KIND					\
	{ 0, "Stage" },					\
	{ 1, "Dep" },					\
	{ 2, "Progress" }

#define RUST_JQ_CHECK_REASON				\
	{ 0, "Unknown" }

TRACE_EVENT(rust_jq_process_stage_enter,
	TP_PROTO(u32 entry_idx, u32 stage_i, u32 stage_kind),
	TP_ARGS(entry_idx, stage_i, stage_kind),
	TP_STRUCT__entry(
		__field(u32, entry_idx)
		__field(u32, stage_i)
		__field(u32, stage_kind)
	),
	TP_fast_assign(
		__entry->entry_idx = entry_idx;
		__entry->stage_i = stage_i;
		__entry->stage_kind = stage_kind;
	),
	TP_printk("entry=%u stage_i=%u kind=%s",
		  __entry->entry_idx, __entry->stage_i,
		  __print_symbolic(__entry->stage_kind, RUST_JQ_STAGE_KIND))
);

TRACE_EVENT(rust_jq_stage_advance,
	TP_PROTO(u32 entry_idx, u32 stage_i, u32 advance_kind,
		 s64 wait_ms_or_errno),
	TP_ARGS(entry_idx, stage_i, advance_kind, wait_ms_or_errno),
	TP_STRUCT__entry(
		__field(u32, entry_idx)
		__field(u32, stage_i)
		__field(u32, advance_kind)
		__field(s64, wait_ms_or_errno)
	),
	TP_fast_assign(
		__entry->entry_idx = entry_idx;
		__entry->stage_i = stage_i;
		__entry->advance_kind = advance_kind;
		__entry->wait_ms_or_errno = wait_ms_or_errno;
	),
	TP_printk("entry=%u stage_i=%u advance=%s extra=%lld",
		  __entry->entry_idx, __entry->stage_i,
		  __print_symbolic(__entry->advance_kind, RUST_JQ_ADVANCE_KIND),
		  __entry->wait_ms_or_errno)
);

TRACE_EVENT(rust_jq_register_cb,
	TP_PROTO(u32 entry_idx, u32 cb_kind, u64 fence_ctx, u64 fence_seqno),
	TP_ARGS(entry_idx, cb_kind, fence_ctx, fence_seqno),
	TP_STRUCT__entry(
		__field(u32, entry_idx)
		__field(u32, cb_kind)
		__field(u64, fence_ctx)
		__field(u64, fence_seqno)
	),
	TP_fast_assign(
		__entry->entry_idx = entry_idx;
		__entry->cb_kind = cb_kind;
		__entry->fence_ctx = fence_ctx;
		__entry->fence_seqno = fence_seqno;
	),
	TP_printk("entry=%u cb=%s fence=%llu/%llu",
		  __entry->entry_idx,
		  __print_symbolic(__entry->cb_kind, RUST_JQ_CB_KIND),
		  __entry->fence_ctx, __entry->fence_seqno)
);

TRACE_EVENT(rust_jq_cb_fire,
	TP_PROTO(u32 cb_kind, u64 fence_ctx, u64 fence_seqno),
	TP_ARGS(cb_kind, fence_ctx, fence_seqno),
	TP_STRUCT__entry(
		__field(u32, cb_kind)
		__field(u64, fence_ctx)
		__field(u64, fence_seqno)
	),
	TP_fast_assign(
		__entry->cb_kind = cb_kind;
		__entry->fence_ctx = fence_ctx;
		__entry->fence_seqno = fence_seqno;
	),
	TP_printk("cb=%s fence=%llu/%llu",
		  __print_symbolic(__entry->cb_kind, RUST_JQ_CB_KIND),
		  __entry->fence_ctx, __entry->fence_seqno)
);

TRACE_EVENT(rust_jq_fence_state,
	TP_PROTO(u32 entry_idx, u64 fence_ctx, u64 fence_seqno, u8 signaled),
	TP_ARGS(entry_idx, fence_ctx, fence_seqno, signaled),
	TP_STRUCT__entry(
		__field(u32, entry_idx)
		__field(u64, fence_ctx)
		__field(u64, fence_seqno)
		__field(u8, signaled)
	),
	TP_fast_assign(
		__entry->entry_idx = entry_idx;
		__entry->fence_ctx = fence_ctx;
		__entry->fence_seqno = fence_seqno;
		__entry->signaled = signaled;
	),
	TP_printk("entry=%u fence=%llu/%llu signaled=%u",
		  __entry->entry_idx, __entry->fence_ctx,
		  __entry->fence_seqno, __entry->signaled)
);

TRACE_EVENT(rust_jq_check_progress,
	TP_PROTO(u32 reason),
	TP_ARGS(reason),
	TP_STRUCT__entry(
		__field(u32, reason)
	),
	TP_fast_assign(
		__entry->reason = reason;
	),
	TP_printk("reason=%s",
		  __print_symbolic(__entry->reason, RUST_JQ_CHECK_REASON))
);

#endif /* _RUST_JQ_DEBUG_TRACE_H */

/* This part must be outside protection. */
#include <trace/define_trace.h>
