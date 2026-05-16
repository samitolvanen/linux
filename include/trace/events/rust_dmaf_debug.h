/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Debug tracepoints for the Rust dma_fence abstraction.
 *
 * Downstream-only instrumentation; not intended for upstream.
 *
 * Copyright (C) 2026 Google LLC.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM rust_dmaf_debug

#if !defined(_RUST_DMAF_DEBUG_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _RUST_DMAF_DEBUG_TRACE_H

#include <linux/tracepoint.h>
#include <linux/types.h>

TRACE_EVENT(rust_dmaf_signal,
	TP_PROTO(u64 fence_ctx, u64 fence_seqno, s32 errno),
	TP_ARGS(fence_ctx, fence_seqno, errno),
	TP_STRUCT__entry(
		__field(u64, fence_ctx)
		__field(u64, fence_seqno)
		__field(s32, errno)
	),
	TP_fast_assign(
		__entry->fence_ctx = fence_ctx;
		__entry->fence_seqno = fence_seqno;
		__entry->errno = errno;
	),
	TP_printk("fence=%llu/%llu errno=%d",
		  __entry->fence_ctx, __entry->fence_seqno, __entry->errno)
);

TRACE_EVENT(rust_dmaf_callback_fire,
	TP_PROTO(u64 fence_ctx, u64 fence_seqno),
	TP_ARGS(fence_ctx, fence_seqno),
	TP_STRUCT__entry(
		__field(u64, fence_ctx)
		__field(u64, fence_seqno)
	),
	TP_fast_assign(
		__entry->fence_ctx = fence_ctx;
		__entry->fence_seqno = fence_seqno;
	),
	TP_printk("fence=%llu/%llu",
		  __entry->fence_ctx, __entry->fence_seqno)
);

#endif /* _RUST_DMAF_DEBUG_TRACE_H */

/* This part must be outside protection. */
#include <trace/define_trace.h>
