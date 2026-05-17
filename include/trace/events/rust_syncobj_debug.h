/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Debug tracepoints for the Rust DRM syncobj abstraction.
 *
 * Downstream-only instrumentation; not intended for upstream.
 *
 * Copyright (C) 2026 Google LLC.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM rust_syncobj_debug

#if !defined(_RUST_SYNCOBJ_DEBUG_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _RUST_SYNCOBJ_DEBUG_TRACE_H

#include <linux/tracepoint.h>
#include <linux/types.h>

/*
 * `syncobj_ptr` is the kernel `struct drm_syncobj *` address, used as a
 * file-independent identity for a shared sync object (e.g. one imported
 * across VkInstances via OPAQUE_FD). It is a debug correlation key only and
 * is never dereferenced.
 */

TRACE_EVENT(rust_syncobj_replace_fence,
	TP_PROTO(u64 syncobj_ptr, u64 fence_ctx, u64 fence_seqno),
	TP_ARGS(syncobj_ptr, fence_ctx, fence_seqno),
	TP_STRUCT__entry(
		__field(u64, syncobj_ptr)
		__field(u64, fence_ctx)
		__field(u64, fence_seqno)
	),
	TP_fast_assign(
		__entry->syncobj_ptr = syncobj_ptr;
		__entry->fence_ctx = fence_ctx;
		__entry->fence_seqno = fence_seqno;
	),
	TP_printk("syncobj=0x%llx fence=%llu/%llu",
		  __entry->syncobj_ptr, __entry->fence_ctx,
		  __entry->fence_seqno)
);

TRACE_EVENT(rust_syncobj_add_point,
	TP_PROTO(u64 syncobj_ptr, u64 point, u64 fence_ctx, u64 fence_seqno),
	TP_ARGS(syncobj_ptr, point, fence_ctx, fence_seqno),
	TP_STRUCT__entry(
		__field(u64, syncobj_ptr)
		__field(u64, point)
		__field(u64, fence_ctx)
		__field(u64, fence_seqno)
	),
	TP_fast_assign(
		__entry->syncobj_ptr = syncobj_ptr;
		__entry->point = point;
		__entry->fence_ctx = fence_ctx;
		__entry->fence_seqno = fence_seqno;
	),
	TP_printk("syncobj=0x%llx point=%llu fence=%llu/%llu",
		  __entry->syncobj_ptr, __entry->point,
		  __entry->fence_ctx, __entry->fence_seqno)
);

TRACE_EVENT(rust_syncobj_find_fence,
	TP_PROTO(u64 syncobj_ptr, u64 point, u64 fence_ctx, u64 fence_seqno,
		 u8 signaled),
	TP_ARGS(syncobj_ptr, point, fence_ctx, fence_seqno, signaled),
	TP_STRUCT__entry(
		__field(u64, syncobj_ptr)
		__field(u64, point)
		__field(u64, fence_ctx)
		__field(u64, fence_seqno)
		__field(u8, signaled)
	),
	TP_fast_assign(
		__entry->syncobj_ptr = syncobj_ptr;
		__entry->point = point;
		__entry->fence_ctx = fence_ctx;
		__entry->fence_seqno = fence_seqno;
		__entry->signaled = signaled;
	),
	TP_printk("syncobj=0x%llx point=%llu fence=%llu/%llu signaled=%u",
		  __entry->syncobj_ptr, __entry->point,
		  __entry->fence_ctx, __entry->fence_seqno,
		  __entry->signaled)
);

#endif /* _RUST_SYNCOBJ_DEBUG_TRACE_H */

/* This part must be outside protection. */
#include <trace/define_trace.h>
