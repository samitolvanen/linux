/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Debug tracepoint for DRM sync object fence replacement.
 *
 * Downstream-only instrumentation; not intended for upstream. Captures every
 * fence stored into a `struct drm_syncobj` via drm_syncobj_replace_fence() -
 * including cross-instance OPAQUE_FD transfers and imports that bypass a
 * driver's own submit path - keyed on the file-independent
 * `struct drm_syncobj *` address so the same shared object can be correlated
 * across DRM files. When the stored fence is a dma_fence_chain (a timeline
 * point), the wrapped fence is reported too, so a binary semaphore fed from a
 * timeline point can be traced back to the underlying completion fence.
 *
 * Copyright (C) 2026 Google LLC.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM drm_syncobj_debug

#if !defined(_DRM_SYNCOBJ_DEBUG_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _DRM_SYNCOBJ_DEBUG_TRACE_H

#include <linux/tracepoint.h>
#include <linux/types.h>
#include <linux/dma-fence.h>
#include <linux/dma-fence-chain.h>

struct drm_syncobj;

/*
 * `syncobj_ptr` is the kernel `struct drm_syncobj *` address, used as a
 * file-independent identity for a shared sync object (e.g. one imported across
 * VkInstances via OPAQUE_FD). It is a debug correlation key only and is never
 * dereferenced by the trace consumer.
 */

TRACE_EVENT(drm_syncobj_replace_fence,
	TP_PROTO(struct drm_syncobj *syncobj, struct dma_fence *fence),
	TP_ARGS(syncobj, fence),
	TP_STRUCT__entry(
		__field(u64, syncobj_ptr)
		__field(u64, fence_ctx)
		__field(u64, fence_seqno)
		__field(u8, is_chain)
		__field(u64, wrapped_ctx)
		__field(u64, wrapped_seqno)
	),
	TP_fast_assign(
		struct dma_fence_chain *__chain =
			fence ? to_dma_fence_chain(fence) : NULL;
		__entry->syncobj_ptr = (u64)(uintptr_t)syncobj;
		__entry->fence_ctx = fence ? fence->context : 0;
		__entry->fence_seqno = fence ? fence->seqno : 0;
		__entry->is_chain = __chain ? 1 : 0;
		__entry->wrapped_ctx =
			(__chain && __chain->fence) ? __chain->fence->context : 0;
		__entry->wrapped_seqno =
			(__chain && __chain->fence) ? __chain->fence->seqno : 0;
	),
	TP_printk("syncobj=0x%llx fence=%llu/%llu chain=%u wraps=%llu/%llu",
		  __entry->syncobj_ptr, __entry->fence_ctx, __entry->fence_seqno,
		  __entry->is_chain, __entry->wrapped_ctx, __entry->wrapped_seqno)
);

#endif /* _DRM_SYNCOBJ_DEBUG_TRACE_H */

/* This part must be outside protection. */
#include <trace/define_trace.h>
