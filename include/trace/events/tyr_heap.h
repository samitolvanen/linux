/* SPDX-License-Identifier: GPL-2.0 or MIT */
/*
 * Tiler-heap dump tracepoints for the Tyr Rust DRM driver.
 *
 * These live in their own trace system because the periodic heap-state
 * dump worker gates its scheduler-lock and heap-XArray walk on their
 * static keys. Keeping them out of the `tyr` system means a blanket
 * enable of `tyr` stays passive, and the dump is armed only by enabling
 * `tyr_heap`.
 *
 * Copyright (C) 2026 Google LLC.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM tyr_heap

#if !defined(_TYR_HEAP_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TYR_HEAP_TRACE_H

#include <linux/tracepoint.h>
#include <linux/types.h>

/*
 * 32-byte snapshot of one tiler-heap context entry, taken from the
 * kernel vmap of the pool's heap-context BO at CS_FAULT / CS_FATAL
 * time. `heap_index` is the XArray index of the heap within the
 * faulting group's pool and `heap_context_va` is that entry's GPU VA.
 * `chunk_count` is the number of chunks currently linked into the
 * heap. Downstream debug aid used to spot drift in the heap context
 * descriptors when chasing DATA_INVALID_FAULT regressions.
 */
TRACE_EVENT(tyr_heap_context_dump,
	TP_PROTO(u64 group_id, u32 cs_id, u32 heap_index,
		 u64 heap_context_va, u32 chunk_count, const u8 *content),
	TP_ARGS(group_id, cs_id, heap_index, heap_context_va,
		chunk_count, content),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u32, heap_index)
		__field(u64, heap_context_va)
		__field(u32, chunk_count)
		__array(u8, content, 32)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->heap_index = heap_index;
		__entry->heap_context_va = heap_context_va;
		__entry->chunk_count = chunk_count;
		memcpy(__entry->content, content, 32);
	),
	TP_printk("group=%llu cs=%u heap=%u va=0x%llx chunks=%u content=%s",
		  __entry->group_id, __entry->cs_id, __entry->heap_index,
		  __entry->heap_context_va, __entry->chunk_count,
		  __print_hex(__entry->content, 32))
);

/*
 * 64-byte snapshot of one tiler-heap chunk header (the `next` pointer
 * plus 14 reserved u32s), taken from the kernel vmap of the chunk BO
 * at CS_FAULT / CS_FATAL time. `chunk_index` is the chunk's position
 * within its heap's chunk chain. Downstream debug aid that lets a trace
 * consumer walk the chain and check whether `next` has drifted or a
 * chunk has been reused under fragment activity.
 */
TRACE_EVENT(tyr_heap_chunk_dump,
	TP_PROTO(u64 group_id, u32 cs_id, u32 heap_index, u32 chunk_index,
		 u64 chunk_va, const u8 *header),
	TP_ARGS(group_id, cs_id, heap_index, chunk_index, chunk_va, header),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u32, heap_index)
		__field(u32, chunk_index)
		__field(u64, chunk_va)
		__array(u8, header, 64)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->heap_index = heap_index;
		__entry->chunk_index = chunk_index;
		__entry->chunk_va = chunk_va;
		memcpy(__entry->header, header, 64);
	),
	TP_printk("group=%llu cs=%u heap=%u chunk=%u va=0x%llx header=%s",
		  __entry->group_id, __entry->cs_id, __entry->heap_index,
		  __entry->chunk_index, __entry->chunk_va,
		  __print_hex(__entry->header, 64))
);

#endif /* _TYR_HEAP_TRACE_H */

/* This part must be outside protection. */
#include <trace/define_trace.h>
