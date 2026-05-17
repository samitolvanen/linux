/* SPDX-License-Identifier: GPL-2.0 or MIT */
/*
 * Tracepoints for the Tyr Rust DRM driver.
 *
 * Copyright (C) 2026 Google LLC.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM tyr

#if !defined(_TYR_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TYR_TRACE_H

#include <linux/tracepoint.h>
#include <linux/types.h>

/*
 * Tyr's Rust enums and bitfields are not visible from C, so the
 * symbolic maps below mirror their values as numeric literals. Keep
 * them in sync with drivers/gpu/drm/tyr/sched/group.rs (state /
 * GroupListState) and drivers/gpu/drm/tyr/fw/interfaces.rs
 * (CSG_REQ / CS_REQ bit positions).
 */

#define TYR_GROUP_STATES		\
	{ 0, "CREATED" },		\
	{ 1, "ACTIVE" },		\
	{ 2, "SUSPENDED" },		\
	{ 3, "TERMINATED" },		\
	{ 4, "UNKNOWN" }

#define TYR_GROUP_LIST_STATES		\
	{ 0, "NONE" },			\
	{ 1, "IDLE" },			\
	{ 2, "RUNNABLE" }

/*
 * CSG_REQ/CSG_ACK bit-flag entries (excluding the 3-bit state field
 * at bits 0-2). Use TYR_CSG_STATE_VALUES to decode the state field
 * and TYR_CSG_REQ_FLAGS for the remaining flag bits in a register
 * value. Use TYR_CSG_REQ_MASK_FLAGS to decode update/toggle bit
 * masks, where the state field is owned as a single STATE_MASK.
 */
#define TYR_CSG_STATE_VALUES			\
	{ 0, "TERMINATE" },			\
	{ 1, "START" },				\
	{ 2, "SUSPEND" },			\
	{ 3, "RESUME" }

#define TYR_CSG_REQ_FLAGS			\
	{ 0x00000010, "EP_CFG" },		\
	{ 0x00000020, "STATUS_UPDATE" },	\
	{ 0x10000000, "SYNC_UPDATE" },		\
	{ 0x20000000, "IDLE" },			\
	{ 0x80000000, "PROGRESS_TIMER_EVENT" }

#define TYR_CSG_REQ_MASK_FLAGS			\
	{ 0x00000007, "STATE_MASK" },		\
	{ 0x00000010, "EP_CFG" },		\
	{ 0x00000020, "STATUS_UPDATE" },	\
	{ 0x10000000, "SYNC_UPDATE" },		\
	{ 0x20000000, "IDLE" },			\
	{ 0x80000000, "PROGRESS_TIMER_EVENT" }

#define TYR_CS_REQ_FLAGS			\
	{ 0x00000007, "STATE" },		\
	{ 0x00000010, "EXTRACT_EVENT" },	\
	{ 0x00000100, "IDLE_SYNC_WAIT" },	\
	{ 0x00000400, "IDLE_EMPTY" },		\
	{ 0x04000000, "TILER_OOM" }

/*
 * Bits in drm_panthor_vm_bind_op_flags as wired up in
 * drivers/gpu/drm/tyr/vm.rs (VmFlag).
 */
#define TYR_VM_MAP_FLAGS			\
	{ 0x00000001, "RO" },			\
	{ 0x00000002, "NOEXEC" },		\
	{ 0x00000004, "UNCACHED" }

TRACE_EVENT(tyr_fw_glb_req,
	TP_PROTO(u32 req_val, u32 toggle_mask),
	TP_ARGS(req_val, toggle_mask),
	TP_STRUCT__entry(
		__field(u32, req_val)
		__field(u32, toggle_mask)
	),
	TP_fast_assign(
		__entry->req_val = req_val;
		__entry->toggle_mask = toggle_mask;
	),
	TP_printk("req=0x%08x toggle_mask=0x%08x",
		  __entry->req_val, __entry->toggle_mask)
);

TRACE_EVENT(tyr_fw_glb_doorbell_req,
	TP_PROTO(u32 req_val, u32 toggle_mask),
	TP_ARGS(req_val, toggle_mask),
	TP_STRUCT__entry(
		__field(u32, req_val)
		__field(u32, toggle_mask)
	),
	TP_fast_assign(
		__entry->req_val = req_val;
		__entry->toggle_mask = toggle_mask;
	),
	TP_printk("req=0x%08x toggle_mask=0x%08x",
		  __entry->req_val, __entry->toggle_mask)
);

TRACE_EVENT(tyr_glb_irq,
	TP_PROTO(u32 req, u32 ack),
	TP_ARGS(req, ack),
	TP_STRUCT__entry(
		__field(u32, req)
		__field(u32, ack)
	),
	TP_fast_assign(
		__entry->req = req;
		__entry->ack = ack;
	),
	TP_printk("req=0x%08x ack=0x%08x pending=0x%08x",
		  __entry->req, __entry->ack, __entry->req ^ __entry->ack)
);

TRACE_EVENT(tyr_fw_csg_req,
	TP_PROTO(u32 csg_id, u64 group_id, u32 req_val, u32 update_mask,
		 u32 toggle_mask),
	TP_ARGS(csg_id, group_id, req_val, update_mask, toggle_mask),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, group_id)
		__field(u32, req_val)
		__field(u32, update_mask)
		__field(u32, toggle_mask)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->group_id = group_id;
		__entry->req_val = req_val;
		__entry->update_mask = update_mask;
		__entry->toggle_mask = toggle_mask;
	),
	TP_printk("csg=%u group=%llu req=0x%08x(state=%s flags=%s) update_mask=%s toggle_mask=%s",
		  __entry->csg_id, __entry->group_id, __entry->req_val,
		  __print_symbolic(__entry->req_val & 0x7, TYR_CSG_STATE_VALUES),
		  __print_flags(__entry->req_val & ~0x7u, "|", TYR_CSG_REQ_FLAGS),
		  __print_flags(__entry->update_mask, "|", TYR_CSG_REQ_MASK_FLAGS),
		  __print_flags(__entry->toggle_mask, "|", TYR_CSG_REQ_MASK_FLAGS))
);

TRACE_EVENT(tyr_fw_csg_doorbell_req,
	TP_PROTO(u32 csg_id, u32 req_val, u32 update_mask, u32 toggle_mask),
	TP_ARGS(csg_id, req_val, update_mask, toggle_mask),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, req_val)
		__field(u32, update_mask)
		__field(u32, toggle_mask)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->req_val = req_val;
		__entry->update_mask = update_mask;
		__entry->toggle_mask = toggle_mask;
	),
	TP_printk("csg=%u req=0x%08x update_mask=0x%08x toggle_mask=0x%08x",
		  __entry->csg_id, __entry->req_val,
		  __entry->update_mask, __entry->toggle_mask)
);

TRACE_EVENT(tyr_fw_csg_status_update,
	TP_PROTO(u32 csg_id, u64 group_id, u32 status_state),
	TP_ARGS(csg_id, group_id, status_state),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, group_id)
		__field(u32, status_state)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->group_id = group_id;
		__entry->status_state = status_state;
	),
	TP_printk("csg=%u group=%llu state=0x%08x",
		  __entry->csg_id, __entry->group_id, __entry->status_state)
);

TRACE_EVENT(tyr_fw_cs_req,
	TP_PROTO(u32 csg_id, u32 cs_id, u64 group_id, u32 req_val,
		 u32 update_mask, u32 toggle_mask),
	TP_ARGS(csg_id, cs_id, group_id, req_val, update_mask, toggle_mask),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, cs_id)
		__field(u64, group_id)
		__field(u32, req_val)
		__field(u32, update_mask)
		__field(u32, toggle_mask)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->cs_id = cs_id;
		__entry->group_id = group_id;
		__entry->req_val = req_val;
		__entry->update_mask = update_mask;
		__entry->toggle_mask = toggle_mask;
	),
	TP_printk("csg=%u cs=%u group=%llu req=0x%08x update_mask=%s toggle_mask=%s",
		  __entry->csg_id, __entry->cs_id, __entry->group_id,
		  __entry->req_val,
		  __print_flags(__entry->update_mask, "|", TYR_CS_REQ_FLAGS),
		  __print_flags(__entry->toggle_mask, "|", TYR_CS_REQ_FLAGS))
);

TRACE_EVENT(tyr_fw_cs_status_update,
	TP_PROTO(u32 csg_id, u32 cs_id, u64 group_id, u32 status_blocked_reason),
	TP_ARGS(csg_id, cs_id, group_id, status_blocked_reason),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, cs_id)
		__field(u64, group_id)
		__field(u32, status_blocked_reason)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->cs_id = cs_id;
		__entry->group_id = group_id;
		__entry->status_blocked_reason = status_blocked_reason;
	),
	TP_printk("csg=%u cs=%u group=%llu blocked_reason=0x%08x",
		  __entry->csg_id, __entry->cs_id, __entry->group_id,
		  __entry->status_blocked_reason)
);

TRACE_EVENT(tyr_gpu_irq,
	TP_PROTO(u32 status),
	TP_ARGS(status),
	TP_STRUCT__entry(
		__field(u32, status)
	),
	TP_fast_assign(
		__entry->status = status;
	),
	TP_printk("status=0x%08x", __entry->status)
);

TRACE_EVENT(tyr_fw_irq,
	TP_PROTO(u32 status),
	TP_ARGS(status),
	TP_STRUCT__entry(
		__field(u32, status)
	),
	TP_fast_assign(
		__entry->status = status;
	),
	TP_printk("status=0x%08x(glb=%c csg=0x%08x)",
		  __entry->status,
		  (__entry->status & 0x80000000) ? 'y' : 'n',
		  __entry->status & 0x7fffffff)
);

TRACE_EVENT(tyr_csg_irq,
	TP_PROTO(u32 csg_id, u64 group_id, u32 req, u32 ack, u32 irq_req,
		 u32 irq_ack),
	TP_ARGS(csg_id, group_id, req, ack, irq_req, irq_ack),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, group_id)
		__field(u32, req)
		__field(u32, ack)
		__field(u32, irq_req)
		__field(u32, irq_ack)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->group_id = group_id;
		__entry->req = req;
		__entry->ack = ack;
		__entry->irq_req = irq_req;
		__entry->irq_ack = irq_ack;
	),
	TP_printk("csg=%u group=%llu req=0x%08x(state=%s flags=%s) ack=0x%08x(state=%s flags=%s) irq_req=0x%08x irq_ack=0x%08x",
		  __entry->csg_id, __entry->group_id,
		  __entry->req,
		  __print_symbolic(__entry->req & 0x7, TYR_CSG_STATE_VALUES),
		  __print_flags(__entry->req & ~0x7u, "|", TYR_CSG_REQ_FLAGS),
		  __entry->ack,
		  __print_symbolic(__entry->ack & 0x7, TYR_CSG_STATE_VALUES),
		  __print_flags(__entry->ack & ~0x7u, "|", TYR_CSG_REQ_FLAGS),
		  __entry->irq_req, __entry->irq_ack)
);

TRACE_EVENT(tyr_cs_irq,
	TP_PROTO(u32 csg_id, u32 cs_id, u32 req, u32 ack),
	TP_ARGS(csg_id, cs_id, req, ack),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, cs_id)
		__field(u32, req)
		__field(u32, ack)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->cs_id = cs_id;
		__entry->req = req;
		__entry->ack = ack;
	),
	TP_printk("csg=%u cs=%u req=0x%08x ack=0x%08x",
		  __entry->csg_id, __entry->cs_id, __entry->req, __entry->ack)
);

TRACE_EVENT(tyr_job_irq_clear,
	TP_PROTO(u32 status),
	TP_ARGS(status),
	TP_STRUCT__entry(
		__field(u32, status)
	),
	TP_fast_assign(
		__entry->status = status;
	),
	TP_printk("status=0x%08x(glb=%c csg=0x%08x)",
		  __entry->status,
		  (__entry->status & 0x80000000) ? 'y' : 'n',
		  __entry->status & 0x7fffffff)
);

TRACE_EVENT(tyr_group_update,
	TP_PROTO(u64 group_id, u32 state),
	TP_ARGS(group_id, state),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, state)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->state = state;
	),
	TP_printk("group=%llu state=%s", __entry->group_id,
		  __print_symbolic(__entry->state, TYR_GROUP_STATES))
);

TRACE_EVENT(tyr_group_list,
	TP_PROTO(u64 group_id, u32 list_state),
	TP_ARGS(group_id, list_state),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, list_state)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->list_state = list_state;
	),
	TP_printk("group=%llu list_state=%s", __entry->group_id,
		  __print_symbolic(__entry->list_state, TYR_GROUP_LIST_STATES))
);

TRACE_EVENT(tyr_group_wait,
	TP_PROTO(u64 group_id, bool waiting),
	TP_ARGS(group_id, waiting),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(bool, waiting)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->waiting = waiting;
	),
	TP_printk("group=%llu waiting=%d", __entry->group_id, __entry->waiting)
);

TRACE_EVENT(tyr_group_bind,
	TP_PROTO(u64 group_id, u32 csg_id),
	TP_ARGS(group_id, csg_id),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, csg_id)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->csg_id = csg_id;
	),
	TP_printk("group=%llu csg=%u", __entry->group_id, __entry->csg_id)
);

TRACE_EVENT(tyr_group_unbind,
	TP_PROTO(u64 group_id, u32 csg_id),
	TP_ARGS(group_id, csg_id),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, csg_id)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->csg_id = csg_id;
	),
	TP_printk("group=%llu csg=%u", __entry->group_id, __entry->csg_id)
);

TRACE_EVENT(tyr_group_timedout,
	TP_PROTO(u64 group_id),
	TP_ARGS(group_id),
	TP_STRUCT__entry(
		__field(u64, group_id)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
	),
	TP_printk("group=%llu", __entry->group_id)
);

TRACE_EVENT(tyr_sched_evict,
	TP_PROTO(u32 csg_id, u64 group_id, u8 sw_prio),
	TP_ARGS(csg_id, group_id, sw_prio),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, group_id)
		__field(u8, sw_prio)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->group_id = group_id;
		__entry->sw_prio = sw_prio;
	),
	TP_printk("csg=%u group=%llu sw_prio=%u", __entry->csg_id,
		  __entry->group_id, __entry->sw_prio)
);

TRACE_EVENT(tyr_sched_keep,
	TP_PROTO(u32 csg_id, u64 group_id, u8 sw_prio, u32 fw_prio),
	TP_ARGS(csg_id, group_id, sw_prio, fw_prio),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, group_id)
		__field(u8, sw_prio)
		__field(u32, fw_prio)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->group_id = group_id;
		__entry->sw_prio = sw_prio;
		__entry->fw_prio = fw_prio;
	),
	TP_printk("csg=%u group=%llu sw_prio=%u fw_prio=%u",
		  __entry->csg_id, __entry->group_id, __entry->sw_prio,
		  __entry->fw_prio)
);

TRACE_EVENT(tyr_sched_bind,
	TP_PROTO(u32 csg_id, u64 group_id, u8 sw_prio, u32 fw_prio),
	TP_ARGS(csg_id, group_id, sw_prio, fw_prio),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, group_id)
		__field(u8, sw_prio)
		__field(u32, fw_prio)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->group_id = group_id;
		__entry->sw_prio = sw_prio;
		__entry->fw_prio = fw_prio;
	),
	TP_printk("csg=%u group=%llu sw_prio=%u fw_prio=%u",
		  __entry->csg_id, __entry->group_id, __entry->sw_prio,
		  __entry->fw_prio)
);

TRACE_EVENT(tyr_queue_state,
	TP_PROTO(u64 group_id, u32 cs_id, bool blocked),
	TP_ARGS(group_id, cs_id, blocked),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(bool, blocked)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->blocked = blocked;
	),
	TP_printk("group=%llu cs=%u blocked=%d",
		  __entry->group_id, __entry->cs_id, __entry->blocked)
);

TRACE_EVENT(tyr_queue_idle_state,
	TP_PROTO(u64 group_id, u32 cs_id, bool idle),
	TP_ARGS(group_id, cs_id, idle),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(bool, idle)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->idle = idle;
	),
	TP_printk("group=%llu cs=%u idle=%d",
		  __entry->group_id, __entry->cs_id, __entry->idle)
);

TRACE_EVENT(tyr_queue_fatal_state,
	TP_PROTO(u64 group_id, u32 cs_id, bool fatal),
	TP_ARGS(group_id, cs_id, fatal),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(bool, fatal)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->fatal = fatal;
	),
	TP_printk("group=%llu cs=%u fatal=%d",
		  __entry->group_id, __entry->cs_id, __entry->fatal)
);

TRACE_EVENT(tyr_queue_timeout_state,
	TP_PROTO(u64 group_id, u32 cs_id, bool suspended),
	TP_ARGS(group_id, cs_id, suspended),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(bool, suspended)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->suspended = suspended;
	),
	TP_printk("group=%llu cs=%u suspended=%d",
		  __entry->group_id, __entry->cs_id, __entry->suspended)
);

TRACE_EVENT(tyr_queue_doorbell,
	TP_PROTO(u64 group_id, u32 cs_id, u32 doorbell_id),
	TP_ARGS(group_id, cs_id, doorbell_id),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u32, doorbell_id)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->doorbell_id = doorbell_id;
	),
	TP_printk("group=%llu cs=%u doorbell=%u",
		  __entry->group_id, __entry->cs_id, __entry->doorbell_id)
);

TRACE_EVENT(tyr_csg_slot_idle,
	TP_PROTO(u32 csg_id, u64 group_id, bool idle),
	TP_ARGS(csg_id, group_id, idle),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, group_id)
		__field(bool, idle)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->group_id = group_id;
		__entry->idle = idle;
	),
	TP_printk("csg=%u group=%llu idle=%d",
		  __entry->csg_id, __entry->group_id, __entry->idle)
);

TRACE_EVENT(tyr_csg_slot_progress_timeout,
	TP_PROTO(u32 csg_id),
	TP_ARGS(csg_id),
	TP_STRUCT__entry(
		__field(u32, csg_id)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
	),
	TP_printk("csg=%u", __entry->csg_id)
);

TRACE_EVENT(tyr_csg_slots_status,
	TP_PROTO(u32 used_slots, u32 total_slots),
	TP_ARGS(used_slots, total_slots),
	TP_STRUCT__entry(
		__field(u32, used_slots)
		__field(u32, total_slots)
	),
	TP_fast_assign(
		__entry->used_slots = used_slots;
		__entry->total_slots = total_slots;
	),
	TP_printk("used=%u total=%u",
		  __entry->used_slots, __entry->total_slots)
);

TRACE_EVENT(tyr_cs_ring_ptrs,
	TP_PROTO(u64 group_id, u32 cs_id, u64 insert, u64 extract),
	TP_ARGS(group_id, cs_id, insert, extract),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u64, insert)
		__field(u64, extract)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->insert = insert;
		__entry->extract = extract;
	),
	TP_printk("group=%llu cs=%u insert=0x%llx extract=0x%llx",
		  __entry->group_id, __entry->cs_id, __entry->insert,
		  __entry->extract)
);

TRACE_EVENT(tyr_job_submit,
	TP_PROTO(u64 completion_point, u64 group_id, u32 cs_id,
		 u32 user_stream_size),
	TP_ARGS(completion_point, group_id, cs_id, user_stream_size),
	TP_STRUCT__entry(
		__field(u64, completion_point)
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u32, user_stream_size)
	),
	TP_fast_assign(
		__entry->completion_point = completion_point;
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->user_stream_size = user_stream_size;
	),
	TP_printk("completion_point=%llu group=%llu cs=%u user_stream=%u",
		  __entry->completion_point, __entry->group_id, __entry->cs_id,
		  __entry->user_stream_size)
);

TRACE_EVENT(tyr_submit_fence_signal,
	TP_PROTO(u64 group_id, u32 cs_id, u64 completion_point, int result),
	TP_ARGS(group_id, cs_id, completion_point, result),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u64, completion_point)
		__field(int, result)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->completion_point = completion_point;
		__entry->result = result;
	),
	TP_printk("group=%llu cs=%u completion_point=%llu result=%d",
		  __entry->group_id, __entry->cs_id,
		  __entry->completion_point, __entry->result)
);

TRACE_EVENT(tyr_job_status,
	TP_PROTO(u64 seqno, u64 group_id, u32 cs_id, const char *status),
	TP_ARGS(seqno, group_id, cs_id, status),
	TP_STRUCT__entry(
		__field(u64, seqno)
		__field(u64, group_id)
		__field(u32, cs_id)
		__string(status, status)
	),
	TP_fast_assign(
		__entry->seqno = seqno;
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__assign_str(status);
	),
	TP_printk("seqno=%llu group=%llu cs=%u status=%s",
		  __entry->seqno, __entry->group_id, __entry->cs_id,
		  __get_str(status))
);

TRACE_EVENT(tyr_mmu_bind_start,
	TP_PROTO(u64 vm_id, u64 va, u64 size),
	TP_ARGS(vm_id, va, size),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u64, va)
		__field(u64, size)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->va = va;
		__entry->size = size;
	),
	TP_printk("vm=%llu va=0x%llx size=0x%llx",
		  __entry->vm_id, __entry->va, __entry->size)
);

TRACE_EVENT(tyr_mmu_bind_done,
	TP_PROTO(u64 vm_id, u64 va, u64 size, int result),
	TP_ARGS(vm_id, va, size, result),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u64, va)
		__field(u64, size)
		__field(int, result)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->va = va;
		__entry->size = size;
		__entry->result = result;
	),
	TP_printk("vm=%llu va=0x%llx size=0x%llx result=%d",
		  __entry->vm_id, __entry->va, __entry->size, __entry->result)
);

TRACE_EVENT(tyr_work_run,
	TP_PROTO(const char *work_name),
	TP_ARGS(work_name),
	TP_STRUCT__entry(
		__string(work_name, work_name)
	),
	TP_fast_assign(
		__assign_str(work_name);
	),
	TP_printk("work=%s", __get_str(work_name))
);

TRACE_EVENT(tyr_devfreq_target,
	TP_PROTO(u64 prev_freq, u64 target_freq),
	TP_ARGS(prev_freq, target_freq),
	TP_STRUCT__entry(
		__field(u64, prev_freq)
		__field(u64, target_freq)
	),
	TP_fast_assign(
		__entry->prev_freq = prev_freq;
		__entry->target_freq = target_freq;
	),
	TP_printk("prev=%llu target=%llu",
		  __entry->prev_freq, __entry->target_freq)
);

TRACE_EVENT(tyr_sync_upd_drain,
	TP_PROTO(u64 group_id, u32 cs_id, u64 completion_point,
		 u32 drained_count),
	TP_ARGS(group_id, cs_id, completion_point, drained_count),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u64, completion_point)
		__field(u32, drained_count)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->completion_point = completion_point;
		__entry->drained_count = drained_count;
	),
	TP_printk("group=%llu cs=%u completion_point=%llu drained=%u",
		  __entry->group_id, __entry->cs_id,
		  __entry->completion_point, __entry->drained_count)
);

TRACE_EVENT(tyr_deadline_check,
	TP_PROTO(u64 group_id, u32 cs_id, u32 elapsed_ms, u32 allowance_ms,
		 bool faulted),
	TP_ARGS(group_id, cs_id, elapsed_ms, allowance_ms, faulted),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u32, elapsed_ms)
		__field(u32, allowance_ms)
		__field(bool, faulted)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->elapsed_ms = elapsed_ms;
		__entry->allowance_ms = allowance_ms;
		__entry->faulted = faulted;
	),
	TP_printk("group=%llu cs=%u elapsed_ms=%u allowance_ms=%u faulted=%d",
		  __entry->group_id, __entry->cs_id, __entry->elapsed_ms,
		  __entry->allowance_ms, __entry->faulted)
);

TRACE_EVENT(tyr_tick_decision_summary,
	TP_PROTO(u32 evict_count, u32 bind_count, u32 keep_count,
		 u32 runnable_remaining),
	TP_ARGS(evict_count, bind_count, keep_count, runnable_remaining),
	TP_STRUCT__entry(
		__field(u32, evict_count)
		__field(u32, bind_count)
		__field(u32, keep_count)
		__field(u32, runnable_remaining)
	),
	TP_fast_assign(
		__entry->evict_count = evict_count;
		__entry->bind_count = bind_count;
		__entry->keep_count = keep_count;
		__entry->runnable_remaining = runnable_remaining;
	),
	TP_printk("evict=%u bind=%u keep=%u runnable_remaining=%u",
		  __entry->evict_count, __entry->bind_count,
		  __entry->keep_count, __entry->runnable_remaining)
);

TRACE_EVENT(tyr_devfreq_mark,
	TP_PROTO(bool busy, u64 prev_busy_ns, u64 prev_idle_ns),
	TP_ARGS(busy, prev_busy_ns, prev_idle_ns),
	TP_STRUCT__entry(
		__field(bool, busy)
		__field(u64, prev_busy_ns)
		__field(u64, prev_idle_ns)
	),
	TP_fast_assign(
		__entry->busy = busy;
		__entry->prev_busy_ns = prev_busy_ns;
		__entry->prev_idle_ns = prev_idle_ns;
	),
	TP_printk("busy=%d prev_busy_ns=%llu prev_idle_ns=%llu",
		  __entry->busy, __entry->prev_busy_ns, __entry->prev_idle_ns)
);

TRACE_EVENT(tyr_devfreq_status,
	TP_PROTO(u64 busy_time_ns, u64 total_time_ns, u64 current_freq),
	TP_ARGS(busy_time_ns, total_time_ns, current_freq),
	TP_STRUCT__entry(
		__field(u64, busy_time_ns)
		__field(u64, total_time_ns)
		__field(u64, current_freq)
	),
	TP_fast_assign(
		__entry->busy_time_ns = busy_time_ns;
		__entry->total_time_ns = total_time_ns;
		__entry->current_freq = current_freq;
	),
	TP_printk("busy_ns=%llu total_ns=%llu freq=%llu",
		  __entry->busy_time_ns, __entry->total_time_ns,
		  __entry->current_freq)
);

TRACE_EVENT(tyr_fw_csg_ack_poll,
	TP_PROTO(u32 csg_id, u32 req, u32 ack, u32 mask),
	TP_ARGS(csg_id, req, ack, mask),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, req)
		__field(u32, ack)
		__field(u32, mask)
		__field(u32, pending)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->req = req;
		__entry->ack = ack;
		__entry->mask = mask;
		__entry->pending = (req ^ ack) & mask;
	),
	TP_printk("csg=%u req=0x%08x(state=%s flags=%s) ack=0x%08x(state=%s flags=%s) mask=0x%08x pending=0x%08x(state=%s flags=%s)",
		  __entry->csg_id,
		  __entry->req,
		  __print_symbolic(__entry->req & 0x7, TYR_CSG_STATE_VALUES),
		  __print_flags(__entry->req & ~0x7u, "|", TYR_CSG_REQ_FLAGS),
		  __entry->ack,
		  __print_symbolic(__entry->ack & 0x7, TYR_CSG_STATE_VALUES),
		  __print_flags(__entry->ack & ~0x7u, "|", TYR_CSG_REQ_FLAGS),
		  __entry->mask,
		  __entry->pending,
		  __print_symbolic(__entry->pending & 0x7, TYR_CSG_STATE_VALUES),
		  __print_flags(__entry->pending & ~0x7u, "|", TYR_CSG_REQ_FLAGS))
);

TRACE_EVENT(tyr_fw_doorbell_ring,
	TP_PROTO(u32 doorbell_id),
	TP_ARGS(doorbell_id),
	TP_STRUCT__entry(
		__field(u32, doorbell_id)
	),
	TP_fast_assign(
		__entry->doorbell_id = doorbell_id;
	),
	TP_printk("doorbell=%u", __entry->doorbell_id)
);

TRACE_EVENT(tyr_fw_csg_ep_req_write,
	TP_PROTO(u32 csg_id, u32 raw_value),
	TP_ARGS(csg_id, raw_value),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, raw_value)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->raw_value = raw_value;
	),
	TP_printk("csg=%u ep_req=0x%08x",
		  __entry->csg_id, __entry->raw_value)
);

TRACE_EVENT(tyr_fw_glb_alloc_en,
	TP_PROTO(u64 value),
	TP_ARGS(value),
	TP_STRUCT__entry(
		__field(u64, value)
	),
	TP_fast_assign(
		__entry->value = value;
	),
	TP_printk("value=0x%016llx", __entry->value)
);

TRACE_EVENT(tyr_fw_csg_activate_bufs,
	TP_PROTO(u32 csg_id, u64 suspend_buf, u64 protm_suspend_buf),
	TP_ARGS(csg_id, suspend_buf, protm_suspend_buf),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, suspend_buf)
		__field(u64, protm_suspend_buf)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->suspend_buf = suspend_buf;
		__entry->protm_suspend_buf = protm_suspend_buf;
	),
	TP_printk("csg=%u suspend_buf=0x%llx protm_suspend_buf=0x%llx",
		  __entry->csg_id, __entry->suspend_buf,
		  __entry->protm_suspend_buf)
);

TRACE_EVENT(tyr_fw_csg_activate_config,
	TP_PROTO(u32 csg_id, u32 ep_req_raw, u32 config_raw, u64 allow_compute,
		 u64 allow_fragment, u32 allow_other),
	TP_ARGS(csg_id, ep_req_raw, config_raw, allow_compute, allow_fragment,
		allow_other),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, ep_req_raw)
		__field(u32, config_raw)
		__field(u64, allow_compute)
		__field(u64, allow_fragment)
		__field(u32, allow_other)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->ep_req_raw = ep_req_raw;
		__entry->config_raw = config_raw;
		__entry->allow_compute = allow_compute;
		__entry->allow_fragment = allow_fragment;
		__entry->allow_other = allow_other;
	),
	TP_printk("csg=%u ep_req=0x%08x(compute=%u fragment=%u tiler=%u prio=%u) config=0x%08x(jasid=%u) allow_compute=0x%llx allow_fragment=0x%llx allow_other=0x%08x",
		  __entry->csg_id, __entry->ep_req_raw,
		  __entry->ep_req_raw & 0xff,
		  (__entry->ep_req_raw >> 8) & 0xff,
		  (__entry->ep_req_raw >> 16) & 0xf,
		  (__entry->ep_req_raw >> 28) & 0xf,
		  __entry->config_raw,
		  __entry->config_raw & 0xf,
		  __entry->allow_compute, __entry->allow_fragment,
		  __entry->allow_other)
);

TRACE_EVENT(tyr_fw_cs_activate_inputs,
	TP_PROTO(u32 csg_id, u32 cs_id, u64 ringbuf_base, u32 ringbuf_size,
		 u64 ringbuf_input_va, u64 ringbuf_output_va, u32 config),
	TP_ARGS(csg_id, cs_id, ringbuf_base, ringbuf_size, ringbuf_input_va,
		ringbuf_output_va, config),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, cs_id)
		__field(u64, ringbuf_base)
		__field(u32, ringbuf_size)
		__field(u64, ringbuf_input_va)
		__field(u64, ringbuf_output_va)
		__field(u32, config)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->cs_id = cs_id;
		__entry->ringbuf_base = ringbuf_base;
		__entry->ringbuf_size = ringbuf_size;
		__entry->ringbuf_input_va = ringbuf_input_va;
		__entry->ringbuf_output_va = ringbuf_output_va;
		__entry->config = config;
	),
	TP_printk("csg=%u cs=%u ringbuf_base=0x%llx size=0x%x ringbuf_input=0x%llx ringbuf_output=0x%llx config=0x%08x(priority=%u doorbell=%u)",
		  __entry->csg_id, __entry->cs_id, __entry->ringbuf_base,
		  __entry->ringbuf_size, __entry->ringbuf_input_va,
		  __entry->ringbuf_output_va, __entry->config,
		  __entry->config & 0xf, (__entry->config >> 8) & 0xff)
);

TRACE_EVENT(tyr_fw_cs_ringbuf_publish,
	TP_PROTO(u64 group_id, u32 cs_id, u64 insert, u64 extract_init),
	TP_ARGS(group_id, cs_id, insert, extract_init),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u64, insert)
		__field(u64, extract_init)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->insert = insert;
		__entry->extract_init = extract_init;
	),
	TP_printk("group=%llu cs=%u insert=0x%llx extract_init=0x%llx",
		  __entry->group_id, __entry->cs_id, __entry->insert,
		  __entry->extract_init)
);

TRACE_EVENT(tyr_vm_map_bo,
	TP_PROTO(u64 vm_id, u64 va, u64 size, u32 flags, int result),
	TP_ARGS(vm_id, va, size, flags, result),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u64, va)
		__field(u64, size)
		__field(u32, flags)
		__field(int, result)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->va = va;
		__entry->size = size;
		__entry->flags = flags;
		__entry->result = result;
	),
	TP_printk("vm=%llu va=0x%llx size=0x%llx flags=0x%08x(%s) result=%d",
		  __entry->vm_id, __entry->va, __entry->size, __entry->flags,
		  __print_flags(__entry->flags, "|", TYR_VM_MAP_FLAGS),
		  __entry->result)
);

TRACE_EVENT(tyr_vm_unmap_bo,
	TP_PROTO(u64 vm_id, u64 va, u64 size, int result),
	TP_ARGS(vm_id, va, size, result),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u64, va)
		__field(u64, size)
		__field(int, result)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->va = va;
		__entry->size = size;
		__entry->result = result;
	),
	TP_printk("vm=%llu va=0x%llx size=0x%llx result=%d",
		  __entry->vm_id, __entry->va, __entry->size, __entry->result)
);

TRACE_EVENT(tyr_as_slot_assign,
	TP_PROTO(u64 vm_id, u32 as_slot, bool assigned),
	TP_ARGS(vm_id, as_slot, assigned),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u32, as_slot)
		__field(bool, assigned)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->as_slot = as_slot;
		__entry->assigned = assigned;
	),
	TP_printk("vm=%llu as_slot=%u assigned=%d",
		  __entry->vm_id, __entry->as_slot, __entry->assigned)
);

TRACE_EVENT(tyr_fw_boot_complete,
	TP_PROTO(u32 glb_version, u32 csg_count, u32 cs_per_csg),
	TP_ARGS(glb_version, csg_count, cs_per_csg),
	TP_STRUCT__entry(
		__field(u32, glb_version)
		__field(u32, csg_count)
		__field(u32, cs_per_csg)
	),
	TP_fast_assign(
		__entry->glb_version = glb_version;
		__entry->csg_count = csg_count;
		__entry->cs_per_csg = cs_per_csg;
	),
	TP_printk("glb_version=0x%08x csg_count=%u cs_per_csg=%u",
		  __entry->glb_version, __entry->csg_count,
		  __entry->cs_per_csg)
);

TRACE_EVENT(tyr_l2_power_on,
	TP_PROTO(int result),
	TP_ARGS(result),
	TP_STRUCT__entry(
		__field(int, result)
	),
	TP_fast_assign(
		__entry->result = result;
	),
	TP_printk("result=%d", __entry->result)
);

TRACE_EVENT(tyr_cs_status_snapshot,
	TP_PROTO(u32 csg, u32 cs, u32 req, u32 ack, u32 status_wait,
		 u32 blocked_reason, u32 scoreboards, u64 sync_pointer),
	TP_ARGS(csg, cs, req, ack, status_wait, blocked_reason, scoreboards,
		sync_pointer),
	TP_STRUCT__entry(
		__field(u32, csg)
		__field(u32, cs)
		__field(u32, req)
		__field(u32, ack)
		__field(u32, status_wait)
		__field(u32, blocked_reason)
		__field(u32, scoreboards)
		__field(u64, sync_pointer)
	),
	TP_fast_assign(
		__entry->csg = csg;
		__entry->cs = cs;
		__entry->req = req;
		__entry->ack = ack;
		__entry->status_wait = status_wait;
		__entry->blocked_reason = blocked_reason;
		__entry->scoreboards = scoreboards;
		__entry->sync_pointer = sync_pointer;
	),
	TP_printk("csg=%u cs=%u req=0x%08x ack=0x%08x status_wait=0x%08x blocked_reason=%u scoreboards=0x%08x sync_pointer=0x%llx",
		  __entry->csg, __entry->cs, __entry->req, __entry->ack,
		  __entry->status_wait, __entry->blocked_reason,
		  __entry->scoreboards, __entry->sync_pointer)
);

TRACE_EVENT(tyr_cs_ringbuf_dump,
	TP_PROTO(u64 group, u32 cs, u64 start, u64 word0, u64 word1, u64 word2,
		 u64 word3),
	TP_ARGS(group, cs, start, word0, word1, word2, word3),
	TP_STRUCT__entry(
		__field(u64, group)
		__field(u32, cs)
		__field(u64, start)
		__field(u64, word0)
		__field(u64, word1)
		__field(u64, word2)
		__field(u64, word3)
	),
	TP_fast_assign(
		__entry->group = group;
		__entry->cs = cs;
		__entry->start = start;
		__entry->word0 = word0;
		__entry->word1 = word1;
		__entry->word2 = word2;
		__entry->word3 = word3;
	),
	TP_printk("group=%llu cs=%u start=0x%llx word0=0x%016llx word1=0x%016llx word2=0x%016llx word3=0x%016llx",
		  __entry->group, __entry->cs, __entry->start, __entry->word0,
		  __entry->word1, __entry->word2, __entry->word3)
);

TRACE_EVENT(tyr_csg_slot_assign,
	TP_PROTO(u32 csg, u64 group, bool assigned),
	TP_ARGS(csg, group, assigned),
	TP_STRUCT__entry(
		__field(u32, csg)
		__field(u64, group)
		__field(bool, assigned)
	),
	TP_fast_assign(
		__entry->csg = csg;
		__entry->group = group;
		__entry->assigned = assigned;
	),
	TP_printk("csg=%u group=%llu assigned=%d",
		  __entry->csg, __entry->group, __entry->assigned)
);

TRACE_EVENT(tyr_fw_csg_dump_output,
	TP_PROTO(u32 csg, u32 ack, u32 status_state, u32 status_ep_current,
		 u32 status_ep_req, u32 resource_dep),
	TP_ARGS(csg, ack, status_state, status_ep_current, status_ep_req,
		resource_dep),
	TP_STRUCT__entry(
		__field(u32, csg)
		__field(u32, ack)
		__field(u32, status_state)
		__field(u32, status_ep_current)
		__field(u32, status_ep_req)
		__field(u32, resource_dep)
	),
	TP_fast_assign(
		__entry->csg = csg;
		__entry->ack = ack;
		__entry->status_state = status_state;
		__entry->status_ep_current = status_ep_current;
		__entry->status_ep_req = status_ep_req;
		__entry->resource_dep = resource_dep;
	),
	TP_printk("csg=%u ack=0x%08x(state=%s flags=%s) status_state=0x%08x(idle=%c) status_ep_current=0x%08x(compute=%u fragment=%u tiler=%u) status_ep_req=0x%08x(compute=%u fragment=%u tiler=%u) resource_dep=0x%08x",
		  __entry->csg, __entry->ack,
		  __print_symbolic(__entry->ack & 0x7, TYR_CSG_STATE_VALUES),
		  __print_flags(__entry->ack & ~0x7u, "|", TYR_CSG_REQ_FLAGS),
		  __entry->status_state,
		  (__entry->status_state & 0x1) ? 'y' : 'n',
		  __entry->status_ep_current,
		  __entry->status_ep_current & 0xff,
		  (__entry->status_ep_current >> 8) & 0xff,
		  (__entry->status_ep_current >> 16) & 0xf,
		  __entry->status_ep_req,
		  __entry->status_ep_req & 0xff,
		  (__entry->status_ep_req >> 8) & 0xff,
		  (__entry->status_ep_req >> 16) & 0xf,
		  __entry->resource_dep)
);

TRACE_EVENT(tyr_shader_power_state,
	TP_PROTO(u64 ready, u64 pwrtrans, u64 pwractive),
	TP_ARGS(ready, pwrtrans, pwractive),
	TP_STRUCT__entry(
		__field(u64, ready)
		__field(u64, pwrtrans)
		__field(u64, pwractive)
	),
	TP_fast_assign(
		__entry->ready = ready;
		__entry->pwrtrans = pwrtrans;
		__entry->pwractive = pwractive;
	),
	TP_printk("ready=0x%016llx pwrtrans=0x%016llx pwractive=0x%016llx",
		  __entry->ready, __entry->pwrtrans, __entry->pwractive)
);

/*
 * Per-op record of a DRM_IOCTL_PANTHOR_VM_BIND submission, emitted from
 * the ioctl handler after each op has been parsed. `op_kind` matches the
 * UAPI op-type field shifted by 28, so 0=MAP, 1=UNMAP, 2=SYNC_ONLY.
 */
#define TYR_VM_BIND_OP_KINDS		\
	{ 0, "MAP" },			\
	{ 1, "UNMAP" },			\
	{ 2, "SYNC_ONLY" }

/*
 * Path through DRM_IOCTL_PANTHOR_VM_BIND: SYNC is the in-line ioctl
 * path, ASYNC dispatches each op through the bind job queue.
 */
#define TYR_VM_BIND_IOCTL_KINDS		\
	{ 0, "SYNC" },			\
	{ 1, "ASYNC" }

/*
 * Reason tag for `tyr_group_state_transition`, set explicitly by the
 * caller at each `Group::set_state` invocation. Keep in sync with
 * `StateChangeReason` in drivers/gpu/drm/tyr/sched/group.rs.
 */
#define TYR_GROUP_STATE_REASONS		\
	{ 0, "CREATED" },		\
	{ 1, "BOUND" },			\
	{ 2, "ACTIVE" },		\
	{ 3, "IDLE_ACK" },		\
	{ 4, "BLOCKED" },		\
	{ 5, "UNBINDING" },		\
	{ 6, "FAULTED" },		\
	{ 7, "TIMED_OUT" },		\
	{ 8, "TORN_DOWN" },		\
	{ 9, "FW_ACK" },		\
	{ 10, "OTHER" }

TRACE_EVENT(tyr_group_state_transition,
	TP_PROTO(u64 group_id, u32 old_state, u32 new_state, u32 reason),
	TP_ARGS(group_id, old_state, new_state, reason),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, old_state)
		__field(u32, new_state)
		__field(u32, reason)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->old_state = old_state;
		__entry->new_state = new_state;
		__entry->reason = reason;
	),
	TP_printk("group=%llu old=%s new=%s reason=%s",
		  __entry->group_id,
		  __print_symbolic(__entry->old_state, TYR_GROUP_STATES),
		  __print_symbolic(__entry->new_state, TYR_GROUP_STATES),
		  __print_symbolic(__entry->reason, TYR_GROUP_STATE_REASONS))
);

/*
 * Direction of a single sync op inside a `DRM_IOCTL_PANTHOR_VM_BIND`
 * batch. `tyr_vm_bind_syncop` carries one record per parsed op.
 */
#define TYR_VM_BIND_SYNCOP_KINDS	\
	{ 0, "WAIT" },			\
	{ 1, "SIGNAL" }

TRACE_EVENT(tyr_vm_bind_syncop,
	TP_PROTO(u64 vm_id, u32 op_index, u32 syncop_index, u32 kind,
		 u32 syncobj_handle, u64 timeline_value),
	TP_ARGS(vm_id, op_index, syncop_index, kind, syncobj_handle,
		timeline_value),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u32, op_index)
		__field(u32, syncop_index)
		__field(u32, kind)
		__field(u32, syncobj_handle)
		__field(u64, timeline_value)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->op_index = op_index;
		__entry->syncop_index = syncop_index;
		__entry->kind = kind;
		__entry->syncobj_handle = syncobj_handle;
		__entry->timeline_value = timeline_value;
	),
	TP_printk("vm=%llu op_index=%u syncop_index=%u kind=%s syncobj=%u timeline_value=%llu",
		  __entry->vm_id, __entry->op_index, __entry->syncop_index,
		  __print_symbolic(__entry->kind, TYR_VM_BIND_SYNCOP_KINDS),
		  __entry->syncobj_handle, __entry->timeline_value)
);

TRACE_EVENT(tyr_vm_bind_ioctl_entry,
	TP_PROTO(u64 vm_id, u32 kind, u32 op_count, u32 in_flight_fences),
	TP_ARGS(vm_id, kind, op_count, in_flight_fences),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u32, kind)
		__field(u32, op_count)
		__field(u32, in_flight_fences)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->kind = kind;
		__entry->op_count = op_count;
		__entry->in_flight_fences = in_flight_fences;
	),
	TP_printk("vm=%llu kind=%s op_count=%u in_flight_fences=%u",
		  __entry->vm_id,
		  __print_symbolic(__entry->kind, TYR_VM_BIND_IOCTL_KINDS),
		  __entry->op_count, __entry->in_flight_fences)
);

TRACE_EVENT(tyr_vm_bind_op,
	TP_PROTO(u64 vm_id, u32 op_kind, u64 va, u64 size, u32 n_waits,
		 u32 n_signals),
	TP_ARGS(vm_id, op_kind, va, size, n_waits, n_signals),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u32, op_kind)
		__field(u64, va)
		__field(u64, size)
		__field(u32, n_waits)
		__field(u32, n_signals)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->op_kind = op_kind;
		__entry->va = va;
		__entry->size = size;
		__entry->n_waits = n_waits;
		__entry->n_signals = n_signals;
	),
	TP_printk("vm=%llu op=%s va=0x%llx size=0x%llx n_waits=%u n_signals=%u",
		  __entry->vm_id,
		  __print_symbolic(__entry->op_kind, TYR_VM_BIND_OP_KINDS),
		  __entry->va, __entry->size, __entry->n_waits,
		  __entry->n_signals)
);

TRACE_EVENT(tyr_vm_bind_unmap_exec,
	TP_PROTO(u64 vm_id, u64 va, u64 size, u32 in_flight_fences),
	TP_ARGS(vm_id, va, size, in_flight_fences),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u64, va)
		__field(u64, size)
		__field(u32, in_flight_fences)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->va = va;
		__entry->size = size;
		__entry->in_flight_fences = in_flight_fences;
	),
	TP_printk("vm=%llu va=0x%llx size=0x%llx in_flight_fences=%u",
		  __entry->vm_id, __entry->va, __entry->size,
		  __entry->in_flight_fences)
);

#define TYR_USER_STREAM_HEAD_STATUS	\
	{ 0, "OK" },			\
	{ 1, "LOOKUP_FAILED" },		\
	{ 2, "VMAP_FAILED" }

TRACE_EVENT(tyr_user_stream_head,
	TP_PROTO(u64 group_id, u32 cs_id, u64 stream_va, u64 first_qword,
		 u32 status),
	TP_ARGS(group_id, cs_id, stream_va, first_qword, status),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u64, stream_va)
		__field(u64, first_qword)
		__field(u32, status)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->stream_va = stream_va;
		__entry->first_qword = first_qword;
		__entry->status = status;
	),
	TP_printk("group=%llu cs=%u stream_va=0x%llx first_qword=0x%016llx status=%s",
		  __entry->group_id, __entry->cs_id, __entry->stream_va,
		  __entry->first_qword,
		  __print_symbolic(__entry->status, TYR_USER_STREAM_HEAD_STATUS))
);

TRACE_EVENT(tyr_mmu_fault,
	TP_PROTO(u32 as_slot, u64 fault_va, u32 raw_fault_status,
		 u32 exception_type, u32 access_type, u32 source_id,
		 u64 group_id, u32 csg_id, const u64 *cs_ringbuf_ptrs,
		 const u64 *ringbuf_words),
	TP_ARGS(as_slot, fault_va, raw_fault_status, exception_type,
		access_type, source_id, group_id, csg_id, cs_ringbuf_ptrs,
		ringbuf_words),
	TP_STRUCT__entry(
		__field(u32, as_slot)
		__field(u64, fault_va)
		__field(u32, raw_fault_status)
		__field(u32, exception_type)
		__field(u32, access_type)
		__field(u32, source_id)
		__field(u64, group_id)
		__field(u32, csg_id)
		__array(u64, cs_ringbuf_ptrs, 4)
		__array(u64, ringbuf_words, 8)
	),
	TP_fast_assign(
		__entry->as_slot = as_slot;
		__entry->fault_va = fault_va;
		__entry->raw_fault_status = raw_fault_status;
		__entry->exception_type = exception_type;
		__entry->access_type = access_type;
		__entry->source_id = source_id;
		__entry->group_id = group_id;
		__entry->csg_id = csg_id;
		memcpy(__entry->cs_ringbuf_ptrs, cs_ringbuf_ptrs,
		       sizeof(__entry->cs_ringbuf_ptrs));
		memcpy(__entry->ringbuf_words, ringbuf_words,
		       sizeof(__entry->ringbuf_words));
	),
	TP_printk("as=%u va=0x%016llx fault_status=0x%08x exception=0x%02x access=%u source_id=0x%x group=%llu csg=%u cs0_insert=0x%llx cs0_extract=0x%llx cs1_insert=0x%llx cs1_extract=0x%llx rb=[%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx]",
		  __entry->as_slot, __entry->fault_va,
		  __entry->raw_fault_status, __entry->exception_type,
		  __entry->access_type, __entry->source_id,
		  __entry->group_id, __entry->csg_id,
		  __entry->cs_ringbuf_ptrs[0], __entry->cs_ringbuf_ptrs[1],
		  __entry->cs_ringbuf_ptrs[2], __entry->cs_ringbuf_ptrs[3],
		  __entry->ringbuf_words[0], __entry->ringbuf_words[1],
		  __entry->ringbuf_words[2], __entry->ringbuf_words[3],
		  __entry->ringbuf_words[4], __entry->ringbuf_words[5],
		  __entry->ringbuf_words[6], __entry->ringbuf_words[7])
);

/*
 * Kind tags for cleanup-workqueue trace events. KERNEL_BO carries the
 * deferred GPU unmap + BO refcount drop from `KernelBo::drop`;
 * MAPPED_BO_VMAP carries the deferred kernel vmap teardown from
 * `MappedBo::drop`.
 */
#define TYR_CLEANUP_WQ_KINDS			\
	{ 0, "KERNEL_BO" },			\
	{ 1, "MAPPED_BO_VMAP" }

TRACE_EVENT(tyr_cleanup_wq_enqueue,
	TP_PROTO(u32 kind, u64 va, u64 size),
	TP_ARGS(kind, va, size),
	TP_STRUCT__entry(
		__field(u32, kind)
		__field(u64, va)
		__field(u64, size)
	),
	TP_fast_assign(
		__entry->kind = kind;
		__entry->va = va;
		__entry->size = size;
	),
	TP_printk("kind=%s va=0x%llx size=0x%llx",
		  __print_symbolic(__entry->kind, TYR_CLEANUP_WQ_KINDS),
		  __entry->va, __entry->size)
);

TRACE_EVENT(tyr_cleanup_wq_exec,
	TP_PROTO(u32 kind, u64 va, u64 size),
	TP_ARGS(kind, va, size),
	TP_STRUCT__entry(
		__field(u32, kind)
		__field(u64, va)
		__field(u64, size)
	),
	TP_fast_assign(
		__entry->kind = kind;
		__entry->va = va;
		__entry->size = size;
	),
	TP_printk("kind=%s va=0x%llx size=0x%llx",
		  __print_symbolic(__entry->kind, TYR_CLEANUP_WQ_KINDS),
		  __entry->va, __entry->size)
);

/*
 * Per-CS sync-wait operand captured from the firmware when a CS is
 * reported as BlockedReason::SyncWait. `sync_size` is 8 for 64-bit
 * sync objects and 4 for 32-bit ones, matching the awaited word
 * width the firmware decoded from CS_STATUS_WAIT.
 */
TRACE_EVENT(tyr_cs_sync_wait_operand,
	TP_PROTO(u64 group_id, u32 cs_id, u64 gpu_va, u64 ref_val, u32 sync_size),
	TP_ARGS(group_id, cs_id, gpu_va, ref_val, sync_size),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u64, gpu_va)
		__field(u64, ref_val)
		__field(u32, sync_size)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->gpu_va = gpu_va;
		__entry->ref_val = ref_val;
		__entry->sync_size = sync_size;
	),
	TP_printk("group=%llu cs=%u gpu_va=0x%llx ref_val=0x%llx sync_size=%u",
		  __entry->group_id, __entry->cs_id, __entry->gpu_va,
		  __entry->ref_val, __entry->sync_size)
);

/*
 * Sync-wait operand about to be stored into the queue's syncwait
 * snapshot in `sync_csg_slot_queues_state`. Fires only on the branch
 * that observed BlockedReason::SyncWait, just before the
 * `Queue::set_syncwait` call, so the trace records what is being
 * captured for the later eval_syncwait pass. Pairs with the
 * eval_syncwait failure log so the lifecycle of one syncwait
 * snapshot is visible end to end.
 */
TRACE_EVENT(tyr_syncwait_capture,
	TP_PROTO(u64 vm_id, u64 group_id, u32 cs_id, u64 gpu_va, u64 ref_val,
		 u32 sync64, u32 gt),
	TP_ARGS(vm_id, group_id, cs_id, gpu_va, ref_val, sync64, gt),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u64, gpu_va)
		__field(u64, ref_val)
		__field(u32, sync64)
		__field(u32, gt)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->gpu_va = gpu_va;
		__entry->ref_val = ref_val;
		__entry->sync64 = sync64;
		__entry->gt = gt;
	),
	TP_printk("vm=%llu group=%llu cs=%u gpu_va=0x%llx ref_val=0x%llx sync64=%u gt=%u",
		  __entry->vm_id, __entry->group_id, __entry->cs_id,
		  __entry->gpu_va, __entry->ref_val, __entry->sync64,
		  __entry->gt)
);

/*
 * Caller-site tag for `tyr_queue_blocked_state_change`. Keep in sync
 * with `QueueBlockedCaller` in drivers/gpu/drm/tyr/trace.rs.
 */
#define TYR_QUEUE_BLOCKED_CALLERS	\
	{ 0, "SYNC_SLOT_APPLY" },	\
	{ 1, "APPLY_RESULTS" }

/*
 * One transition of a queue's bit in `GroupInner::blocked_queues`,
 * emitted immediately after the corresponding `set_queue_blocked`
 * call. `caller` distinguishes the apply-side site in
 * `sync_csg_slot_queues_state` from the syncwait-result-side site
 * in `apply_syncwait_results`, so the bitmap update can be
 * correlated with snapshot capture and eval_syncwait outcome.
 */
TRACE_EVENT(tyr_queue_blocked_state_change,
	TP_PROTO(u64 group_id, u32 cs_id, u32 blocked, u32 caller),
	TP_ARGS(group_id, cs_id, blocked, caller),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u32, blocked)
		__field(u32, caller)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->blocked = blocked;
		__entry->caller = caller;
	),
	TP_printk("group=%llu cs=%u blocked=%u caller=%s",
		  __entry->group_id, __entry->cs_id, __entry->blocked,
		  __print_symbolic(__entry->caller, TYR_QUEUE_BLOCKED_CALLERS))
);

/*
 * Per-op record of a synchronous DRM_IOCTL_PANTHOR_VM_BIND submission,
 * emitted from the ioctl handler after each op has been parsed. Mirrors
 * `tyr_vm_bind_op` but for the non-async path, so async vs sync calls are
 * easy to distinguish in the trace. The sync path rejects per-op syncs so
 * `n_waits` and `n_signals` are always 0.
 */
TRACE_EVENT(tyr_vm_bind_op_sync,
	TP_PROTO(u64 vm_id, u32 op_kind, u64 va, u64 size, u32 n_waits,
		 u32 n_signals),
	TP_ARGS(vm_id, op_kind, va, size, n_waits, n_signals),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u32, op_kind)
		__field(u64, va)
		__field(u64, size)
		__field(u32, n_waits)
		__field(u32, n_signals)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->op_kind = op_kind;
		__entry->va = va;
		__entry->size = size;
		__entry->n_waits = n_waits;
		__entry->n_signals = n_signals;
	),
	TP_printk("vm=%llu op=%s va=0x%llx size=0x%llx n_waits=%u n_signals=%u",
		  __entry->vm_id,
		  __print_symbolic(__entry->op_kind, TYR_VM_BIND_OP_KINDS),
		  __entry->va, __entry->size, __entry->n_waits,
		  __entry->n_signals)
);

/*
 * Per-group outcome of one scheduler-tick rule-engine evaluation.
 * Keep in sync with `TickDecision` and `TickDecisionReason` in
 * drivers/gpu/drm/tyr/sched/tick.rs.
 */
#define TYR_TICK_DECISIONS		\
	{ 0, "KEEP" },			\
	{ 1, "TAKE" },			\
	{ 2, "EVICT" },			\
	{ 3, "SKIP" }

#define TYR_TICK_DECISION_REASONS	\
	{ 0, "RUNNABLE" },		\
	{ 1, "IDLE" },			\
	{ 2, "NOT_RUNNABLE" },		\
	{ 3, "ALREADY_BOUND" },		\
	{ 4, "FAULTED" },		\
	{ 5, "PREEMPTED" },		\
	{ 6, "ACTIVATE_FAILED" },	\
	{ 7, "OTHER" }

TRACE_EVENT(tyr_tick_decision_per_group,
	TP_PROTO(u64 group_id, u32 decision, u32 reason, u8 sw_prio,
		 u32 fw_prio, u32 bound_ticks),
	TP_ARGS(group_id, decision, reason, sw_prio, fw_prio, bound_ticks),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, decision)
		__field(u32, reason)
		__field(u8, sw_prio)
		__field(u32, fw_prio)
		__field(u32, bound_ticks)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->decision = decision;
		__entry->reason = reason;
		__entry->sw_prio = sw_prio;
		__entry->fw_prio = fw_prio;
		__entry->bound_ticks = bound_ticks;
	),
	TP_printk("group=%llu decision=%s reason=%s sw_prio=%u fw_prio=%u bound_ticks=%u",
		  __entry->group_id,
		  __print_symbolic(__entry->decision, TYR_TICK_DECISIONS),
		  __print_symbolic(__entry->reason, TYR_TICK_DECISION_REASONS),
		  __entry->sw_prio, __entry->fw_prio, __entry->bound_ticks)
);

/*
 * Kind tag for a decoded CS-level exception, distinguishing recoverable
 * faults from terminating fatals so both can share one trace event.
 */
#define TYR_CS_FAULT_EVENT_KINDS	\
	{ 0, "FAULT" },			\
	{ 1, "FATAL" }

/*
 * One decoded CS_FAULT or CS_FATAL ack, emitted immediately after the
 * firmware register snapshot is read but before the driver's
 * `fatal_queues` / `fatal_error` bookkeeping runs. This ensures the
 * trace records every FW-reported exception even when the driver later
 * drops or coalesces it.
 */
TRACE_EVENT(tyr_cs_fault_event,
	TP_PROTO(u64 group_id, u32 cs_id, u32 kind, u32 exception_type,
		 u32 exception_data, u64 fatal_info, u64 cs_insert,
		 u64 cs_extract, const u64 *ringbuf_words),
	TP_ARGS(group_id, cs_id, kind, exception_type, exception_data,
		fatal_info, cs_insert, cs_extract, ringbuf_words),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u32, kind)
		__field(u32, exception_type)
		__field(u32, exception_data)
		__field(u64, fatal_info)
		__field(u64, cs_insert)
		__field(u64, cs_extract)
		__array(u64, ringbuf_words, 8)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->kind = kind;
		__entry->exception_type = exception_type;
		__entry->exception_data = exception_data;
		__entry->fatal_info = fatal_info;
		__entry->cs_insert = cs_insert;
		__entry->cs_extract = cs_extract;
		memcpy(__entry->ringbuf_words, ringbuf_words,
		       sizeof(__entry->ringbuf_words));
	),
	TP_printk("group=%llu cs=%u kind=%s exception_type=0x%02x exception_data=0x%06x fatal_info=0x%016llx cs_insert=0x%llx cs_extract=0x%llx rb=[%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx]",
		  __entry->group_id, __entry->cs_id,
		  __print_symbolic(__entry->kind, TYR_CS_FAULT_EVENT_KINDS),
		  __entry->exception_type, __entry->exception_data,
		  __entry->fatal_info, __entry->cs_insert,
		  __entry->cs_extract,
		  __entry->ringbuf_words[0], __entry->ringbuf_words[1],
		  __entry->ringbuf_words[2], __entry->ringbuf_words[3],
		  __entry->ringbuf_words[4], __entry->ringbuf_words[5],
		  __entry->ringbuf_words[6], __entry->ringbuf_words[7])
);

/*
 * Kind tag for one gpuvm step callback, distinguishing the three
 * shapes the gpuvm framework drives: a new map, an unmap, or a remap
 * (split) of an existing mapping.
 */
#define TYR_GPUVM_NODE_OPS	\
	{ 0, "MAP" },		\
	{ 1, "UNMAP" },		\
	{ 2, "REMAP" }

/*
 * One MAP / UNMAP / REMAP step on the gpuvm interval tree, emitted
 * from the matching `sm_step_*` callback before the operation is
 * committed. The reported `va` and `size` are the actual range
 * affected by the step (for REMAP, this is the unmapped sub-range).
 */
TRACE_EVENT(tyr_gpuvm_node_op,
	TP_PROTO(u64 vm_id, u32 op, u64 va, u64 size),
	TP_ARGS(vm_id, op, va, size),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u32, op)
		__field(u64, va)
		__field(u64, size)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->op = op;
		__entry->va = va;
		__entry->size = size;
	),
	TP_printk("vm=%llu op=%s va=0x%llx size=0x%llx",
		  __entry->vm_id,
		  __print_symbolic(__entry->op, TYR_GPUVM_NODE_OPS),
		  __entry->va, __entry->size)
);

/*
 * One WAIT syncop from a DRM_IOCTL_PANTHOR_VM_BIND submission, emitted
 * after the WAIT has been resolved to a dma_fence but before that
 * fence is registered with the vm_bind job-queue framework.
 * `signalled` reflects `dma_fence_is_signaled()` at registration time.
 */
TRACE_EVENT(tyr_vm_bind_wait_fence,
	TP_PROTO(u64 vm_id, u32 op_index, u32 syncop_index,
		 u64 fence_context, u64 fence_seqno, bool signalled),
	TP_ARGS(vm_id, op_index, syncop_index, fence_context, fence_seqno,
		signalled),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u32, op_index)
		__field(u32, syncop_index)
		__field(u64, fence_context)
		__field(u64, fence_seqno)
		__field(bool, signalled)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->op_index = op_index;
		__entry->syncop_index = syncop_index;
		__entry->fence_context = fence_context;
		__entry->fence_seqno = fence_seqno;
		__entry->signalled = signalled;
	),
	TP_printk("vm=%llu op_index=%u syncop_index=%u fence_context=%llu fence_seqno=%llu signalled=%d",
		  __entry->vm_id, __entry->op_index, __entry->syncop_index,
		  __entry->fence_context, __entry->fence_seqno,
		  __entry->signalled)
);

/*
 * Result of one DRM_IOCTL_PANTHOR_GROUP_GET_STATE invocation, emitted
 * just before the ioctl returns. `returned_state` is the value being
 * written back to userspace in `drm_panthor_group_get_state.state` and
 * `fatal_queues` is the matching per-CS fatal bitmap.
 */
TRACE_EVENT(tyr_group_state_query,
	TP_PROTO(u64 vm_id, u64 group_id, u32 returned_state, u32 fatal_queues),
	TP_ARGS(vm_id, group_id, returned_state, fatal_queues),
	TP_STRUCT__entry(
		__field(u64, vm_id)
		__field(u64, group_id)
		__field(u32, returned_state)
		__field(u32, fatal_queues)
	),
	TP_fast_assign(
		__entry->vm_id = vm_id;
		__entry->group_id = group_id;
		__entry->returned_state = returned_state;
		__entry->fatal_queues = fatal_queues;
	),
	TP_printk("vm=%llu group=%llu state=0x%08x fatal_queues=0x%08x",
		  __entry->vm_id, __entry->group_id,
		  __entry->returned_state, __entry->fatal_queues)
);

/*
 * Status tag for tyr_cs_user_stream_dump describing the outcome of the
 * lookup-and-read attempt for `cs_extract`.
 *   OK              - `bytes`/`len` carry payload read from a kernel
 *                     vmap.
 *   NO_BO_AT_VA     - `Vm::try_get_bo_for_va` returned no mapping
 *                     covering the resolved GPU VA; payload is empty.
 *   BO_NOT_VMAPPED  - a BO was located but no kernel vmap is reachable
 *                     in IRQ context without taking dma_resv_lock;
 *                     payload is empty.
 *   BO_IMPORTED     - the BO is dma-buf imported; kernel reads through
 *                     it are not attempted; payload is empty.
 *   WINDOW_CLAMPED  - the window was clamped to BO bounds. `len` is
 *                     the actual byte count; zero means the BO offset
 *                     fell outside the BO.
 *   LOCK_CONTENDED  - `gpuvm_unique` was held by another thread; the
 *                     lookup was skipped to preserve dma-fence
 *                     signalling rules. Payload is empty.
 */
#define TYR_CS_USER_STREAM_DUMP_STATUS	\
	{ 0, "OK" },			\
	{ 1, "NO_BO_AT_VA" },		\
	{ 2, "BO_NOT_VMAPPED" },	\
	{ 3, "BO_IMPORTED" },		\
	{ 4, "WINDOW_CLAMPED" },	\
	{ 5, "LOCK_CONTENDED" }

/*
 * 256-byte window from the BO containing the GPU VA derived from the
 * faulting CS's `cs_extract` counter. Emitted from the CSG IRQ
 * handler alongside `tyr_cs_fault_event` so trace consumers can
 * inspect 32 Mali CS instructions around the consumption point.
 *
 * Per the CSF architecture spec, `cs_extract` is a monotonically
 * increasing byte counter relative to the per-queue ring buffer
 * base; the GPU VA used for the lookup is `CS_BASE + (cs_extract %
 * CS_SIZE)`. `bo_gpu_va_base` is the located BO's base GPU VA and
 * `bo_offset` is the offset within that BO that corresponds to the
 * consumption point. `payload_offset` is the offset at which `bytes`
 * starts (`bo_offset - 128` clamped to BO bounds on success, zero
 * otherwise).
 */
TRACE_EVENT(tyr_cs_user_stream_dump,
	TP_PROTO(u64 group_id, u32 cs_id, u64 cs_extract, u64 bo_gpu_va_base,
		 u64 bo_offset, u64 payload_offset, u32 status, u32 len,
		 const u8 *bytes),
	TP_ARGS(group_id, cs_id, cs_extract, bo_gpu_va_base, bo_offset,
		payload_offset, status, len, bytes),
	TP_STRUCT__entry(
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u64, cs_extract)
		__field(u64, bo_gpu_va_base)
		__field(u64, bo_offset)
		__field(u64, payload_offset)
		__field(u32, status)
		__field(u32, len)
		__array(u8, bytes, 256)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->cs_extract = cs_extract;
		__entry->bo_gpu_va_base = bo_gpu_va_base;
		__entry->bo_offset = bo_offset;
		__entry->payload_offset = payload_offset;
		__entry->status = status;
		__entry->len = len;
		memset(__entry->bytes, 0, sizeof(__entry->bytes));
		if (len)
			memcpy(__entry->bytes, bytes, len);
	),
	TP_printk("group=%llu cs=%u cs_extract=0x%llx bo_va_base=0x%llx bo_offset=0x%llx payload_offset=0x%llx status=%s len=%u",
		  __entry->group_id, __entry->cs_id, __entry->cs_extract,
		  __entry->bo_gpu_va_base, __entry->bo_offset,
		  __entry->payload_offset,
		  __print_symbolic(__entry->status,
				   TYR_CS_USER_STREAM_DUMP_STATUS),
		  __entry->len)
);

#endif /* _TYR_TRACE_H */

/* This part must be outside protection. */
#include <trace/define_trace.h>
