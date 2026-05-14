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

#define TYR_CSG_REQ_FLAGS			\
	{ 0x00000007, "STATE" },		\
	{ 0x00000010, "EP_CFG" },		\
	{ 0x00000020, "STATUS_UPDATE" },	\
	{ 0x10000000, "SYNC_UPDATE" },		\
	{ 0x20000000, "IDLE" },			\
	{ 0x80000000, "PROGRESS_TIMER_EVENT" }

#define TYR_CS_REQ_FLAGS			\
	{ 0x00000007, "STATE" },		\
	{ 0x00000100, "IDLE_SYNC_WAIT" },	\
	{ 0x00000400, "IDLE_EMPTY" },		\
	{ 0x04000000, "TILER_OOM" }

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
	TP_printk("csg=%u group=%llu req=0x%08x update_mask=%s toggle_mask=%s",
		  __entry->csg_id, __entry->group_id, __entry->req_val,
		  __print_flags(__entry->update_mask, "|", TYR_CSG_REQ_FLAGS),
		  __print_flags(__entry->toggle_mask, "|", TYR_CSG_REQ_FLAGS))
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

TRACE_EVENT(tyr_fw_irq,
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
	TP_printk("csg=%u group=%llu req=0x%08x ack=0x%08x irq_req=0x%08x irq_ack=0x%08x",
		  __entry->csg_id, __entry->group_id, __entry->req,
		  __entry->ack, __entry->irq_req, __entry->irq_ack)
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
	TP_printk("status=0x%08x", __entry->status)
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

#endif /* _TYR_TRACE_H */

/* This part must be outside protection. */
#include <trace/define_trace.h>
