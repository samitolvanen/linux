#undef TRACE_SYSTEM
#define TRACE_SYSTEM panthor

#if !defined(_PANTHOR_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _PANTHOR_TRACE_H

#include <linux/tracepoint.h>
#include "../../../drivers/gpu/drm/panthor/panthor_fw.h"

#define PANTHOR_GLB_REQ_FLAGS \
	{ GLB_HALT, "HALT" }, \
	{ GLB_CFG_PROGRESS_TIMER, "CFG_PROGRESS_TIMER" }, \
	{ GLB_CFG_ALLOC_EN, "CFG_ALLOC_EN" }, \
	{ GLB_CFG_POWEROFF_TIMER, "CFG_POWEROFF_TIMER" }, \
	{ GLB_PROTM_ENTER, "PROTM_ENTER" }, \
	{ GLB_PERFCNT_EN, "PERFCNT_EN" }, \
	{ GLB_PERFCNT_SAMPLE, "PERFCNT_SAMPLE" }, \
	{ GLB_COUNTER_EN, "COUNTER_EN" }, \
	{ GLB_PING, "PING" }, \
	{ GLB_FWCFG_UPDATE, "FWCFG_UPDATE" }, \
	{ GLB_IDLE_EN, "IDLE_EN" }, \
	{ GLB_SLEEP, "SLEEP" }, \
	{ GLB_INACTIVE_COMPUTE, "INACTIVE_COMPUTE" }, \
	{ GLB_INACTIVE_FRAGMENT, "INACTIVE_FRAGMENT" }, \
	{ GLB_INACTIVE_TILER, "INACTIVE_TILER" }, \
	{ GLB_PROTM_EXIT, "PROTM_EXIT" }, \
	{ GLB_PERFCNT_THRESHOLD, "PERFCNT_THRESHOLD" }, \
	{ GLB_PERFCNT_OVERFLOW, "PERFCNT_OVERFLOW" }, \
	{ GLB_IDLE, "IDLE" }, \
	{ GLB_DBG_CSF, "DBG_CSF" }, \
	{ GLB_DBG_HOST, "DBG_HOST" }


#define PANTHOR_GROUP_LIST_STATES \
	{ 0, "NONE" }, \
	{ 1, "IDLE" }, \
	{ 2, "RUNNABLE" }

#define PANTHOR_GROUP_STATES \
	{ 0, "CREATED" }, \
	{ 1, "ACTIVE" }, \
	{ 2, "SUSPENDED" }, \
	{ 3, "TERMINATED" }, \
	{ 4, "UNKNOWN" }

#define PANTHOR_CSG_REQ_FLAGS \
	{ 7, "STATE_MASK" }, \
	{ CSG_STATE_RESUME, "STATE_RESUME" }, \
	{ CSG_STATE_SUSPEND, "STATE_SUSPEND" }, \
	{ CSG_STATE_START, "STATE_START" }, \
	{ CSG_STATE_TERMINATE, "STATE_TERMINATE" }, \
	{ CSG_ENDPOINT_CONFIG, "ENDPOINT_CONFIG" }, \
	{ CSG_STATUS_UPDATE, "STATUS_UPDATE" }, \
	{ CSG_SYNC_UPDATE, "SYNC_UPDATE" }, \
	{ CSG_IDLE, "IDLE" }, \
	{ CSG_DOORBELL, "DOORBELL" }, \
	{ CSG_PROGRESS_TIMER_EVENT, "PROGRESS_TIMER_EVENT" }

#define PANTHOR_CS_REQ_FLAGS \
	{ 7, "STATE_MASK" }, \
	{ CS_STATE_START, "STATE_START" }, \
	{ CS_STATE_STOP, "STATE_STOP" }, \
	{ CS_EXTRACT_EVENT, "EXTRACT_EVENT" }, \
	{ CS_IDLE_SYNC_WAIT, "IDLE_SYNC_WAIT" }, \
	{ CS_IDLE_PROTM_PENDING, "IDLE_PROTM_PENDING" }, \
	{ CS_IDLE_EMPTY, "IDLE_EMPTY" }, \
	{ CS_IDLE_RESOURCE_REQ, "IDLE_RESOURCE_REQ" }, \
	{ CS_TILER_OOM, "TILER_OOM" }, \
	{ CS_PROTM_PENDING, "PROTM_PENDING" }, \
	{ CS_FATAL, "FATAL" }, \
	{ CS_FAULT, "FAULT" }

#define PANTHOR_FW_IRQ_FLAGS \
	{ BIT(31), "GLOBAL_IF" }

#define PANTHOR_CSG_IRQ_FLAGS \
	{ CSG_ENDPOINT_CONFIG, "ENDPOINT_CONFIG" }, \
	{ CSG_STATUS_UPDATE, "STATUS_UPDATE" }, \
	{ CSG_SYNC_UPDATE, "SYNC_UPDATE" }, \
	{ CSG_IDLE, "IDLE" }, \
	{ CSG_DOORBELL, "DOORBELL" }, \
	{ CSG_PROGRESS_TIMER_EVENT, "PROGRESS_TIMER" }

#define PANTHOR_CS_IRQ_FLAGS \
	{ CS_TILER_OOM, "TILER_OOM" }, \
	{ CS_PROTM_PENDING, "PROTM_PENDING" }, \
	{ CS_FATAL, "FATAL" }, \
	{ CS_FAULT, "FAULT" }

#define PANTHOR_JOB_INT_FLAGS \
	{ BIT(31), "GLOBAL_IF" }, \
	{ BIT(0), "CSG0" }, \
	{ BIT(1), "CSG1" }, \
	{ BIT(2), "CSG2" }, \
	{ BIT(3), "CSG3" }, \
	{ BIT(4), "CSG4" }, \
	{ BIT(5), "CSG5" }, \
	{ BIT(6), "CSG6" }, \
	{ BIT(7), "CSG7" }, \
	{ BIT(8), "CSG8" }, \
	{ BIT(9), "CSG9" }, \
	{ BIT(10), "CSG10" }, \
	{ BIT(11), "CSG11" }, \
	{ BIT(12), "CSG12" }, \
	{ BIT(13), "CSG13" }, \
	{ BIT(14), "CSG14" }, \
	{ BIT(15), "CSG15" }, \
	{ BIT(16), "CSG16" }, \
	{ BIT(17), "CSG17" }, \
	{ BIT(18), "CSG18" }, \
	{ BIT(19), "CSG19" }, \
	{ BIT(20), "CSG20" }, \
	{ BIT(21), "CSG21" }, \
	{ BIT(22), "CSG22" }, \
	{ BIT(23), "CSG23" }, \
	{ BIT(24), "CSG24" }, \
	{ BIT(25), "CSG25" }, \
	{ BIT(26), "CSG26" }, \
	{ BIT(27), "CSG27" }, \
	{ BIT(28), "CSG28" }, \
	{ BIT(29), "CSG29" }, \
	{ BIT(30), "CSG30" }

#define PANTHOR_CS_IRQ_REQ_FLAGS \
	{ BIT(0), "CS0" }, \
	{ BIT(1), "CS1" }, \
	{ BIT(2), "CS2" }, \
	{ BIT(3), "CS3" }, \
	{ BIT(4), "CS4" }, \
	{ BIT(5), "CS5" }, \
	{ BIT(6), "CS6" }, \
	{ BIT(7), "CS7" }, \
	{ BIT(8), "CS8" }, \
	{ BIT(9), "CS9" }, \
	{ BIT(10), "CS10" }, \
	{ BIT(11), "CS11" }, \
	{ BIT(12), "CS12" }, \
	{ BIT(13), "CS13" }, \
	{ BIT(14), "CS14" }, \
	{ BIT(15), "CS15" }, \
	{ BIT(16), "CS16" }, \
	{ BIT(17), "CS17" }, \
	{ BIT(18), "CS18" }, \
	{ BIT(19), "CS19" }, \
	{ BIT(20), "CS20" }, \
	{ BIT(21), "CS21" }, \
	{ BIT(22), "CS22" }, \
	{ BIT(23), "CS23" }, \
	{ BIT(24), "CS24" }, \
	{ BIT(25), "CS25" }, \
	{ BIT(26), "CS26" }, \
	{ BIT(27), "CS27" }, \
	{ BIT(28), "CS28" }, \
	{ BIT(29), "CS29" }, \
	{ BIT(30), "CS30" }, \
	{ BIT(31), "CS31" }

#define PANTHOR_CS_STATUS_BLOCKED_REASON_VALUES \
	{ CS_STATUS_BLOCKED_REASON_UNBLOCKED, "UNBLOCKED" }, \
	{ CS_STATUS_BLOCKED_REASON_SB_WAIT, "SB_WAIT" }, \
	{ CS_STATUS_BLOCKED_REASON_PROGRESS_WAIT, "PROGRESS_WAIT" }, \
	{ CS_STATUS_BLOCKED_REASON_SYNC_WAIT, "SYNC_WAIT" }, \
	{ CS_STATUS_BLOCKED_REASON_DEFERRED, "DEFERRED" }, \
	{ CS_STATUS_BLOCKED_REASON_RESOURCE, "RESOURCE" }, \
	{ CS_STATUS_BLOCKED_REASON_FLUSH, "FLUSH" }

#define PANTHOR_CS_STATUS_REQ_RESOURCE_FLAGS \
	{ BIT(0), "COMPUTE_REQUESTED" }, \
	{ BIT(1), "FRAGMENT_REQUESTED" }, \
	{ BIT(2), "TILER_REQUESTED" }, \
	{ BIT(3), "IDVS_REQUESTED" }, \
	{ BIT(16), "COMPUTE_GRANTED" }, \
	{ BIT(17), "FRAGMENT_GRANTED" }, \
	{ BIT(18), "TILER_GRANTED" }, \
	{ BIT(19), "IDVS_GRANTED" }

TRACE_EVENT(panthor_fw_glb_req,
	TP_PROTO(const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask),
	TP_ARGS(reg_name, req_val, update_mask, toggle_mask),
	TP_STRUCT__entry(
		__string(reg_name, reg_name)
		__field(u32, req_val)
		__field(u32, update_mask)
		__field(u32, toggle_mask)
	),
	TP_fast_assign(
		__assign_str(reg_name);
		__entry->req_val = req_val;
		__entry->update_mask = update_mask;
		__entry->toggle_mask = toggle_mask;
	),
	TP_printk("reg=%s req=0x%08x (%s) update=0x%08x (%s) toggle=0x%08x (%s)",
		  __get_str(reg_name),
		  __entry->req_val, __print_flags(__entry->req_val, "|", PANTHOR_GLB_REQ_FLAGS),
		  __entry->update_mask, __print_flags(__entry->update_mask, "|", PANTHOR_GLB_REQ_FLAGS),
		  __entry->toggle_mask, __print_flags(__entry->toggle_mask, "|", PANTHOR_GLB_REQ_FLAGS))
);

TRACE_EVENT(panthor_fw_glb_doorbell_req,
	TP_PROTO(const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask),
	TP_ARGS(reg_name, req_val, update_mask, toggle_mask),
	TP_STRUCT__entry(
		__string(reg_name, reg_name)
		__field(u32, req_val)
		__field(u32, toggle_mask)
	),
	TP_fast_assign(
		__assign_str(reg_name);
		__entry->req_val = req_val;
		__entry->toggle_mask = toggle_mask;
	),
	TP_printk("reg=%s toggled=0x%08x (%s) doorbell_req=0x%08x (%s)",
		  __get_str(reg_name),
		  __entry->toggle_mask, __print_flags(__entry->toggle_mask, "|", PANTHOR_JOB_INT_FLAGS),
		  __entry->req_val, __print_flags(__entry->req_val, "|", PANTHOR_JOB_INT_FLAGS))
);

TRACE_EVENT(panthor_glb_irq,
	TP_PROTO(u32 req, u32 ack),
	TP_ARGS(req, ack),
	TP_STRUCT__entry(
		__field(u32, req)
		__field(u32, ack)
		__field(u32, events)
	),
	TP_fast_assign(
		__entry->req = req;
		__entry->ack = ack;
		__entry->events = req ^ ack;
	),
	TP_printk("events=0x%08x (%s) req=0x%08x (%s) ack=0x%08x (%s)",
		  __entry->events, __print_flags(__entry->events, "|", PANTHOR_GLB_REQ_FLAGS),
		  __entry->req, __print_flags(__entry->req, "|", PANTHOR_GLB_REQ_FLAGS),
		  __entry->ack, __print_flags(__entry->ack, "|", PANTHOR_GLB_REQ_FLAGS))
);

TRACE_EVENT(panthor_fw_csg_req,
	TP_PROTO(u32 csg_id, u64 group_id, const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask),
	TP_ARGS(csg_id, group_id, reg_name, req_val, update_mask, toggle_mask),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, group_id)
		__string(reg_name, reg_name)
		__field(u32, req_val)
		__field(u32, update_mask)
		__field(u32, toggle_mask)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->group_id = group_id;
		__assign_str(reg_name);
		__entry->req_val = req_val;
		__entry->update_mask = update_mask;
		__entry->toggle_mask = toggle_mask;
	),
	TP_printk("csg_id=%u group_id=%llu reg=%s req=0x%08x (%s) update=0x%08x (%s) toggle=0x%08x (%s)",
		  __entry->csg_id, __entry->group_id, __get_str(reg_name),
		  __entry->req_val, __print_flags(__entry->req_val, "|", PANTHOR_CSG_REQ_FLAGS),
		  __entry->update_mask, __print_flags(__entry->update_mask, "|", PANTHOR_CSG_REQ_FLAGS),
		  __entry->toggle_mask, __print_flags(__entry->toggle_mask, "|", PANTHOR_CSG_REQ_FLAGS))
);

TRACE_EVENT(panthor_fw_csg_doorbell_req,
	TP_PROTO(u32 csg_id, const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask),
	TP_ARGS(csg_id, reg_name, req_val, update_mask, toggle_mask),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__string(reg_name, reg_name)
		__field(u32, req_val)
		__field(u32, toggle_mask)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__assign_str(reg_name);
		__entry->req_val = req_val;
		__entry->toggle_mask = toggle_mask;
	),
	TP_printk("csg_id=%u reg=%s toggled=0x%08x (%s) doorbell_req=0x%08x (%s)",
		  __entry->csg_id, __get_str(reg_name),
		  __entry->toggle_mask, __print_flags(__entry->toggle_mask, "|", PANTHOR_CS_IRQ_REQ_FLAGS),
		  __entry->req_val, __print_flags(__entry->req_val, "|", PANTHOR_CS_IRQ_REQ_FLAGS))
);

TRACE_EVENT(panthor_fw_csg_ack,
	TP_PROTO(u32 csg_id, u64 group_id, u32 ack_mask),
	TP_ARGS(csg_id, group_id, ack_mask),
	TP_STRUCT__entry(__field(u32, csg_id) __field(u64, group_id) __field(u32, ack_mask)),
	TP_fast_assign(__entry->csg_id = csg_id; __entry->group_id = group_id; __entry->ack_mask = ack_mask;),
	TP_printk("csg_id=%u group_id=%llu ack_mask=0x%08x (%s)", __entry->csg_id, __entry->group_id, __entry->ack_mask, __print_flags(__entry->ack_mask, "|", PANTHOR_CSG_REQ_FLAGS))
);

TRACE_EVENT(panthor_fw_csg_status_update,
	TP_PROTO(u32 csg_id, u64 group_id, u32 status_endpoint_current, u32 status_endpoint_req, u32 status_state, u32 resource_dep),
	TP_ARGS(csg_id, group_id, status_endpoint_current, status_endpoint_req, status_state, resource_dep),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, group_id)
		__field(u32, status_endpoint_current)
		__field(u32, status_endpoint_req)
		__field(u32, status_state)
		__field(u32, resource_dep)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->group_id = group_id;
		__entry->status_endpoint_current = status_endpoint_current;
		__entry->status_endpoint_req = status_endpoint_req;
		__entry->status_state = status_state;
		__entry->resource_dep = resource_dep;
	),
	TP_printk("csg_id=%u group_id=%llu status_endpoint_current=0x%08x status_endpoint_req=0x%08x status_state=0x%08x resource_dep=0x%08x",
		  __entry->csg_id, __entry->group_id, __entry->status_endpoint_current, __entry->status_endpoint_req,
		  __entry->status_state, __entry->resource_dep)
);

TRACE_EVENT(panthor_fw_cs_req,
	TP_PROTO(u32 csg_id, u32 cs_id, u64 group_id, const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask),
	TP_ARGS(csg_id, cs_id, group_id, reg_name, req_val, update_mask, toggle_mask),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, cs_id)
		__field(u64, group_id)
		__string(reg_name, reg_name)
		__field(u32, req_val)
		__field(u32, update_mask)
		__field(u32, toggle_mask)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->cs_id = cs_id;
		__entry->group_id = group_id;
		__assign_str(reg_name);
		__entry->req_val = req_val;
		__entry->update_mask = update_mask;
		__entry->toggle_mask = toggle_mask;
	),
	TP_printk("csg_id=%u cs_id=%u group_id=%llu reg=%s req=0x%08x (%s) update=0x%08x (%s) toggle=0x%08x (%s)",
		  __entry->csg_id, __entry->cs_id, __entry->group_id, __get_str(reg_name),
		  __entry->req_val, __print_flags(__entry->req_val, "|", PANTHOR_CS_REQ_FLAGS),
		  __entry->update_mask, __print_flags(__entry->update_mask, "|", PANTHOR_CS_REQ_FLAGS),
		  __entry->toggle_mask, __print_flags(__entry->toggle_mask, "|", PANTHOR_CS_REQ_FLAGS))
);

TRACE_EVENT(panthor_fw_irq,
	TP_PROTO(u32 status),
	TP_ARGS(status),
	TP_STRUCT__entry(
		__field(u32, status)
	),
	TP_fast_assign(
		__entry->status = status;
	),
	TP_printk("status=0x%08x (%s)", __entry->status, __print_flags(__entry->status, "|", PANTHOR_JOB_INT_FLAGS))
);

TRACE_EVENT(panthor_group_update,
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
	TP_printk("group_id=%llu state=0x%08x (%s)",
		  __entry->group_id, __entry->state,
		  __print_symbolic(__entry->state, PANTHOR_GROUP_STATES))
);

TRACE_EVENT(panthor_queue_state,
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
	TP_printk("group_id=%llu cs_id=%u blocked=%d", __entry->group_id, __entry->cs_id, __entry->blocked)
);

TRACE_EVENT(panthor_queue_timeout_state,
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
	TP_printk("group_id=%llu cs_id=%u suspended=%d", __entry->group_id, __entry->cs_id, __entry->suspended)
);

TRACE_EVENT(panthor_queue_doorbell,
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
	TP_printk("group_id=%llu cs_id=%u doorbell_id=%u", __entry->group_id, __entry->cs_id, __entry->doorbell_id)
);

TRACE_EVENT(panthor_cs_ring_ptrs,
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
	TP_printk("group_id=%llu cs_id=%u insert=%llu extract=%llu", __entry->group_id, __entry->cs_id, __entry->insert, __entry->extract)
);

TRACE_EVENT(panthor_job_submit,
	TP_PROTO(u64 job_id, u64 group_id, u32 cs_id, u32 stream_size),
	TP_ARGS(job_id, group_id, cs_id, stream_size),
	TP_STRUCT__entry(
		__field(u64, job_id)
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(u32, stream_size)
	),
	TP_fast_assign(
		__entry->job_id = job_id;
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->stream_size = stream_size;
	),
	TP_printk("job_id=%llu group_id=%llu cs_id=%u stream_size=%u",
		  __entry->job_id, __entry->group_id, __entry->cs_id, __entry->stream_size)
);

TRACE_EVENT(panthor_job_done,
	TP_PROTO(u64 job_id, u64 group_id, u32 cs_id, int result),
	TP_ARGS(job_id, group_id, cs_id, result),
	TP_STRUCT__entry(
		__field(u64, job_id)
		__field(u64, group_id)
		__field(u32, cs_id)
		__field(int, result)
	),
	TP_fast_assign(
		__entry->job_id = job_id;
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__entry->result = result;
	),
	TP_printk("job_id=%llu group_id=%llu cs_id=%u result=%d",
		  __entry->job_id, __entry->group_id, __entry->cs_id, __entry->result)
);

TRACE_EVENT(panthor_mmu_bind_start,
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
	TP_printk("vm_id=%llu va=0x%llx size=0x%llx",
		  __entry->vm_id, __entry->va, __entry->size)
);

TRACE_EVENT(panthor_mmu_bind_done,
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
	TP_printk("vm_id=%llu va=0x%llx size=0x%llx result=%d",
		  __entry->vm_id, __entry->va, __entry->size, __entry->result)
);

TRACE_EVENT(panthor_group_list,
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
	TP_printk("group_id=%llu list_state=%u (%s)", __entry->group_id, __entry->list_state, __print_symbolic(__entry->list_state, PANTHOR_GROUP_LIST_STATES))
);

TRACE_EVENT(panthor_group_wait,
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
	TP_printk("group_id=%llu waiting=%d", __entry->group_id, __entry->waiting)
);

TRACE_EVENT(panthor_group_bind,
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
	TP_printk("group_id=%llu csg_id=%u", __entry->group_id, __entry->csg_id)
);

TRACE_EVENT(panthor_group_unbind,
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
	TP_printk("group_id=%llu csg_id=%u", __entry->group_id, __entry->csg_id)
);

TRACE_EVENT(panthor_sched_evict,
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
	TP_printk("csg_id=%u group_id=%llu sw_prio=%u", __entry->csg_id, __entry->group_id, __entry->sw_prio)
);

TRACE_EVENT(panthor_sched_keep,
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
	TP_printk("csg_id=%u group_id=%llu sw_prio=%u fw_prio=%u", __entry->csg_id, __entry->group_id, __entry->sw_prio, __entry->fw_prio)
);

TRACE_EVENT(panthor_sched_bind,
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
	TP_printk("csg_id=%u group_id=%llu sw_prio=%u fw_prio=%u", __entry->csg_id, __entry->group_id, __entry->sw_prio, __entry->fw_prio)
);

TRACE_EVENT(panthor_devfreq_target,
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
	TP_printk("prev_freq=%llu target_freq=%llu", __entry->prev_freq, __entry->target_freq)
);

TRACE_EVENT(panthor_work_run,
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

TRACE_EVENT(panthor_csg_slots_status,
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
	TP_printk("used=%u total=%u", __entry->used_slots, __entry->total_slots)
);

TRACE_EVENT(panthor_job_status,
	TP_PROTO(u64 job_id, u64 group_id, u32 cs_id, const char *status),
	TP_ARGS(job_id, group_id, cs_id, status),
	TP_STRUCT__entry(
		__field(u64, job_id)
		__field(u64, group_id)
		__field(u32, cs_id)
		__string(status, status)
	),
	TP_fast_assign(
		__entry->job_id = job_id;
		__entry->group_id = group_id;
		__entry->cs_id = cs_id;
		__assign_str(status);
	),
	TP_printk("job_id=%llu group_id=%llu cs_id=%u status=%s", __entry->job_id, __entry->group_id, __entry->cs_id, __get_str(status))
);

TRACE_EVENT(panthor_csg_irq,
	TP_PROTO(u32 csg_id, u64 group_id, u32 req, u32 ack, u32 irq_req, u32 irq_ack),
	TP_ARGS(csg_id, group_id, req, ack, irq_req, irq_ack),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u64, group_id)
		__field(u32, req)
		__field(u32, ack)
		__field(u32, irq_req)
		__field(u32, irq_ack)
		__field(u32, events)
		__field(u32, cs_irqs)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->group_id = group_id;
		__entry->req = req;
		__entry->ack = ack;
		__entry->irq_req = irq_req;
		__entry->irq_ack = irq_ack;
		__entry->events = (req ^ ack);
		__entry->cs_irqs = irq_req ^ irq_ack;
	),
	TP_printk("csg_id=%u group_id=%llu events=0x%08x (%s) cs_irqs=0x%08x (%s) req=0x%08x (%s) ack=0x%08x (%s) irq_req=0x%08x (%s) irq_ack=0x%08x (%s)",
		  __entry->csg_id, __entry->group_id,
		  __entry->events,
		  __print_flags(__entry->events, "|", PANTHOR_CSG_REQ_FLAGS),
		  __entry->cs_irqs,
		  __print_flags(__entry->cs_irqs, "|", PANTHOR_CS_IRQ_REQ_FLAGS),
		  __entry->req, __print_flags(__entry->req, "|", PANTHOR_CSG_REQ_FLAGS),
		  __entry->ack, __print_flags(__entry->ack, "|", PANTHOR_CSG_REQ_FLAGS),
		  __entry->irq_req, __print_flags(__entry->irq_req, "|", PANTHOR_CS_IRQ_REQ_FLAGS),
		  __entry->irq_ack, __print_flags(__entry->irq_ack, "|", PANTHOR_CS_IRQ_REQ_FLAGS))
);

TRACE_EVENT(panthor_cs_irq,
	TP_PROTO(u32 csg_id, u32 cs_id, u32 req, u32 ack),
	TP_ARGS(csg_id, cs_id, req, ack),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, cs_id)
		__field(u32, req)
		__field(u32, ack)
		__field(u32, events)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->cs_id = cs_id;
		__entry->req = req;
		__entry->ack = ack;
		__entry->events = (req ^ ack);
	),
	TP_printk("csg_id=%u cs_id=%u events=0x%08x (%s) req=0x%08x (%s) ack=0x%08x (%s)",
		  __entry->csg_id, __entry->cs_id,
		  __entry->events,
		  __print_flags(__entry->events, "|", PANTHOR_CS_REQ_FLAGS),
		  __entry->req, __print_flags(__entry->req, "|", PANTHOR_CS_REQ_FLAGS),
		  __entry->ack, __print_flags(__entry->ack, "|", PANTHOR_CS_REQ_FLAGS))
);

TRACE_EVENT(panthor_job_irq_clear,
	TP_PROTO(u32 status),
	TP_ARGS(status),
	TP_STRUCT__entry(
		__field(u32, status)
	),
	TP_fast_assign(
		__entry->status = status;
	),
	TP_printk("status=0x%08x (%s)", __entry->status, __print_flags(__entry->status, "|", PANTHOR_JOB_INT_FLAGS))
);

TRACE_EVENT(panthor_fw_cs_status_update,
	TP_PROTO(u32 csg_id, u32 cs_id, u64 group_id, u32 status_wait, u32 status_blocked_reason, u32 status_req_resource),
	TP_ARGS(csg_id, cs_id, group_id, status_wait, status_blocked_reason, status_req_resource),
	TP_STRUCT__entry(
		__field(u32, csg_id)
		__field(u32, cs_id)
		__field(u64, group_id)
		__field(u32, status_wait)
		__field(u32, status_blocked_reason)
		__field(u32, status_req_resource)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
		__entry->cs_id = cs_id;
		__entry->group_id = group_id;
		__entry->status_wait = status_wait;
		__entry->status_blocked_reason = status_blocked_reason;
		__entry->status_req_resource = status_req_resource;
	),
	TP_printk("csg_id=%u cs_id=%u group_id=%llu status_wait=0x%08x status_blocked_reason=0x%08x (%s) status_req_resource=0x%08x (%s)",
		  __entry->csg_id, __entry->cs_id, __entry->group_id, __entry->status_wait,
		  __entry->status_blocked_reason,
		  __print_symbolic(__entry->status_blocked_reason, PANTHOR_CS_STATUS_BLOCKED_REASON_VALUES),
		  __entry->status_req_resource, __print_flags(__entry->status_req_resource, "|", PANTHOR_CS_STATUS_REQ_RESOURCE_FLAGS))
);

TRACE_EVENT(panthor_csg_slot_idle,
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
	TP_printk("csg_id=%u group_id=%llu idle=%d", __entry->csg_id, __entry->group_id, __entry->idle)
);

TRACE_EVENT(panthor_csg_slot_progress_timeout,
	TP_PROTO(u32 csg_id),
	TP_ARGS(csg_id),
	TP_STRUCT__entry(
		__field(u32, csg_id)
	),
	TP_fast_assign(
		__entry->csg_id = csg_id;
	),
	TP_printk("csg_id=%u", __entry->csg_id)
);

TRACE_EVENT(panthor_queue_idle_state,
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
	TP_printk("group_id=%llu cs_id=%u idle=%d", __entry->group_id, __entry->cs_id, __entry->idle)
);

TRACE_EVENT(panthor_queue_fatal_state,
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
	TP_printk("group_id=%llu cs_id=%u fatal=%d", __entry->group_id, __entry->cs_id, __entry->fatal)
);

TRACE_EVENT(panthor_group_timedout,
	TP_PROTO(u64 group_id),
	TP_ARGS(group_id),
	TP_STRUCT__entry(
		__field(u64, group_id)
	),
	TP_fast_assign(
		__entry->group_id = group_id;
	),
	TP_printk("group_id=%llu", __entry->group_id)
);

#endif /* _PANTHOR_TRACE_H */
#include <trace/define_trace.h>
