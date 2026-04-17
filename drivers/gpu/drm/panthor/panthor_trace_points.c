#include <linux/module.h>
#include <linux/types.h>
#include <linux/export.h>
#include "panthor_trace.h"

#define CREATE_TRACE_POINTS
#include <trace/events/panthor.h>

void rust_do_trace_panthor_fw_glb_req(const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask)
{
	trace_panthor_fw_glb_req(reg_name, req_val, update_mask, toggle_mask);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_fw_glb_req);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_fw_glb_req);

void rust_do_trace_panthor_fw_glb_doorbell_req(const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask)
{
	trace_panthor_fw_glb_doorbell_req(reg_name, req_val, update_mask, toggle_mask);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_fw_glb_doorbell_req);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_fw_glb_doorbell_req);

void rust_do_trace_panthor_glb_irq(u32 req, u32 ack)
{
	trace_panthor_glb_irq(req, ack);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_glb_irq);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_glb_irq);

void rust_do_trace_panthor_fw_csg_req(u32 csg_id, u64 group_id, const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask)
{
	trace_panthor_fw_csg_req(csg_id, group_id, reg_name, req_val, update_mask, toggle_mask);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_fw_csg_req);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_fw_csg_req);

void rust_do_trace_panthor_fw_csg_doorbell_req(u32 csg_id, const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask)
{
	trace_panthor_fw_csg_doorbell_req(csg_id, reg_name, req_val, update_mask, toggle_mask);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_fw_csg_doorbell_req);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_fw_csg_doorbell_req);

void rust_do_trace_panthor_fw_csg_ack(u32 csg_id, u64 group_id, u32 ack_mask)
{
	trace_panthor_fw_csg_ack(csg_id, group_id, ack_mask);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_fw_csg_ack);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_fw_csg_ack);

void rust_do_trace_panthor_fw_csg_status_update(u32 csg_id, u64 group_id, u32 status_endpoint_current, u32 status_endpoint_req, u32 status_state, u32 resource_dep)
{
	trace_panthor_fw_csg_status_update(csg_id, group_id, status_endpoint_current, status_endpoint_req, status_state, resource_dep);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_fw_csg_status_update);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_fw_csg_status_update);

void rust_do_trace_panthor_fw_cs_req(u32 csg_id, u32 cs_id, u64 group_id, const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask)
{
	trace_panthor_fw_cs_req(csg_id, cs_id, group_id, reg_name, req_val, update_mask, toggle_mask);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_fw_cs_req);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_fw_cs_req);

void rust_do_trace_panthor_fw_irq(u32 status)
{
	trace_panthor_fw_irq(status);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_fw_irq);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_fw_irq);

void rust_do_trace_panthor_group_update(u64 group_id, u32 state)
{
	trace_panthor_group_update(group_id, state);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_group_update);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_group_update);

void rust_do_trace_panthor_queue_state(u64 group_id, u32 cs_id, bool blocked)
{
	trace_panthor_queue_state(group_id, cs_id, blocked);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_queue_state);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_queue_state);

void rust_do_trace_panthor_queue_timeout_state(u64 group_id, u32 cs_id, bool suspended)
{
	trace_panthor_queue_timeout_state(group_id, cs_id, suspended);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_queue_timeout_state);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_queue_timeout_state);

void rust_do_trace_panthor_queue_doorbell(u64 group_id, u32 cs_id, u32 doorbell_id)
{
	trace_panthor_queue_doorbell(group_id, cs_id, doorbell_id);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_queue_doorbell);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_queue_doorbell);

void rust_do_trace_panthor_cs_ring_ptrs(u64 group_id, u32 cs_id, u64 insert, u64 extract)
{
	trace_panthor_cs_ring_ptrs(group_id, cs_id, insert, extract);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_cs_ring_ptrs);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_cs_ring_ptrs);

void rust_do_trace_panthor_job_submit(u64 job_id, u64 group_id, u32 cs_id, u32 stream_size)
{
	trace_panthor_job_submit(job_id, group_id, cs_id, stream_size);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_job_submit);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_job_submit);

void rust_do_trace_panthor_job_done(u64 job_id, u64 group_id, u32 cs_id, int result)
{
	trace_panthor_job_done(job_id, group_id, cs_id, result);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_job_done);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_job_done);

void rust_do_trace_panthor_mmu_bind_start(u64 vm_id, u64 va, u64 size)
{
	trace_panthor_mmu_bind_start(vm_id, va, size);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_mmu_bind_start);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_mmu_bind_start);

void rust_do_trace_panthor_mmu_bind_done(u64 vm_id, u64 va, u64 size, int result)
{
	trace_panthor_mmu_bind_done(vm_id, va, size, result);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_mmu_bind_done);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_mmu_bind_done);

void rust_do_trace_panthor_group_list(u64 group_id, u32 list_state)
{
	trace_panthor_group_list(group_id, list_state);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_group_list);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_group_list);

void rust_do_trace_panthor_group_wait(u64 group_id, bool waiting)
{
	trace_panthor_group_wait(group_id, waiting);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_group_wait);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_group_wait);

void rust_do_trace_panthor_group_bind(u64 group_id, u32 csg_id)
{
	trace_panthor_group_bind(group_id, csg_id);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_group_bind);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_group_bind);

void rust_do_trace_panthor_group_unbind(u64 group_id, u32 csg_id)
{
	trace_panthor_group_unbind(group_id, csg_id);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_group_unbind);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_group_unbind);

void rust_do_trace_panthor_sched_evict(u32 csg_id, u64 group_id, u8 sw_prio)
{
	trace_panthor_sched_evict(csg_id, group_id, sw_prio);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_sched_evict);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_sched_evict);

void rust_do_trace_panthor_sched_keep(u32 csg_id, u64 group_id, u8 sw_prio, u32 fw_prio)
{
	trace_panthor_sched_keep(csg_id, group_id, sw_prio, fw_prio);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_sched_keep);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_sched_keep);

void rust_do_trace_panthor_sched_bind(u32 csg_id, u64 group_id, u8 sw_prio, u32 fw_prio)
{
	trace_panthor_sched_bind(csg_id, group_id, sw_prio, fw_prio);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_sched_bind);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_sched_bind);

void rust_do_trace_panthor_devfreq_target(u64 prev_freq, u64 target_freq)
{
	trace_panthor_devfreq_target(prev_freq, target_freq);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_devfreq_target);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_devfreq_target);

void rust_do_trace_panthor_work_run(const char *work_name)
{
	trace_panthor_work_run(work_name);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_work_run);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_work_run);

void rust_do_trace_panthor_csg_slots_status(u32 used_slots, u32 total_slots)
{
	trace_panthor_csg_slots_status(used_slots, total_slots);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_csg_slots_status);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_csg_slots_status);

void rust_do_trace_panthor_job_status(u64 job_id, u64 group_id, u32 cs_id, const char *status)
{
	trace_panthor_job_status(job_id, group_id, cs_id, status);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_job_status);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_job_status);

void rust_do_trace_panthor_csg_irq(u32 csg_id, u64 group_id, u32 req, u32 ack, u32 irq_req, u32 irq_ack)
{
	trace_panthor_csg_irq(csg_id, group_id, req, ack, irq_req, irq_ack);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_csg_irq);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_csg_irq);

void rust_do_trace_panthor_cs_irq(u32 csg_id, u32 cs_id, u32 req, u32 ack)
{
	trace_panthor_cs_irq(csg_id, cs_id, req, ack);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_cs_irq);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_cs_irq);

void rust_do_trace_panthor_fw_cs_status_update(u32 csg_id, u32 cs_id, u64 group_id, u32 status_wait, u32 status_blocked_reason, u32 status_req_resource)
{
	trace_panthor_fw_cs_status_update(csg_id, cs_id, group_id, status_wait, status_blocked_reason, status_req_resource);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_fw_cs_status_update);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_fw_cs_status_update);

void rust_do_trace_panthor_csg_slot_idle(u32 csg_id, u64 group_id, bool idle)
{
	trace_panthor_csg_slot_idle(csg_id, group_id, idle);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_csg_slot_idle);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_csg_slot_idle);

void rust_do_trace_panthor_csg_slot_progress_timeout(u32 csg_id)
{
	trace_panthor_csg_slot_progress_timeout(csg_id);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_csg_slot_progress_timeout);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_csg_slot_progress_timeout);

void rust_do_trace_panthor_job_irq_clear(u32 status)
{
	trace_panthor_job_irq_clear(status);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_job_irq_clear);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_job_irq_clear);

void rust_do_trace_panthor_queue_idle_state(u64 group_id, u32 cs_id, bool idle)
{
	trace_panthor_queue_idle_state(group_id, cs_id, idle);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_queue_idle_state);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_queue_idle_state);

void rust_do_trace_panthor_queue_fatal_state(u64 group_id, u32 cs_id, bool fatal)
{
	trace_panthor_queue_fatal_state(group_id, cs_id, fatal);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_queue_fatal_state);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_queue_fatal_state);

void rust_do_trace_panthor_group_timedout(u64 group_id)
{
	trace_panthor_group_timedout(group_id);
}
EXPORT_SYMBOL_GPL(rust_do_trace_panthor_group_timedout);
EXPORT_TRACEPOINT_SYMBOL_GPL(panthor_group_timedout);

MODULE_LICENSE("GPL and additional rights");
MODULE_DESCRIPTION("Panthor Tracepoints");
