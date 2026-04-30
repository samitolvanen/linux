#ifndef _PANTHOR_TRACE_WRAPPERS_H_
#define _PANTHOR_TRACE_WRAPPERS_H_

#include <linux/types.h>

void rust_do_trace_panthor_fw_glb_req(const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask);
void rust_do_trace_panthor_fw_glb_doorbell_req(const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask);
void rust_do_trace_panthor_glb_irq(u32 req, u32 ack);
void rust_do_trace_panthor_fw_csg_req(u32 csg_id, u64 group_id, const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask);
void rust_do_trace_panthor_fw_csg_doorbell_req(u32 csg_id, const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask);
void rust_do_trace_panthor_fw_csg_ack(u32 csg_id, u64 group_id, u32 ack_mask);
void rust_do_trace_panthor_fw_csg_status_update(u32 csg_id, u64 group_id, u32 status_endpoint_current, u32 status_endpoint_req, u32 status_state, u32 resource_dep);
void rust_do_trace_panthor_fw_cs_req(u32 csg_id, u32 cs_id, u64 group_id, const char *reg_name, u32 req_val, u32 update_mask, u32 toggle_mask);
void rust_do_trace_panthor_fw_irq(u32 status);
void rust_do_trace_panthor_group_update(u64 group_id, u32 state);
void rust_do_trace_panthor_queue_state(u64 group_id, u32 cs_id, bool blocked);
void rust_do_trace_panthor_queue_timeout_state(u64 group_id, u32 cs_id, bool suspended);
void rust_do_trace_panthor_queue_doorbell(u64 group_id, u32 cs_id, u32 doorbell_id);
void rust_do_trace_panthor_cs_ring_ptrs(u64 group_id, u32 cs_id, u64 insert, u64 extract);
void rust_do_trace_panthor_job_submit(u64 job_id, u64 group_id, u32 cs_id, u32 stream_size);
void rust_do_trace_panthor_job_done(u64 job_id, u64 group_id, u32 cs_id, int result);
void rust_do_trace_panthor_mmu_bind_start(u64 vm_id, u64 va, u64 size);
void rust_do_trace_panthor_mmu_bind_done(u64 vm_id, u64 va, u64 size, int result);
void rust_do_trace_panthor_group_list(u64 group_id, u32 list_state);
void rust_do_trace_panthor_group_wait(u64 group_id, bool waiting);
void rust_do_trace_panthor_group_bind(u64 group_id, u32 csg_id);
void rust_do_trace_panthor_group_unbind(u64 group_id, u32 csg_id);
void rust_do_trace_panthor_sched_evict(u32 csg_id, u64 group_id, u8 sw_prio);
void rust_do_trace_panthor_sched_keep(u32 csg_id, u64 group_id, u8 sw_prio, u32 fw_prio);
void rust_do_trace_panthor_sched_bind(u32 csg_id, u64 group_id, u8 sw_prio, u32 fw_prio);
void rust_do_trace_panthor_devfreq_target(u64 prev_freq, u64 target_freq);
void rust_do_trace_panthor_work_run(const char *work_name);
void rust_do_trace_panthor_csg_slots_status(u32 used_slots, u32 total_slots);
void rust_do_trace_panthor_job_status(u64 job_id, u64 group_id, u32 cs_id, const char *status);
void rust_do_trace_panthor_csg_irq(u32 csg_id, u64 group_id, u32 req, u32 ack, u32 irq_req, u32 irq_ack);
void rust_do_trace_panthor_cs_irq(u32 csg_id, u32 cs_id, u32 req, u32 ack);

void rust_do_trace_panthor_fw_cs_status_update(u32 csg_id, u32 cs_id, u64 group_id, u32 status_wait, u32 status_blocked_reason, u32 status_req_resource);
void rust_do_trace_panthor_csg_slot_idle(u32 csg_id, u64 group_id, bool idle);
void rust_do_trace_panthor_csg_slot_progress_timeout(u32 csg_id);
void rust_do_trace_panthor_job_irq_clear(u32 status);

void rust_do_trace_panthor_queue_idle_state(u64 group_id, u32 cs_id, bool idle);
void rust_do_trace_panthor_queue_fatal_state(u64 group_id, u32 cs_id, bool fatal);
void rust_do_trace_panthor_group_timedout(u64 group_id);

#endif /* _PANTHOR_TRACE_WRAPPERS_H_ */
