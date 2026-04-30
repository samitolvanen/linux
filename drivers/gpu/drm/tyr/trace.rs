//! Tracepoints for Tyr.

use core::ffi::c_char; //
use core::ffi::c_int; //
use kernel::str::CStr;

extern "C" {
    fn rust_do_trace_panthor_fw_glb_req(
        reg_name: *const c_char,
        req_val: u32,
        update_mask: u32,
        toggle_mask: u32,
    );
    fn rust_do_trace_panthor_fw_glb_doorbell_req(
        reg_name: *const c_char,
        req_val: u32,
        update_mask: u32,
        toggle_mask: u32,
    );
    fn rust_do_trace_panthor_glb_irq(req: u32, ack: u32);
    fn rust_do_trace_panthor_fw_csg_req(
        csg_id: u32,
        group_id: u64,
        reg_name: *const c_char,
        req_val: u32,
        update_mask: u32,
        toggle_mask: u32,
    );
    fn rust_do_trace_panthor_fw_csg_doorbell_req(
        csg_id: u32,
        reg_name: *const c_char,
        req_val: u32,
        update_mask: u32,
        toggle_mask: u32,
    );

    fn rust_do_trace_panthor_fw_csg_status_update(
        csg_id: u32,
        group_id: u64,
        status_endpoint_current: u32,
        status_endpoint_req: u32,
        status_state: u32,
        resource_dep: u32,
    );
    fn rust_do_trace_panthor_fw_cs_status_update(
        csg_id: u32,
        cs_id: u32,
        group_id: u64,
        status_wait: u32,
        status_blocked_reason: u32,
        status_req_resource: u32,
    );
    fn rust_do_trace_panthor_csg_slot_idle(csg_id: u32, group_id: u64, idle: bool);
    fn rust_do_trace_panthor_csg_slot_progress_timeout(csg_id: u32);
    fn rust_do_trace_panthor_queue_idle_state(group_id: u64, cs_id: u32, idle: bool);
    fn rust_do_trace_panthor_queue_fatal_state(group_id: u64, cs_id: u32, fatal: bool);
    fn rust_do_trace_panthor_group_timedout(group_id: u64);
    fn rust_do_trace_panthor_fw_cs_req(
        csg_id: u32,
        cs_id: u32,
        group_id: u64,
        reg_name: *const c_char,
        req_val: u32,
        update_mask: u32,
        toggle_mask: u32,
    );
    fn rust_do_trace_panthor_fw_irq(status: u32);
    fn rust_do_trace_panthor_group_update(group_id: u64, state: u32);
    fn rust_do_trace_panthor_queue_state(group_id: u64, cs_id: u32, blocked: bool);
    fn rust_do_trace_panthor_queue_timeout_state(group_id: u64, cs_id: u32, suspended: bool);
    fn rust_do_trace_panthor_queue_doorbell(group_id: u64, cs_id: u32, doorbell_id: u32);
    fn rust_do_trace_panthor_cs_ring_ptrs(group_id: u64, cs_id: u32, insert: u64, extract: u64);
    fn rust_do_trace_panthor_job_submit(job_id: u64, group_id: u64, cs_id: u32, stream_size: u32);
    fn rust_do_trace_panthor_job_done(job_id: u64, group_id: u64, cs_id: u32, result: c_int);
    fn rust_do_trace_panthor_mmu_bind_start(vm_id: u64, va: u64, size: u64);
    fn rust_do_trace_panthor_mmu_bind_done(vm_id: u64, va: u64, size: u64, result: c_int);
    fn rust_do_trace_panthor_group_list(group_id: u64, list_state: u32);
    fn rust_do_trace_panthor_group_wait(group_id: u64, waiting: bool);
    fn rust_do_trace_panthor_group_bind(group_id: u64, csg_id: u32);
    fn rust_do_trace_panthor_group_unbind(group_id: u64, csg_id: u32);
    fn rust_do_trace_panthor_sched_evict(csg_id: u32, group_id: u64, sw_prio: u8);
    fn rust_do_trace_panthor_sched_keep(csg_id: u32, group_id: u64, sw_prio: u8, fw_prio: u32);
    fn rust_do_trace_panthor_sched_bind(csg_id: u32, group_id: u64, sw_prio: u8, fw_prio: u32);
    fn rust_do_trace_panthor_work_run(work_name: *const c_char);
    fn rust_do_trace_panthor_devfreq_target(prev_freq: u64, target_freq: u64);
    fn rust_do_trace_panthor_csg_slots_status(used_slots: u32, total_slots: u32);
    fn rust_do_trace_panthor_job_status(
        job_id: u64,
        group_id: u64,
        cs_id: u32,
        status: *const c_char,
    );
    fn rust_do_trace_panthor_csg_irq(
        csg_id: u32,
        group_id: u64,
        req: u32,
        ack: u32,
        irq_req: u32,
        irq_ack: u32,
    );
    fn rust_do_trace_panthor_cs_irq(csg_id: u32, cs_id: u32, req: u32, ack: u32);
    fn rust_do_trace_panthor_job_irq_clear(status: u32);
}

pub(crate) fn csg_irq(csg_id: u32, group_id: u64, req: u32, ack: u32, irq_req: u32, irq_ack: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_csg_irq(csg_id, group_id, req, ack, irq_req, irq_ack) };
}

pub(crate) fn cs_irq(csg_id: u32, cs_id: u32, req: u32, ack: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_cs_irq(csg_id, cs_id, req, ack) };
}

pub(crate) fn job_irq_clear(status: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_job_irq_clear(status) };
}

pub(crate) fn fw_glb_req(reg_name: &CStr, req_val: u32, update_mask: u32, toggle_mask: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe {
        rust_do_trace_panthor_fw_glb_req(reg_name.as_ptr(), req_val, update_mask, toggle_mask)
    };
}

pub(crate) fn fw_glb_doorbell_req(
    reg_name: &CStr,
    req_val: u32,
    update_mask: u32,
    toggle_mask: u32,
) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe {
        rust_do_trace_panthor_fw_glb_doorbell_req(
            reg_name.as_ptr(),
            req_val,
            update_mask,
            toggle_mask,
        )
    };
}

pub(crate) fn glb_irq(req: u32, ack: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_glb_irq(req, ack) };
}

pub(crate) fn fw_csg_req(
    csg_id: u32,
    group_id: u64,
    reg_name: &CStr,
    req_val: u32,
    update_mask: u32,
    toggle_mask: u32,
) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe {
        rust_do_trace_panthor_fw_csg_req(
            csg_id,
            group_id,
            reg_name.as_ptr(),
            req_val,
            update_mask,
            toggle_mask,
        )
    };
}

pub(crate) fn fw_csg_doorbell_req(
    csg_id: u32,
    reg_name: &CStr,
    req_val: u32,
    update_mask: u32,
    toggle_mask: u32,
) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe {
        rust_do_trace_panthor_fw_csg_doorbell_req(
            csg_id,
            reg_name.as_ptr(),
            req_val,
            update_mask,
            toggle_mask,
        )
    };
}

pub(crate) fn fw_csg_status_update(
    csg_id: u32,
    group_id: u64,
    status_endpoint_current: u32,
    status_endpoint_req: u32,
    status_state: u32,
    resource_dep: u32,
) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe {
        rust_do_trace_panthor_fw_csg_status_update(
            csg_id,
            group_id,
            status_endpoint_current,
            status_endpoint_req,
            status_state,
            resource_dep,
        )
    };
}

pub(crate) fn fw_cs_req(
    csg_id: u32,
    cs_id: u32,
    group_id: u64,
    reg_name: &CStr,
    req_val: u32,
    update_mask: u32,
    toggle_mask: u32,
) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe {
        rust_do_trace_panthor_fw_cs_req(
            csg_id,
            cs_id,
            group_id,
            reg_name.as_ptr(),
            req_val,
            update_mask,
            toggle_mask,
        )
    };
}
#[inline]
pub(crate) fn fw_cs_status_update(
    csg_id: u32,
    cs_id: u32,
    group_id: u64,
    status_wait: u32,
    status_blocked_reason: u32,
    status_req_resource: u32,
) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe {
        rust_do_trace_panthor_fw_cs_status_update(
            csg_id,
            cs_id,
            group_id,
            status_wait,
            status_blocked_reason,
            status_req_resource,
        )
    };
}

pub(crate) fn csg_slot_idle(csg_id: u32, group_id: u64, idle: bool) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_csg_slot_idle(csg_id, group_id, idle) };
}

pub(crate) fn csg_slot_progress_timeout(csg_id: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_csg_slot_progress_timeout(csg_id) };
}

pub(crate) fn queue_idle_state(group_id: u64, cs_id: u32, idle: bool) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_queue_idle_state(group_id, cs_id, idle) };
}

pub(crate) fn queue_fatal_state(group_id: u64, cs_id: u32, fatal: bool) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_queue_fatal_state(group_id, cs_id, fatal) };
}

pub(crate) fn group_timedout(group_id: u64) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_group_timedout(group_id) };
}

pub(crate) fn fw_irq(status: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_fw_irq(status) };
}

pub(crate) fn group_update(group_id: u64, state: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_group_update(group_id, state) };
}

pub(crate) fn queue_state(group_id: u64, cs_id: u32, blocked: bool) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_queue_state(group_id, cs_id, blocked) };
}

pub(crate) fn queue_timeout_state(group_id: u64, cs_id: u32, suspended: bool) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_queue_timeout_state(group_id, cs_id, suspended) };
}

pub(crate) fn queue_doorbell(group_id: u64, cs_id: u32, doorbell_id: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_queue_doorbell(group_id, cs_id, doorbell_id) };
}

pub(crate) fn cs_ring_ptrs(group_id: u64, cs_id: u32, insert: u64, extract: u64) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_cs_ring_ptrs(group_id, cs_id, insert, extract) };
}

pub(crate) fn job_submit(job_id: u64, group_id: u64, cs_id: u32, stream_size: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_job_submit(job_id, group_id, cs_id, stream_size) };
}

pub(crate) fn job_done(job_id: u64, group_id: u64, cs_id: u32, result: i32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_job_done(job_id, group_id, cs_id, result) };
}

pub(crate) fn mmu_bind_start(vm_id: u64, va: u64, size: u64) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_mmu_bind_start(vm_id, va, size) };
}

pub(crate) fn mmu_bind_done(vm_id: u64, va: u64, size: u64, result: i32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_mmu_bind_done(vm_id, va, size, result) };
}

pub(crate) fn group_list(group_id: u64, list_state: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_group_list(group_id, list_state) };
}

pub(crate) fn group_wait(group_id: u64, waiting: bool) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_group_wait(group_id, waiting) };
}

pub(crate) fn group_bind(group_id: u64, csg_id: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_group_bind(group_id, csg_id) };
}

pub(crate) fn group_unbind(group_id: u64, csg_id: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_group_unbind(group_id, csg_id) };
}

pub(crate) fn sched_evict(csg_id: u32, group_id: u64, sw_prio: u8) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_sched_evict(csg_id, group_id, sw_prio) };
}

pub(crate) fn sched_keep(csg_id: u32, group_id: u64, sw_prio: u8, fw_prio: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_sched_keep(csg_id, group_id, sw_prio, fw_prio) };
}

pub(crate) fn sched_bind(csg_id: u32, group_id: u64, sw_prio: u8, fw_prio: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_sched_bind(csg_id, group_id, sw_prio, fw_prio) };
}

pub(crate) fn work_run(work_name: &CStr) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_work_run(work_name.as_ptr()) };
}

pub(crate) fn devfreq_target(prev_freq: u64, target_freq: u64) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_devfreq_target(prev_freq, target_freq) };
}

pub(crate) fn csg_slots_status(used_slots: u32, total_slots: u32) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_csg_slots_status(used_slots, total_slots) };
}

pub(crate) fn job_status(job_id: u64, group_id: u64, cs_id: u32, status: &CStr) {
    // SAFETY: Tracepoints are safe to call from any context.
    unsafe { rust_do_trace_panthor_job_status(job_id, group_id, cs_id, status.as_ptr()) };
}
