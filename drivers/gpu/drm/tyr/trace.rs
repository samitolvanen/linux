// SPDX-License-Identifier: GPL-2.0 or MIT

//! Tyr tracepoints.
//!
//! Safe Rust wrappers around the C tracepoint thunks declared in
//! `include/trace/events/tyr.h`. The unsafe `tyr_*` block is private to
//! this module; the rest of the driver calls the `pub(crate) fn`
//! wrappers below.

use kernel::ffi::{
    c_char,
    c_int, //
};
use kernel::str::{
    CStr,
    CStrExt, //
};

kernel::declare_trace! {
    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_glb_req(req_val: u32, toggle_mask: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_glb_doorbell_req(req_val: u32, toggle_mask: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_glb_irq(req: u32, ack: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_csg_req(
        csg_id: u32,
        group_id: u64,
        req_val: u32,
        update_mask: u32,
        toggle_mask: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_csg_doorbell_req(
        csg_id: u32,
        req_val: u32,
        update_mask: u32,
        toggle_mask: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_csg_status_update(csg_id: u32, group_id: u64, status_state: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_cs_req(
        csg_id: u32,
        cs_id: u32,
        group_id: u64,
        req_val: u32,
        update_mask: u32,
        toggle_mask: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_cs_status_update(
        csg_id: u32,
        cs_id: u32,
        group_id: u64,
        status_blocked_reason: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_irq(status: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_csg_irq(
        csg_id: u32,
        group_id: u64,
        req: u32,
        ack: u32,
        irq_req: u32,
        irq_ack: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_cs_irq(csg_id: u32, cs_id: u32, req: u32, ack: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_job_irq_clear(status: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_update(group_id: u64, state: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_list(group_id: u64, list_state: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_wait(group_id: u64, waiting: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_bind(group_id: u64, csg_id: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_unbind(group_id: u64, csg_id: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_timedout(group_id: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_sched_evict(csg_id: u32, group_id: u64, sw_prio: u8);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_sched_keep(csg_id: u32, group_id: u64, sw_prio: u8, fw_prio: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_sched_bind(csg_id: u32, group_id: u64, sw_prio: u8, fw_prio: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_queue_state(group_id: u64, cs_id: u32, blocked: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_queue_idle_state(group_id: u64, cs_id: u32, idle: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_queue_fatal_state(group_id: u64, cs_id: u32, fatal: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_queue_timeout_state(group_id: u64, cs_id: u32, suspended: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_queue_doorbell(group_id: u64, cs_id: u32, doorbell_id: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_csg_slot_idle(csg_id: u32, group_id: u64, idle: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_csg_slot_progress_timeout(csg_id: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_csg_slots_status(used_slots: u32, total_slots: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_cs_ring_ptrs(group_id: u64, cs_id: u32, insert: u64, extract: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_job_submit(
        completion_point: u64,
        group_id: u64,
        cs_id: u32,
        user_stream_size: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_submit_fence_signal(
        group_id: u64,
        cs_id: u32,
        completion_point: u64,
        result: c_int,
    );

    /// # Safety
    ///
    /// `status` must be a valid, nul-terminated C string pointer.
    unsafe fn tyr_job_status(seqno: u64, group_id: u64, cs_id: u32, status: *const c_char);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_mmu_bind_start(vm_id: u64, va: u64, size: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_mmu_bind_done(vm_id: u64, va: u64, size: u64, result: c_int);

    /// # Safety
    ///
    /// `work_name` must be a valid, nul-terminated C string pointer.
    unsafe fn tyr_work_run(work_name: *const c_char);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_devfreq_target(prev_freq: u64, target_freq: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_sync_upd_drain(
        group_id: u64,
        cs_id: u32,
        completion_point: u64,
        drained_count: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_deadline_check(
        group_id: u64,
        cs_id: u32,
        elapsed_ms: u32,
        allowance_ms: u32,
        faulted: bool,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_tick_decision_summary(
        evict_count: u32,
        bind_count: u32,
        keep_count: u32,
        runnable_remaining: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_devfreq_mark(busy: bool, prev_busy_ns: u64, prev_idle_ns: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_devfreq_status(busy_time_ns: u64, total_time_ns: u64, current_freq: u64);
}

/// Global firmware request register write.
pub(crate) fn fw_glb_req(req_val: u32, toggle_mask: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_glb_req(req_val, toggle_mask) }
}

/// Global doorbell request register write.
pub(crate) fn fw_glb_doorbell_req(req_val: u32, toggle_mask: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_glb_doorbell_req(req_val, toggle_mask) }
}

/// Global firmware IRQ acknowledgement.
pub(crate) fn glb_irq(req: u32, ack: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_glb_irq(req, ack) }
}

/// Per-CSG firmware request register write.
pub(crate) fn fw_csg_req(
    csg_id: u32,
    group_id: u64,
    req_val: u32,
    update_mask: u32,
    toggle_mask: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_csg_req(csg_id, group_id, req_val, update_mask, toggle_mask) }
}

/// Per-CSG doorbell request register write.
pub(crate) fn fw_csg_doorbell_req(csg_id: u32, req_val: u32, update_mask: u32, toggle_mask: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_csg_doorbell_req(csg_id, req_val, update_mask, toggle_mask) }
}

/// CSG status registers captured after a CSG_REQ.status_update ack.
pub(crate) fn fw_csg_status_update(csg_id: u32, group_id: u64, status_state: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_csg_status_update(csg_id, group_id, status_state) }
}

/// Per-CS firmware request register write.
pub(crate) fn fw_cs_req(
    csg_id: u32,
    cs_id: u32,
    group_id: u64,
    req_val: u32,
    update_mask: u32,
    toggle_mask: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_cs_req(csg_id, cs_id, group_id, req_val, update_mask, toggle_mask) }
}

/// Per-CS status registers captured after a CSG_REQ.status_update ack.
pub(crate) fn fw_cs_status_update(
    csg_id: u32,
    cs_id: u32,
    group_id: u64,
    status_blocked_reason: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_cs_status_update(csg_id, cs_id, group_id, status_blocked_reason) }
}

/// Job-IRQ entry status.
pub(crate) fn fw_irq(status: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_irq(status) }
}

/// CSG-level IRQ delivery.
pub(crate) fn csg_irq(csg_id: u32, group_id: u64, req: u32, ack: u32, irq_req: u32, irq_ack: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_csg_irq(csg_id, group_id, req, ack, irq_req, irq_ack) }
}

/// Per-CS IRQ delivery.
pub(crate) fn cs_irq(csg_id: u32, cs_id: u32, req: u32, ack: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_cs_irq(csg_id, cs_id, req, ack) }
}

/// Write to the job-IRQ clear register.
pub(crate) fn job_irq_clear(status: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_job_irq_clear(status) }
}

/// Group lifecycle state transition.
pub(crate) fn group_update(group_id: u64, state: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_update(group_id, state) }
}

/// Group scheduler-list membership transition.
pub(crate) fn group_list(group_id: u64, list_state: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_list(group_id, list_state) }
}

/// Group added to / removed from the wait list.
pub(crate) fn group_wait(group_id: u64, waiting: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_wait(group_id, waiting) }
}

/// Group bound to a CSG slot.
pub(crate) fn group_bind(group_id: u64, csg_id: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_bind(group_id, csg_id) }
}

/// Group unbound from a CSG slot.
pub(crate) fn group_unbind(group_id: u64, csg_id: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_unbind(group_id, csg_id) }
}

/// A queue in the group exceeded its per-job deadline.
pub(crate) fn group_timedout(group_id: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_timedout(group_id) }
}

/// Rule engine evicted a CSG slot.
pub(crate) fn sched_evict(csg_id: u32, group_id: u64, sw_prio: u8) {
    // SAFETY: Always safe to call.
    unsafe { tyr_sched_evict(csg_id, group_id, sw_prio) }
}

/// Rule engine kept a CSG slot.
pub(crate) fn sched_keep(csg_id: u32, group_id: u64, sw_prio: u8, fw_prio: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_sched_keep(csg_id, group_id, sw_prio, fw_prio) }
}

/// Rule engine bound a new group to a CSG slot.
pub(crate) fn sched_bind(csg_id: u32, group_id: u64, sw_prio: u8, fw_prio: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_sched_bind(csg_id, group_id, sw_prio, fw_prio) }
}

/// Queue blocked/unblocked state transition.
pub(crate) fn queue_state(group_id: u64, cs_id: u32, blocked: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_queue_state(group_id, cs_id, blocked) }
}

/// Queue idle bit transition.
pub(crate) fn queue_idle_state(group_id: u64, cs_id: u32, idle: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_queue_idle_state(group_id, cs_id, idle) }
}

/// Queue fatal bit raised or cleared.
pub(crate) fn queue_fatal_state(group_id: u64, cs_id: u32, fatal: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_queue_fatal_state(group_id, cs_id, fatal) }
}

/// Queue suspend-timeout accounting transition.
pub(crate) fn queue_timeout_state(group_id: u64, cs_id: u32, suspended: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_queue_timeout_state(group_id, cs_id, suspended) }
}

/// Queue doorbell rung.
pub(crate) fn queue_doorbell(group_id: u64, cs_id: u32, doorbell_id: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_queue_doorbell(group_id, cs_id, doorbell_id) }
}

/// CSG slot idle-bit transition.
pub(crate) fn csg_slot_idle(csg_id: u32, group_id: u64, idle: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_csg_slot_idle(csg_id, group_id, idle) }
}

/// CSG slot firmware progress-timer expired.
pub(crate) fn csg_slot_progress_timeout(csg_id: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_csg_slot_progress_timeout(csg_id) }
}

/// CSG slot usage summary at the end of a tick.
pub(crate) fn csg_slots_status(used_slots: u32, total_slots: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_csg_slots_status(used_slots, total_slots) }
}

/// Ring-buffer INSERT/EXTRACT pointer snapshot.
pub(crate) fn cs_ring_ptrs(group_id: u64, cs_id: u32, insert: u64, extract: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_cs_ring_ptrs(group_id, cs_id, insert, extract) }
}

/// One Job committed to a queue ringbuffer.
pub(crate) fn job_submit(completion_point: u64, group_id: u64, cs_id: u32, user_stream_size: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_job_submit(completion_point, group_id, cs_id, user_stream_size) }
}

/// Submit fence signalled (success or error).
pub(crate) fn submit_fence_signal(group_id: u64, cs_id: u32, completion_point: u64, result: i32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_submit_fence_signal(group_id, cs_id, completion_point, result) }
}

/// Job lifecycle milestone (e.g. "prepared", "ringbuf_committed").
pub(crate) fn job_status(seqno: u64, group_id: u64, cs_id: u32, status: &CStr) {
    // SAFETY: `status` is a valid C string pointer for the call.
    unsafe { tyr_job_status(seqno, group_id, cs_id, status.as_char_ptr()) }
}

/// VM_BIND ioctl dispatch.
pub(crate) fn mmu_bind_start(vm_id: u64, va: u64, size: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_mmu_bind_start(vm_id, va, size) }
}

/// VM_BIND op completion.
pub(crate) fn mmu_bind_done(vm_id: u64, va: u64, size: u64, result: i32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_mmu_bind_done(vm_id, va, size, result) }
}

/// Worker entry.
pub(crate) fn work_run(work_name: &CStr) {
    // SAFETY: `work_name` is a valid C string pointer for the call.
    unsafe { tyr_work_run(work_name.as_char_ptr()) }
}

/// Devfreq target callback (frequency change request).
pub(crate) fn devfreq_target(prev_freq: u64, target_freq: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_devfreq_target(prev_freq, target_freq) }
}

/// Sync-update drain summary.
pub(crate) fn sync_upd_drain(group_id: u64, cs_id: u32, completion_point: u64, drained_count: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_sync_upd_drain(group_id, cs_id, completion_point, drained_count) }
}

/// Per-evaluation deadline check.
pub(crate) fn deadline_check(
    group_id: u64,
    cs_id: u32,
    elapsed_ms: u32,
    allowance_ms: u32,
    faulted: bool,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_deadline_check(group_id, cs_id, elapsed_ms, allowance_ms, faulted) }
}

/// End-of-tick scheduling decision summary.
pub(crate) fn tick_decision_summary(
    evict_count: u32,
    bind_count: u32,
    keep_count: u32,
    runnable_remaining: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_tick_decision_summary(evict_count, bind_count, keep_count, runnable_remaining) }
}

/// Devfreq mark_busy / mark_idle transition.
pub(crate) fn devfreq_mark(busy: bool, prev_busy_ns: u64, prev_idle_ns: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_devfreq_mark(busy, prev_busy_ns, prev_idle_ns) }
}

/// Devfreq get_dev_status callback snapshot.
pub(crate) fn devfreq_status(busy_time_ns: u64, total_time_ns: u64, current_freq: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_devfreq_status(busy_time_ns, total_time_ns, current_freq) }
}
