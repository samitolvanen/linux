// SPDX-License-Identifier: GPL-2.0 or MIT

//! Tyr tracepoints.
//!
//! Safe Rust wrappers around the C tracepoint thunks declared in
//! `include/trace/events/tyr.h`. The unsafe `tyr_*` block is private to
//! this module.

use kernel::c_str;
use kernel::ffi::{
    c_char,
    c_int, //
};
use kernel::prelude::*;
use kernel::str::{
    CStr,
    CStrExt, //
};

/// Helper that formats a byte slice as space-separated lowercase hex
/// digits for the downstream-debug `pr_err!` fallback emitted alongside
/// the byte-dump tracepoints. libtraceevent has repeatedly failed to
/// parse the binary format strings used by those events, so the bytes
/// are additionally printed to dmesg.
struct HexBytes<'a>(&'a [u8]);

impl kernel::fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut kernel::fmt::Formatter<'_>) -> kernel::fmt::Result {
        let mut first = true;
        for b in self.0 {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "{b:02x}")?;
            first = false;
        }
        Ok(())
    }
}

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
    unsafe fn tyr_gpu_irq(status: u32);

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
    unsafe fn tyr_group_update(group_id: u64, group_uid: u64, state: u32);

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
    unsafe fn tyr_group_bind(group_id: u64, group_uid: u64, csg_id: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_unbind(group_id: u64, group_uid: u64, csg_id: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_timedout(group_id: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_innocent(group_id: u64, group_uid: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_sched_evict(csg_id: u32, group_id: u64, sw_prio: u8, forced: bool);

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
    unsafe fn tyr_sched_gate(suspended: bool);

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
    unsafe fn tyr_cs_ring_ptrs(group_id: u64, group_uid: u64, cs_id: u32, insert: u64, extract: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_cs_activate_ringbuf_state(
        group_id: u64,
        cs_id: u32,
        insert: u64,
        extract: u64,
        extract_init: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_job_submit(
        completion_point: u64,
        group_id: u64,
        group_uid: u64,
        cs_id: u32,
        user_stream_size: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_submit_fence_signal(
        group_id: u64,
        group_uid: u64,
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
    /// Always safe to call.
    unsafe fn tyr_mmu_map_segment(vm_id: u64, iova: u64, paddr: u64, len: u64);

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
        raw_seqno: u64,
        status: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_csg_syncobj(
        group_id: u64,
        group_uid: u64,
        cs_id: u32,
        phase: u32,
        seqno: u64,
        status: u32,
        next_seqno: u64,
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

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_csg_ack_poll(csg_id: u32, req: u32, ack: u32, mask: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_doorbell_ring(doorbell_id: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_csg_ep_req_write(csg_id: u32, raw_value: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_glb_alloc_en(value: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_csg_activate_bufs(csg_id: u32, suspend_buf: u64, protm_suspend_buf: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_csg_activate_config(
        csg_id: u32,
        ep_req_raw: u32,
        config_raw: u32,
        allow_compute: u64,
        allow_fragment: u64,
        allow_other: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_cs_activate_inputs(
        csg_id: u32,
        cs_id: u32,
        ringbuf_base: u64,
        ringbuf_size: u32,
        ringbuf_input_va: u64,
        ringbuf_output_va: u64,
        config: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_cs_ringbuf_publish(
        group_id: u64,
        cs_id: u32,
        insert: u64,
        extract_init: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_vm_map_bo(vm_id: u64, va: u64, size: u64, flags: u32, result: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_vm_unmap_bo(vm_id: u64, va: u64, size: u64, result: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_as_slot_assign(vm_id: u64, as_slot: u32, assigned: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_boot_complete(glb_version: u32, csg_count: u32, cs_per_csg: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_l2_power_on(result: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_cs_status_snapshot(
        csg: u32,
        group_uid: u64,
        cs: u32,
        req: u32,
        ack: u32,
        status_wait: u32,
        blocked_reason: u32,
        scoreboards: u32,
        sync_pointer: u64,
        cur_val: u64,
        cur_val_valid: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_csg_ack_timeout_state(
        csg_id: u32,
        cs_id: u32,
        req_mask: u32,
        acked: u32,
        insert: u64,
        extract: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_cs_ringbuf_dump(
        group: u64,
        cs: u32,
        start: u64,
        word0: u64,
        word1: u64,
        word2: u64,
        word3: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_csg_slot_assign(csg: u32, group: u64, group_uid: u64, assigned: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_csg_dump_output(
        csg: u32,
        ack: u32,
        status_state: u32,
        status_ep_current: u32,
        status_ep_req: u32,
        resource_dep: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_shader_power_state(ready: u64, pwrtrans: u64, pwractive: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_vm_bind_op(
        vm_id: u64,
        op_kind: u32,
        va: u64,
        size: u64,
        n_waits: u32,
        n_signals: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_vm_bind_unmap_exec(vm_id: u64, va: u64, size: u64, in_flight_fences: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_vm_bind_op_sync(
        vm_id: u64,
        op_kind: u32,
        va: u64,
        size: u64,
        n_waits: u32,
        n_signals: u32,
        bo: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_cs_sync_wait_operand(
        group_id: u64,
        cs_id: u32,
        gpu_va: u64,
        ref_val: u64,
        sync_size: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_syncwait_capture(
        vm_id: u64,
        group_id: u64,
        group_uid: u64,
        cs_id: u32,
        gpu_va: u64,
        ref_val: u64,
        sync64: u32,
        gt: u32,
        cur_val: u64,
        cur_val_valid: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_queue_blocked_state_change(
        group_id: u64,
        cs_id: u32,
        blocked: u32,
        caller: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_cleanup_wq_enqueue(kind: u32, va: u64, size: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_cleanup_wq_exec(kind: u32, va: u64, size: u64);

    /// # Safety
    ///
    /// `cs_ringbuf_ptrs` must point to four valid, readable `u64`
    /// values (cs0_insert, cs0_extract, cs1_insert, cs1_extract) and
    /// `ringbuf_words` must point to eight valid, readable `u64`
    /// values; both must remain valid for the duration of the call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_mmu_fault(
        as_slot: u32,
        fault_va: u64,
        raw_fault_status: u32,
        exception_type: u32,
        access_type: u32,
        source_id: u32,
        group_id: u64,
        group_uid: u64,
        csg_id: u32,
        cs_ringbuf_ptrs: *const u64,
        ringbuf_words: *const u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_user_stream_head(
        group_id: u64,
        cs_id: u32,
        stream_va: u64,
        first_qword: u64,
        status: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_wrapper_call(
        group_id: u64,
        queue_index: u32,
        job_counter: u64,
        cs_va: u64,
        cs_size: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_vm_bind_ioctl_entry(
        vm_id: u64,
        kind: u32,
        op_count: u32,
        in_flight_fences: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_state_transition(
        group_id: u64,
        group_uid: u64,
        old_state: u32,
        new_state: u32,
        reason: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_vm_bind_syncop(
        vm_id: u64,
        op_index: u32,
        syncop_index: u32,
        kind: u32,
        syncobj_handle: u32,
        timeline_value: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_tick_decision_per_group(
        group_id: u64,
        decision: u32,
        reason: u32,
        sw_prio: u8,
        fw_prio: u32,
        bound_ticks: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_state_query(
        vm_id: u64,
        group_id: u64,
        returned_state: u32,
        fatal_queues: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_bo_sync(
        bo: u64,
        sync_type: u32,
        offset: u64,
        size: u64,
        imported: bool,
        wc: bool,
        errno: c_int,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_group_submit_entry(group_handle: u32, queue_count: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_bo_set_label(bo: u64, has_label: bool);

    /// # Safety
    ///
    /// `ringbuf_words` must point to eight valid, readable `u64`
    /// values for the duration of the call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_cs_fault_event(
        group_id: u64,
        cs_id: u32,
        kind: u32,
        exception_type: u32,
        exception_data: u32,
        fatal_info: u64,
        cs_insert: u64,
        cs_extract: u64,
        ringbuf_words: *const u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_vm_bind_wait_fence(
        vm_id: u64,
        op_index: u32,
        syncop_index: u32,
        fence_context: u64,
        fence_seqno: u64,
        signalled: bool,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_gpuvm_node_op(vm_id: u64, op: u32, va: u64, size: u64);

    /// # Safety
    ///
    /// `bytes` must point to at least `len` valid, readable bytes for
    /// the duration of the call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_cs_user_stream_dump(
        group_id: u64,
        cs_id: u32,
        cs_extract: u64,
        bo_gpu_va_base: u64,
        bo_offset: u64,
        payload_offset: u64,
        status: u32,
        len: u32,
        bytes: *const u8,
    );

    /// # Safety
    ///
    /// `content` must point to 32 valid, readable bytes for the
    /// duration of the call.
    unsafe fn tyr_heap_context_dump(
        group_id: u64,
        cs_id: u32,
        heap_index: u32,
        heap_context_va: u64,
        chunk_count: u32,
        content: *const u8,
    );

    /// # Safety
    ///
    /// `header` must point to 64 valid, readable bytes for the
    /// duration of the call.
    unsafe fn tyr_heap_chunk_dump(
        group_id: u64,
        cs_id: u32,
        heap_index: u32,
        chunk_index: u32,
        chunk_va: u64,
        header: *const u8,
    );

    /// # Safety
    ///
    /// `mnemonic` must be a valid, nul-terminated C string pointer
    /// and `bytes` must point to at least `len` valid, readable bytes
    /// for the duration of the call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_cs_fault_instruction_decode(
        group_id: u64,
        cs_id: u32,
        cs_extract: u64,
        ringbuf_va: u64,
        opcode: u32,
        mnemonic: *const c_char,
        bytes: *const u8,
        len: u32,
    );

    /// # Safety
    ///
    /// `bytes` must point to at least `len` valid, readable bytes for
    /// the duration of the call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_cs_fault_info_dump(
        group_id: u64,
        cs_id: u32,
        info_va: u64,
        bo_va_base: u64,
        bo_size: u64,
        bo_offset: u64,
        bytes: *const u8,
        len: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_vm_bind_fence_signal(
        vm_id: u64,
        fence_ctx: u64,
        fence_seqno: u64,
        op_kind: u32,
        op_count: u32,
        errno: c_int,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_vm_bind_op_run(
        vm_id: u64,
        op_kind: u32,
        va_base: u64,
        va_len: u64,
        gem_offset: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_job_dep_added(
        group_id: u64,
        queue_index: u32,
        job_counter: u64,
        source: u32,
        handle: u32,
        point: u64,
        dep_ctx: u64,
        dep_seqno: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_job_deps_satisfied(
        group_id: u64,
        queue_index: u32,
        job_counter: u64,
        dep_count: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_syncobj_publish(
        syncobj_handle: u32,
        point: u64,
        fence_ctx: u64,
        fence_seqno: u64,
        kind: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_intra_batch_dep_resolved(
        group_id: u64,
        queue_index: u32,
        job_counter: u64,
        handle: u32,
        point: u64,
        dep_ctx: u64,
        dep_seqno: u64,
        dep_signaled: bool,
    );

    /// # Safety
    ///
    /// Always safe to call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_syncobj_wait(
        group_id: u64,
        queue_index: u32,
        job_counter: u64,
        syncobj_handle: u32,
        point: u64,
        fence_ctx: u64,
        fence_seqno: u64,
        signaled: bool,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_as_enable(vm_id: u64, as_slot: u32, transtab: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_as_disable(vm_id: u64, as_slot: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_as_update_start(vm_id: u64, as_slot: u32, region_start: u64, region_size: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_as_update_end(vm_id: u64, as_slot: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_gpu_flush_caches(as_slot: u32, l2: u32, lsc: u32, other: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_pm_runtime_suspend(phase: u32, errno: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_pm_runtime_resume(phase: u32, errno: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_pm_devfreq(op: u32, errno: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_pm_usage(event: u32, acquired: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_pm_hw(step: u32, errno: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_reset_request(reason: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_reset_schedule(outcome: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_reset_worker(outcome: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_reset_cycle(phase: u32, errno: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_reset_pm(path: u32, errno: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn tyr_fw_ping(event: u32, errno: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_wedge_glb_probe(
        csg_id: u32,
        req_mask: u32,
        glb_req_before: u32,
        glb_ack_before: u32,
        glb_req_after: u32,
        glb_ack_after: u32,
        ping_acked: bool,
        mcu_status: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_wedge_cs_state(
        csg_id: u32,
        group_uid: u64,
        cs_id: u32,
        status_wait: u32,
        blocked_reason: u32,
        req_resource: u32,
        heap_address: u64,
        vt_start: u32,
        vt_end: u32,
        frag_end: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    #[allow(clippy::too_many_arguments)]
    unsafe fn tyr_heap_grow_decision(
        group_uid: u64,
        cs_id: u32,
        chunk_count: u32,
        max_chunks: u32,
        renderpasses_in_flight: u32,
        target_in_flight: u32,
        pending_frag_count: u32,
        outcome: u32,
    );
}

/// Returns whether the tiler-heap-state dump should run, i.e. whether
/// either heap-dump tracepoint is enabled. This mirrors the
/// static-branch query that `declare_trace!` performs before emitting an
/// event, so the dump's lock-free, allocation-free walk is skipped
/// entirely while the tracepoints are off (the default). Enable at
/// runtime with `echo 1 > .../events/tyr_heap/enable`.
#[cfg(CONFIG_TRACEPOINTS)]
pub(crate) fn heap_dump_enabled() -> bool {
    // SAFETY: It's always okay to query the static key for a tracepoint.
    let chunk = unsafe {
        kernel::jump_label::static_branch_unlikely!(
            kernel::bindings::__tracepoint_tyr_heap_chunk_dump,
            kernel::bindings::tracepoint,
            key
        )
    };
    // SAFETY: It's always okay to query the static key for a tracepoint.
    let context = unsafe {
        kernel::jump_label::static_branch_unlikely!(
            kernel::bindings::__tracepoint_tyr_heap_context_dump,
            kernel::bindings::tracepoint,
            key
        )
    };
    chunk || context
}

/// Without `CONFIG_TRACEPOINTS` the `__tracepoint_*` symbols do not
/// exist, so the dump can never produce trace output and is always off.
#[cfg(not(CONFIG_TRACEPOINTS))]
pub(crate) fn heap_dump_enabled() -> bool {
    false
}

/// Returns whether the scoreboard read-back for [`syncwait_capture`]
/// should run, i.e. whether the tracepoint is enabled. Mirrors the
/// static-branch query that `declare_trace!` performs, so the
/// lock-free resolve and transient page map are skipped while the
/// tracepoint is off (the default).
#[cfg(CONFIG_TRACEPOINTS)]
pub(crate) fn syncwait_capture_enabled() -> bool {
    // SAFETY: It's always okay to query the static key for a tracepoint.
    unsafe {
        kernel::jump_label::static_branch_unlikely!(
            kernel::bindings::__tracepoint_tyr_syncwait_capture,
            kernel::bindings::tracepoint,
            key
        )
    }
}

/// Without `CONFIG_TRACEPOINTS` the `__tracepoint_*` symbols do not
/// exist, so the read-back can never produce trace output.
#[cfg(not(CONFIG_TRACEPOINTS))]
pub(crate) fn syncwait_capture_enabled() -> bool {
    false
}

/// Returns whether the scoreboard read-back for [`cs_status_snapshot`]
/// should run. The snapshot polls heavily while a group is blocked,
/// so the read costs nothing while the tracepoint is off (the
/// default).
#[cfg(CONFIG_TRACEPOINTS)]
pub(crate) fn cs_status_snapshot_enabled() -> bool {
    // SAFETY: It's always okay to query the static key for a tracepoint.
    unsafe {
        kernel::jump_label::static_branch_unlikely!(
            kernel::bindings::__tracepoint_tyr_cs_status_snapshot,
            kernel::bindings::tracepoint,
            key
        )
    }
}

/// Without `CONFIG_TRACEPOINTS` the `__tracepoint_*` symbols do not
/// exist, so the read-back can never produce trace output.
#[cfg(not(CONFIG_TRACEPOINTS))]
pub(crate) fn cs_status_snapshot_enabled() -> bool {
    false
}

/// Direction tag for `vm_bind_syncop`. Keep in sync with
/// `TYR_VM_BIND_SYNCOP_KINDS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum VmBindSyncopKind {
    Wait = 0,
    Signal = 1,
}

/// Kind tags for `vm_bind_ioctl_entry`. Keep in sync with
/// `TYR_VM_BIND_IOCTL_KINDS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum VmBindIoctlKind {
    Sync = 0,
    Async = 1,
}

/// Reason tag for `group_state_transition`, identifying the call site
/// that triggered the state assignment. Keep in sync with
/// `TYR_GROUP_STATE_REASONS` in `include/trace/events/tyr.h`.
#[repr(u32)]
#[allow(dead_code)]
pub(crate) enum StateChangeReason {
    Created = 0,
    Bound = 1,
    Active = 2,
    IdleAck = 3,
    Blocked = 4,
    Unbinding = 5,
    Faulted = 6,
    TimedOut = 7,
    TornDown = 8,
    FwAck = 9,
    Other = 10,
}

/// Status tags for `user_stream_head`. Keep in sync with
/// `TYR_USER_STREAM_HEAD_STATUS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum UserStreamHeadStatus {
    /// `first_qword` was read from a kernel vmap of the user BO.
    Ok = 0,
    /// `vm.get_bo_for_va` returned no mapping for `stream_va`.
    LookupFailed = 1,
    /// The BO was found but a kernel vmap could not be obtained.
    VmapFailed = 2,
}

/// Kind tags for the cleanup-workqueue trace events. Keep in sync with
/// `TYR_CLEANUP_WQ_KINDS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum CleanupWqKind {
    KernelBo = 0,
    MappedBoVmap = 1,
}

/// Kind tag for a decoded CS-level exception event. Keep in sync with
/// `TYR_CS_FAULT_EVENT_KINDS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum CsFaultEventKind {
    Fault = 0,
    Fatal = 1,
}

/// Status tag for `cs_user_stream_dump`. Keep in sync with
/// `TYR_CS_USER_STREAM_DUMP_STATUS` in `include/trace/events/tyr.h`.
#[repr(u32)]
#[derive(Clone, Copy)]
pub(crate) enum CsUserStreamDumpStatus {
    /// `bytes` carries a full 256-byte window read from a kernel vmap.
    Ok = 0,
    /// `Vm::try_get_bo_for_va` returned no mapping; payload is empty.
    NoBoAtVa = 1,
    /// A BO was found but no kernel vmap is reachable from this
    /// context; payload is empty.
    BoNotVmapped = 2,
    /// The BO is dma-buf imported; kernel reads through it are not
    /// attempted; payload is empty.
    BoImported = 3,
    /// Bytes were successfully read but the window was clamped to BO
    /// bounds; `len` is the actual byte count.
    WindowClamped = 4,
    /// `gpuvm_unique` was held by another thread; the lookup was
    /// skipped to preserve dma-fence signalling rules. Payload is
    /// empty.
    LockContended = 5,
}

/// Result of a single CS user-stream dump attempt. Returned by
/// [`crate::sched::queue::QueueData::user_stream_window_around`] and
/// consumed by [`cs_user_stream_dump`].
pub(crate) struct CsUserStreamDump {
    /// Located BO's base GPU VA, or `0` when no BO was located.
    pub(crate) bo_va_base: u64,
    /// `cs_extract`-derived offset within the located BO, or `0`
    /// when no BO was located. Independent of `payload_offset`, this is
    /// always the actual consumption point.
    pub(crate) bo_offset: u64,
    /// Offset within the located BO at which `bytes` starts. On
    /// success this is `bo_offset.saturating_sub(128)` clamped to BO
    /// bounds; zero when no payload was captured.
    pub(crate) payload_offset: u64,
    /// Outcome category.
    pub(crate) status: CsUserStreamDumpStatus,
    /// Fixed 256-byte buffer. Only the first `len` bytes are valid.
    pub(crate) bytes: [u8; 256],
    /// Number of valid bytes in `bytes`.
    pub(crate) len: u32,
}

impl Default for CsUserStreamDump {
    /// The default is the `NoBoAtVa` sentinel, meaning no BO was located and
    /// no payload was captured.
    fn default() -> Self {
        Self {
            bo_va_base: 0,
            bo_offset: 0,
            payload_offset: 0,
            status: CsUserStreamDumpStatus::NoBoAtVa,
            bytes: [0u8; 256],
            len: 0,
        }
    }
}

/// Kind tag for one gpuvm step callback. Keep in sync with
/// `TYR_GPUVM_NODE_OPS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum GpuVmNodeOp {
    Map = 0,
    Unmap = 1,
    Remap = 2,
}

/// Caller-site tag for `queue_blocked_state_change`. Keep in sync
/// with `TYR_QUEUE_BLOCKED_CALLERS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum QueueBlockedCaller {
    /// Fired from `sync_csg_slot_queues_state` after the per-CS
    /// blocked classification is applied to `GroupInner`.
    SyncSlotApply = 0,
    /// Fired from `apply_syncwait_results` after a queue's bit is
    /// cleared from `blocked_queues` in response to a positive
    /// eval_syncwait outcome.
    ApplyResults = 1,
}

/// Per-group outcome reached by the rule engine on one scheduler tick.
/// Keep in sync with `TYR_TICK_DECISIONS` in
/// `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum TickDecision {
    Keep = 0,
    Take = 1,
    Evict = 2,
    Skip = 3,
}

/// Reason carried alongside a [`TickDecision`]. Keep in sync with
/// `TYR_TICK_DECISION_REASONS` in `include/trace/events/tyr.h`.
#[repr(u32)]
#[allow(dead_code)]
pub(crate) enum TickDecisionReason {
    Runnable = 0,
    Idle = 1,
    NotRunnable = 2,
    AlreadyBound = 3,
    Faulted = 4,
    Preempted = 5,
    ActivateFailed = 6,
    Other = 7,
}

/// Op-kind tag for `vm_bind_fence_signal`. `Mixed` is reported when a
/// batch contained both Map and Unmap ops. Keep in sync with
/// `TYR_VM_BIND_FENCE_OP_KINDS` in `include/trace/events/tyr.h`.
#[repr(u32)]
#[derive(Clone, Copy)]
pub(crate) enum VmBindFenceOpKind {
    Map = 0,
    Unmap = 1,
    Mixed = 2,
}

/// Op-kind tag for `vm_bind_op_run`. Shares numeric values with the
/// UAPI op-type field used by `vm_bind_op`. Keep in sync with
/// `TYR_VM_BIND_OP_KINDS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum VmBindOpRunKind {
    Map = 0,
    Unmap = 1,
}

/// Source tag for `job_dep_added`. Keep in sync with
/// `TYR_JOB_DEP_SOURCES` in `include/trace/events/tyr.h`.
#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum JobDepSource {
    External = 0,
    IntraBatch = 1,
}

/// Kind tag for `syncobj_publish`. Keep in sync with
/// `TYR_SYNCOBJ_PUBLISH_KINDS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum SyncobjPublishKind {
    Binary = 0,
    Timeline = 1,
}

/// Phase tag for `csg_syncobj`. Keep in sync with
/// `TYR_CSG_SYNCOBJ_PHASES` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum CsgSyncobjPhase {
    Suspend = 0,
    Resume = 1,
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

/// GPU-IRQ entry status.
pub(crate) fn gpu_irq(status: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_gpu_irq(status) }
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
pub(crate) fn group_update(group_id: u64, group_uid: u64, state: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_update(group_id, group_uid, state) }
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
pub(crate) fn group_bind(group_id: u64, group_uid: u64, csg_id: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_bind(group_id, group_uid, csg_id) }
}

/// Group unbound from a CSG slot.
pub(crate) fn group_unbind(group_id: u64, group_uid: u64, csg_id: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_unbind(group_id, group_uid, csg_id) }
}

/// A queue in the group exceeded its per-job deadline.
pub(crate) fn group_timedout(group_id: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_timedout(group_id) }
}

/// Group marked as innocent collateral of another group's failure.
pub(crate) fn group_innocent(group_id: u64, group_uid: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_innocent(group_id, group_uid) }
}

/// Rule engine evicted a CSG slot. `forced` is true for a suspend or
/// reset teardown, false for a scheduler-chosen preemption.
pub(crate) fn sched_evict(csg_id: u32, group_id: u64, sw_prio: u8, forced: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_sched_evict(csg_id, group_id, sw_prio, forced) }
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

/// Scheduler suspend gate toggled. `suspended` is the new gate state.
pub(crate) fn sched_gate(suspended: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_sched_gate(suspended) }
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
pub(crate) fn cs_ring_ptrs(group_id: u64, group_uid: u64, cs_id: u32, insert: u64, extract: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_cs_ring_ptrs(group_id, group_uid, cs_id, insert, extract) }
}

/// Firmware-visible ringbuf mailbox pointers sampled at CSG-bind time,
/// after `sync_extract_init`, just before `CS_REQ.state = Start` is
/// staged.
pub(crate) fn cs_activate_ringbuf_state(
    group_id: u64,
    cs_id: u32,
    insert: u64,
    extract: u64,
    extract_init: u64,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_cs_activate_ringbuf_state(group_id, cs_id, insert, extract, extract_init) }
}

/// Firmware-visible ringbuf state for a CS on a slot whose STATUS_UPDATE
/// ack timed out. Downstream-only debug aid; not for upstream.
pub(crate) fn csg_ack_timeout_state(
    csg_id: u32,
    cs_id: u32,
    req_mask: u32,
    acked: u32,
    insert: u64,
    extract: u64,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_csg_ack_timeout_state(csg_id, cs_id, req_mask, acked, insert, extract) }
}

/// One Job committed to a queue ringbuffer.
pub(crate) fn job_submit(
    completion_point: u64,
    group_id: u64,
    group_uid: u64,
    cs_id: u32,
    user_stream_size: u32,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_job_submit(
            completion_point,
            group_id,
            group_uid,
            cs_id,
            user_stream_size,
        )
    }
}

/// Submit fence signalled (success or error).
pub(crate) fn submit_fence_signal(
    group_id: u64,
    group_uid: u64,
    cs_id: u32,
    completion_point: u64,
    result: i32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_submit_fence_signal(group_id, group_uid, cs_id, completion_point, result) }
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

/// One VA->PA segment programmed into the page table by `pt_map`.
/// `len` is the byte span of this `map_pages` call (pgsize * pgcount).
pub(crate) fn mmu_map_segment(vm_id: u64, iova: u64, paddr: u64, len: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_mmu_map_segment(vm_id, iova, paddr, len) }
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

/// Sync-update drain summary. `raw_seqno` and `status` are the
/// `SyncObj64b` fields read at drain time, alongside the
/// `completion_point` they drained to.
pub(crate) fn sync_upd_drain(
    group_id: u64,
    cs_id: u32,
    completion_point: u64,
    drained_count: u32,
    raw_seqno: u64,
    status: u32,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_sync_upd_drain(
            group_id,
            cs_id,
            completion_point,
            drained_count,
            raw_seqno,
            status,
        )
    }
}

/// Per-CS syncobj snapshot taken at a CSG suspend or resume.
pub(crate) fn csg_syncobj(
    group_id: u64,
    group_uid: u64,
    cs_id: u32,
    phase: CsgSyncobjPhase,
    seqno: u64,
    status: u32,
    next_seqno: u64,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_csg_syncobj(
            group_id,
            group_uid,
            cs_id,
            phase as u32,
            seqno,
            status,
            next_seqno,
        )
    }
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

/// One per-group decision reached by the rule engine on a scheduler
/// tick, carrying the rule-engine reason and the group's bound-tick
/// counter. Fires alongside the existing `sched_keep`/`sched_bind`/
/// `sched_evict` events and additionally for skip cases that produce
/// no other per-group trace.
pub(crate) fn tick_decision_per_group(
    group_id: u64,
    decision: TickDecision,
    reason: TickDecisionReason,
    sw_prio: u8,
    fw_prio: u32,
    bound_ticks: u32,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_tick_decision_per_group(
            group_id,
            decision as u32,
            reason as u32,
            sw_prio,
            fw_prio,
            bound_ticks,
        )
    }
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

/// One iteration of the CSG_ACK poll inside `wait_csg_acks`. `req` and
/// `ack` are the unmasked register snapshots; `mask` is the wait mask
/// applied to compute the pending bits inside the trace event.
pub(crate) fn fw_csg_ack_poll(csg_id: u32, req: u32, ack: u32, mask: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_csg_ack_poll(csg_id, req, ack, mask) }
}

/// A doorbell register ring (id 0 is the global doorbell, 1..N are
/// per-CSG doorbells).
pub(crate) fn fw_doorbell_ring(doorbell_id: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_doorbell_ring(doorbell_id) }
}

/// `CSG_EP_REQ` input register write.
pub(crate) fn fw_csg_ep_req_write(csg_id: u32, raw_value: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_csg_ep_req_write(csg_id, raw_value) }
}

/// `GLB_ALLOC_EN` input register write. `value` is the shader-core
/// allocation mask programmed into the global input area at firmware
/// enable.
pub(crate) fn fw_glb_alloc_en(value: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_glb_alloc_en(value) }
}

/// Suspend-buffer pointers programmed into the CSG input area at activate.
pub(crate) fn fw_csg_activate_bufs(csg_id: u32, suspend_buf: u64, protm_suspend_buf: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_csg_activate_bufs(csg_id, suspend_buf, protm_suspend_buf) }
}

/// Endpoint, config and core-allow masks programmed into the CSG input
/// area at activate.
pub(crate) fn fw_csg_activate_config(
    csg_id: u32,
    ep_req_raw: u32,
    config_raw: u32,
    allow_compute: u64,
    allow_fragment: u64,
    allow_other: u32,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_fw_csg_activate_config(
            csg_id,
            ep_req_raw,
            config_raw,
            allow_compute,
            allow_fragment,
            allow_other,
        )
    }
}

/// Ringbuf and CS_CONFIG values programmed into the CS input area at
/// activate. `config` is the raw `CS_CONFIG` register value (priority in
/// bits 3:0, doorbell id in bits 15:8).
pub(crate) fn fw_cs_activate_inputs(
    csg_id: u32,
    cs_id: u32,
    ringbuf_base: u64,
    ringbuf_size: u32,
    ringbuf_input_va: u64,
    ringbuf_output_va: u64,
    config: u32,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_fw_cs_activate_inputs(
            csg_id,
            cs_id,
            ringbuf_base,
            ringbuf_size,
            ringbuf_input_va,
            ringbuf_output_va,
            config,
        )
    }
}

/// `INSERT` / `EXTRACT_INIT` values just published into the firmware-
/// visible CS input mailbox by `commit_ringbuf_range`.
pub(crate) fn fw_cs_ringbuf_publish(group_id: u64, cs_id: u32, insert: u64, extract_init: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_cs_ringbuf_publish(group_id, cs_id, insert, extract_init) }
}

/// GPU MMU map operation finished (Ok or Err) for the user-facing
/// `map_bo_range_inner`. `result` is the negative errno from the
/// map, or `0` on success.
pub(crate) fn vm_map_bo(vm_id: u64, va: u64, size: u64, flags: u32, result: c_int) {
    // SAFETY: Always safe to call.
    unsafe { tyr_vm_map_bo(vm_id, va, size, flags, result) }
}

/// GPU MMU unmap operation finished (Ok or Err) for the user-facing
/// `unmap_range_inner`. `result` is the negative errno from the unmap,
/// or `0` on success.
pub(crate) fn vm_unmap_bo(vm_id: u64, va: u64, size: u64, result: c_int) {
    // SAFETY: Always safe to call.
    unsafe { tyr_vm_unmap_bo(vm_id, va, size, result) }
}

/// A VM was assigned to (or released from) a hardware AS slot.
/// `as_slot` is the slot index; `assigned` is `true` on activate and
/// `false` on evict.
pub(crate) fn as_slot_assign(vm_id: u64, as_slot: u32, assigned: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_as_slot_assign(vm_id, as_slot, assigned) }
}

/// Firmware boot wait completed and the global interface is configured.
pub(crate) fn fw_boot_complete(glb_version: u32, csg_count: u32, cs_per_csg: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_boot_complete(glb_version, csg_count, cs_per_csg) }
}

/// L2 power-on poll completed. `result` is `0` on success, otherwise
/// the negative errno from the poll.
pub(crate) fn l2_power_on(result: c_int) {
    // SAFETY: Always safe to call.
    unsafe { tyr_l2_power_on(result) }
}

/// Snapshot of the per-CS status registers read in
/// `sync_csg_slot_queues_state` after a `CSG_REQ.status_update` ack.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cs_status_snapshot(
    csg: u32,
    group_uid: u64,
    cs: u32,
    req: u32,
    ack: u32,
    status_wait: u32,
    blocked_reason: u32,
    scoreboards: u32,
    sync_pointer: u64,
    cur_val: u64,
    cur_val_valid: bool,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_cs_status_snapshot(
            csg,
            group_uid,
            cs,
            req,
            ack,
            status_wait,
            blocked_reason,
            scoreboards,
            sync_pointer,
            cur_val,
            u32::from(cur_val_valid),
        )
    }
}

/// First 32 bytes of the just-committed ringbuffer range, split into
/// four 64-bit little-endian words.
pub(crate) fn cs_ringbuf_dump(
    group: u64,
    cs: u32,
    start: u64,
    word0: u64,
    word1: u64,
    word2: u64,
    word3: u64,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_cs_ringbuf_dump(group, cs, start, word0, word1, word2, word3) }
}

/// A CSG slot was assigned to a group (in `CsgSlotOps::activate`) or
/// released (in `evict`).
pub(crate) fn csg_slot_assign(csg: u32, group: u64, group_uid: u64, assigned: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_csg_slot_assign(csg, group, group_uid, assigned) }
}

/// Snapshot of the per-CSG output state, covering status, endpoint
/// allocation, and resource dependencies. Emitted after a `STATUS_UPDATE` ack
/// and on the timeout path so a stuck slot's reported state is captured even
/// when the wait timed out.
pub(crate) fn fw_csg_dump_output(
    csg: u32,
    ack: u32,
    status_state: u32,
    status_ep_current: u32,
    status_ep_req: u32,
    resource_dep: u32,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_fw_csg_dump_output(
            csg,
            ack,
            status_state,
            status_ep_current,
            status_ep_req,
            resource_dep,
        )
    }
}

/// Snapshot of the shader-core power-domain registers (`SHADER_READY`,
/// `SHADER_PWRTRANS`, `SHADER_PWRACTIVE`). Emitted after L2 power-on
/// and around each scheduler tick so a tick that fails to allocate
/// cores has its shader-domain context captured.
pub(crate) fn shader_power_state(ready: u64, pwrtrans: u64, pwractive: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_shader_power_state(ready, pwrtrans, pwractive) }
}

/// One parsed op from a `DRM_IOCTL_PANTHOR_VM_BIND` submission, emitted
/// from the ioctl handler. `op_kind` is the UAPI op-type field
/// (`drm_panthor_vm_bind_op_flags & TYPE_MASK`) shifted right by 28
/// (0=MAP, 1=UNMAP, 2=SYNC_ONLY). `n_waits` and `n_signals` are the
/// per-op WAIT/SIGNAL syncop counts parsed from the op's syncs array.
pub(crate) fn vm_bind_op(
    vm_id: u64,
    op_kind: u32,
    va: u64,
    size: u64,
    n_waits: u32,
    n_signals: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_vm_bind_op(vm_id, op_kind, va, size, n_waits, n_signals) }
}

/// A VM_BIND unmap op about to execute from the bind queue's submit
/// path, after the bind job's framework deps have resolved.
/// `in_flight_fences` is the count of unsignalled fences observed at
/// `BOOKKEEP` usage on the VM's reservation object at the moment the
/// unmap was about to execute. A non-zero value is the directly
/// testable signature of a Mesa unmap-vs-CS race.
pub(crate) fn vm_bind_unmap_exec(vm_id: u64, va: u64, size: u64, in_flight_fences: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_vm_bind_unmap_exec(vm_id, va, size, in_flight_fences) }
}

/// One parsed op from a synchronous `DRM_IOCTL_PANTHOR_VM_BIND`
/// submission. Mirrors `vm_bind_op` but for the non-async ioctl path
/// so async and sync calls can be told apart in the trace. The sync
/// path rejects per-op syncs, so `n_waits` and `n_signals` are always
/// reported as `0`. `bo` is the address of the mapped/unmapped BO's
/// `struct drm_gem_object` (a file-independent debug identity), or `0`
/// when no BO could be resolved at trace time.
pub(crate) fn vm_bind_op_sync(
    vm_id: u64,
    op_kind: u32,
    va: u64,
    size: u64,
    n_waits: u32,
    n_signals: u32,
    bo: u64,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_vm_bind_op_sync(vm_id, op_kind, va, size, n_waits, n_signals, bo) }
}

/// Per-CS sync-wait operand decoded from `CS_STATUS_WAIT_*` when the
/// firmware reports `BlockedReason::SyncWait`. Carries the awaited GPU
/// VA, the reference value the CS is comparing against and the sync
/// object width in bytes (4 or 8).
pub(crate) fn cs_sync_wait_operand(
    group_id: u64,
    cs_id: u32,
    gpu_va: u64,
    ref_val: u64,
    sync_size: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_cs_sync_wait_operand(group_id, cs_id, gpu_va, ref_val, sync_size) }
}

/// Sync-wait operand about to be installed into a queue's syncwait
/// snapshot by `sync_csg_slot_queues_state`. Fires on the SyncWait
/// branch only, immediately before [`crate::sched::queue::Queue::set_syncwait`]
/// runs, so the trace captures what the eval_syncwait pass will
/// later read back. `cur_val` is the value currently at the awaited
/// scoreboard slot, read back from the BO; `cur_val_valid` is false
/// when the slot could not be resolved or read.
#[allow(clippy::too_many_arguments)]
pub(crate) fn syncwait_capture(
    vm_id: u64,
    group_id: u64,
    group_uid: u64,
    cs_id: u32,
    gpu_va: u64,
    ref_val: u64,
    sync64: bool,
    gt: bool,
    cur_val: u64,
    cur_val_valid: bool,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_syncwait_capture(
            vm_id,
            group_id,
            group_uid,
            cs_id,
            gpu_va,
            ref_val,
            u32::from(sync64),
            u32::from(gt),
            cur_val,
            u32::from(cur_val_valid),
        )
    }
}

/// One transition of a queue's bit in `GroupInner::blocked_queues`, emitted
/// right after `set_queue_blocked`. It fires at the two sites that drive the
/// bitmap, the snapshot apply phase in `sync_csg_slot_queues_state` and the
/// result apply phase in `apply_syncwait_results`. `caller` identifies which
/// one fired.
pub(crate) fn queue_blocked_state_change(
    group_id: u64,
    cs_id: u32,
    blocked: bool,
    caller: QueueBlockedCaller,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_queue_blocked_state_change(group_id, cs_id, u32::from(blocked), caller as u32) }
}

/// A cleanup-workqueue item was enqueued from a deferred-drop path.
/// `va`/`size` carry the GPU VA range for `KernelBo` items and `0`
/// for items that have no GPU range (e.g. `MappedBo` vmap teardown).
pub(crate) fn cleanup_wq_enqueue(kind: CleanupWqKind, va: u64, size: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_cleanup_wq_enqueue(kind as u32, va, size) }
}

/// A cleanup-workqueue item is about to execute. Paired with
/// [`cleanup_wq_enqueue`] so the trace shows the enqueue-to-exec
/// latency and any backlog accumulated under sustained submit load.
pub(crate) fn cleanup_wq_exec(kind: CleanupWqKind, va: u64, size: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_cleanup_wq_exec(kind as u32, va, size) }
}

/// One unhandled MMU page fault, captured at the point the IRQ
/// handler decodes the per-AS fault registers. `group_id` is the pool
/// handle of the group currently bound to the faulting AS, or
/// [`u64::MAX`] when no group was bound; `csg_id` is the matching
/// CSG slot index or [`u32::MAX`]. The `cs0`/`cs1` insert/extract
/// pairs are the kernel-visible ringbuffer cursors for the first two
/// command streams of the bound group, or zero when no group context
/// is available. `ringbuf_words` is an eight-word snapshot of the
/// faulting CS's ringbuffer centred on `INSERT` (the four
/// most-recently-published words and the four words ahead of the
/// publish point), all zero when no ringbuf snapshot was available.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mmu_fault(
    as_slot: u32,
    fault_va: u64,
    raw_fault_status: u32,
    exception_type: u32,
    access_type: u32,
    source_id: u32,
    group_id: u64,
    group_uid: u64,
    csg_id: u32,
    cs0_insert: u64,
    cs0_extract: u64,
    cs1_insert: u64,
    cs1_extract: u64,
    ringbuf_words: [u64; 8],
) {
    let cs_ringbuf_ptrs: [u64; 4] = [cs0_insert, cs0_extract, cs1_insert, cs1_extract];
    // SAFETY: `cs_ringbuf_ptrs` and `ringbuf_words` are stack-allocated
    // arrays whose addresses are valid for the duration of this call.
    unsafe {
        tyr_mmu_fault(
            as_slot,
            fault_va,
            raw_fault_status,
            exception_type,
            access_type,
            source_id,
            group_id,
            group_uid,
            csg_id,
            cs_ringbuf_ptrs.as_ptr(),
            ringbuf_words.as_ptr(),
        )
    }
}

/// First 8 bytes of the userspace command stream at `stream_va`, read
/// from a kernel vmap at submit-prepare time. `status` distinguishes
/// a real read from the failure modes that emit a sentinel
/// `first_qword`.
pub(crate) fn user_stream_head(
    group_id: u64,
    cs_id: u32,
    stream_va: u64,
    first_qword: u64,
    status: UserStreamHeadStatus,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_user_stream_head(group_id, cs_id, stream_va, first_qword, status as u32) }
}

/// The user command-stream VA a wrapped stream `CALL`s, with its byte
/// size, tagged with the same `(group_id, queue_index, job_counter)`
/// identity as the per-job dependency tracepoints. Fires once per piece
/// in `build_wrapped_stream`, so a job that wraps several pieces emits
/// one event per `CALL` target.
pub(crate) fn wrapper_call(
    group_id: u64,
    queue_index: u32,
    job_counter: u64,
    cs_va: u64,
    cs_size: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_wrapper_call(group_id, queue_index, job_counter, cs_va, cs_size) }
}

/// Entry to `DRM_IOCTL_PANTHOR_VM_BIND`. `in_flight_fences` is the
/// count of unsignalled `BOOKKEEP`-usage fences observed on the VM's
/// reservation object at ioctl entry, before any of the batch's ops
/// have been parsed.
pub(crate) fn vm_bind_ioctl_entry(
    vm_id: u64,
    kind: VmBindIoctlKind,
    op_count: u32,
    in_flight_fences: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_vm_bind_ioctl_entry(vm_id, kind as u32, op_count, in_flight_fences) }
}

/// One transition of a [`crate::sched::group::Group`]'s lifecycle
/// state, emitted from `Group::set_state` with the reason supplied by
/// the caller.
pub(crate) fn group_state_transition(
    group_id: u64,
    group_uid: u64,
    old_state: u32,
    new_state: u32,
    reason: StateChangeReason,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_state_transition(group_id, group_uid, old_state, new_state, reason as u32) }
}

/// One parsed sync op inside a `DRM_IOCTL_PANTHOR_VM_BIND` batch,
/// emitted after the op's syncs array has been parsed but before its
/// semantics execute. `timeline_value` is `0` for binary syncobjs.
pub(crate) fn vm_bind_syncop(
    vm_id: u64,
    op_index: u32,
    syncop_index: u32,
    kind: VmBindSyncopKind,
    syncobj_handle: u32,
    timeline_value: u64,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_vm_bind_syncop(
            vm_id,
            op_index,
            syncop_index,
            kind as u32,
            syncobj_handle,
            timeline_value,
        )
    }
}

/// Result of one `DRM_IOCTL_PANTHOR_GROUP_GET_STATE` invocation.
/// Emitted from the ioctl handler just before it returns, with the
/// state word and `fatal_queues` bitmap that will be copied back to
/// userspace.
pub(crate) fn group_state_query(vm_id: u64, group_id: u64, returned_state: u32, fatal_queues: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_state_query(vm_id, group_id, returned_state, fatal_queues) }
}

/// One `DRM_IOCTL_PANTHOR_BO_SYNC` op and its result. Emitted on every
/// exit so a no-op maintenance call is distinguishable from a real one.
/// `bo` is the BO debug identity from `gem::debug_id`.
pub(crate) fn bo_sync(
    bo: u64,
    sync_type: u32,
    offset: u64,
    size: u64,
    imported: bool,
    wc: bool,
    errno: c_int,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_bo_sync(bo, sync_type, offset, size, imported, wc, errno) }
}

/// Entry marker for a `DRM_IOCTL_PANTHOR_GROUP_SUBMIT` batch, so the
/// downstream submit events attribute to their syscall.
pub(crate) fn group_submit_entry(group_handle: u32, queue_count: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_submit_entry(group_handle, queue_count) }
}

/// A `DRM_IOCTL_PANTHOR_BO_SET_LABEL` call. `has_label` is false when
/// the label is cleared. `bo` is the BO debug identity from
/// `gem::debug_id`.
pub(crate) fn bo_set_label(bo: u64, has_label: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_bo_set_label(bo, has_label) }
}

/// One decoded CS_FAULT or CS_FATAL ack. Emitted from the events
/// handler immediately after the firmware register snapshot is read
/// but before the driver translates the exception into `fatal_queues`
/// or `fatal_error` state, so the trace captures every reported
/// exception independent of subsequent driver bookkeeping.
/// `cs_insert`/`cs_extract` are the kernel-visible ringbuffer cursors
/// for the faulting CS, and `ringbuf_words` is an eight-word snapshot
/// of that ringbuffer centred on `cs_insert` (the four
/// most-recently-published words and the four words ahead of the
/// publish point), all zero when no ringbuf snapshot was available.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cs_fault_event(
    group_id: u64,
    cs_id: u32,
    kind: CsFaultEventKind,
    exception_type: u32,
    exception_data: u32,
    fatal_info: u64,
    cs_insert: u64,
    cs_extract: u64,
    ringbuf_words: [u64; 8],
) {
    // SAFETY: `ringbuf_words` is a stack-allocated array whose address
    // is valid for the duration of this call.
    unsafe {
        tyr_cs_fault_event(
            group_id,
            cs_id,
            kind as u32,
            exception_type,
            exception_data,
            fatal_info,
            cs_insert,
            cs_extract,
            ringbuf_words.as_ptr(),
        )
    }
}

/// One WAIT syncop in a `DRM_IOCTL_PANTHOR_VM_BIND` submission,
/// emitted once the WAIT has been resolved to a dma_fence and before
/// the bind job is committed.
pub(crate) fn vm_bind_wait_fence(
    vm_id: u64,
    op_index: u32,
    syncop_index: u32,
    fence_context: u64,
    fence_seqno: u64,
    signalled: bool,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_vm_bind_wait_fence(
            vm_id,
            op_index,
            syncop_index,
            fence_context,
            fence_seqno,
            signalled,
        )
    }
}

/// One MAP / UNMAP / REMAP step on the gpuvm interval tree, emitted
/// from the matching `sm_step_*` callback before the step commits.
pub(crate) fn gpuvm_node_op(vm_id: u64, op: GpuVmNodeOp, va: u64, size: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_gpuvm_node_op(vm_id, op as u32, va, size) }
}

/// 256-byte window from the BO that contains the GPU VA derived from
/// `cs_extract` for the faulting queue. Emitted from the CSG IRQ
/// handler alongside [`cs_fault_event`] on the CS_FAULT and CS_FATAL
/// paths so a trace consumer can see the actual bytes the firmware
/// was decoding at the time of the fault.
///
/// `dump.bytes` carries `dump.len` valid bytes; the C side zero-fills
/// the trailing `256 - len` bytes of the record.
pub(crate) fn cs_user_stream_dump(
    group_id: u64,
    cs_id: u32,
    cs_extract: u64,
    dump: &CsUserStreamDump,
) {
    let len = dump.len.min(256);
    let ptr = if len == 0 {
        core::ptr::null()
    } else {
        dump.bytes.as_ptr()
    };
    pr_err!(
        "tyr DBG cs_user_stream_dump: group={} cs={} cs_extract={:#x} bo_va_base={:#x} bo_offset={:#x} payload_offset={:#x} status={} len={} bytes={}\n",
        group_id,
        cs_id,
        cs_extract,
        dump.bo_va_base,
        dump.bo_offset,
        dump.payload_offset,
        dump.status as u32,
        len,
        HexBytes(&dump.bytes[..len as usize]),
    );
    // SAFETY: `ptr` is either NULL (when `len == 0`) or points into
    // `dump.bytes`, which is a `[u8; 256]` field owned by `dump` and
    // valid for `len <= 256` bytes for the duration of this call.
    unsafe {
        tyr_cs_user_stream_dump(
            group_id,
            cs_id,
            cs_extract,
            dump.bo_va_base,
            dump.bo_offset,
            dump.payload_offset,
            dump.status as u32,
            len,
            ptr,
        )
    }
}

/// 32-byte snapshot of one tiler-heap context entry, dumped from the
/// kernel vmap of the pool's heap-context BO on CS_FAULT / CS_FATAL.
pub(crate) fn heap_context_dump(
    group_id: u64,
    cs_id: u32,
    heap_index: u32,
    heap_context_va: u64,
    chunk_count: u32,
    content: &[u8; 32],
) {
    pr_err!(
        "tyr DBG heap_context_dump: group={} cs={} heap_index={} heap_context_va={:#x} chunk_count={} bytes={}\n",
        group_id,
        cs_id,
        heap_index,
        heap_context_va,
        chunk_count,
        HexBytes(&content[..]),
    );
    // SAFETY: `content` is a borrow of a `[u8; 32]`, so the pointer is
    // valid and readable for 32 bytes for the duration of the call.
    unsafe {
        tyr_heap_context_dump(
            group_id,
            cs_id,
            heap_index,
            heap_context_va,
            chunk_count,
            content.as_ptr(),
        )
    }
}

/// 64-byte snapshot of one tiler-heap chunk header, dumped from the
/// kernel vmap of the chunk BO on CS_FAULT / CS_FATAL.
pub(crate) fn heap_chunk_dump(
    group_id: u64,
    cs_id: u32,
    heap_index: u32,
    chunk_index: u32,
    chunk_va: u64,
    header: &[u8; 64],
) {
    pr_err!(
        "tyr DBG heap_chunk_dump: group={} cs={} heap_index={} chunk_index={} chunk_va={:#x} bytes={}\n",
        group_id,
        cs_id,
        heap_index,
        chunk_index,
        chunk_va,
        HexBytes(&header[..]),
    );
    // SAFETY: `header` is a borrow of a `[u8; 64]`, so the pointer is
    // valid and readable for 64 bytes for the duration of the call.
    unsafe {
        tyr_heap_chunk_dump(
            group_id,
            cs_id,
            heap_index,
            chunk_index,
            chunk_va,
            header.as_ptr(),
        )
    }
}

/// Returns a short mnemonic for a Mali CSF instruction opcode (the
/// most-significant byte of the 8-byte little-endian instruction
/// word). The table covers the common opcodes observed in Mesa-emitted
/// command streams; anything else falls through to `"UNKNOWN"`.
///
/// Reference: Mesa's panfrost `genxml/v10.xml` and `lib/pan_csf.h`.
/// `0x33` is a HEAP_OPERATION variant seen in the kmscube workload;
/// the canonical Mali HEAP_OPERATION opcode is `0x31`.
fn cs_opcode_mnemonic(opcode: u8) -> &'static CStr {
    match opcode {
        0x00 => c_str!("NOP"),
        0x01 => c_str!("MOVE32"),
        0x02 => c_str!("MOVE48"),
        0x03 => c_str!("ADD32"),
        0x04 => c_str!("LSHIFT32"),
        0x05 => c_str!("RSHIFT32"),
        0x06 => c_str!("ICMP32"),
        0x07 => c_str!("UCMP32"),
        0x08 => c_str!("BRANCH"),
        0x09 => c_str!("WAIT"),
        0x0a => c_str!("ADD64"),
        0x10 => c_str!("LD_AT"),
        0x11 => c_str!("LD_AT_IMM"),
        0x14 => c_str!("STR_AT"),
        0x15 => c_str!("STR_AT_IMM"),
        0x16 => c_str!("EVADD"),
        0x17 => c_str!("EVSTR"),
        0x18 => c_str!("EVWAIT"),
        0x20 => c_str!("CALL"),
        0x21 => c_str!("JUMP"),
        0x22 => c_str!("RETURN"),
        0x24 => c_str!("ENDPT"),
        0x2a => c_str!("PROGRESS_STORE"),
        0x2b => c_str!("PROGRESS_LOAD"),
        0x2f => c_str!("RUN_IDVS"),
        0x30 => c_str!("RUN_TILING_PASS"),
        0x31 | 0x33 => c_str!("HEAP_OPERATION"),
        0x32 => c_str!("RUN_FRAGMENT"),
        0x34 => c_str!("SYNC_ADD32"),
        0x35 => c_str!("SYNC_ADD64"),
        0x36 => c_str!("SYNC_SET32"),
        0x37 => c_str!("SYNC_SET64"),
        0x38 => c_str!("SYNC_WAIT32"),
        0x39 => c_str!("SYNC_WAIT64"),
        0x3a => c_str!("SYNC_ADD_AND_UPDATE32"),
        0x3b => c_str!("STORE_STATE"),
        0x3c => c_str!("PROT_REGION_OUTER_ENABLE"),
        0x3d => c_str!("REGISTER_DUMP"),
        _ => c_str!("UNKNOWN"),
    }
}

/// Eight-instruction decode of the CS bytes starting at the firmware's
/// execution pointer. `bytes` carries `len` valid bytes (`len <= 64`
/// and is a multiple of 8 on a clean read); the first eight describe
/// the instruction the GPU is decoding now and the opcode/mnemonic
/// fields are derived from it. `ringbuf_va` is the GPU VA the
/// instructions were read from (i.e. `ringbuf_base + (cs_extract %
/// ringbuf_size)`).
pub(crate) fn cs_fault_instruction_decode(
    group_id: u64,
    cs_id: u32,
    cs_extract: u64,
    ringbuf_va: u64,
    bytes: &[u8],
) {
    let len = bytes.len().min(64) as u32;
    let opcode = if bytes.len() >= 8 { bytes[7] } else { 0 };
    let mnemonic = cs_opcode_mnemonic(opcode);
    let ptr = if len == 0 {
        core::ptr::null()
    } else {
        bytes.as_ptr()
    };
    pr_err!(
        "tyr DBG cs_fault_instruction_decode: group={} cs={} cs_extract={:#x} ringbuf_va={:#x} opcode={:#04x} mnemonic={} len={} bytes={}\n",
        group_id,
        cs_id,
        cs_extract,
        ringbuf_va,
        opcode,
        mnemonic.to_str().unwrap_or("UNKNOWN"),
        len,
        HexBytes(&bytes[..len as usize]),
    );
    // SAFETY: `mnemonic` is a `&'static CStr` (valid nul-terminated C
    // string), and `ptr` is either NULL (when `len == 0`) or borrows
    // `bytes` for at least `len` bytes for the duration of this call.
    unsafe {
        tyr_cs_fault_instruction_decode(
            group_id,
            cs_id,
            cs_extract,
            ringbuf_va,
            u32::from(opcode),
            mnemonic.as_char_ptr(),
            ptr,
            len,
        )
    }
}

/// Byte window from the BO covering `CS_FAULT_INFO`. `bytes.len()`
/// may be `0` when no BO covers `info_va` or when no kernel mapping
/// is reachable; in that case `bo_va_base`/`bo_size`/`bo_offset` still
/// carry whatever metadata could be resolved (zeros for the no-BO
/// case).
pub(crate) fn cs_fault_info_dump(
    group_id: u64,
    cs_id: u32,
    info_va: u64,
    bo_va_base: u64,
    bo_size: u64,
    bo_offset: u64,
    bytes: &[u8],
) {
    let len = bytes.len().min(256) as u32;
    let ptr = if len == 0 {
        core::ptr::null()
    } else {
        bytes.as_ptr()
    };
    pr_err!(
        "tyr DBG cs_fault_info_dump: group={} cs={} info_va={:#x} bo_va_base={:#x} bo_size={:#x} bo_offset={:#x} len={} bytes={}\n",
        group_id,
        cs_id,
        info_va,
        bo_va_base,
        bo_size,
        bo_offset,
        len,
        HexBytes(&bytes[..len as usize]),
    );
    // SAFETY: `ptr` is either NULL (when `len == 0`) or borrows
    // `bytes` for at least `len` bytes for the duration of this call.
    unsafe {
        tyr_cs_fault_info_dump(
            group_id, cs_id, info_va, bo_va_base, bo_size, bo_offset, ptr, len,
        )
    }
}

/// VM_BIND fence about to be signalled from the bind queue's submit
/// callback. Fires inside the dma-fence signalling section, immediately
/// before `DriverDmaFence::signal`.
pub(crate) fn vm_bind_fence_signal(
    vm_id: u64,
    fence_ctx: u64,
    fence_seqno: u64,
    op_kind: VmBindFenceOpKind,
    op_count: u32,
    errno: i32,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_vm_bind_fence_signal(
            vm_id,
            fence_ctx,
            fence_seqno,
            op_kind as u32,
            op_count,
            errno,
        )
    }
}

/// One VM_BIND op about to execute (map / unmap) from the bind queue's
/// submit callback, after the bind job's framework deps have resolved.
/// Pair with [`vm_bind_fence_signal`] to expose the delta between the
/// page-table mutation and the bind fence signal. Fires inside the
/// dma-fence signalling section.
pub(crate) fn vm_bind_op_run(
    vm_id: u64,
    op_kind: VmBindOpRunKind,
    va_base: u64,
    va_len: u64,
    gem_offset: u64,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_vm_bind_op_run(vm_id, op_kind as u32, va_base, va_len, gem_offset) }
}

/// One dependency fence appended to a prepared Tyr job. Fires per-dep
/// at prepare time for [`JobDepSource::External`] deps and per-dep at
/// commit time for [`JobDepSource::IntraBatch`] deps; the latter fires
/// inside the dma-fence signalling section. `handle`/`point` carry the
/// Mesa-supplied syncobj handle and timeline point of the WAIT syncop
/// that produced the dep.
#[allow(clippy::too_many_arguments)]
pub(crate) fn job_dep_added(
    group_id: u64,
    queue_index: u32,
    job_counter: u64,
    source: JobDepSource,
    handle: u32,
    point: u64,
    dep_ctx: u64,
    dep_seqno: u64,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_job_dep_added(
            group_id,
            queue_index,
            job_counter,
            source as u32,
            handle,
            point,
            dep_ctx,
            dep_seqno,
        )
    }
}

/// All dependency fences for a Tyr job have been observed signalled
/// and the framework has handed the job to the driver's submit
/// callback. Fires inside the dma-fence signalling section.
pub(crate) fn job_deps_satisfied(
    group_id: u64,
    queue_index: u32,
    job_counter: u64,
    dep_count: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_job_deps_satisfied(group_id, queue_index, job_counter, dep_count) }
}

/// A batch-produced submit fence is about to be installed onto its
/// user-visible syncobj by [`crate::sched::deps::Context::push_fences`].
/// Runs outside the dma-fence signalling section.
pub(crate) fn syncobj_publish(
    syncobj_handle: u32,
    point: u64,
    fence_ctx: u64,
    fence_seqno: u64,
    kind: SyncobjPublishKind,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_syncobj_publish(syncobj_handle, point, fence_ctx, fence_seqno, kind as u32) }
}

/// One intra-batch WAIT has been resolved to the matching producer's
/// submit fence inside [`crate::sched::deps::Context::commit`].
/// `dep_signaled` reflects `dma_fence_is_signaled()` at resolution
/// time; a `true` value identifies an ordering bug where the producer
/// has already signalled by the time the consumer commits. Fires
/// inside the dma-fence signalling section.
#[allow(clippy::too_many_arguments)]
pub(crate) fn intra_batch_dep_resolved(
    group_id: u64,
    queue_index: u32,
    job_counter: u64,
    handle: u32,
    point: u64,
    dep_ctx: u64,
    dep_seqno: u64,
    dep_signaled: bool,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_intra_batch_dep_resolved(
            group_id,
            queue_index,
            job_counter,
            handle,
            point,
            dep_ctx,
            dep_seqno,
            dep_signaled,
        )
    }
}

/// One external WAIT syncop has been resolved to a dependency fence via
/// `drm_syncobj_find_fence` in [`crate::sched::deps::Context::prepare`].
/// The symmetric counterpart of [`syncobj_publish`] on the consumer side.
/// `fence_ctx`/`fence_seqno` identify the producer fence the consumer's
/// job will wait on, and `signaled` reflects `dma_fence_is_signaled()` at
/// resolution time. `point` is `0` for binary syncobjs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn syncobj_wait(
    group_id: u64,
    queue_index: u32,
    job_counter: u64,
    syncobj_handle: u32,
    point: u64,
    fence_ctx: u64,
    fence_seqno: u64,
    signaled: bool,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_syncobj_wait(
            group_id,
            queue_index,
            job_counter,
            syncobj_handle,
            point,
            fence_ctx,
            fence_seqno,
            signaled,
        )
    }
}

/// An AS hardware slot was enabled with the given VM's page-table base.
/// `transtab` is the value programmed into `TRANSTAB_LO/HI`, so the slot
/// can be checked against the VM's actual page tables.
pub(crate) fn as_enable(vm_id: u64, as_slot: u32, transtab: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_as_enable(vm_id, as_slot, transtab) }
}

/// An AS hardware slot was disabled and its translation registers
/// cleared.
pub(crate) fn as_disable(vm_id: u64, as_slot: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_as_disable(vm_id, as_slot) }
}

/// An atomic translation-table update began on an AS slot (MMU LOCK).
/// `region_size` is the unrounded size of the requested locked range.
pub(crate) fn as_update_start(vm_id: u64, as_slot: u32, region_start: u64, region_size: u64) {
    // SAFETY: Always safe to call.
    unsafe { tyr_as_update_start(vm_id, as_slot, region_start, region_size) }
}

/// An atomic translation-table update completed on an AS slot (cache
/// flush followed by MMU UNLOCK), i.e. the per-bind TLB invalidation
/// point.
pub(crate) fn as_update_end(vm_id: u64, as_slot: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_as_update_end(vm_id, as_slot) }
}

/// The GPU-side `flush_caches` command issued during an AS disable or
/// translation-table update. `l2`, `lsc` and `other` are the
/// `FlushMode` discriminants for each cache.
pub(crate) fn gpu_flush_caches(as_slot: u32, l2: u32, lsc: u32, other: u32) {
    // SAFETY: Always safe to call.
    unsafe { tyr_gpu_flush_caches(as_slot, l2, lsc, other) }
}

/// Begin/end phase shared by the runtime suspend and resume events.
/// Keep in sync with `TYR_PM_PHASES` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum PmPhase {
    Begin = 0,
    End = 1,
}

/// Devfreq sub-step. Keep in sync with `TYR_PM_DEVFREQ_OPS` in
/// `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum PmDevfreqOp {
    Suspend = 0,
    Resume = 1,
}

/// Scheduler usage-reference event. Keep in sync with
/// `TYR_PM_USAGE_EVENTS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum PmUsageEvent {
    /// A usage reference was taken for the scheduler.
    Acquire = 0,
    /// The held usage reference was dropped.
    Release = 1,
    /// `get_if_active` reported the device down, so a hardware access
    /// was skipped.
    SkipInactive = 2,
    /// A resident-queue doorbell kick was requested after a failed
    /// runtime suspend.
    ResidentKick = 3,
}

/// Suspend/resume choreography step. Keep in sync with
/// `TYR_PM_HW_STEPS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum PmHwStep {
    FwSuspend = 0,
    FwResume = 1,
    L2On = 2,
    L2Off = 3,
    MmuSuspend = 4,
    /// The runtime-suspend flush of the scheduler workers began.
    DrainWorkBegin = 5,
    /// The runtime-suspend flush of the scheduler workers finished.
    DrainWorkEnd = 6,
}

/// Runtime suspend entry and exit. `errno` is meaningful only on
/// [`PmPhase::End`].
pub(crate) fn pm_runtime_suspend(phase: PmPhase, errno: c_int) {
    // SAFETY: Always safe to call.
    unsafe { tyr_pm_runtime_suspend(phase as u32, errno) }
}

/// Runtime resume entry and exit. `errno` is meaningful only on
/// [`PmPhase::End`].
pub(crate) fn pm_runtime_resume(phase: PmPhase, errno: c_int) {
    // SAFETY: Always safe to call.
    unsafe { tyr_pm_runtime_resume(phase as u32, errno) }
}

/// Result of a devfreq suspend or resume sub-step.
pub(crate) fn pm_devfreq(op: PmDevfreqOp, errno: c_int) {
    // SAFETY: Always safe to call.
    unsafe { tyr_pm_devfreq(op as u32, errno) }
}

/// Scheduler runtime-PM usage-reference event. `acquired` reports
/// whether a reference is held after the event.
pub(crate) fn pm_usage(event: PmUsageEvent, acquired: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_pm_usage(event as u32, acquired) }
}

/// A suspend or resume choreography step and its result.
pub(crate) fn pm_hw(step: PmHwStep, errno: c_int) {
    // SAFETY: Always safe to call.
    unsafe { tyr_pm_hw(step as u32, errno) }
}

/// Why a reset was requested. Keep in sync with `TYR_RESET_REASONS` in
/// `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum ResetReason {
    /// The firmware missed a liveness ping.
    FwPingTimeout = 0,
    /// A CSG slot reported an unknown execution state.
    CsgStateUnknown = 1,
    /// The firmware cannot resume an unrecoverable command stream.
    CsUnrecoverable = 2,
    /// A CSG request timed out during a scheduler tick.
    CsgReqTimeout = 3,
    /// An address-space slot's `AS_ACTIVE` bit stayed set.
    AsActiveStuck = 4,
    /// A cache-flush command was never acknowledged.
    CacheFlushTimeout = 5,
}

/// Outcome of one `schedule()` call. Keep in sync with
/// `TYR_RESET_SCHEDULE_OUTCOMES` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum ResetScheduleOutcome {
    /// No DRM device is bound, so the request was dropped.
    NoDevice = 0,
    /// The device is not runtime-active, so the request latched
    /// without queuing the worker.
    Latched = 1,
    /// A reset that is already pending or in progress absorbed the
    /// request.
    Coalesced = 2,
    /// The request was newly latched and the worker queued.
    Queued = 3,
}

/// Outcome of one reset-worker invocation. Keep in sync with
/// `TYR_RESET_WORKER_OUTCOMES` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum ResetWorkerOutcome {
    /// No DRM device is bound, so the request was consumed without
    /// touching the hardware.
    NoDevice = 0,
    /// The device is not runtime-active, so the request stays latched
    /// for the resume path to claim.
    PmInactive = 1,
    /// The request could not be claimed because it was already consumed or
    /// another reset owns the state machine.
    ClaimFailed = 2,
    /// The worker claimed the request and runs the reset cycle.
    Run = 3,
}

/// Reset-cycle phase. The worker's `Run` outcome marks the cycle
/// start. `errno` is meaningful on `SoftReset` and `FwReboot`. On
/// `End` it carries the first failing errno of those steps, or `0` on
/// success. Keep in sync with `TYR_RESET_CYCLE_PHASES` in
/// `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum ResetCyclePhase {
    /// The scheduler, firmware and MMU pre-reset work has completed.
    Quiesced = 0,
    /// The soft reset ran.
    SoftReset = 1,
    /// The firmware reboot ran.
    FwReboot = 2,
    /// The cycle is complete.
    End = 3,
}

/// Runtime-PM path that handled a reset out of band. Keep in sync
/// with `TYR_RESET_PM_PATHS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum ResetPmPath {
    /// Suspend waits for an in-flight reset worker to finish.
    SuspendFlush = 0,
    /// Resume claimed a latched request and completed it with a full
    /// firmware reload instead of the fast reboot.
    ResumeReload = 1,
    /// Resume claimed a request that latched during its own firmware
    /// reboot and reloaded again.
    ResumeLateReload = 2,
}

/// Firmware ping watchdog event. Keep in sync with
/// `TYR_FW_PING_EVENTS` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum FwPingEvent {
    /// The ping ran; `errno` is `0` for an acknowledged ping.
    Result = 0,
    /// The ping was skipped because a reset is in progress.
    SkipReset = 1,
    /// The ping was skipped because the device is not runtime-active.
    SkipInactive = 2,
}

/// A reset request and its trigger, emitted before the request is
/// scheduled.
pub(crate) fn reset_request(reason: ResetReason) {
    // SAFETY: Always safe to call.
    unsafe { tyr_reset_request(reason as u32) }
}

/// Outcome of one reset `schedule()` call.
pub(crate) fn reset_schedule(outcome: ResetScheduleOutcome) {
    // SAFETY: Always safe to call.
    unsafe { tyr_reset_schedule(outcome as u32) }
}

/// Outcome of one reset-worker invocation.
pub(crate) fn reset_worker(outcome: ResetWorkerOutcome) {
    // SAFETY: Always safe to call.
    unsafe { tyr_reset_worker(outcome as u32) }
}

/// A reset-cycle phase transition and its result.
pub(crate) fn reset_cycle(phase: ResetCyclePhase, errno: c_int) {
    // SAFETY: Always safe to call.
    unsafe { tyr_reset_cycle(phase as u32, errno) }
}

/// A runtime-PM path that handled a reset out of band.
pub(crate) fn reset_pm(path: ResetPmPath, errno: c_int) {
    // SAFETY: Always safe to call.
    unsafe { tyr_reset_pm(path as u32, errno) }
}

/// A firmware ping watchdog event and its result.
pub(crate) fn fw_ping(event: FwPingEvent, errno: c_int) {
    // SAFETY: Always safe to call.
    unsafe { tyr_fw_ping(event as u32, errno) }
}

/// Global-interface liveness probe run for a CSG slot whose request
/// stayed unacked through a re-kick. Downstream-only debug aid.
/// Not for upstream.
#[allow(clippy::too_many_arguments)]
pub(crate) fn wedge_glb_probe(
    csg_id: u32,
    req_mask: u32,
    glb_req_before: u32,
    glb_ack_before: u32,
    glb_req_after: u32,
    glb_ack_after: u32,
    ping_acked: bool,
    mcu_status: u32,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_wedge_glb_probe(
            csg_id,
            req_mask,
            glb_req_before,
            glb_ack_before,
            glb_req_after,
            glb_ack_after,
            ping_acked,
            mcu_status,
        )
    }
}

/// Wait, block and tiler-heap output state of one CS interface, dumped
/// for every CSG slot when a CSG ack times out. `group_uid` is 0 and the
/// state is stale when no group is bound to the slot, and
/// `blocked_reason` is `u32::MAX` when the firmware value does not
/// decode. Downstream-only debug aid. Not for upstream.
#[allow(clippy::too_many_arguments)]
pub(crate) fn wedge_cs_state(
    csg_id: u32,
    group_uid: u64,
    cs_id: u32,
    status_wait: u32,
    blocked_reason: u32,
    req_resource: u32,
    heap_address: u64,
    vt_start: u32,
    vt_end: u32,
    frag_end: u32,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_wedge_cs_state(
            csg_id,
            group_uid,
            cs_id,
            status_wait,
            blocked_reason,
            req_resource,
            heap_address,
            vt_start,
            vt_end,
            frag_end,
        )
    }
}

/// Outcome of one tiler-heap grow attempt. Keep in sync with
/// `TYR_HEAP_GROW_OUTCOMES` in `include/trace/events/tyr.h`.
#[repr(u32)]
pub(crate) enum HeapGrowOutcome {
    /// A chunk was linked into the heap.
    Grown = 0,
    /// The heap cannot grow, so the firmware is asked to reclaim.
    Reclaim = 1,
    /// The grow failed unexpectedly and the queue is marked fatal.
    Fatal = 2,
}

/// State a tiler-heap grow decision was taken on, and its outcome. The
/// counts are the ones the decision was taken on, so on a grow they
/// precede the new chunk. A `Fatal` outcome can carry zeroes, because
/// the heap the grow addressed was never found.
#[allow(clippy::too_many_arguments)]
pub(crate) fn heap_grow_decision(
    group_uid: u64,
    cs_id: u32,
    chunk_count: u32,
    max_chunks: u32,
    renderpasses_in_flight: u32,
    target_in_flight: u32,
    pending_frag_count: u32,
    outcome: HeapGrowOutcome,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_heap_grow_decision(
            group_uid,
            cs_id,
            chunk_count,
            max_chunks,
            renderpasses_in_flight,
            target_in_flight,
            pending_frag_count,
            outcome as u32,
        )
    }
}
