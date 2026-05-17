// SPDX-License-Identifier: GPL-2.0 or MIT

//! Tyr tracepoints.
//!
//! Safe Rust wrappers around the C tracepoint thunks declared in
//! `include/trace/events/tyr.h`. The unsafe `tyr_*` block is private to
//! this module.

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
        cs: u32,
        req: u32,
        ack: u32,
        status_wait: u32,
        blocked_reason: u32,
        scoreboards: u32,
        sync_pointer: u64,
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
    unsafe fn tyr_csg_slot_assign(csg: u32, group: u64, assigned: bool);

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
    unsafe fn tyr_syncwait_capture(
        vm_id: u64,
        group_id: u64,
        cs_id: u32,
        gpu_va: u64,
        ref_val: u64,
        sync64: u32,
        gt: u32,
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
    /// when no BO was located. Independent of `payload_offset`: this
    /// is always the actual consumption point.
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
    /// `NoBoAtVa` sentinel: no BO located, no payload captured.
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
    cs: u32,
    req: u32,
    ack: u32,
    status_wait: u32,
    blocked_reason: u32,
    scoreboards: u32,
    sync_pointer: u64,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_cs_status_snapshot(
            csg,
            cs,
            req,
            ack,
            status_wait,
            blocked_reason,
            scoreboards,
            sync_pointer,
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
pub(crate) fn csg_slot_assign(csg: u32, group: u64, assigned: bool) {
    // SAFETY: Always safe to call.
    unsafe { tyr_csg_slot_assign(csg, group, assigned) }
}

/// Snapshot of the per-CSG output state: status, endpoint allocation
/// and resource dependencies. Emitted after a `STATUS_UPDATE` ack and
/// on the timeout path so a stuck slot's reported state is captured
/// even when the wait timed out.
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
/// reported as `0`.
pub(crate) fn vm_bind_op_sync(
    vm_id: u64,
    op_kind: u32,
    va: u64,
    size: u64,
    n_waits: u32,
    n_signals: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_vm_bind_op_sync(vm_id, op_kind, va, size, n_waits, n_signals) }
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
/// later read back.
pub(crate) fn syncwait_capture(
    vm_id: u64,
    group_id: u64,
    cs_id: u32,
    gpu_va: u64,
    ref_val: u64,
    sync64: bool,
    gt: bool,
) {
    // SAFETY: Always safe to call.
    unsafe {
        tyr_syncwait_capture(
            vm_id,
            group_id,
            cs_id,
            gpu_va,
            ref_val,
            u32::from(sync64),
            u32::from(gt),
        )
    }
}

/// One transition of a queue's bit in `GroupInner::blocked_queues`,
/// emitted right after `set_queue_blocked` at the two sites that
/// drive the bitmap: the snapshot apply phase in
/// `sync_csg_slot_queues_state` and the result apply phase in
/// `apply_syncwait_results`. `caller` identifies which one fired.
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
    old_state: u32,
    new_state: u32,
    reason: StateChangeReason,
) {
    // SAFETY: Always safe to call.
    unsafe { tyr_group_state_transition(group_id, old_state, new_state, reason as u32) }
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
/// emitted after the WAIT has been resolved to a dma_fence but before
/// that fence is registered with the vm_bind job-queue framework.
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
