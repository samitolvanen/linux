// SPDX-License-Identifier: GPL-2.0

//! Debug tracepoints for [`JobQueue`](super::JobQueue).
//!
//! Downstream-only debug aid, not for upstream. The events are described in
//! `include/trace/events/rust_jq_debug.h`, which decodes the enums below.
//!
//! The tracepoints are not exported, but `JobQueue` is generic and
//! instantiated in drivers. So the wrappers are non-generic and never inlined.

// `declare_trace!` passes its arguments to an `unsafe` call.
#![allow(clippy::macro_metavars_in_unsafe)]

use crate::{
    dma_buf::dma_fence::Fence,
    drm::job_queue::RunResult,
    prelude::*,
    tracepoint::declare_trace, //
};

/// What happened to a fence passed to a job as a dependency.
pub(crate) enum DepAction {
    Added = 0,
    Signaled = 1,
    OwnDropped = 2,
    AllocFail = 3,
    With = 4,
}

/// A JobQueue worker.
pub(crate) enum Worker {
    Submit = 0,
    Drop = 1,
}

/// What kicks a worker.
pub(crate) enum KickSource {
    Submit = 0,
    Dep = 1,
    Completion = 2,
    Wake = 3,
    Unpark = 4,
    RunRace = 5,
}

/// Why the SubmitWorker stops.
pub(crate) enum EndReason {
    Empty = 0,
    Parked = 1,
    Deps = 2,
    Capacity = 3,
    NoResources = 4,
    Revoked = 5,
}

/// The phase of the drop of a batch of jobs.
pub(crate) enum DropPhase {
    Begin = 0,
    End = 1,
}

declare_trace! {
    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_job_new(jq_id: u64, job: usize, cost: u32, max_capacity: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_dep(jq_id: u64, job: usize, dep_ctx: u64, dep_seqno: u64, action: u32);

    /// # Safety
    ///
    /// Always safe to call.
    #[expect(clippy::too_many_arguments)]
    unsafe fn rust_jq_dep_walk(
        jq_id: u64,
        job: usize,
        ctx: u64,
        seqno: u64,
        truncated: bool,
        visited: usize,
        rest_ctx: u64,
        rest_seqno: u64,
        budget_left: usize,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_submit(
        jq_id: u64,
        seqno: u64,
        job: usize,
        cost: u32,
        pending_deps: u32,
        capacity: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_dep_signal(
        jq_id: u64,
        job: usize,
        dep_ctx: u64,
        dep_seqno: u64,
        errno: c_int,
        remaining: u32,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_kill(jq_id: u64, errno: c_int);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_kick(jq_id: u64, worker: u32, source: u32, queued: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_worker_begin(
        jq_id: u64,
        capacity: u64,
        last_completed: u64,
        parked: bool,
        waiting_empty: bool,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_run_job(jq_id: u64, seqno: u64, cost: u32, capacity: u64);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_run_job_done(
        jq_id: u64,
        seqno: u64,
        result: u32,
        completed_in_run: bool,
        capacity: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_worker_end(
        jq_id: u64,
        reason: u32,
        ran: u32,
        head_seqno: u64,
        head_deps: u32,
        head_cost: u32,
        capacity: u64,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_complete(
        jq_id: u64,
        seqno: u64,
        count: u32,
        errno: c_int,
        capacity: u64,
        waiting: bool,
        stale: bool,
    );

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_drop_batch(jq_id: u64, count: u32, phase: u32);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_park(jq_id: u64, parked: bool);

    /// # Safety
    ///
    /// Always safe to call.
    unsafe fn rust_jq_teardown(jq_id: u64, running: u32, waiting: u32, errno: c_int);
}

fn to_errno(res: Result) -> c_int {
    match res {
        Ok(()) => 0,
        Err(err) => err.to_errno(),
    }
}

#[inline(never)]
pub(crate) fn job_new(jq_id: u64, job: usize, cost: u32, max_capacity: u64) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_job_new(jq_id, job, cost, max_capacity) }
}

#[inline(never)]
pub(crate) fn dep(jq_id: u64, job: usize, fence: &Fence, action: DepAction) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_dep(jq_id, job, fence.context_id(), fence.seqno(), action as u32) }
}

#[inline(never)]
pub(crate) fn dep_walk(
    jq_id: u64,
    job: usize,
    fence: &Fence,
    visited: usize,
    rest: Option<&Fence>,
    budget_left: usize,
) {
    let (rest_ctx, rest_seqno) = rest.map_or((0, 0), |rest| (rest.context_id(), rest.seqno()));
    // SAFETY: Always safe to call.
    unsafe {
        rust_jq_dep_walk(
            jq_id,
            job,
            fence.context_id(),
            fence.seqno(),
            rest.is_some(),
            visited,
            rest_ctx,
            rest_seqno,
            budget_left,
        )
    }
}

#[inline(never)]
pub(crate) fn submit(
    jq_id: u64,
    seqno: u64,
    job: usize,
    cost: u32,
    pending_deps: u32,
    capacity: u64,
) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_submit(jq_id, seqno, job, cost, pending_deps, capacity) }
}

#[inline(never)]
pub(crate) fn dep_signal(
    jq_id: u64,
    job: usize,
    dep_ctx: u64,
    dep_seqno: u64,
    res: Result,
    remaining: u32,
) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_dep_signal(jq_id, job, dep_ctx, dep_seqno, to_errno(res), remaining) }
}

#[inline(never)]
pub(crate) fn kill(jq_id: u64, err: Error) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_kill(jq_id, err.to_errno()) }
}

#[inline(never)]
pub(crate) fn kick(jq_id: u64, worker: Worker, source: KickSource, queued: bool) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_kick(jq_id, worker as u32, source as u32, queued) }
}

#[inline(never)]
pub(crate) fn worker_begin(
    jq_id: u64,
    capacity: u64,
    last_completed: u64,
    parked: bool,
    waiting_empty: bool,
) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_worker_begin(jq_id, capacity, last_completed, parked, waiting_empty) }
}

#[inline(never)]
pub(crate) fn run_job(jq_id: u64, seqno: u64, cost: u32, capacity: u64) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_run_job(jq_id, seqno, cost, capacity) }
}

#[inline(never)]
pub(crate) fn run_job_done(
    jq_id: u64,
    seqno: u64,
    result: RunResult,
    completed_in_run: bool,
    capacity: u64,
) {
    let result = match result {
        RunResult::Ran => 0,
        RunResult::NoResources => 1,
    };
    // SAFETY: Always safe to call.
    unsafe { rust_jq_run_job_done(jq_id, seqno, result, completed_in_run, capacity) }
}

#[inline(never)]
pub(crate) fn worker_end(
    jq_id: u64,
    reason: EndReason,
    ran: u32,
    head_seqno: u64,
    head_deps: u32,
    head_cost: u32,
    capacity: u64,
) {
    // SAFETY: Always safe to call.
    unsafe {
        rust_jq_worker_end(
            jq_id,
            reason as u32,
            ran,
            head_seqno,
            head_deps,
            head_cost,
            capacity,
        )
    }
}

#[inline(never)]
pub(crate) fn complete(
    jq_id: u64,
    seqno: u64,
    count: u32,
    res: Result,
    capacity: u64,
    waiting: bool,
    stale: bool,
) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_complete(jq_id, seqno, count, to_errno(res), capacity, waiting, stale) }
}

#[inline(never)]
pub(crate) fn drop_batch(jq_id: u64, count: u32, phase: DropPhase) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_drop_batch(jq_id, count, phase as u32) }
}

#[inline(never)]
pub(crate) fn park(jq_id: u64, parked: bool) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_park(jq_id, parked) }
}

#[inline(never)]
pub(crate) fn teardown(jq_id: u64, running: u32, waiting: u32, err: Error) {
    // SAFETY: Always safe to call.
    unsafe { rust_jq_teardown(jq_id, running, waiting, err.to_errno()) }
}
