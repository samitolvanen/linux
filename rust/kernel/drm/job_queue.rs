// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2025, 2026 Red Hat Inc.:
//   - Philipp Stanner <pstanner@redhat.com>

//! Job Queue - An XArray-backed pipeline that manages job dependencies
//!
//! This module provides a simplified alternative to the DRM GPU scheduler for
//! firmware-assisted GPU scheduling scenarios. Instead of making scheduling
//! decisions, it focuses on dependency tracking, driver submission, and
//! lifecycle management.
//!
//! # Architecture
//!
//! Jobs live in a single XArray, allocated via `xa_alloc_cyclic`. Internally,
//! the JobQueue splits this allocation into multiple stages by maintaining
//! "cursor" indices that track which entries belong to each stage.
//!
//! Stage transitions are O(1) cursor advances on [`WrapRange`] boundaries and
//! no data is copied or moved. The five stages form a pipeline:
//!
//! Submitted -> WaitingForDeps -> WaitingForExec -> Executing -> Done
//!
//! - Submitted: The job is in the XArray but not yet visible to the pipeline.
//!   The public `submit()` method inserts the entry under the `inbox` mutex
//!   (which also covers the XArray's internal `xa_lock`) and advances
//!   `submitted_end`.
//!
//!   At the top of each `check_progress()`, the pipeline drains entries from
//!   `submitted_start..submitted_end` into `deps_range`. This allows the queue
//!   to accept more submissions while the rest of the queue is locked due to a
//!   progress check taking place. Ignoring this separation may cause a deadlock
//!   because the driver's `submit()` path may take driver locks and then wait
//!   on the `state` mutex held by `check_progress()`, while `check_progress()`
//!   waits on said locks driver locks during `handler.submit()`.
//!
//!   The current design solves this lock ordering problem by splitting
//!   `submit()` and `check_progress()` state into two separate locks: `inbox`
//!   for the submission path, and `state` for the progress check path. The
//!   `inbox` mutex is only held briefly at the top of `check_progress()` to
//!   drain new submissions, while the rest of the progress check logic
//!   (including calls to the driver's `submit()`) happens under the `state`
//!   mutex, which is never touched by `submit()`.  This allows the driver to
//!   acquire its own locks and call back into the job queue from its `submit()`
//!   implementation without risking deadlock with the progress check logic.
//!
//!
//!   - WaitingForDeps: The job's dependency fences have not all signaled yet.
//!   Dependencies are walked one at a time: a single callback is registered on
//!   the current dependency, and when it fires, `check_progress()`
//!   fast-forwards through any already-signaled deps before registering the
//!   next callback. If there are no further deps, the job moves to
//!   WaitingForExec.
//!
//!   Dependency callback registration only happens inside `check_progress()`,
//!   never inside a fence `signaled()` callback. This avoids the deadlock where
//!   `dma_fence_add_callback` is called while already holding a fence context
//!   spinlock from a prior `signaled()` invocation.
//!
//!
//! - WaitingForExec: All dependencies are met. The pipeline calls the
//!   driver's submit function. If the driver returns [`SubmitResult::NoResources`],
//!   the job stays here and is retried on the next progress check.
//!
//!
//! - Executing: The driver accepted the job and returned a hardware fence.
//!   When the HW fence signals, the submit fence is signaled directly from the
//!   HW fence callback, and the job moves to Done on the next progress check.
//!
//!
//! - Done: Cleanup stage. Entries are removed from the XArray in process
//!   context (via `cleanup_work`), freeing the `JobEntry` and allowing the
//!   XArray to shrink. This ensures that Jobs are dropped in process context.
//!
//! The current design allows more stages to be added by introducing new cursor
//! ranges and adding logic in `check_progress()`.

use core::sync::atomic::{
    AtomicBool,
    AtomicU64,
    Ordering, //
};

use crate::{
    c_str,
    dma_fence::{
        CallbackError,
        DmaFenceWork,
        DmaFenceWorkItem,
        DmaFenceWorkqueue,
        DriverDmaFence,
        DriverDmaFenceOps,
        FenceCallback,
        FenceCallbackRegistration,
        PublicDmaFence, //
        Published,
        UninitDmaFence,
    },
    error::Result,
    impl_has_dma_fence_work,
    impl_has_work,
    new_dma_fence_work,
    new_mutex,
    new_work,
    prelude::*,
    sync::{
        Arc,
        Mutex, //
    },
    types::ARef, //
    workqueue::{
        DelayedWork,
        OwnedQueue,
        Work,
        WorkItem,
        WqFlags, //
    },
    xarray::{
        AllocKind,
        ReservedIndex,
        XArray,
        XaLimit, //
    },
};

/// The result of a driver's submit call.
pub enum SubmitResult<FD: DriverDmaFenceOps> {
    /// The driver accepted the job and took ownership of the submit fence.
    /// The driver must eventually call [`DriverDmaFence::signal`] when the
    /// job completes or fails (directly or via a registered callback).
    Submitted,
    /// The driver has no resources available (e.g. ring buffer full).
    /// The fence is returned so the pipeline can retry on the next progress
    /// check, which is triggered by job completions or new submissions.
    NoResources(DriverDmaFence<FD, Published>),
}

/// A read-only reference to a submitted job, provided to the driver's submit
/// callback.
pub struct JobRef<'a, J: Send + Sync + 'static> {
    /// The driver's job data.
    pub job: &'a J,
    /// The public fence that will be signaled when this job completes.
    pub submit_fence: &'a ARef<PublicDmaFence>,
    /// Monotonic job counter, useful for debug/logging.
    pub counter: u64,
}

/// Driver callbacks for [`JobQueue`] -- all calls happen in process context.
pub trait QueueOps: Send + Sync + 'static {
    /// The type of job this handler processes.
    type Job: Send + Sync + 'static;

    /// The driver data type embedded in submit fences.
    ///
    /// Use a zero-sized type to avoid per-job allocation overhead.
    type FenceData: DriverDmaFenceOps + Send + 'static;

    /// Submit a job to the hardware. Called from process context.
    ///
    /// `fence` is owned by the call. On [`SubmitResult::Submitted`] the driver
    /// takes ownership and must eventually call [`DriverDmaFence::signal`]
    /// (directly or via a callback) when the job completes or fails. On
    /// [`SubmitResult::NoResources`] the fence is returned to the queue for
    /// the next retry. On `Err(..)` the driver must signal `fence` with the
    /// error before returning.
    fn submit(
        &self,
        job: &JobRef<'_, Self::Job>,
        fence: DriverDmaFence<Self::FenceData, Published>,
        wq: &DmaFenceWorkqueue,
    ) -> Result<SubmitResult<Self::FenceData>>;
}
/// A wrapping range over `u32` indices.
///
/// Used to track which XArray indices belong to each pipeline stage.
/// Handles wraparound at `u32::MAX` via wrapping arithmetic.
#[derive(Debug, Clone, Copy)]
struct WrapRange {
    start: u32,
    end: u32,
}

impl WrapRange {
    const fn new() -> Self {
        Self { start: 0, end: 0 }
    }

    fn is_empty(&self) -> bool {
        self.start == self.end
    }

    fn pop_front(&mut self) -> Option<u32> {
        if self.is_empty() {
            None
        } else {
            let idx = self.start;
            self.start = self.start.wrapping_add(1);
            Some(idx)
        }
    }

    fn push_back(&mut self) -> u32 {
        let idx = self.end;
        self.end = self.end.wrapping_add(1);
        idx
    }
}

/// Dependency tracking state for a single job.
struct JobDependencies<T: QueueOps> {
    /// All dependency fences, set at submit time.
    fences: KVec<ARef<PublicDmaFence>>,
    /// Which dependency we're currently waiting on.
    current_idx: usize,
    /// The currently active dependency callback (at most one at a time).
    active_cb: Option<Pin<KBox<FenceCallbackRegistration<DepCallback<T>>>>>,
}

/// A single per-job allocation stored in the XArray.
///
/// Each job gets exactly one `JobEntry` that lives for its entire lifetime in
/// the pipeline.
struct JobEntry<T: QueueOps> {
    /// The driver's job data.
    job: Arc<T::Job>,

    /// The public fence returned to the caller of `submit()`. Shared with
    /// dependency waiters and other observers.
    submit_fence: ARef<PublicDmaFence>,

    /// The driver-side submit fence handle. Present from job creation until
    /// the job is passed to [`QueueOps::submit`]; `None` thereafter (the
    /// driver owns it and will signal it when done, or on drop signals
    /// `ECANCELED`).
    submit_fence_drv: Option<DriverDmaFence<T::FenceData, Published>>,

    /// Monotonic job counter for debugging.
    counter: u64,

    deps: JobDependencies<T>,

    /// Callback registered on the submit fence to trigger a pipeline check
    /// promptly when the driver signals it.
    progress_cb: Option<Pin<KBox<FenceCallbackRegistration<ProgressCallback<T>>>>>,
}

// State managed by `submit()`. This is separate from `PipelineState` to avoid
// lock ordering issues between `submit()` and `check_progress()`. In other
// words, new jobs can be submitted even if the pipeline itself is locked.
struct InboxState {
    /// The `next` cursor for `xa_alloc_cyclic`.
    cyclic_next: u32,

    /// One past the last XArray index that `submit()` has written.
    /// `check_progress()` advances `submitted_start` up to this value to pull
    /// new entries into `deps_range`.
    submitted_end: u32,
}

/// The locked pipeline state.
struct PipelineState {
    /// Where the pipeline has consumed up to in the submitted range.
    /// Jobs in `submitted_start..inbox.submitted_end` have not yet
    /// been pulled into `deps_range`.
    submitted_start: u32,

    /// Jobs waiting for their dependency fences to signal.
    deps_range: WrapRange,

    /// Jobs whose deps are met, waiting for driver to accept.
    exec_range: WrapRange,

    /// Jobs on hardware, waiting for the driver fence to signal.
    hw_range: WrapRange,

    /// Completed jobs awaiting XArray cleanup in process context.
    done_range: WrapRange,

    /// When true, `check_exec()` stops at the exec stage and leaves jobs
    /// parked in `exec_range` until unparked. This is the analogue of
    /// removing a drm_sched entity from its run-queue.
    parked: bool,
}

impl PipelineState {
    fn new() -> Self {
        Self {
            submitted_start: 0,
            deps_range: WrapRange::new(),
            exec_range: WrapRange::new(),
            hw_range: WrapRange::new(),
            done_range: WrapRange::new(),
            parked: false,
        }
    }
}

/// The inner state of the job queue, shared via `Arc`.
#[pin_data]
struct JobQueueInner<T: QueueOps> {
    /// The XArray holding all job entries.
    ///
    /// Shared between `submit()` (insert) and `check_progress()`
    /// (read/modify/remove).
    ///
    ///  Access is serialized by the XArray's internal `xa_lock` spinlock.
    #[pin]
    fifo: XArray<KBox<JobEntry<T>>>,

    /// Inbox metadata.
    #[pin]
    inbox: Mutex<InboxState>,

    /// Pipeline cursors.
    #[pin]
    state: Mutex<PipelineState>,

    handler: T,

    /// Runs `check_progress()` in process context.
    #[pin]
    work: DmaFenceWork<JobQueueInner<T>>,

    /// Deferred drop of JobEntry in process context.
    #[pin]
    cleanup_work: Work<JobQueueInner<T>, 3>,

    /// Workqueue for the main pipeline check (enforces DMA fence signaling rules).
    wq: Arc<DmaFenceWorkqueue>,

    /// Internal workqueue for cleanup work.
    aux_queue: OwnedQueue,

    /// DMA fence context ID allocated at creation time.
    fence_ctx_id: u64,

    /// Monotonically increasing sequence number for submit fences.
    fence_seqno: AtomicU64,

    /// Monotonic job counter.
    job_counter: AtomicU64,

    /// When true, fence callbacks skip scheduling ticks via the workqueue, and
    /// ticks have to be manually triggered. This allows batching multiple fence
    /// signals into a single tick.
    coalesce: AtomicBool,
}

unsafe impl<T: QueueOps> Send for JobQueueInner<T> {}
unsafe impl<T: QueueOps> Sync for JobQueueInner<T> {}

impl_has_dma_fence_work! {
    impl{T: QueueOps} HasDmaFenceWork<JobQueueInner<T>> for JobQueueInner<T> { self.work }
}

impl_has_work! {
    impl{T: QueueOps} HasWork<JobQueueInner<T>, 3> for JobQueueInner<T> { self.cleanup_work }
}

impl<T: QueueOps> DmaFenceWorkItem for JobQueueInner<T> {
    type Pointer = Arc<Self>;

    fn run(this: Arc<Self>) {
        this.check_progress();
    }
}

impl<T: QueueOps> WorkItem<3> for JobQueueInner<T> {
    type Pointer = Arc<Self>;

    fn run(this: Arc<Self>) {
        this.do_cleanup();
    }
}

impl<T: QueueOps> JobQueueInner<T> {
    /// Pull newly submitted jobs from the inbox into `deps_range`.
    fn drain_inbox(&self, state: &mut PipelineState) {
        let end = self.inbox.lock().submitted_end;
        while state.submitted_start != end {
            state.deps_range.push_back();
            state.submitted_start = state.submitted_start.wrapping_add(1);
        }
    }

    /// The main pipeline tick. Runs in process context.
    fn check_progress(self: &Arc<Self>) {
        let mut state = self.state.lock();

        // Submitted -> WaitingForDeps.
        self.drain_inbox(&mut state);

        //  WaitingForDeps -> WaitingForExec.
        self.check_deps(&mut state);

        //  WaitingForExec -> Executing.
        self.check_exec(&mut state);

        //  Executing -> Done.
        self.check_retire(&mut state);

        //  Schedule deferred work as needed.
        let needs_cleanup = !state.done_range.is_empty();
        drop(state);

        if needs_cleanup {
            self.schedule_cleanup();
        }
    }

    /// Process the deps stage: walk dependency fences one at a time.
    ///
    /// For each job at the front of `deps_range`, we fast-forward through
    /// already-signaled fences, then register a callback on the next unsignaled
    /// one. If all deps are met, the job advances to `exec_range`.
    fn check_deps(self: &Arc<Self>, state: &mut PipelineState) {
        while !state.deps_range.is_empty() {
            let idx = state.deps_range.start;

            loop {
                let current_dependency = {
                    let guard = self.fifo.lock();
                    let Some(entry) = guard.get(idx as usize) else {
                        pr_err!(
                            "JobQueue: check_deps() BUG: xa_idx={} missing in deps_range, advancing\n",
                            idx
                        );
                        state.deps_range.pop_front();
                        state.exec_range.push_back();
                        break;
                    };

                    if entry.deps.current_idx >= entry.deps.fences.len() {
                        None // All deps satisfied
                    } else {
                        Some(entry.deps.fences[entry.deps.current_idx].clone())
                    }
                };

                let Some(dep_fence) = current_dependency else {
                    let mut guard = self.fifo.lock();
                    if let Some(entry) = guard.get_mut(idx as usize) {
                        // Free this allocation and drop the fences.
                        entry.deps.fences = KVec::new();
                    }
                    state.deps_range.pop_front();
                    state.exec_range.push_back();
                    break;
                };

                let callback = DepCallback {
                    inner: self.clone(),
                };
                match KBox::try_pin_init(
                    FenceCallbackRegistration::new(&dep_fence, callback),
                    GFP_KERNEL,
                ) {
                    Ok(registration) => {
                        let mut guard = self.fifo.lock();
                        if let Some(entry) = guard.get_mut(idx as usize) {
                            entry.deps.active_cb = Some(registration);
                        }
                        return;
                    }
                    Err(CallbackError::AlreadySignaled(_)) => {
                        let mut guard = self.fifo.lock();
                        if let Some(entry) = guard.get_mut(idx as usize) {
                            entry.deps.active_cb = None;
                            entry.deps.current_idx += 1;
                        }
                        // Continue inner loop for next dep.
                    }
                    Err(CallbackError::Other(e)) => {
                        pr_err!(
                            "JobQueue: check_deps() dep cb alloc failed: {:?}, skipping dep for job {}",
                            e,
                            idx
                        );
                        // Skip this dependency and try the next one.
                        let mut guard = self.fifo.lock();
                        if let Some(entry) = guard.get_mut(idx as usize) {
                            entry.deps.active_cb = None;
                            entry.deps.current_idx += 1;
                        }
                        // Continue inner loop for next dep.
                    }
                }
            }
        }
    }

    /// Process the exec stage: call the driver's submit handler.
    fn check_exec(self: &Arc<Self>, state: &mut PipelineState) {
        // If the queue is parked leave jobs in exec_range and wait for unpark()
        // to trigger a new tick.
        if state.parked {
            return;
        }

        while !state.exec_range.is_empty() {
            let idx = state.exec_range.start;

            let (job, submit_fence, counter) = {
                let guard = self.fifo.lock();
                let Some(entry) = guard.get(idx as usize) else {
                    pr_err!(
                        "JobQueue: check_exec() BUG: xa_idx={} missing in exec_range, advancing\n",
                        idx
                    );
                    state.exec_range.pop_front();
                    state.hw_range.push_back();
                    continue;
                };
                (entry.job.clone(), entry.submit_fence.clone(), entry.counter)
            };

            // Take the submit fence out of the entry *before* calling the
            // driver so the driver can take immediate ownership on Submitted.
            let fence = {
                let mut guard = self.fifo.lock();
                guard
                    .get_mut(idx as usize)
                    .and_then(|e| e.submit_fence_drv.take())
            };
            let Some(fence) = fence else {
                // Already submitted — shouldn't happen.
                state.exec_range.pop_front();
                state.hw_range.push_back();
                continue;
            };

            let job_ref = JobRef {
                job: &*job,
                submit_fence: &submit_fence,
                counter,
            };

            // Notice that the XArray spinlock is not held here.
            match self.handler.submit(&job_ref, fence, &self.wq) {
                Ok(SubmitResult::Submitted) => {
                    // Register a callback on the public submit fence so that
                    // check_retire() is triggered promptly when the driver
                    // signals it.
                    let cb_result = KBox::try_pin_init(
                        FenceCallbackRegistration::new(
                            &submit_fence,
                            ProgressCallback {
                                inner: self.clone(),
                            },
                        ),
                        GFP_KERNEL,
                    );

                    match cb_result {
                        Ok(registration) => {
                            let mut guard = self.fifo.lock();
                            if let Some(entry) = guard.get_mut(idx as usize) {
                                entry.progress_cb = Some(registration);
                            }
                        }
                        Err(CallbackError::AlreadySignaled(cb)) => {
                            // Fence already signaled — trigger check immediately.
                            cb.inner.maybe_check_progress();
                        }
                        Err(CallbackError::Other(e)) => {
                            pr_err!(
                                "JobQueue: check_exec() progress cb alloc failed: {:?}, job {}\n",
                                e,
                                counter
                            );
                        }
                    }

                    state.exec_range.pop_front();
                    state.hw_range.push_back();
                }
                Ok(SubmitResult::NoResources(fence)) => {
                    // Put the fence back and retry on the next tick.
                    let mut guard = self.fifo.lock();
                    if let Some(entry) = guard.get_mut(idx as usize) {
                        entry.submit_fence_drv = Some(fence);
                    }
                    return;
                }
                Err(e) => {
                    // The driver must have signaled `fence` with `e` before
                    // returning Err. If it did not, the fence will be signaled
                    // ECANCELED when the driver drops it.
                    pr_err!(
                        "JobQueue: check_exec() submit failed: {:?}, job {}\n",
                        e,
                        counter
                    );
                    state.exec_range.pop_front();
                    state.done_range.push_back();
                }
            }
        }
    }

    /// Retire completed HW jobs (in-order from the front).
    ///
    /// Advances jobs whose submit fences have been signaled from `hw_range`
    /// to `done_range`.
    fn check_retire(&self, state: &mut PipelineState) {
        while !state.hw_range.is_empty() {
            let idx = state.hw_range.start;

            let signaled = {
                let guard = self.fifo.lock();
                let Some(entry) = guard.get(idx as usize) else {
                    pr_err!(
                        "JobQueue: check_retire() BUG: xa_idx={} missing in hw_range, advancing\n",
                        idx
                    );
                    state.hw_range.pop_front();
                    state.done_range.push_back();
                    continue;
                };
                entry.submit_fence.is_signaled()
            };

            if signaled {
                state.hw_range.pop_front();
                state.done_range.push_back();
            } else {
                break;
            }
        }
    }

    /// Remove and drop completed entries. Runs in process context.
    fn do_cleanup(self: &Arc<Self>) {
        let mut entries_to_drop: KVec<KBox<JobEntry<T>>> = KVec::new();

        {
            let mut state = self.state.lock();
            while let Some(idx) = state.done_range.pop_front() {
                let mut guard = self.fifo.lock();
                if let Some(entry) = guard.remove(idx as usize) {
                    let _ = entries_to_drop.push(entry, GFP_KERNEL);
                }
            }
        }

        drop(entries_to_drop);
    }

    /// Schedule a pipeline check on the system workqueue, unless suppressed
    /// by an active [`CoalesceGuard`].
    fn drain_range_into(
        &self,
        range: &mut WrapRange,
        entries: &mut KVec<KBox<JobEntry<T>>>,
    ) -> Result {
        while let Some(idx) = range.pop_front() {
            let mut guard = self.fifo.lock();
            if let Some(entry) = guard.remove(idx as usize) {
                entries.push(entry, GFP_KERNEL)?;
            }
        }
        Ok(())
    }

    /// Schedule a pipeline check on the system workqueue, unless suppressed
    /// by an active [`CoalesceGuard`].
    fn maybe_check_progress(self: &Arc<Self>) {
        if !self.coalesce.load(Ordering::Relaxed) {
            let _ = self.wq.enqueue::<Arc<Self>, 0>(self.clone());
        }
    }

    /// Schedule deferred cleanup of completed entries.
    fn schedule_cleanup(self: &Arc<Self>) {
        let _ = self.aux_queue.enqueue::<Arc<Self>, 3>(self.clone());
    }
}

/// Dependency fence callback. Triggers a tick when a dependency signals.
///
/// No fence subscription or allocation happens inside `signaled()`, avoiding
/// the deadlock where `dma_fence_add_callback` is called while holding a fence
/// context spinlock from a prior `signaled()` invocation.
struct DepCallback<T: QueueOps> {
    inner: Arc<JobQueueInner<T>>,
}

impl<T: QueueOps> FenceCallback for DepCallback<T> {
    fn signaled(self, _fence: &ARef<PublicDmaFence>) {
        self.inner.maybe_check_progress();
    }
}

/// Callback registered on the public submit fence. Triggers a pipeline check
/// when the driver signals the fence so that `check_retire()` runs promptly.
struct ProgressCallback<T: QueueOps> {
    inner: Arc<JobQueueInner<T>>,
}

impl<T: QueueOps> FenceCallback for ProgressCallback<T> {
    fn signaled(self, _fence: &ARef<PublicDmaFence>) {
        self.inner.maybe_check_progress();
    }
}

/// A process-context job queue that manages job dependencies, driver
/// submission, and hardware completion for GPU jobs.
pub struct JobQueue<T: QueueOps> {
    inner: Arc<JobQueueInner<T>>,
}

/// A guard that coalesces multiple fence completions into a single pipeline
/// tick. While held, automatic tick scheduling from fence callbacks is
/// suppressed. When dropped, a single tick is performed — either inline
/// (created via [`JobQueue::coalesce_inline`]) or via the workqueue
/// (created via [`JobQueue::coalesce`]).
pub struct CoalesceGuard<T: QueueOps> {
    inner: Arc<JobQueueInner<T>>,
    /// When true, the tick on drop runs inline in the caller's context.
    /// When false, the tick is dispatched via the system workqueue.
    inline: bool,
}

impl<T: QueueOps> Drop for CoalesceGuard<T> {
    fn drop(&mut self) {
        self.inner.coalesce.store(false, Ordering::Relaxed);
        if self.inline {
            self.inner.check_progress();
        } else {
            self.inner.maybe_check_progress();
        }
    }
}

/// A job that has been fully prepared (all major resources allocated) but not
/// yet committed to the pipeline.
///
/// Produced by [`JobQueue::prepare`] and consumed by [`JobQueue::commit`].
///
/// If dropped before [`commit`](JobQueue::commit) is called, the reserved
/// XArray slot is released and the [`UninitDmaFence`] is freed via `kfree`.
/// Because [`dma_fence_init`](crate::dma_fence) was never called, no seqno
/// was assigned and no fence ever existed — rollback is a pure `kfree` with
/// no `ECANCELED` signal and no hole in the seqno sequence.
pub struct PreparedJob<T: QueueOps> {
    inner: Arc<JobQueueInner<T>>,
    job: Arc<T::Job>,
    /// Partially-initialized fence allocation.  `None` once consumed by
    /// `commit()`, which calls `dma_fence_init` to assign the seqno.
    uninit_fence: Option<UninitDmaFence<T::FenceData>>,
    /// Reserved XArray slot. `None` once consumed by `commit()`.
    xa_index: Option<ReservedIndex>,
    /// Pre-allocated dependency vector (empty on creation, capacity reserved).
    deps: KVec<ARef<PublicDmaFence>>,
    counter: u64,
}

impl<T: QueueOps> Drop for PreparedJob<T> {
    fn drop(&mut self) {
        // Release the reserved XArray slot if commit() didn't consume it.
        if let Some(idx) = self.xa_index.take() {
            self.inner.fifo.lock().release(idx);
        }
        // uninit_fence: if Some (not yet committed), UninitDmaFence::drop
        // drops T::data and kfrees the allocation.  dma_fence_init was never
        // called, so no seqno was assigned and no ECANCELED is signaled.
    }
}

impl<T: QueueOps> JobQueue<T> {
    /// Create a new job queue.
    ///
    /// `handler` is the driver's submission logic.
    /// `wq` is the DMA fence workqueue to schedule pipeline checks on.
    pub fn new(handler: T, wq: Arc<DmaFenceWorkqueue>) -> Result<Self> {
        let aux_queue = OwnedQueue::new(
            c_str!("job_queue_aux"),
            WqFlags::HIGHPRI | WqFlags::MEM_RECLAIM,
            0,
        )?;
        // SAFETY: dma_fence_context_alloc is always safe to call.
        let fence_ctx_id = unsafe { bindings::dma_fence_context_alloc(1) };

        let inner = Arc::pin_init(
            try_pin_init!(JobQueueInner {
                fifo <- XArray::new(AllocKind::Alloc),
                inbox <- new_mutex!(InboxState {
                    cyclic_next: 0,
                    submitted_end: 0,
                }),
                state <- new_mutex!(PipelineState::new()),
                handler,
                work <- new_dma_fence_work!("JobQueue::work"),
                cleanup_work <- new_work!("JobQueue::cleanup_work"),
                wq,
                aux_queue,
                fence_ctx_id,
                fence_seqno: AtomicU64::new(1),
                job_counter: AtomicU64::new(0),
                coalesce: AtomicBool::new(false),
            }),
            GFP_KERNEL,
        )?;

        Ok(Self { inner })
    }

    /// Prepare a job for submission, allocating all resources upfront.
    ///
    /// Call [`commit`](Self::commit) to assign the seqno, insert the job into
    /// the pipeline, and receive the public fence.
    pub fn prepare(
        &self,
        job: T::Job,
        num_deps: usize,
        fence_data: T::FenceData,
    ) -> Result<PreparedJob<T>> {
        let uninit_fence = UninitDmaFence::new(fence_data)?;
        let counter = self.inner.job_counter.fetch_add(1, Ordering::SeqCst);
        let job = Arc::new(job, GFP_KERNEL)?;
        let deps = KVec::with_capacity(num_deps, GFP_KERNEL)?;

        let xa_index = {
            let mut inbox = self.inner.inbox.lock();
            let mut guard = self.inner.fifo.lock();
            guard.alloc_cyclic_reserve(XaLimit::LIMIT_32B, &mut inbox.cyclic_next, GFP_KERNEL)?
        };

        Ok(PreparedJob {
            inner: self.inner.clone(),
            job,
            uninit_fence: Some(uninit_fence),
            xa_index: Some(xa_index),
            deps,
            counter,
        })
    }

    /// Commit a prepared job to the pipeline.
    ///
    /// Returns the public submit fence.
    pub fn commit(
        &self,
        mut prepared: PreparedJob<T>,
        deps: &[ARef<PublicDmaFence>],
    ) -> Result<ARef<PublicDmaFence>> {
        // Consume xa_index and uninit_fence from `prepared`.
        // On any failure below we release xa_index manually; PreparedJob::drop
        // is a no-op for these fields once they are taken.
        let xa_index = prepared
            .xa_index
            .take()
            .expect("JobQueue::commit: xa_index already consumed");
        let uninit_fence = prepared
            .uninit_fence
            .take()
            .expect("JobQueue::commit: uninit_fence already consumed");

        let seqno = self.inner.fence_seqno.fetch_add(1, Ordering::Relaxed);
        let (submit_fence_drv, submit_fence) = uninit_fence.init(self.inner.fence_ctx_id, seqno);

        // Copy deps into the pre-allocated vector.
        let mut dep_vec = core::mem::replace(&mut prepared.deps, KVec::new());
        let _ = dep_vec.extend_from_slice(deps, GFP_KERNEL);

        // Allocate the JobEntry box.  On OOM the struct constructor is
        // evaluated first, so `submit_fence_drv` is moved in and then dropped
        // when the aborted `KBox` drops the value — signaling ECANCELED.
        let entry = match KBox::new(
            JobEntry {
                job: prepared.job.clone(),
                submit_fence: submit_fence.clone(),
                submit_fence_drv: Some(submit_fence_drv),
                counter: prepared.counter,
                deps: JobDependencies {
                    fences: dep_vec,
                    current_idx: 0,
                    active_cb: None,
                },
                progress_cb: None,
            },
            GFP_KERNEL,
        ) {
            Ok(e) => e,
            Err(_) => {
                self.inner.fifo.lock().release(xa_index);
                return Err(ENOMEM);
            }
        };

        // Store entry in the reserved slot.
        let mut inbox = self.inner.inbox.lock();
        {
            let mut guard = self.inner.fifo.lock();
            if let Err(store_err) = guard.store_reserved(xa_index, entry, GFP_KERNEL) {
                // Slot still holds XA_ZERO_ENTRY..release it.
                // store_err.value (the KBox<JobEntry>) is dropped here, leading to ECANCELED.
                drop(store_err);
                guard.release(xa_index);
                drop(inbox);
                return Err(ENOMEM);
            }
        }

        let expected = inbox.submitted_end;
        if xa_index.index() as u32 != expected {
            pr_err!(
                "JobQueue: commit() BUG: xa_idx={} != submitted_end={} (job={})\n",
                xa_index.index(),
                expected,
                prepared.counter
            );
        }
        inbox.submitted_end = inbox.submitted_end.wrapping_add(1);
        drop(inbox);

        self.inner.maybe_check_progress();
        Ok(submit_fence)
    }

    /// Coalesce fence completions into a single deferred tick.
    ///
    /// While the returned guard is held, fence callbacks skip scheduling
    /// workqueue ticks. When the guard is dropped, a single tick is
    /// dispatched via the system workqueue.
    ///
    /// This is safe to call from any context (including atomic/IRQ).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let guard = job_queue.coalesce();
    /// hw_fence_1.signal();
    /// hw_fence_2.signal();
    /// drop(guard); // single workqueue tick processes both completions
    /// ```
    pub fn coalesce(&self) -> CoalesceGuard<T> {
        self.inner.coalesce.store(true, Ordering::Relaxed);
        CoalesceGuard {
            inner: self.inner.clone(),
            inline: false,
        }
    }

    /// Coalesce fence completions into a single inline tick.
    ///
    /// Like [`coalesce`](Self::coalesce), but the tick runs inline in
    /// the caller's context when the guard is dropped, avoiding the
    /// workqueue roundtrip. This reduces latency when the caller is
    /// already in process context (e.g. a threaded IRQ handler).
    ///
    /// Must be called from process context (the tick acquires a mutex).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let guard = job_queue.coalesce_inline();
    /// hw_fence_1.signal();
    /// hw_fence_2.signal();
    /// hw_fence_3.signal();
    /// drop(guard); // single inline tick processes all three completions
    /// ```
    pub fn coalesce_inline(&self) -> CoalesceGuard<T> {
        self.inner.coalesce.store(true, Ordering::Relaxed);
        CoalesceGuard {
            inner: self.inner.clone(),
            inline: true,
        }
    }

    /// Park the queue, preventing any further jobs from being submitted to
    /// the driver.
    ///
    /// Jobs already in `WaitingForExec` stay there and are not failed , they
    /// will be submitted once `unpark()` is called.
    pub fn park(&self) {
        self.inner.state.lock().parked = true;
    }

    /// Unpark the queue, allowing jobs to be submitted to the driver again.
    ///
    /// Immediately schedules a progress check so that any jobs that accumulated
    /// in `WaitingForExec` while the queue was parked are drained without
    /// delay.
    pub fn unpark(&self) {
        self.inner.state.lock().parked = false;
        self.inner.maybe_check_progress();
    }

    /// Cancel all pending and running jobs. Waits for HW jobs to drain.
    ///
    /// Must be called from process context (it may sleep while waiting for
    /// hardware fences).
    pub fn cancel_all(&self) -> Result {
        let mut entries: KVec<KBox<JobEntry<T>>> = KVec::new();
        let mut hw_fences: KVec<ARef<PublicDmaFence>> = KVec::new();

        {
            let mut state = self.inner.state.lock();

            // First, drain inbox so all submitted jobs become visible.
            self.inner.drain_inbox(&mut state);

            self.inner
                .drain_range_into(&mut state.deps_range, &mut entries)?;
            self.inner
                .drain_range_into(&mut state.exec_range, &mut entries)?;

            // hw_range needs special handling: wait for HW jobs to drain.
            // The driver owns the DriverDmaFence for these jobs and will
            // signal the public submit fence when done.
            while let Some(idx) = state.hw_range.pop_front() {
                let mut guard = self.inner.fifo.lock();
                if let Some(entry) = guard.remove(idx as usize) {
                    hw_fences.push(entry.submit_fence.clone(), GFP_KERNEL)?;
                    entries.push(entry, GFP_KERNEL)?;
                }
            }

            self.inner
                .drain_range_into(&mut state.done_range, &mut entries)?;
        }

        for fence in &hw_fences {
            // TODO: I wonder whether we should take a "cancel: bool" argument
            // and just signal with ECANCELED instead of waiting in this case.
            //
            // Boris: WDYT?
            let _ = fence.wait();
        }

        // Signal remaining submit fences (those not yet passed to the
        // driver) with ECANCELED, and drop all entries.
        for mut entry in entries {
            // Cancel the progress callback to avoid stale triggers.
            drop(entry.progress_cb.take());
            // If the fence was not yet passed to the driver, signal it now.
            if let Some(f) = entry.submit_fence_drv.take() {
                f.signal(Err(ECANCELED));
            }
            // For hw_range entries the fence is held by the driver; we
            // already waited above for the public submit_fence to signal.
        }

        Ok(())
    }
}

impl<T: QueueOps> Drop for JobQueue<T> {
    fn drop(&mut self) {
        if let Err(e) = self.cancel_all() {
            pr_err!("JobQueue::drop: cancel_all() failed: {:?}\n", e);
        }
    }
}
