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
//! Jobs live in a single XArray, allocated via `xa_alloc_cyclic`. Each job
//! progresses through an ordered sequence of pipeline stages. Every stage owns
//! a [`WrapRange`] cursor into the XArray; stage transitions are O(1) cursor
//! advances and involve no data copies.
//!
//! ## Stage layout
//!
//! The pipeline is represented as `JobQueueInner::stages: KVec<StageKind<T>>`,
//! assembled once at construction time by [`JobQueue::new`]:
//!
//! ```text
//! [WaitingForDeps, WaitingForExec, <driver stages or Executing>]
//!       0               1                    2..
//! ```
//!
//! Each index `i` has a matching `PipelineState::stage_ranges[i]` holding the
//! XArray indices of jobs currently at that stage.
//!
//! ## Built-in stages
//!
//! - **WaitingForDeps** — waits for all dependency fences. Walks them one
//!   at a time: registers a callback on the next unsignaled fence, fires
//!   `check_progress()` when it signals, and advances when all are met.
//!
//! - **WaitingForExec** — calls the driver's [`QueueOps::submit`]. On
//!   `Submitted` the job advances; on `NoResources` it stays and is retried
//!   on the next tick; on `Err` it is retired to Done.
//!   A callback on the public submit fence ensures a tick fires when the
//!   driver eventually signals it.
//!
//! - **Executing** (only when no driver stages are given) — advances
//!   the job as soon as its submit fence signals. Preserves the original
//!   three-stage (WaitingForDeps -> WaitingForExec -> Executing -> Done)
//!   behaviour.
//!
//! ## Driver-defined stages
//!
//! Drivers supply zero or more stages via [`PipelineBuilder`]. They are
//! appended after `WaitingForExec`, replacing `Executing`. Each stage implements
//! [`StageOps`] and returns a [`StageAdvance`] variant:
//!
//! - `Advance`   — move to the next stage (or Done if already last)
//! - `Wait`      — park until the next external tick
//! - `WaitOn`    — register a fence callback; re-run when it fires
//! - `WaitFor`   — schedule a delayed work item; re-run after the delay
//! - `TimedOut`  — retire the job to Done with an error
//!
//! ## Lock topology
//!
//! Two mutexes prevent deadlocks between `submit()` and `check_progress()`:
//!
//! - **`inbox`** — guards `InboxState` (the XArray and cyclic-alloc cursor).
//!   Held only briefly at submission time and at the very start of each
//!   `check_progress()` to drain new entries.
//!
//! - **`state`** — guards `PipelineState` (all stage ranges). Held for the
//!   entire duration of `check_progress()`, but never during `submit()`.
//!   This lets the driver call back into the queue from its `submit()`
//!   implementation (e.g. to query fence state) without deadlocking.
//!
//! - **Done** — Entries are removed from the XArray and dropped in process
//!   context via `cleanup_work` so that `JobEntry` is never freed in IRQ or
//!   atomic context.

use core::sync::atomic::{
    AtomicBool,
    AtomicU64,
    Ordering, //
};

use crate::{
    c_str,
    dma_fence::{
        CallbackError,
        DmaFenceDelayedWork,
        DmaFenceDelayedWorkItem,
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
    impl_has_dma_fence_delayed_work,
    impl_has_dma_fence_work,
    new_dma_fence_delayed_work,
    new_dma_fence_work,
    new_mutex,
    prelude::*,
    sync::{
        Arc,
        Mutex, //
    },
    time::{msecs_to_jiffies, Delta, Instant, Jiffies, Monotonic},
    types::ARef, //
    workqueue::{
        WqFlags, //
    },
    xarray::{
        AllocKind,
        ReservedIndex,
        XArray,
        XaLimit, //
    },
};

/// The result returned by a stage's [`StageOps::process`] call.
///
/// # Examples
///
/// A stage that waits for hardware completion and enforces a 5-second deadline:
///
/// ```ignore
/// fn process(&self, ctx: &StageContext<'_, T>) -> StageAdvance {
///     if ctx.submit_fence.is_signaled() {
///         return StageAdvance::Advance;
///     }
///     let elapsed = msecs_to_jiffies(ctx.stage_elapsed().as_millis().max(0) as u32);
///     if elapsed >= self.timeout {
///         // Deadline passed — kick off a GPU reset and retire the job.
///         self.trigger_reset(ctx.job);
///         return StageAdvance::TimedOut(ETIMEDOUT);
///     }
///     // Schedule a wakeup at the deadline so we don't miss it.
///     StageAdvance::WaitFor(self.timeout - elapsed)
/// }
/// ```
pub enum StageAdvance {
    /// The job has passed this stage; advance it to the next, or to Done.
    Advance,
    /// Re-check when `fence` signals.
    ///
    /// The pipeline registers a callback on `fence` and re-invokes
    /// [`StageOps::process`] when it fires.
    WaitOn(ARef<PublicDmaFence>),
    /// Re-check after `delay` jiffies.
    ///
    /// Useful for polling intervals or deadline timers. The pipeline schedules
    /// a delayed work item and re-invokes [`StageOps::process`] when it fires.
    WaitFor(Jiffies),
    /// Re-check on the next external tick (new submission, fence signal, or
    /// explicit driver wakeup). Use when there is no fence or deadline to wait on.
    Wait,
    /// The job failed; it is retired to Done immediately.
    ///
    /// If the job was already submitted to hardware, the driver must eventually
    /// signal the submit fence (e.g. after a GPU reset).
    TimedOut(Error),
}

/// Per-job context passed to [`StageOps::process`].
///
/// Provides access to the job's data, its submit fence, and timing
/// information. Use [`stage_elapsed`](Self::stage_elapsed) to enforce
/// per-stage deadlines and [`pipeline_elapsed`](Self::pipeline_elapsed) for
/// a total pipeline deadline.
///
/// # Examples
///
/// A stage with both a per-stage and a total pipeline timeout:
///
/// ```ignore
/// fn process(&self, ctx: &StageContext<'_, T>) -> StageAdvance {
///     if ctx.submit_fence.is_signaled() {
///         return StageAdvance::Advance;
///     }
///     let stage_elapsed    = msecs_to_jiffies(ctx.stage_elapsed().as_millis().max(0) as u32);
///     let pipeline_elapsed = msecs_to_jiffies(ctx.pipeline_elapsed().as_millis().max(0) as u32);
///     if stage_elapsed >= self.hw_timeout || pipeline_elapsed >= self.pipeline_timeout {
///         self.trigger_reset(ctx.job);
///         return StageAdvance::TimedOut(ETIMEDOUT);
///     }
///     // Wake at whichever deadline comes first.
///     StageAdvance::WaitFor((self.hw_timeout - stage_elapsed).min(self.pipeline_timeout - pipeline_elapsed))
/// }
/// ```
pub struct StageContext<'a, T: QueueOps> {
    /// The driver's job data.
    pub job: &'a T::Job,
    /// Monotonic job counter.
    pub counter: u64,
    /// The public submit fence for this job.
    pub submit_fence: &'a ARef<PublicDmaFence>,
    entered_at: Instant<Monotonic>,
    pipeline_entered_at: Instant<Monotonic>,
}

impl<'a, T: QueueOps> StageContext<'a, T> {
    /// Returns how long this job has been in the current stage.
    ///
    /// The clock resets on every stage transition, so this always measures
    /// time since the job entered the current stage only.
    pub fn stage_elapsed(&self) -> Delta {
        self.entered_at.elapsed()
    }

    /// Returns how long this job has been in the pipeline since it was first
    /// committed (i.e. its total age across all stages, from deps to done).
    ///
    /// This clock never resets. Combine with a pipeline timeout set via
    /// [`PipelineBuilder::set_pipeline_timeout`] to enforce an end-to-end
    /// deadline, or check it directly in a driver stage.
    pub fn pipeline_elapsed(&self) -> Delta {
        self.pipeline_entered_at.elapsed()
    }
}

/// A driver-defined pipeline stage.
///
/// Implement this trait to add custom logic between hardware submission and
/// job completion. Stages are applied in the order they are added to
/// [`PipelineBuilder`], after the job has been handed to hardware.
///
/// The pipeline calls [`process`](Self::process) on the job at the head of
/// the stage; jobs behind it are not processed until the front advances.
/// All methods are called from process context.
///
/// # Examples
///
/// A stage that waits for hardware completion with a configurable timeout:
///
/// ```ignore
/// struct HwStage {
///     timeout: Jiffies,
/// }
///
/// impl StageOps<MyHandler> for HwStage {
///     fn process(&self, ctx: &StageContext<'_, MyHandler>) -> StageAdvance {
///         if ctx.submit_fence.is_signaled() {
///             return StageAdvance::Advance;
///         }
///         let elapsed = msecs_to_jiffies(ctx.stage_elapsed().as_millis().max(0) as u32);
///         if elapsed >= self.timeout {
///             ctx.job.device.reset();
///             return StageAdvance::TimedOut(EIO);
///         }
///         StageAdvance::WaitFor(self.timeout - elapsed)
///     }
///
///     fn cancel(&self, _job: &MyJob, counter: u64) {
///         pr_warn!("Job {} cancelled in hw stage\n", counter);
///     }
/// }
/// ```
pub trait StageOps<T: QueueOps>: Send + Sync + 'static {
    /// Called by the pipeline on each progress tick for the job at the head
    /// of this stage. Returns what the pipeline should do next.
    fn process(&self, ctx: &StageContext<'_, T>) -> StageAdvance;

    /// Called when the job is cancelled (e.g. via [`JobQueue::cancel_all`])
    /// before it passes through this stage. The default does nothing.
    fn cancel(&self, _job: &T::Job, _counter: u64) {}
}

/// Builder for a driver-defined list of pipeline stages.
///
/// Driver stages run after the job has been submitted to hardware. If no
/// stages are added, the pipeline advances jobs as soon as their submit
/// fence signals.
///
/// Pass the finished builder to [`JobQueue::new`].
///
/// # Examples
///
/// A queue with a 5-second per-stage hw timeout:
///
/// ```ignore
/// let pipeline = PipelineBuilder::new()
///     .add_stage(HwStage { timeout: msecs_to_jiffies(5000) })?;
/// let queue = JobQueue::new(handler, wq, pipeline)?;
/// ```
///
/// A queue with a 10-second total pipeline deadline:
///
/// ```ignore
/// let pipeline = PipelineBuilder::new()
///     .set_pipeline_timeout(msecs_to_jiffies(10000))
///     .add_stage(HwStage { timeout: msecs_to_jiffies(5000) })?;
/// let queue = JobQueue::new(handler, wq, pipeline)?;
/// ```
pub struct PipelineBuilder<T: QueueOps> {
    stages: KVec<Arc<dyn StageOps<T>>>,
    pipeline_timeout: Option<Jiffies>,
}

impl<T: QueueOps> PipelineBuilder<T> {
    /// Create an empty builder with no stages and no pipeline timeout.
    pub fn new() -> Self {
        Self {
            stages: KVec::new(),
            pipeline_timeout: None,
        }
    }

    /// Append a driver-defined stage.
    ///
    /// Stages are applied in the order they are added, after the job has
    /// been submitted to hardware.
    pub fn add_stage<S: StageOps<T>>(mut self, stage: S) -> Result<Self> {
        let arc: Arc<dyn StageOps<T>> = Arc::new(stage, GFP_KERNEL)?;
        self.stages.push(arc, GFP_KERNEL)?;
        Ok(self)
    }

    /// Set a total pipeline timeout.
    ///
    /// Jobs that remain in the pipeline for longer than `timeout` jiffies
    /// are retired with [`ETIMEDOUT`]. The built-in stages enforce this
    /// automatically; driver stages can observe the total elapsed time via
    /// [`StageContext::pipeline_elapsed`].
    pub fn set_pipeline_timeout(mut self, timeout: Jiffies) -> Self {
        self.pipeline_timeout = Some(timeout);
        self
    }
}

/// Internal representation of a pipeline stage stored in
/// [`JobQueueInner::stages`]. Built-in stages carry no data; driver stages
/// wrap an [`Arc`]-ed [`StageOps`] implementation.
enum StageKind<T: QueueOps> {
    /// Walk dependency fences one at a time, advancing when all are met.
    WaitingForDeps,
    /// Call the driver's [`QueueOps::submit`]; advance on acceptance.
    WaitingForExec,
    /// Default HW-wait: advance when the submit fence signals.
    /// Used when the driver supplies no custom stages.
    Executing,
    /// A driver-provided stage (replaces [`Executing`] when present).
    Driver(Arc<dyn StageOps<T>>),
}

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

    /// Timestamp of when the job entered the current stage.
    stage_entered_at: Instant<Monotonic>,

    /// Timestamp of when the job first entered the pipeline (set at commit
    /// time, never reset). Exposed via [`StageContext::pipeline_elapsed`].
    pipeline_entered_at: Instant<Monotonic>,

    /// Optional callback registered when a stage returns [`StageAdvance::WaitOn`].
    stage_wake_cb: Option<Pin<KBox<FenceCallbackRegistration<StageWakeCallback<T>>>>>,
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
    /// Jobs in `submitted_start..inbox.submitted_end` have not yet been
    /// pulled into `stage_ranges[0]`.
    submitted_start: u32,

    /// Per-stage queues, indexed identically to `JobQueueInner::stages`.
    /// `stage_ranges[i]` holds the XArray indices of jobs currently at
    /// stage `i`.
    stage_ranges: KVec<WrapRange>,

    /// Completed jobs awaiting XArray cleanup in process context.
    done_range: WrapRange,

    /// When `Some(n)`, the pipeline loop stops before advancing any job into
    /// stage `n`. Used to park the queue at the exec stage.
    parked_at: Option<usize>,
}

impl PipelineState {
    fn new(stage_count: usize) -> Result<Self> {
        let mut stage_ranges = KVec::new();
        for _ in 0..stage_count {
            stage_ranges.push(WrapRange::new(), GFP_KERNEL)?;
        }
        Ok(Self {
            submitted_start: 0,
            stage_ranges,
            done_range: WrapRange::new(),
            parked_at: None,
        })
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
    cleanup_work: DmaFenceWork<JobQueueInner<T>, 3>,

    /// Workqueue for the main pipeline check (enforces DMA fence signaling rules).
    wq: Arc<DmaFenceWorkqueue>,

    /// Internal workqueue for cleanup work.
    aux_wq: DmaFenceWorkqueue,

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

    /// All pipeline stages in order: `[WaitingForDeps, WaitingForExec, <driver
    /// stages or Executing>]`. Built once at construction time.
    stages: KVec<StageKind<T>>,

    /// Optional total pipeline deadline. If set, jobs that remain in the
    /// pipeline longer than this are retired with [`ETIMEDOUT`]. The built-in
    /// stages enforce it automatically; driver stages can observe the elapsed
    /// time via [`StageContext::pipeline_elapsed`].
    pipeline_timeout: Option<Jiffies>,

    /// Delayed work for stage-timer wakeups.
    #[pin]
    stage_timer: DmaFenceDelayedWork<JobQueueInner<T>, 4>,
}

unsafe impl<T: QueueOps> Send for JobQueueInner<T> {}
unsafe impl<T: QueueOps> Sync for JobQueueInner<T> {}

impl_has_dma_fence_work! {
    impl{T: QueueOps} HasDmaFenceWork<JobQueueInner<T>> for JobQueueInner<T> { self.work }
}

impl_has_dma_fence_work! {
    impl{T: QueueOps} HasDmaFenceWork<JobQueueInner<T>, 3> for JobQueueInner<T> { self.cleanup_work }
}

impl<T: QueueOps> DmaFenceWorkItem for JobQueueInner<T> {
    type Pointer = Arc<Self>;

    fn run(this: Arc<Self>) {
        this.check_progress();
    }
}

impl<T: QueueOps> DmaFenceWorkItem<3> for JobQueueInner<T> {
    type Pointer = Arc<Self>;

    fn run(this: Arc<Self>) {
        this.do_cleanup();
    }
}

impl<T: QueueOps> DmaFenceDelayedWorkItem<4> for JobQueueInner<T> {
    type Pointer = Arc<Self>;

    fn run(this: Arc<Self>) {
        this.check_progress();
    }
}

impl_has_dma_fence_delayed_work! {
    impl{T: QueueOps} HasDmaFenceDelayedWork<JobQueueInner<T>, 4>
        for JobQueueInner<T> { self.stage_timer }
}

impl<T: QueueOps> JobQueueInner<T> {
    /// Pull newly submitted jobs from the inbox into `stage_ranges[0]`.
    fn drain_inbox(&self, state: &mut PipelineState) {
        let end = self.inbox.lock().submitted_end;
        while state.submitted_start != end {
            state.stage_ranges[0].push_back();
            state.submitted_start = state.submitted_start.wrapping_add(1);
        }
    }

    /// The main pipeline tick. Runs in process context.
    ///
    /// Iterates over every stage in `self.stages` in order. For each stage,
    /// loops over the jobs queued there (front first) calling the appropriate
    /// per-stage helper until the stage returns anything other than `Advance`.
    /// Stage transitions are managed here; helpers only return a [`StageAdvance`]
    /// without touching `PipelineState` themselves.
    fn check_progress(self: &Arc<Self>) {
        let mut state = self.state.lock();

        // Drain newly submitted jobs into stage_ranges[0] (DepsStage).
        self.drain_inbox(&mut state);

        for stage_i in 0..self.stages.len() {
            if state.parked_at == Some(stage_i) {
                break;
            }

            'stage_loop: loop {
                if state.stage_ranges[stage_i].is_empty() {
                    break 'stage_loop;
                }
                let entry_idx = state.stage_ranges[stage_i].start;

                let advance = match &self.stages[stage_i] {
                    StageKind::WaitingForDeps => self.process_deps(entry_idx),
                    StageKind::WaitingForExec => self.process_exec(entry_idx),
                    StageKind::Executing => self.process_default_hw_wait(entry_idx),
                    StageKind::Driver(stage) => self.process_driver_stage(stage.clone(), entry_idx),
                };

                match advance {
                    StageAdvance::Advance => {
                        state.stage_ranges[stage_i].pop_front();
                        if stage_i + 1 < self.stages.len() {
                            state.stage_ranges[stage_i + 1].push_back();
                            // Reset the elapsed timer when entering a new stage.
                            let mut guard = self.fifo.lock();
                            if let Some(entry) = guard.get_mut(entry_idx as usize) {
                                entry.stage_entered_at = Instant::now();
                            }
                        } else {
                            state.done_range.push_back();
                        }
                        // Continue inner loop: process the new front of this stage.
                    }
                    StageAdvance::TimedOut(_) => {
                        state.stage_ranges[stage_i].pop_front();
                        state.done_range.push_back();
                        break 'stage_loop;
                    }
                    StageAdvance::WaitOn(fence) => {
                        let cb = FenceCallbackRegistration::new(
                            &fence,
                            StageWakeCallback {
                                inner: self.clone(),
                            },
                        );
                        match KBox::try_pin_init(cb, GFP_KERNEL) {
                            Ok(registration) => {
                                let mut guard = self.fifo.lock();
                                if let Some(entry) = guard.get_mut(entry_idx as usize) {
                                    entry.stage_wake_cb = Some(registration);
                                }
                            }
                            Err(CallbackError::AlreadySignaled(cb)) => {
                                cb.inner.maybe_check_progress();
                            }
                            Err(CallbackError::Other(e)) => {
                                pr_err!(
                                    "JobQueue: stage WaitOn cb alloc failed: {:?}, entry {}\n",
                                    e,
                                    entry_idx
                                );
                            }
                        }
                        break 'stage_loop;
                    }
                    StageAdvance::WaitFor(delay) => {
                        let _ = self.wq.enqueue_delayed::<Arc<Self>, 4>(self.clone(), delay);
                        break 'stage_loop;
                    }
                    StageAdvance::Wait => break 'stage_loop,
                }
            }
        }

        let needs_cleanup = !state.done_range.is_empty();
        drop(state);
        if needs_cleanup {
            self.schedule_cleanup();
        }
    }

    /// Deps-stage helper: walk dependency fences one at a time.
    ///
    /// Fast-forwards through already-signaled fences, registers a callback on
    /// the next unsignaled one, and returns `Wait`. Returns `Advance` once all
    /// dependencies are met.
    fn process_deps(self: &Arc<Self>, entry_idx: u32) -> StageAdvance {
        loop {
            let current_dependency = {
                let guard = self.fifo.lock();
                let Some(entry) = guard.get(entry_idx as usize) else {
                    pr_err!(
                        "JobQueue: process_deps() BUG: xa_idx={} missing\n",
                        entry_idx
                    );
                    return StageAdvance::Advance;
                };
                if entry.deps.current_idx >= entry.deps.fences.len() {
                    None // All deps satisfied.
                } else {
                    Some(entry.deps.fences[entry.deps.current_idx].clone())
                }
            };

            let Some(dep_fence) = current_dependency else {
                // All deps met — free the allocation and advance.
                let mut guard = self.fifo.lock();
                if let Some(entry) = guard.get_mut(entry_idx as usize) {
                    entry.deps.fences = KVec::new();
                }
                return StageAdvance::Advance;
            };

            let callback = DepCallback {
                inner: self.clone(),
            };
            match KBox::try_pin_init(
                FenceCallbackRegistration::new(&dep_fence, callback),
                GFP_KERNEL,
            ) {
                Ok(registration) => {
                    {
                        let mut guard = self.fifo.lock();
                        if let Some(entry) = guard.get_mut(entry_idx as usize) {
                            entry.deps.active_cb = Some(registration);
                        }
                    }
                    return self.pipeline_wait_or_timeout(entry_idx);
                }
                Err(CallbackError::AlreadySignaled(_)) => {
                    let mut guard = self.fifo.lock();
                    if let Some(entry) = guard.get_mut(entry_idx as usize) {
                        entry.deps.active_cb = None;
                        entry.deps.current_idx += 1;
                    }
                    // Continue loop: try the next dependency.
                }
                Err(CallbackError::Other(e)) => {
                    pr_err!(
                        "JobQueue: process_deps() cb alloc failed: {:?}, skipping dep for entry {}\n",
                        e,
                        entry_idx
                    );
                    let mut guard = self.fifo.lock();
                    if let Some(entry) = guard.get_mut(entry_idx as usize) {
                        entry.deps.active_cb = None;
                        entry.deps.current_idx += 1;
                    }
                    // Continue loop: try the next dependency.
                }
            }
        }
    }

    /// Exec-stage helper: call the driver's submit handler.
    ///
    /// Returns `Advance` on `Submitted`, `Wait` on `NoResources`, and
    /// `TimedOut(e)` on a driver error.
    fn process_exec(self: &Arc<Self>, entry_idx: u32) -> StageAdvance {
        let (job, submit_fence, counter) = {
            let guard = self.fifo.lock();
            let Some(entry) = guard.get(entry_idx as usize) else {
                pr_err!(
                    "JobQueue: process_exec() BUG: xa_idx={} missing\n",
                    entry_idx
                );
                return StageAdvance::Advance;
            };
            (entry.job.clone(), entry.submit_fence.clone(), entry.counter)
        };

        // Take the fence *before* calling the driver so ownership transfers
        // cleanly on `Submitted`.
        let fence = {
            let mut guard = self.fifo.lock();
            guard
                .get_mut(entry_idx as usize)
                .and_then(|e| e.submit_fence_drv.take())
        };
        let Some(fence) = fence else {
            // Already submitted — shouldn't happen in normal operation.
            return StageAdvance::Advance;
        };

        let job_ref = JobRef {
            job: &*job,
            submit_fence: &submit_fence,
            counter,
        };

        match self.handler.submit(&job_ref, fence, &self.wq) {
            Ok(SubmitResult::Submitted) => {
                // Register a callback on the public submit fence so that the
                // HW-wait stage wakes up promptly when the driver signals it.
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
                        if let Some(entry) = guard.get_mut(entry_idx as usize) {
                            entry.progress_cb = Some(registration);
                        }
                    }
                    Err(CallbackError::AlreadySignaled(cb)) => {
                        cb.inner.maybe_check_progress();
                    }
                    Err(CallbackError::Other(e)) => {
                        pr_err!(
                            "JobQueue: process_exec() progress cb alloc failed: {:?}, job {}\n",
                            e,
                            counter
                        );
                    }
                }
                StageAdvance::Advance
            }
            Ok(SubmitResult::NoResources(fence)) => {
                // Return the fence and retry on the next tick.
                {
                    let mut guard = self.fifo.lock();
                    if let Some(entry) = guard.get_mut(entry_idx as usize) {
                        entry.submit_fence_drv = Some(fence);
                    }
                }
                self.pipeline_wait_or_timeout(entry_idx)
            }
            Err(e) => {
                // Driver must have set the error on `fence` before returning
                // Err; if it did not, the fence will be signaled ECANCELED
                // when the driver drops it.
                pr_err!(
                    "JobQueue: process_exec() submit failed: {:?}, job {}\n",
                    e,
                    counter
                );
                StageAdvance::TimedOut(e)
            }
        }
    }

    /// Default HW-wait helper: advance once the submit fence signals.
    fn process_default_hw_wait(&self, entry_idx: u32) -> StageAdvance {
        {
            let guard = self.fifo.lock();
            if let Some(entry) = guard.get(entry_idx as usize) {
                if entry.submit_fence.is_signaled() {
                    return StageAdvance::Advance;
                }
            }
        }
        self.pipeline_wait_or_timeout(entry_idx)
    }

    /// Returns the appropriate wait advance for a built-in stage that would
    /// otherwise stall indefinitely:
    ///
    /// - [`StageAdvance::TimedOut`] if the pipeline deadline has expired.
    /// - [`StageAdvance::WaitFor(remaining)`] if the deadline is set but has
    ///   not yet expired — the stage timer will re-run the stage at the right
    ///   moment.
    /// - [`StageAdvance::Wait`] if no pipeline timeout is configured.
    fn pipeline_wait_or_timeout(&self, entry_idx: u32) -> StageAdvance {
        let Some(timeout) = self.pipeline_timeout else {
            return StageAdvance::Wait;
        };
        let elapsed = {
            let guard = self.fifo.lock();
            let Some(entry) = guard.get(entry_idx as usize) else {
                return StageAdvance::Wait;
            };
            msecs_to_jiffies(entry.pipeline_entered_at.elapsed().as_millis().max(0) as u32)
        };
        if elapsed >= timeout {
            StageAdvance::TimedOut(ETIMEDOUT)
        } else {
            StageAdvance::WaitFor(timeout - elapsed)
        }
    }

    /// Driver-stage helper: build a [`StageContext`] and delegate to the
    /// driver's [`StageOps::process`].
    fn process_driver_stage(&self, stage: Arc<dyn StageOps<T>>, entry_idx: u32) -> StageAdvance {
        // Clear any stale wake callback before re-evaluating; the callback
        // may have already fired and triggered this check.
        {
            let mut guard = self.fifo.lock();
            if let Some(entry) = guard.get_mut(entry_idx as usize) {
                entry.stage_wake_cb = None;
            }
        }

        let (job, submit_fence, counter, stage_entered_at, pipeline_entered_at) = {
            let guard = self.fifo.lock();
            let Some(entry) = guard.get(entry_idx as usize) else {
                pr_err!(
                    "JobQueue: process_driver_stage() BUG: xa_idx={} missing\n",
                    entry_idx
                );
                return StageAdvance::Advance;
            };
            (
                entry.job.clone(),
                entry.submit_fence.clone(),
                entry.counter,
                entry.stage_entered_at,
                entry.pipeline_entered_at,
            )
        };

        let ctx = StageContext {
            job: &*job,
            counter,
            submit_fence: &submit_fence,
            entered_at: stage_entered_at,
            pipeline_entered_at,
        };
        stage.process(&ctx)
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
    fn maybe_check_progress(self: &Arc<Self>) {
        if !self.coalesce.load(Ordering::Relaxed) {
            let _ = self.wq.enqueue::<Arc<Self>, 0>(self.clone());
        }
    }

    /// Schedule deferred cleanup of completed entries.
    fn schedule_cleanup(self: &Arc<Self>) {
        let _ = self.aux_wq.enqueue::<Arc<Self>, 3>(self.clone());
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
/// when the driver signals the fence so that `check_stages()` runs promptly.
struct ProgressCallback<T: QueueOps> {
    inner: Arc<JobQueueInner<T>>,
}

impl<T: QueueOps> FenceCallback for ProgressCallback<T> {
    fn signaled(self, _fence: &ARef<PublicDmaFence>) {
        self.inner.maybe_check_progress();
    }
}

/// Callback registered when a stage returns [`StageAdvance::WaitOn`].
/// Triggers a pipeline tick when the stage's requested fence signals.
struct StageWakeCallback<T: QueueOps> {
    inner: Arc<JobQueueInner<T>>,
}

impl<T: QueueOps> FenceCallback for StageWakeCallback<T> {
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
    /// `pipeline` is the set of driver-defined stages jobs pass through after
    /// HW submission (use [`PipelineBuilder::new()`] for no custom stages).
    pub fn new(
        handler: T,
        wq: Arc<DmaFenceWorkqueue>,
        mut pipeline: PipelineBuilder<T>,
    ) -> Result<Self> {
        let aux_wq = DmaFenceWorkqueue::new(
            c_str!("job_queue_aux"),
            WqFlags::HIGHPRI,
            0,
        )?;
        // SAFETY: dma_fence_context_alloc is always safe to call.
        let fence_ctx_id = unsafe { bindings::dma_fence_context_alloc(1) };

        // Build the unified stages vec:
        //   [WaitingForDeps, WaitingForExec, <driver stages or Executing>]
        let mut all_stages: KVec<StageKind<T>> = KVec::new();
        all_stages.push(StageKind::WaitingForDeps, GFP_KERNEL)?;
        all_stages.push(StageKind::WaitingForExec, GFP_KERNEL)?;
        let pipeline_timeout = pipeline.pipeline_timeout;
        if pipeline.stages.is_empty() {
            all_stages.push(StageKind::Executing, GFP_KERNEL)?;
        } else {
            for s in pipeline.stages.drain_all() {
                all_stages.push(StageKind::Driver(s), GFP_KERNEL)?;
            }
        }
        let pipeline_state = PipelineState::new(all_stages.len())?;

        let inner = Arc::pin_init(
            try_pin_init!(JobQueueInner {
                fifo <- XArray::new(AllocKind::Alloc),
                inbox <- new_mutex!(InboxState {
                    cyclic_next: 0,
                    submitted_end: 0,
                }),
                state <- new_mutex!(pipeline_state),
                handler,
                work <- new_dma_fence_work!("JobQueue::work"),
                cleanup_work <- new_dma_fence_work!("JobQueue::cleanup_work"),
                wq,
                aux_wq,
                fence_ctx_id,
                fence_seqno: AtomicU64::new(1),
                job_counter: AtomicU64::new(0),
                coalesce: AtomicBool::new(false),
                stages: all_stages,
                pipeline_timeout,
                stage_timer <- new_dma_fence_delayed_work!("JobQueue::stage_timer"),
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
                stage_entered_at: Instant::now(),
                pipeline_entered_at: Instant::now(),
                stage_wake_cb: None,
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
    /// Jobs already in the exec stage stay there and are not failed; they
    /// will be submitted once `unpark()` is called.
    pub fn park(&self) {
        // WaitingForExec is always at index 1 in the stages vec.
        self.inner.state.lock().parked_at = Some(1);
    }

    /// Unpark the queue, allowing jobs to be submitted to the driver again.
    ///
    /// Immediately schedules a progress check so that any jobs that accumulated
    /// in the exec stage while the queue was parked are drained without delay.
    pub fn unpark(&self) {
        self.inner.state.lock().parked_at = None;
        self.inner.maybe_check_progress();
    }

    /// Cancel all pending and running jobs. Waits for HW jobs to drain.
    ///
    /// Must be called from process context (it may sleep while waiting for
    /// hardware fences).
    pub fn cancel_all(&self) -> Result {
        // WaitingForExec is always at index 1; stages beyond it have been
        // handed to hardware and need their fences waited on before cancel.
        const EXEC_STAGE_IDX: usize = 1;
        let mut entries: KVec<KBox<JobEntry<T>>> = KVec::new();
        let mut hw_fences: KVec<ARef<PublicDmaFence>> = KVec::new();

        {
            let mut state = self.inner.state.lock();

            // First, drain inbox so all submitted jobs become visible.
            self.inner.drain_inbox(&mut state);

            // Drain all stage ranges. Stages beyond EXEC_STAGE_IDX contain
            // jobs that have been handed to the driver; collect their fences
            // for waiting.
            for stage_i in 0..state.stage_ranges.len() {
                while let Some(idx) = state.stage_ranges[stage_i].pop_front() {
                    let mut guard = self.inner.fifo.lock();
                    if let Some(entry) = guard.remove(idx as usize) {
                        if stage_i > EXEC_STAGE_IDX {
                            // Driver owns the DriverDmaFence; wait for the
                            // public submit fence to signal after recovery.
                            hw_fences.push(entry.submit_fence.clone(), GFP_KERNEL)?;
                        }
                        entries.push(entry, GFP_KERNEL)?;
                    }
                }
            }

            while let Some(idx) = state.done_range.pop_front() {
                let mut guard = self.inner.fifo.lock();
                if let Some(entry) = guard.remove(idx as usize) {
                    entries.push(entry, GFP_KERNEL)?;
                }
            }
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
            // Cancel the progress and stage-wake callbacks to avoid stale triggers.
            drop(entry.progress_cb.take());
            drop(entry.stage_wake_cb.take());
            // Notify driver-defined stages of cancellation.
            for stage in &self.inner.stages {
                if let StageKind::Driver(s) = stage {
                    s.cancel(&*entry.job, entry.counter);
                }
            }
            // If the fence was not yet passed to the driver, signal it now.
            if let Some(f) = entry.submit_fence_drv.take() {
                f.signal(Err(ECANCELED));
            }
            // For HW-stage entries the fence is held by the driver; we
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
