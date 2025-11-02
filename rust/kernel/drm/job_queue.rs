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
//!
//! ## Teardown
//!
//! Dropping a [`JobQueue`] calls [`JobQueue::cancel_all`], which synchronously
//! drains the entire pipeline:
//!
//! - All dependency, progress, and stage-wake callbacks are unregistered before
//!   any entry is freed, so no stale callbacks fire after drop returns.
//! - Every fence that passed through [`JobQueue::commit`] is guaranteed to
//!   signal, either normally or with `ECANCELED`, before drop returns.
//! - Jobs at stages beyond `WaitingForExec` — those already handed to hardware —
//!   are waited on before cancellation. Use
//!   [`PipelineBuilder::set_cancel_timeout`] to bound this wait.
//! - The driver's [`QueueOps`] methods are never called again after drop returns.
//!
//! Together these guarantees make teardown straightforward to reason about: no
//! fence callback or scheduled work item can fire against hardware or firmware
//! state that has already been freed. In the common synchronous case this
//! holds directly — the queue is fully quiesced before the surrounding driver
//! struct's destructor can free any of that state. For async teardown the same
//! invariant must be maintained by the driver; see below.
//!
//! ### Async teardown
//!
//! Drivers that need firmware round-trips before the queue is torn down (e.g.
//! to deregister a context with the firmware) can wrap [`JobQueue`] in a driver
//! type and defer the drop:
//!
//! ```ignore
//! struct ExecQueue<T: QueueOps> {
//!     job_queue: JobQueue<T>,
//!     // ... firmware handles, etc.
//! }
//!
//! impl<T: QueueOps> ExecQueue<T> {
//!     fn destroy(self) {
//!         // Park first: prevents check_progress() from calling StageOps
//!         // callbacks while firmware state is being torn down.
//!         self.job_queue.park();
//!         // Move into async work on a device-level workqueue.
//!         // When the firmware round-trips finish, drop(self) runs
//!         // cancel_all() as usual.
//!     }
//! }
//! ```
//!
//! Parking before starting async teardown is important: without it, fence
//! callbacks could fire [`check_progress`](JobQueue::check_progress) during
//! the firmware teardown window, invoking driver stage callbacks against
//! partially-torn-down state. All resources held by the queue (the job data,
//! the [`QueueOps`] handler, any `Arc`s inside it) stay alive until drop
//! completes normally.

use crate::dma_fence::Fence;
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
        FenceCallback,
        FenceCallbackRegistration,
        FenceWaitResult, //
    },
    error::Result,
    impl_has_dma_fence_delayed_work, impl_has_dma_fence_work, new_dma_fence_delayed_work,
    new_dma_fence_work, new_mutex,
    prelude::*,
    sync::{
        Arc,
        Mutex, //
    },
    time::{
        msecs_to_jiffies,
        Delta,
        Instant,
        Jiffies,
        Monotonic, //
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
    WaitOn(Fence),
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
    pub submit_fence: &'a Fence,
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
/// let queue = JobQueue::new(handler, wq, aux_wq, pipeline)?;
/// ```
///
/// A queue with a 10-second total pipeline deadline:
///
/// ```ignore
/// let pipeline = PipelineBuilder::new()
///     .set_pipeline_timeout(msecs_to_jiffies(10000))
///     .add_stage(HwStage { timeout: msecs_to_jiffies(5000) })?;
/// let queue = JobQueue::new(handler, wq, aux_wq, pipeline)?;
/// ```
pub struct PipelineBuilder<T: QueueOps> {
    stages: KVec<Arc<dyn StageOps<T>>>,
    pipeline_timeout: Option<Jiffies>,
    cancel_timeout: Option<Jiffies>,
}

impl<T: QueueOps> PipelineBuilder<T> {
    /// Create an empty builder with no stages and no pipeline timeout.
    pub fn new() -> Self {
        Self {
            stages: KVec::new(),
            pipeline_timeout: None,
            cancel_timeout: None,
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

    /// Set the per-entry timeout used in [`JobQueue::cancel_all`] when waiting
    /// for hardware fences to signal.
    pub fn set_cancel_timeout(mut self, timeout: Jiffies) -> Self {
        self.cancel_timeout = Some(timeout);
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

/// The result of submitting a job to the driver.
pub enum SubmitResult {
    /// The driver accepted the job and took ownership of the submit fence.
    Submitted,
    /// The driver has no resources available (e.g. ring buffer full).
    NoResources,
}

struct SubmitFenceData;

#[vtable]
impl kernel::dma_fence::FenceOps for SubmitFenceData {
    const USE_64BIT_SEQNO: bool = true;

    fn get_driver_name<'a>(self: &'a kernel::dma_fence::FenceObject<Self>) -> &'a CStr {
        c_str!("tyr")
    }

    fn get_timeline_name<'a>(self: &'a kernel::dma_fence::FenceObject<Self>) -> &'a CStr {
        c_str!("job_queue")
    }
}

/// A read-only reference to a submitted job, provided to the driver's submit
/// callback.
pub struct JobRef<'a, J: Send + Sync + 'static> {
    /// The driver's job data.
    pub job: &'a J,
    /// The public fence that will be signaled when this job completes.
    pub submit_fence: &'a kernel::dma_fence::Fence,
    /// Monotonic job counter, useful for debug/logging.
    pub counter: u64,
}

/// Driver callbacks for [`JobQueue`] -- all calls happen in process context.
pub trait QueueOps: Send + Sync + 'static {
    /// The type of job this handler processes.
    type Job: Send + Sync + 'static;

    /// Submit a job to the hardware. Called from process context.
    fn submit(&self, job: &JobRef<'_, Self::Job>) -> Result<SubmitResult>;
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
        Self { start: 1, end: 1 }
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
    fences: KVec<kernel::dma_fence::Fence>,
    /// Which dependency we're currently waiting on.
    current_idx: usize,
    /// The currently active dependency callback (at most one at a time).
    active_cb: Option<Pin<KBox<FenceCallbackRegistration<DepCallback<T>>>>>,
    /// Pre-allocated uninitialized memory for dependency callbacks.
    prealloc_cbs: KVec<KBox<core::mem::MaybeUninit<FenceCallbackRegistration<DepCallback<T>>>>>,
}

struct JobEntry<T: QueueOps> {
    /// The driver's job data.
    job: Arc<T::Job>,

    /// The public fence returned to the caller of `submit()`. Shared with
    /// dependency waiters and other observers.
    submit_fence: kernel::dma_fence::Fence,

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

    /// Pre-allocated uninitialized memory for the progress callback.
    prealloc_progress_cb:
        Option<KBox<core::mem::MaybeUninit<FenceCallbackRegistration<ProgressCallback<T>>>>>,

    /// Pre-allocated uninitialized memory for the stage wake callback.
    prealloc_stage_cb:
        Option<KBox<core::mem::MaybeUninit<FenceCallbackRegistration<StageWakeCallback<T>>>>>,
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
#[pin_data(PinnedDrop)]
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
    cleanup_work: kernel::dma_fence::DmaFenceWork<JobQueueInner<T>, 3>,

    // Workqueue for the main pipeline check (enforces DMA fence signaling rules).
    wq: Arc<DmaFenceWorkqueue>,

    // Internal workqueue for cleanup work.
    aux_wq: Arc<DmaFenceWorkqueue>,

    contexts: kernel::dma_fence::FenceContexts,

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

    cancel_timeout: Option<Jiffies>,

    /// Delayed work for stage-timer wakeups.
    #[pin]
    stage_timer: DmaFenceDelayedWork<JobQueueInner<T>, 4>,
}

// SAFETY: All fields in `JobQueueInner` are thread-safe (either `Atomic*`,
// protected by a `Mutex`, or are `Send`/`Sync` themselves like `XArray` and
// workqueue types), and the type parameter `T` is required to be `Send` and `Sync`.
unsafe impl<T: QueueOps> Send for JobQueueInner<T> {}
// SAFETY: Same as above.
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

impl<T: QueueOps> kernel::dma_fence::DmaFenceWorkItem<3> for JobQueueInner<T> {
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

#[pinned_drop]
impl<T: QueueOps> PinnedDrop for JobQueueInner<T> {
    fn drop(self: Pin<&mut Self>) {
        self.cancel_all();
    }
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

        self.check_stages(&mut state, Direction::Backward);
        self.check_stages(&mut state, Direction::Forward);

        let needs_cleanup = !state.done_range.is_empty();
        drop(state);
        if needs_cleanup {
            self.schedule_cleanup();
        }
    }

    /// Walk every stage in the given [`Direction`], processing the front job at
    /// each stage until it blocks or the stage empties.
    fn check_stages(self: &Arc<Self>, state: &mut PipelineState, direction: Direction) {
        let park = state.parked_at.unwrap_or(usize::MAX);

        match direction {
            Direction::Forward => {
                for stage_i in 0..self.stages.len() {
                    if stage_i >= park {
                        continue;
                    }
                    self.process_stage(state, stage_i);
                }
            }
            Direction::Backward => {
                for stage_i in (0..self.stages.len()).rev() {
                    if stage_i >= park {
                        continue;
                    }
                    self.process_stage(state, stage_i);
                }
            }
        }
    }

    /// Process the front job at `stage_i` in a loop until the stage empties
    /// or the job blocks.
    fn process_stage(self: &Arc<Self>, state: &mut PipelineState, stage_i: usize) {
        loop {
            if state.stage_ranges[stage_i].is_empty() {
                return;
            }
            let entry_idx = state.stage_ranges[stage_i].start;

            let is_failed = {
                let guard = self.fifo.lock();
                guard
                    .get(entry_idx as usize)
                    .map(|e| e.submit_fence.is_signaled() && e.submit_fence.error() < 0)
                    .unwrap_or(false)
            };

            let advance = if is_failed {
                StageAdvance::Advance
            } else {
                match &self.stages[stage_i] {
                    StageKind::WaitingForDeps => self.process_deps(entry_idx),
                    StageKind::WaitingForExec => self.process_exec(entry_idx),
                    StageKind::Executing => self.process_default_hw_wait(entry_idx),
                    StageKind::Driver(stage) => self.process_driver_stage(stage.clone(), entry_idx),
                }
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
                    // Continue loop: process the new front of this stage.
                }
                StageAdvance::TimedOut(e) => {
                    pr_err!(
                        "JobQueue: stage {} timed out with error {:?}, entry {}\n",
                        stage_i,
                        e,
                        entry_idx
                    );
                    {
                        let mut guard = self.fifo.lock();
                        if let Some(entry) = guard.get_mut(entry_idx as usize) {
                            entry.submit_fence.set_error(e.to_errno());
                            let _ = entry.submit_fence.signal();
                        }
                    }
                    state.stage_ranges[stage_i].pop_front();
                    if stage_i + 1 < self.stages.len() {
                        state.stage_ranges[stage_i + 1].push_back();
                        let mut guard = self.fifo.lock();
                        if let Some(entry) = guard.get_mut(entry_idx as usize) {
                            entry.stage_entered_at = Instant::now();
                        }
                    } else {
                        state.done_range.push_back();
                    }
                    // Continue loop: process the new front of this stage.
                }
                StageAdvance::WaitOn(fence) => {
                    let uninit_box = {
                        let mut guard = self.fifo.lock();
                        guard
                            .get_mut(entry_idx as usize)
                            .and_then(|e| e.prealloc_stage_cb.take())
                    };

                    let cb = FenceCallbackRegistration::new(
                        &fence,
                        StageWakeCallback {
                            inner: self.clone(),
                        },
                    );

                    if let Some(uninit_box) = uninit_box {
                        match uninit_box.write_pin_init(cb) {
                            Ok(registration) => {
                                let mut guard = self.fifo.lock();
                                if let Some(entry) = guard.get_mut(entry_idx as usize) {
                                    entry.stage_wake_cb = Some(registration);
                                }
                            }
                            Err(CallbackError::AlreadySignaled) => {
                                self.maybe_check_progress();
                            }
                            Err(CallbackError::Other(e)) => {
                                pr_err!(
                                    "JobQueue: stage WaitOn prealloc failed: {:?}, entry {}\n",
                                    e,
                                    entry_idx
                                );
                            }
                        }
                    } else {
                        let cb_box = match KBox::new_uninit(GFP_NOWAIT) {
                            Ok(b) => b,
                            Err(_) => {
                                pr_err!(
                                    "JobQueue: stage WaitOn cb alloc failed, entry {}\n",
                                    entry_idx
                                );
                                return;
                            }
                        };
                        match cb_box.write_pin_init(cb) {
                            Ok(registration) => {
                                let mut guard = self.fifo.lock();
                                if let Some(entry) = guard.get_mut(entry_idx as usize) {
                                    entry.stage_wake_cb = Some(registration);
                                }
                            }
                            Err(CallbackError::AlreadySignaled) => {
                                self.maybe_check_progress();
                            }
                            Err(CallbackError::Other(e)) => {
                                pr_err!(
                                    "JobQueue: stage WaitOn cb alloc failed: {:?}, entry {}\n",
                                    e,
                                    entry_idx
                                );
                            }
                        }
                    }
                    return;
                }
                StageAdvance::WaitFor(delay) => {
                    let _ = self.wq.enqueue_delayed::<Arc<Self>, 4>(self.clone(), delay);
                    return;
                }
                StageAdvance::Wait => return,
            }
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

            if dep_fence.is_signaled() {
                let mut guard = self.fifo.lock();
                if let Some(entry) = guard.get_mut(entry_idx as usize) {
                    entry.deps.active_cb = None;
                    entry.deps.current_idx += 1;
                }
                continue;
            }

            // If we've already registered a callback for this dependency, wait.
            let is_waiting = {
                let guard = self.fifo.lock();
                if let Some(entry) = guard.get(entry_idx as usize) {
                    entry.deps.active_cb.is_some()
                } else {
                    false
                }
            };

            if is_waiting {
                return self.pipeline_wait_or_timeout(entry_idx);
            }

            let callback = DepCallback {
                inner: self.clone(),
            };
            let uninit_box = {
                let mut guard = self.fifo.lock();
                guard
                    .get_mut(entry_idx as usize)
                    .unwrap()
                    .deps
                    .prealloc_cbs
                    .pop()
                    .unwrap()
            };
            match uninit_box.write_pin_init(FenceCallbackRegistration::new(&dep_fence, callback)) {
                Ok(registration) => {
                    {
                        let mut guard = self.fifo.lock();
                        if let Some(entry) = guard.get_mut(entry_idx as usize) {
                            entry.deps.active_cb = Some(registration);
                        }
                    }
                    return self.pipeline_wait_or_timeout(entry_idx);
                }
                Err(CallbackError::AlreadySignaled) => {
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
            let mut guard = self.fifo.lock();
            match guard.get_mut(entry_idx as usize) {
                Some(entry) => (entry.job.clone(), entry.submit_fence.clone(), entry.counter),
                None => {
                    pr_err!(
                        "JobQueue: process_exec() BUG: xa_idx={} missing\n",
                        entry_idx
                    );
                    return StageAdvance::Advance;
                }
            }
        };

        let job_ref = JobRef {
            job: &*job,
            submit_fence: &submit_fence,
            counter,
        };

        match self.handler.submit(&job_ref) {
            Ok(SubmitResult::Submitted) => {
                let uninit_box = {
                    let mut guard = self.fifo.lock();
                    match guard.get_mut(entry_idx as usize) {
                        Some(entry) => match entry.prealloc_progress_cb.take() {
                            Some(cb) => cb,
                            None => {
                                pr_err!(
                                    "JobQueue: process_exec() BUG: xa_idx={} missing prealloc_progress_cb\n",
                                    entry_idx
                                );
                                return StageAdvance::Advance;
                            }
                        },
                        None => {
                            pr_err!(
                                "JobQueue: process_exec() BUG: xa_idx={} missing after submit\n",
                                entry_idx
                            );
                            return StageAdvance::Advance;
                        }
                    }
                };
                let cb_result = uninit_box.write_pin_init(FenceCallbackRegistration::new(
                    &submit_fence,
                    ProgressCallback {
                        inner: self.clone(),
                    },
                ));

                match cb_result {
                    Ok(registration) => {
                        let mut guard = self.fifo.lock();
                        if let Some(entry) = guard.get_mut(entry_idx as usize) {
                            entry.progress_cb = Some(registration);
                        }
                    }
                    Err(CallbackError::AlreadySignaled) => {
                        self.maybe_check_progress();
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
            Ok(SubmitResult::NoResources) => self.pipeline_wait_or_timeout(entry_idx),
            Err(e) => {
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
        let mut state = self.state.lock();
        while let Some(idx) = state.done_range.pop_front() {
            drop(self.fifo.lock().remove(idx as usize));
        }
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
    fn signaled(&self, _fence: &Fence) {
        self.inner.maybe_check_progress();
    }
}

/// Callback registered on the public submit fence. Triggers a pipeline check
/// when the driver signals the fence so that `check_stages()` runs promptly.
struct ProgressCallback<T: QueueOps> {
    inner: Arc<JobQueueInner<T>>,
}

impl<T: QueueOps> FenceCallback for ProgressCallback<T> {
    fn signaled(&self, _fence: &Fence) {
        self.inner.maybe_check_progress();
    }
}

/// Callback registered when a stage returns [`StageAdvance::WaitOn`].
/// Triggers a pipeline tick when the stage's requested fence signals.
struct StageWakeCallback<T: QueueOps> {
    inner: Arc<JobQueueInner<T>>,
}

impl<T: QueueOps> FenceCallback for StageWakeCallback<T> {
    fn signaled(&self, _fence: &Fence) {
        self.inner.maybe_check_progress();
    }
}

/// A process-context job queue that manages job dependencies, driver
/// submission, and hardware completion for GPU jobs.
#[derive(Clone)]
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
/// XArray slot is released and the pre-allocated submit fence is dropped
/// without ever being published, so no seqno is consumed.
pub struct PreparedJob<T: QueueOps> {
    inner: Arc<JobQueueInner<T>>,
    job: Arc<T::Job>,
    /// The public submit fence for this job.
    submit_fence: Fence,
    /// Reserved XArray slot. `None` once consumed by `commit()`.
    xa_index: Option<ReservedIndex>,
    /// Pre-allocated dependency vector (empty on creation, capacity reserved).
    deps: KVec<Fence>,
    prealloc_cbs: KVec<KBox<core::mem::MaybeUninit<FenceCallbackRegistration<DepCallback<T>>>>>,
    prealloc_progress_cb:
        Option<KBox<core::mem::MaybeUninit<FenceCallbackRegistration<ProgressCallback<T>>>>>,
    prealloc_stage_cb:
        Option<KBox<core::mem::MaybeUninit<FenceCallbackRegistration<StageWakeCallback<T>>>>>,
    entry_box: Option<KBox<core::mem::MaybeUninit<JobEntry<T>>>>,
    counter: u64,
}

impl<T: QueueOps> Drop for PreparedJob<T> {
    fn drop(&mut self) {
        if let Some(idx) = self.xa_index.take() {
            self.inner.fifo.lock().release(idx);
            self.submit_fence
                .set_error(-(kernel::bindings::ECANCELED as i32));
            let _ = self.submit_fence.signal();
        }
    }
}

/// The direction to walk pipeline stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Walk from stage 0 up to the last stage.
    Forward,
    /// Walk from the last stage down to stage 0.
    Backward,
}

impl<T: QueueOps> JobQueueInner<T> {
    /// Cancel all pending and running jobs.
    pub(crate) fn cancel_all(&self) {
        const EXEC_STAGE_IDX: usize = 1;

        let mut state = self.state.lock();

        // First, drain inbox so all submitted jobs become visible.
        self.drain_inbox(&mut state);

        for stage_i in 0..state.stage_ranges.len() {
            while let Some(idx) = state.stage_ranges[stage_i].pop_front() {
                let Some(mut entry) = self.fifo.lock().remove(idx as usize) else {
                    continue;
                };

                // Perform non-waiting cleanup
                drop(entry.deps.active_cb.take());
                drop(entry.progress_cb.take());
                drop(entry.stage_wake_cb.take());
                for stage in &self.stages {
                    if let StageKind::Driver(s) = stage {
                        s.cancel(&*entry.job, entry.counter);
                    }
                }
                if stage_i <= EXEC_STAGE_IDX {
                    entry
                        .submit_fence
                        .set_error(-(kernel::bindings::ECANCELED as i32));
                    let _ = entry.submit_fence.signal();
                }

                // Wait for HW fence if needed without holding the lock
                if stage_i > EXEC_STAGE_IDX {
                    let fence = entry.submit_fence.clone();
                    drop(state);
                    match self.cancel_timeout {
                        None => {
                            let _ = fence.wait();
                        }
                        Some(t) => {
                            if let Ok(FenceWaitResult::TimedOut) = fence.wait_timeout(t) {
                                pr_warn!(
                                    "JobQueue: timed out waiting for HW fence during teardown\n"
                                );
                            }
                        }
                    }
                    state = self.state.lock();
                }
            }
        }

        while let Some(idx) = state.done_range.pop_front() {
            drop(self.fifo.lock().remove(idx as usize));
        }
    }
}

impl<T: QueueOps> JobQueue<T> {
    /// Returns true if the job queue is completely idle (no jobs in any stage).
    pub fn is_idle(&self) -> bool {
        let state = self.inner.state.lock();
        let inbox = self.inner.inbox.lock();
        if state.submitted_start != inbox.submitted_end {
            return false;
        }
        for i in 0..state.stage_ranges.len() {
            if !state.stage_ranges[i].is_empty() {
                return false;
            }
        }
        state.done_range.is_empty()
    }

    /// Park the queue, preventing jobs from being submitted to the driver.
    pub fn park(&self) {
        // WaitingForExec is always at index 1 in the stages vec.
        self.inner.state.lock().parked_at = Some(1);
    }

    /// Unpark the queue, allowing jobs to be submitted to the driver again.
    pub fn unpark(&self) {
        self.inner.state.lock().parked_at = None;
        self.inner.schedule_cleanup();
    }

    /// Create a new job queue.
    ///
    /// `handler` is the driver's submission logic.
    /// `wq` is the DMA fence workqueue to schedule pipeline checks on.
    /// `aux_wq` is the workqueue for deferred cleanup; the driver may pass the
    /// same workqueue as `wq` if no separation is needed.
    /// `pipeline` is the set of driver-defined stages jobs pass through after
    /// HW submission (use [`PipelineBuilder::new()`] for no custom stages).
    pub fn new(
        handler: T,
        wq: Arc<DmaFenceWorkqueue>,
        aux_wq: Arc<DmaFenceWorkqueue>,
        mut pipeline: PipelineBuilder<T>,
    ) -> Result<Self> {
        let contexts = kernel::dma_fence::FenceContexts::new(1, c_str!("job_queue"), None, 1)?;

        // Build the unified stages vec:
        //   [WaitingForDeps, WaitingForExec, <driver stages or Executing>]
        let mut all_stages: KVec<StageKind<T>> = KVec::new();
        all_stages.push(StageKind::WaitingForDeps, GFP_KERNEL)?;
        all_stages.push(StageKind::WaitingForExec, GFP_KERNEL)?;
        let pipeline_timeout = pipeline.pipeline_timeout;
        let cancel_timeout = pipeline.cancel_timeout;
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
                fifo <- XArray::new(AllocKind::Alloc1),
                inbox <- new_mutex!(InboxState {
                    cyclic_next: 1,
                    submitted_end: 0,
                }),
                state <- new_mutex!(pipeline_state),
                handler,
                work <- new_dma_fence_work!("JobQueue::work"),
                cleanup_work <- kernel::dma_fence::new_dma_fence_work!("JobQueue::cleanup_work"),
                wq,
                aux_wq,
                contexts,
                job_counter: AtomicU64::new(0),
                coalesce: AtomicBool::new(false),
                stages: all_stages,
                pipeline_timeout,
                cancel_timeout,
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
    pub fn prepare(&self, job: T::Job, num_deps: usize) -> Result<PreparedJob<T>> {
        let uf = self.inner.contexts.new_fence(0, SubmitFenceData)?;
        let user_fence: kernel::dma_fence::UserFence<SubmitFenceData> = uf.into();
        let submit_fence = Fence::from_fence(&user_fence);

        let counter = self.inner.job_counter.fetch_add(1, Ordering::SeqCst);
        let job = Arc::new(job, GFP_KERNEL)?;
        let deps = KVec::with_capacity(num_deps, GFP_KERNEL)?;

        let mut prealloc_cbs = KVec::with_capacity(num_deps, GFP_KERNEL)?;
        for _ in 0..num_deps {
            prealloc_cbs.push(KBox::new_uninit(GFP_KERNEL)?, GFP_KERNEL)?;
        }

        let prealloc_progress_cb = Some(KBox::new_uninit(GFP_KERNEL)?);
        let prealloc_stage_cb = Some(KBox::new_uninit(GFP_KERNEL)?);

        let entry_box = Some(KBox::new_uninit(GFP_KERNEL)?);

        let xa_index = {
            let mut inbox = self.inner.inbox.lock();
            let mut guard = self.inner.fifo.lock();
            guard.alloc_cyclic_reserve(XaLimit::LIMIT_32B, &mut inbox.cyclic_next, GFP_KERNEL)?
        };

        Ok(PreparedJob {
            inner: self.inner.clone(),
            job,
            submit_fence,
            xa_index: Some(xa_index),
            deps,
            prealloc_cbs,
            prealloc_progress_cb,
            prealloc_stage_cb,
            entry_box,
            counter,
        })
    }

    /// Commit a prepared job to the pipeline.
    ///
    /// Returns the public submit fence.
    pub fn commit(&self, mut prepared: PreparedJob<T>, deps: &[Fence]) -> Result<Fence> {
        let xa_index = prepared
            .xa_index
            .take()
            .expect("JobQueue::commit: xa_index already consumed");

        let mut dep_vec = core::mem::replace(&mut prepared.deps, KVec::new());
        for d in deps {
            // Capacity was reserved in prepare(); pushing more deps than the
            // num_deps passed there is a contract violation. Surface it so
            // we never run a job whose dependency was silently dropped.
            dep_vec.push(d.clone(), GFP_NOWAIT)?;
        }

        let submit_fence = prepared.submit_fence.clone();

        let mut entry_box = prepared.entry_box.take().unwrap();
        (*entry_box).write(JobEntry {
            job: prepared.job.clone(),
            submit_fence: submit_fence.clone(),
            counter: prepared.counter,
            deps: JobDependencies {
                fences: dep_vec,
                current_idx: 0,
                active_cb: None,
                prealloc_cbs: core::mem::replace(&mut prepared.prealloc_cbs, KVec::new()),
            },
            progress_cb: None,
            stage_entered_at: Instant::now(),
            pipeline_entered_at: Instant::now(),
            stage_wake_cb: None,
            prealloc_progress_cb: prepared.prealloc_progress_cb.take(),
            prealloc_stage_cb: prepared.prealloc_stage_cb.take(),
        });
        // SAFETY: We just wrote the initialized `JobEntry` to `entry_box` above.
        let entry = unsafe { entry_box.assume_init() };

        let mut inbox = self.inner.inbox.lock();

        {
            let mut guard = self.inner.fifo.lock();
            if let Err(store_err) = guard.store_reserved(xa_index, entry, GFP_NOWAIT) {
                drop(store_err);
                guard.release(xa_index);
                drop(inbox);
                return Err(ENOMEM);
            }
        }

        inbox.submitted_end = inbox.submitted_end.wrapping_add(1);

        drop(inbox);

        self.inner.maybe_check_progress();
        Ok(submit_fence)
    }

    /// Submits a job to the queue with the given dependencies.
    pub fn submit(&self, job: T::Job, dependencies: &[Fence]) -> Result<Fence> {
        let prepared = self.prepare(job, dependencies.len())?;
        self.commit(prepared, dependencies)
    }

    /// Cancel all pending and running jobs.
    pub fn cancel_all(&self) {
        self.inner.cancel_all();
    }
}
