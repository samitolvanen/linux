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
//! ## Stage iteration order
//!
//! `check_progress()` walks the pipeline in two passes per tick:
//!
//! 1. Backward — later stages first, so completed jobs free resources
//!    (e.g. ring-buffer slots) before earlier stages try to consume them.
//! 2. Forward — picks up jobs that became eligible during the backward
//!    pass and advances them in the same tick.
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

use crate::{
    dma_buf::dma_fence::{
        DmaFenceWorkqueue,
        DriverDmaFence,
        DriverDmaFenceOps,
        PublicDmaFence, //
        Published,
    },
    error::Result,
    prelude::*,
    sync::aref::ARef,
    time::{Delta, Instant, Jiffies, Monotonic},
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
///     fn teardown(&self, _job: &MyJob, counter: u64) {
///         pr_warn!("Job {} cancelled in hw stage\n", counter);
///     }
/// }
/// ```
pub trait StageOps<T: QueueOps>: Send + Sync + 'static {
    /// Called by the pipeline on each progress tick for the job at the head
    /// of this stage. Returns what the pipeline should do next.
    fn process(&self, ctx: &StageContext<'_, T>) -> StageAdvance;

    /// Called when a job that was in this stage is cancelled (e.g. via
    /// [`JobQueue::cancel_all`]) without completing the stage normally.
    /// The implementation should release any per-stage resources that were
    /// allocated when the job entered this stage.  The default does nothing.
    fn teardown(&self, _job: &T::Job, _counter: u64) {}
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
