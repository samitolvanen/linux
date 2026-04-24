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
