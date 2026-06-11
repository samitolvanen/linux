// SPDX-License-Identifier: GPL-2.0 or MIT

//! Provides asynchronous reset handling for the Tyr DRM driver via `ResetHandle`
//! which runs reset work on a dedicated ordered workqueue and avoids duplicate
//! pending resets.
//!
//! # High-level Execution Flow
//!
//! ```text
//! +------+  schedule()  +---------+
//! | Idle |------------->| Pending |
//! +------+              +---------+
//!                            |
//!                            | reset_work()
//!                            v
//!                       +------------+
//!                       | InProgress |
//!                       +------------+
//!                            |
//!                            | reset done
//!                            v
//!                         +------+
//!                         | Idle |
//!                         +------+
//!
//! Teardown:
//!
//!   - Idle/Pending/InProgress -> ShuttingDown
//! ```
//!
//! A readiness gate holds a request recorded during probe at `Pending`
//! until `set_ready` enqueues the worker.

mod hw_gate;

use kernel::{
    devres::Devres,
    new_mutex,
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            AtomicType,
            Full,
            Relaxed,
            Release, //
        },
        Arc,
        Mutex, //
    },
    workqueue::{
        self,
        OwnedQueue,
        Queue,
        Work, //
    }, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice, //
    },
    gpu, //
};

/// Lifecycle state of the reset worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
enum ResetState {
    /// No reset request exists.
    Idle = 0,
    /// A reset request is recorded and waiting to be claimed by the worker.
    Pending = 1,
    /// Worker has claimed the request and is resetting hardware.
    InProgress = 2,
    /// Teardown has started and no new reset request may start.
    ShuttingDown = 3,
}

// SAFETY: `ResetState` and `i32` have the same size and alignment, and are
// round-trip transmutable.
unsafe impl AtomicType for ResetState {
    type Repr = i32;
}

/// Internal reset orchestrator that owns the state and work item.
#[pin_data]
struct Controller {
    pdev: ARef<platform::Device>,
    /// Mapped register space needed for reset operations.
    iomem: Arc<Devres<IoMem>>,
    /// DRM device reference, set once probe has created the device and
    /// revoked by devres at unbind. Resolving it through `Devres` keeps
    /// the back-reference from pinning the refcount cycle past unbind.
    #[pin]
    ddev: Mutex<Option<Devres<ARef<TyrDrmDevice>>>>,
    /// Lifecycle state of the reset worker.
    state: Atomic<ResetState>,
    /// Set once probe has finished bringing the device up. Requests
    /// recorded before that are held back until it is set.
    #[pin]
    ready: Mutex<bool>,
    /// Work item backing async reset processing.
    #[pin]
    work: Work<Controller>,
}

kernel::impl_has_work! {
    impl HasWork<Controller> for Controller { self.work }
}

impl workqueue::WorkItem for Controller {
    type Pointer = Arc<Self>;

    fn run(this: Arc<Self>) {
        this.reset_work();
    }
}

impl Controller {
    /// Creates an `Arc<Controller>` ready for use.
    fn new(pdev: ARef<platform::Device>, iomem: Arc<Devres<IoMem>>) -> Result<Arc<Self>> {
        Arc::pin_init(
            try_pin_init!(Self {
                pdev,
                iomem,
                ddev <- new_mutex!(None),
                state: Atomic::new(ResetState::Idle),
                ready <- new_mutex!(false),
                work <- kernel::new_work!("tyr::reset"),
            }),
            GFP_KERNEL,
        )
    }

    #[inline]
    fn try_change_state(&self, from: ResetState, to: ResetState) -> bool {
        self.state.cmpxchg(from, to, Full).is_ok()
    }

    /// Records a reset request and returns whether the worker may run it.
    ///
    /// A request recorded before probe opens the reset path stays pending
    /// until `set_ready` enqueues a worker for it.
    fn record_request(&self) -> bool {
        let ready = self.ready.lock();
        // A request lands only from Idle. Other states leave the machine as is.
        let _ = self.try_change_state(ResetState::Idle, ResetState::Pending);
        *ready
    }

    /// Opens the reset path and returns whether a request is waiting.
    ///
    /// Both this and `record_request` run under the `ready` lock. Either
    /// this call sees the recorded request, or the recording call sees the
    /// open path and queues a worker itself.
    fn set_ready(&self) -> bool {
        let mut ready = self.ready.lock();
        *ready = true;
        self.state.load(Relaxed) == ResetState::Pending
    }

    #[inline]
    fn claim_pending(&self) -> bool {
        self.try_change_state(ResetState::Pending, ResetState::InProgress)
    }

    #[inline]
    fn finish_reset(&self) {
        let _ = self.try_change_state(ResetState::InProgress, ResetState::Idle);
    }

    fn begin_teardown(&self) {
        // Every other writer is an edge-checked CAS from a specific state.
        // After this store none of them matches, so the state is final and
        // no reset claim can succeed.
        self.state.store(ResetState::ShuttingDown, Release);
    }

    /// Resolves the DRM device backing this controller.
    ///
    /// Returns `None` before probe wires the reference and after unbind
    /// revokes it. The `ARef` is cloned out of the revocable guard so the
    /// guard's RCU read-side critical section does not span the worker's
    /// sleeps.
    fn device(&self) -> Option<ARef<TyrDrmDevice>> {
        let slot = self.ddev.lock();
        let guard = slot.as_ref()?.try_access()?;
        Some((*guard).clone())
    }

    /// Processes one scheduled reset request.
    ///
    /// If the pending reset cannot be claimed, the worker returns immediately.
    fn reset_work(self: &Arc<Self>) {
        let Some(tdev) = self.device() else {
            // There is no device to reset, so consume the request without
            // touching the hardware.
            if self.claim_pending() {
                self.finish_reset();
            }
            return;
        };

        // The token blocks a suspend when runtime PM can hold a reference. A
        // reset must not run against a powered-off GPU, so a denied token
        // leaves the request pending across the suspend cycle.
        let Some(_active) = tdev.pm_get_if_active() else {
            return;
        };

        if !self.claim_pending() {
            return;
        }

        dev_info!(self.pdev.as_ref(), "Starting GPU reset.\n");

        match gpu::reset(self.pdev.as_ref(), &self.iomem) {
            Ok(()) => dev_info!(self.pdev.as_ref(), "GPU reset completed.\n"),
            Err(e) => {
                dev_err!(self.pdev.as_ref(), "GPU reset failed: {:?}\n", e);

                // TODO: Unplug the GPU.
                // There is no API for unplugging the GPU.
            }
        }

        self.finish_reset();
    }
}

/// User-facing handle for scheduling resets.
///
/// Dropping the handle drains any queued or in-flight reset work to ensure a
/// clean teardown before clocks and regulators are released.
pub(crate) struct ResetHandle {
    controller: Arc<Controller>,
    wq: OwnedQueue,
}

impl Drop for ResetHandle {
    fn drop(&mut self) {
        // Block new reset scheduling before the queue drains, so a
        // queued-but-unstarted reset fails its claim instead of touching the
        // hardware. One that already claimed `InProgress` completes first.
        self.controller.begin_teardown();
    }
}

impl ResetHandle {
    pub(crate) fn new(pdev: ARef<platform::Device>, iomem: Arc<Devres<IoMem>>) -> Result<Self> {
        Ok(Self {
            controller: Controller::new(pdev, iomem)?,
            wq: Queue::new_ordered().build(c"tyr-reset-wq")?,
        })
    }

    /// Waits for an in-flight reset worker to finish.
    pub(crate) fn flush(&self) {
        let _ = workqueue::flush_work::<Controller, Controller, 0>(&self.controller);
    }

    /// Cancels the reset worker at unbind.
    ///
    /// Empties the device slot so requests resolve no device from here
    /// on, then drains an in-flight worker. Unbind runs before devres
    /// teardown, so the drained worker still holds a live register
    /// mapping. A work item enqueued by a racing `schedule` finds the
    /// slot empty and consumes the request without hardware access.
    pub(crate) fn unbind(&self) {
        drop(self.controller.ddev.lock().take());
        self.flush();
    }

    /// Publishes the DRM device reference the reset worker resolves.
    ///
    /// Called once probe has created the device. Devres revokes the
    /// reference at unbind.
    pub(crate) fn set_device(&self, ddev: Devres<ARef<TyrDrmDevice>>) {
        *self.controller.ddev.lock() = Some(ddev);
    }

    /// Opens the reset path once probe has brought the device up.
    ///
    /// A request recorded during probe has no worker queued for it, so
    /// this queues one.
    pub(crate) fn set_ready(&self) {
        if self.controller.set_ready() {
            let _ = self.wq.enqueue(self.controller.clone());
        }
    }

    /// Schedules a GPU reset on the dedicated workqueue.
    ///
    /// If a reset is already pending or in progress the call is a no-op.
    #[expect(dead_code)]
    pub(crate) fn schedule(&self) {
        let Some(tdev) = self.controller.device() else {
            return;
        };

        // Keep only one reset request running or queued. If one is already
        // pending, we ignore new schedule requests.
        if !self.controller.record_request() {
            // Probe is still bringing the device up, so `set_ready` runs the
            // request once it is done.
            return;
        }

        let Some(_active) = tdev.pm_get_if_active() else {
            // The GPU is (or is about to be) powered off, so the recorded
            // request stays pending without a queued worker.
            return;
        };

        // An enqueue failure means the work item is already queued. That run
        // claims the pending request.
        let _ = self.wq.enqueue(self.controller.clone());
    }
}
