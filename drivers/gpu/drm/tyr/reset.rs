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
        TyrDrmDevice,
        TyrDrmRegistrationData, //
    },
    gpu,
    sched::tick, //
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

// SAFETY: `ResetState` and `i32` have the same size and alignment, and
// `ResetState` is round-trip transmutable to `i32`.
unsafe impl AtomicType for ResetState {
    type Repr = i32;
}

/// Internal reset orchestrator that owns the state and work item.
#[pin_data]
struct Controller {
    pdev: ARef<platform::Device>,
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
    fn new(pdev: ARef<platform::Device>) -> Result<Arc<Self>> {
        Arc::pin_init(
            try_pin_init!(Self {
                pdev,
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

    #[inline]
    fn is_in_progress(&self) -> bool {
        self.state.load(Relaxed) == ResetState::InProgress
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

    /// Closes a pending request the worker cannot run.
    #[inline]
    fn consume_request(&self) {
        if self.claim_pending() {
            self.finish_reset();
        }
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
            self.consume_request();
            return;
        };

        // The registration data owns the firmware the reboot below needs.
        // Registration ends at unbind, which also empties the device slot,
        // so treat a missing guard like a missing device.
        let Some(guard) = tdev.registration_guard() else {
            self.consume_request();
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

        let reset_result = guard.registration_data_with(|reg_data| {
            let parked = tick::pre_reset(&tdev, reg_data);
            let reset_result = run_hw_reset(reg_data);
            tick::post_reset(&tdev, parked, reset_result.is_err());

            match reset_result {
                Ok(()) => dev_info!(self.pdev.as_ref(), "GPU reset completed.\n"),
                Err(_) => dev_err!(self.pdev.as_ref(), "GPU reset cycle failed.\n"),
            }

            reset_result
        });

        self.finish_reset();

        if reset_result.is_ok() {
            // With the machine back to idle, rebind the evicted groups and
            // drain the firmware events that arrived during the reset.
            tick::resume(&tdev);
        }
    }
}

/// Runs the hardware half of a reset cycle.
///
/// Shared by the reset worker and the resume path that completes a reset
/// latched while the device was suspended, so both run the identical
/// sequence.
///
/// The firmware reboot is attempted even when the soft reset reports a
/// failure, since only the combined outcome decides whether the cycle
/// failed.
pub(crate) fn run_hw_reset(reg_data: &TyrDrmRegistrationData<'_>) -> Result {
    let io = reg_data.iomem.access(reg_data.pdev.as_ref())?;

    reg_data.fw.pre_reset(&reg_data.job_irq, io);

    let reset_result = gpu::reset(reg_data.pdev.as_ref(), io);
    if let Err(e) = &reset_result {
        dev_err!(reg_data.pdev, "GPU reset failed: {:?}\n", e);
    }

    let core_clk_rate = reg_data.clks.lock().core.rate().as_hz() as u64;
    let reboot_result = reg_data.fw.post_reset(&reg_data.job_irq, core_clk_rate, io);
    if let Err(e) = &reboot_result {
        dev_err!(
            reg_data.pdev,
            "Firmware reboot after reset failed: {:?}\n",
            e
        );

        // TODO: Unplug the GPU.
        // There is no API for unplugging the GPU.
    }

    reset_result.and(reboot_result)
}

/// Shared reset state, made up of the controller and its dedicated workqueue.
struct Inner {
    controller: Arc<Controller>,
    wq: OwnedQueue,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Block new reset scheduling before the queue drains, so a
        // queued-but-unstarted reset fails its claim instead of touching the
        // hardware. One that already claimed `InProgress` completes first.
        self.controller.begin_teardown();
    }
}

/// User-facing handle for scheduling resets. Clones share one
/// controller and workqueue.
///
/// `unbind()` drains the worker at platform unbind, before the clocks and
/// regulators drop. Dropping the last clone then destroys the workqueue.
#[derive(Clone)]
pub(crate) struct ResetHandle {
    inner: Arc<Inner>,
}

impl ResetHandle {
    pub(crate) fn new(pdev: ARef<platform::Device>) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(
                Inner {
                    controller: Controller::new(pdev)?,
                    wq: Queue::new_ordered().build(c"tyr-reset-wq")?,
                },
                GFP_KERNEL,
            )?,
        })
    }

    /// Returns whether the reset worker is executing a claimed reset.
    ///
    /// Scheduler workers check this to stay off the CSG slots while the reset
    /// worker owns them. A merely pending request does not gate them. It can
    /// stay pending across a whole active period, and the worker stops the
    /// scheduler itself after claiming the reset.
    pub(crate) fn in_progress(&self) -> bool {
        self.inner.controller.is_in_progress()
    }

    /// Waits for an in-flight reset worker to finish.
    pub(crate) fn flush(&self) {
        self.inner.controller.work.flush();
    }

    /// Cancels the reset worker at unbind.
    ///
    /// Empties the device slot so requests resolve no device from here
    /// on, then drains an in-flight worker. Unbind runs before devres
    /// teardown, so the drained worker still holds a live register
    /// mapping. A work item enqueued by a racing `schedule` finds the
    /// slot empty and consumes the request without hardware access.
    pub(crate) fn unbind(&self) {
        self.clear_device();
        self.flush();
    }

    /// Empties the device slot.
    ///
    /// Probe calls this on its failure path while it still holds a
    /// device reference. If devres empties the slot instead, the
    /// revocation drops the last reference and the device teardown
    /// deadlocks in the same `Devres`.
    pub(crate) fn clear_device(&self) {
        // Dropping the entry can wait for a concurrent revocation, so take
        // it out of the slot first.
        let ddev = self.inner.controller.ddev.lock().take();
        drop(ddev);
    }

    /// Claims a reset request recorded while the device was suspended.
    ///
    /// Returns `true` if a pending request was claimed. The caller then
    /// performs the reset work itself (the resume path completes it
    /// with a full firmware reload) and closes the cycle with
    /// `Self::complete_claimed`.
    pub(crate) fn claim_pending(&self) -> bool {
        self.inner.controller.claim_pending()
    }

    /// Completes a reset cycle claimed with `Self::claim_pending`.
    pub(crate) fn complete_claimed(&self) {
        self.inner.controller.finish_reset()
    }

    /// Publishes the DRM device reference the reset worker resolves.
    ///
    /// Called once probe has created the device. Devres revokes the
    /// reference at unbind.
    pub(crate) fn set_device(&self, ddev: Devres<ARef<TyrDrmDevice>>) {
        *self.inner.controller.ddev.lock() = Some(ddev);
    }

    /// Opens the reset path once probe has brought the device up.
    ///
    /// A request recorded during probe has no worker queued for it, so
    /// this queues one.
    pub(crate) fn set_ready(&self) {
        if self.inner.controller.set_ready() {
            let _ = self.inner.wq.enqueue(self.inner.controller.clone());
        }
    }

    /// Schedules a GPU reset on the dedicated workqueue.
    ///
    /// A reset that is already pending or in progress absorbs new requests.
    pub(crate) fn schedule(&self) {
        let Some(tdev) = self.inner.controller.device() else {
            return;
        };

        // Record before the enqueue below so a worker already queued but not
        // yet started observes and claims the request. A duplicate enqueue is
        // rejected harmlessly.
        if !self.inner.controller.record_request() {
            // Probe is still bringing the device up, so `set_ready` runs the
            // request once it is done.
            return;
        }

        let Some(_active) = tdev.pm_get_if_active() else {
            // The GPU is (or is about to be) powered off, so the resume path
            // claims the recorded request.
            return;
        };

        // Queue a worker even when a request is already pending, since a
        // request recorded while the device was inactive has no worker.
        let _ = self.inner.wq.enqueue(self.inner.controller.clone());
    }
}
