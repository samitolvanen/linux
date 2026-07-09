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

use kernel::{
    device::Device,
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
    gpu,
    mmu,
    sched::tick,
    trace, //
};

pub(crate) mod hw_gate;

use hw_gate::HwGate;

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

/// What `Controller::record_request` did with a reset request.
struct RequestRecord {
    /// The reset path is open, so the caller may queue a worker.
    ready: bool,
    /// The state machine was not idle, so this request folded into
    /// whatever it was already doing. Downstream-only debug aid.
    coalesced: bool,
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
    /// Gate closed around the reset so VM updates and address-space
    /// operations drain before the hardware is wiped.
    gate: Arc<HwGate>,
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
        let gate = Arc::pin_init(HwGate::new(), GFP_KERNEL)?;
        Arc::pin_init(
            try_pin_init!(Self {
                pdev,
                iomem,
                ddev <- new_mutex!(None),
                state: Atomic::new(ResetState::Idle),
                ready <- new_mutex!(false),
                gate,
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
    fn record_request(&self) -> RequestRecord {
        let ready = self.ready.lock();
        // A request lands only from Idle. Other states leave the machine as is.
        let landed = self.try_change_state(ResetState::Idle, ResetState::Pending);
        RequestRecord {
            ready: *ready,
            coalesced: !landed,
        }
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
            trace::reset_worker(trace::ResetWorkerOutcome::NoDevice);
            if self.claim_pending() {
                self.finish_reset();
            }
            return;
        };

        // The token blocks a suspend when runtime PM can hold a reference. A
        // reset must not run against a powered-off GPU, so a denied token
        // leaves the request pending across the suspend cycle.
        let Some(_active) = tdev.pm_get_if_active() else {
            trace::reset_worker(trace::ResetWorkerOutcome::PmInactive);
            return;
        };

        if !self.claim_pending() {
            trace::reset_worker(trace::ResetWorkerOutcome::ClaimFailed);
            return;
        }

        trace::reset_worker(trace::ResetWorkerOutcome::Run);
        dev_info!(self.pdev.as_ref(), "Starting GPU reset.\n");

        tdev.cancel_fw_ping();
        let parked = tick::pre_reset(&tdev);
        let reset_result = run_hw_reset(&tdev, self.pdev.as_ref(), &self.iomem, &self.gate);
        tick::post_reset(&tdev, parked, reset_result.is_err());

        match reset_result {
            Ok(()) => dev_info!(self.pdev.as_ref(), "GPU reset completed.\n"),
            Err(_) => dev_err!(self.pdev.as_ref(), "GPU reset cycle failed.\n"),
        }
        trace::reset_cycle(
            trace::ResetCyclePhase::End,
            reset_result.as_ref().err().map_or(0, |e| e.to_errno()),
        );

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
/// The hardware-access gate is closed around the register wipe so in-flight
/// readers drain first. Shared by the reset worker and the resume path that
/// completes a reset latched while the device was suspended, so both run the
/// identical sequence.
///
/// The firmware reboot is attempted even when the soft reset reports a
/// failure, since only the combined outcome decides whether the cycle
/// failed.
pub(crate) fn run_hw_reset(
    tdev: &TyrDrmDevice,
    dev: &Device,
    iomem: &Devres<IoMem>,
    gate: &HwGate,
) -> Result {
    tdev.fw.pre_reset(tdev);
    mmu::pre_reset(tdev, iomem);
    trace::reset_cycle(trace::ResetCyclePhase::Quiesced, 0);

    // A span parked on the closed gate holds a VM op lock while it waits.
    // Taking an op lock here would deadlock against such a span, so this
    // path takes none while the gate is closed.
    let hw = gate.close();

    let reset_result = gpu::reset(dev, iomem);
    trace::reset_cycle(
        trace::ResetCyclePhase::SoftReset,
        reset_result.as_ref().err().map_or(0, |e| e.to_errno()),
    );
    if let Err(e) = &reset_result {
        dev_err!(dev, "GPU reset failed: {:?}\n", e);
    }

    mmu::post_reset(tdev, iomem);

    tdev.gpu_irq.reset_resume(iomem, gpu::irq::gpu_irq_enable);

    // Reopen before fw.post_reset reactivates the MCU VM through the gate.
    drop(hw);

    let reboot_result = tdev.fw.post_reset(tdev);
    trace::reset_cycle(
        trace::ResetCyclePhase::FwReboot,
        reboot_result.as_ref().err().map_or(0, |e| e.to_errno()),
    );
    if let Err(e) = &reboot_result {
        dev_err!(dev, "Firmware reboot after reset failed: {:?}\n", e);

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
    pub(crate) fn new(pdev: ARef<platform::Device>, iomem: Arc<Devres<IoMem>>) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(
                Inner {
                    controller: Controller::new(pdev, iomem)?,
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

    /// Returns a handle to the reset hardware-access gate.
    ///
    /// Readers acquire it around reset-sensitive hardware access so the
    /// reset worker can drain them before wiping the hardware.
    pub(crate) fn hw_gate(&self) -> Arc<HwGate> {
        self.inner.controller.gate.clone()
    }

    /// Waits for an in-flight reset worker to finish.
    pub(crate) fn flush(&self) {
        let _ = workqueue::flush_work::<Controller, Controller, 0>(&self.inner.controller);
    }

    /// Cancels the reset worker at unbind.
    ///
    /// Empties the device slot so requests resolve no device from here
    /// on, then drains an in-flight worker. Unbind runs before devres
    /// teardown, so the drained worker still holds a live register
    /// mapping. A work item enqueued by a racing `schedule` finds the
    /// slot empty and consumes the request without hardware access.
    pub(crate) fn unbind(&self) {
        drop(self.inner.controller.ddev.lock().take());
        self.flush();
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
            trace::reset_schedule(trace::ResetScheduleOutcome::NoDevice);
            return;
        };

        // Record before the enqueue below so a worker already queued but not
        // yet started observes and claims the request. A duplicate enqueue is
        // rejected harmlessly.
        let record = self.inner.controller.record_request();
        if !record.ready {
            // Probe is still bringing the device up, so `set_ready` runs the
            // request once it is done.
            return;
        }

        let Some(_active) = tdev.pm_get_if_active() else {
            // The GPU is (or is about to be) powered off, so any later
            // resume claims the recorded request.
            trace::reset_schedule(if record.coalesced {
                trace::ResetScheduleOutcome::Coalesced
            } else {
                trace::ResetScheduleOutcome::Latched
            });
            return;
        };

        // Queue a worker even when a request is already pending, since a
        // request recorded while the device was inactive has no worker.
        let _ = self.inner.wq.enqueue(self.inner.controller.clone());
        trace::reset_schedule(if record.coalesced {
            trace::ResetScheduleOutcome::Coalesced
        } else {
            trace::ResetScheduleOutcome::Queued
        });
    }
}
