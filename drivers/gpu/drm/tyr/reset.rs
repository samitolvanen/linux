// SPDX-License-Identifier: GPL-2.0 or MIT

//! Provides asynchronous reset handling for the Tyr DRM driver via [`ResetHandle`]
//! which runs reset work on a dedicated ordered workqueue and avoids duplicate
//! pending resets.
//!
//! # High-level Execution Flow
//!
//! ```text
//!                       queued
//! +------+  schedule()  +------------+              +---------+
//! | Idle |------------->| Enqueueing |------------->| Pending |
//! +------+              +------------+              +---------+
//!                             |                           |
//!                             | queue failed              | reset_work()
//!                             v                           v
//!                          +------+                  +------------+
//!                          | Idle |                  | InProgress |
//!                          +------+                  +------------+
//!                                                        |
//!                                                        | reset done
//!                                                        v
//!                                                     +------+
//!                                                     | Idle |
//!                                                     +------+
//!
//! Teardown:
//!
//!   - Idle/Pending/InProgress -> ShuttingDown
//!   - Enqueueing -> wait for schedule() to publish Pending or roll back to Idle.
//! ```

mod hw_gate;

use hw_gate::HwGate;

use kernel::{
    device::{
        Bound,
        Device, //
    },
    devres::Devres,
    io::{
        poll,
        Io, //
    },
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::AtomicType,
        Arc, //
    },
    time,
    workqueue::{
        self,
        OwnedQueue,
        Queue,
        Work, //
    },
};

use crate::{
    driver::IoMem,
    gpu,
    regs::gpu_control::*, //
};

/// Lifecycle state of the reset worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
enum ResetState {
    /// Hardware is available and no reset request exists.
    Idle = 0,
    /// `schedule()` has reserved a reset but has not returned from queueing the
    /// work item yet.
    Enqueueing = 1,
    /// Reset work item is queued and waiting to be claimed by the worker.
    Pending = 2,
    /// Worker has claimed the request and is resetting hardware.
    InProgress = 3,
    /// Teardown has started and no new hardware access or reset request may start.
    ShuttingDown = 4,
}

// SAFETY: `ResetState` and `i32` have the same size and alignment, and are
// round-trip transmutable.
unsafe impl AtomicType for ResetState {
    type Repr = i32;
}

/// Trait for the reset-managed hardware.
///
/// [`ActiveHwState`] groups the hardware blocks that implement this trait
/// and defines their pre-reset and post-reset hook sequence.
///
/// Once reset scheduling flips the gate out of [`ResetState::Idle`], the reset
/// worker first drains any pre-existing SRCU readers before running pre_reset()
/// and post_reset() hooks.
///
/// `pre_reset()` is infallible and returning `Err` from `post_reset()` is treated
/// as a reset-cycle failure.
pub(crate) trait Resettable: Send + Sync {
    /// Called before the reset sequence starts and the hardware is reset.
    ///
    /// Before this is called, the reset worker waits for all pre-existing
    /// hardware accesses to complete.
    fn pre_reset(&self);

    /// Called after the hardware reset completes.
    ///
    /// `reset_failed` is `true` if an earlier stage in the current reset cycle
    /// has already failed. Returning `Err` fails the entire cycle.
    fn post_reset(&self, reset_failed: bool) -> Result;
}

/// Reset-managed hardware state coordinated by [`HwGate`].
///
/// Groups the driver components that must quiesce before a GPU reset and resume
/// afterwards. The [`Resettable`] implementation defines the pre-reset and post-reset
/// hook sequence for those components.
struct ActiveHwState {
    // mmu: Arc<Mmu>,
}

impl Resettable for ActiveHwState {
    fn pre_reset(&self) {
        // self.mmu.pre_reset();
    }

    fn post_reset(&self, _reset_failed: bool) -> Result {
        // self.mmu.post_reset()?;
        Ok(())
    }
}

/// Internal reset orchestrator that owns the gate and work item.
#[pin_data]
struct Controller {
    /// Parent platform device.
    pdev: ARef<platform::Device>,
    /// Mapped register space needed for reset operations.
    iomem: Arc<Devres<IoMem>>,
    /// Access gate for reset managed hardware users.
    #[pin]
    hw: HwGate<ActiveHwState>,
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
    /// Creates an [`Arc<Controller>`] ready for use.
    fn new(pdev: ARef<platform::Device>, iomem: Arc<Devres<IoMem>>) -> Result<Arc<Self>> {
        Arc::pin_init(
            try_pin_init!(Self {
                pdev,
                iomem,
                hw <- HwGate::new(ActiveHwState {}),
                work <- kernel::new_work!("tyr::reset"),
            }),
            GFP_KERNEL,
        )
    }

    /// Processes one scheduled reset request.
    ///
    /// If the pending reset cannot be claimed, the worker returns immediately.
    ///
    /// It first claims [`ResetState::Pending`] or [`ResetState::Enqueueing`],
    /// then waits for earlier hardware accesses to complete before running the
    /// pre-reset hook. After that it issues the hardware reset, runs the
    /// post-reset hooks and finally returns the gate to [`ResetState::Idle`].
    ///
    /// Panthor reference:
    /// - drivers/gpu/drm/panthor/panthor_device.c::panthor_device_reset_work()
    fn reset_work(self: &Arc<Self>) {
        let Some(resetting) = self.hw.start_reset() else {
            // Another reset is already pending or in progress, so we skip this one.
            return;
        };

        dev_info!(self.pdev.as_ref(), "Starting GPU reset.\n");

        // SAFETY: `Controller` is part of driver-private data and only exists
        // while the platform device is bound.
        let pdev = unsafe { self.pdev.as_ref().as_bound() };

        // Wait for all hardware accesses that started before reset became
        // visible to finish before running the reset callbacks.
        //
        // TODO: If these state transitions ever become fallible, make sure failures do not
        // leave the gate in `InProgress`.
        let quiesced = resetting.synchronize().pre_reset();

        let (finishing, reset_result) = quiesced.run(|| run_reset(pdev, &self.iomem));
        let reset_failed = reset_result.is_err();

        if let Err(e) = &reset_result {
            dev_err!(self.pdev.as_ref(), "GPU reset failed: {:?}\n", e);
        }

        let (_done, post_reset_result) = finishing.post_reset(reset_failed);
        let cycle_failed = reset_failed || post_reset_result.is_err();

        if let Err(e) = post_reset_result {
            dev_err!(self.pdev.as_ref(), "GPU post-reset failed: {:?}\n", e);

            // TODO: Unplug the GPU.
            // There is no API for unplugging the GPU and this is unreachable
            // for now since there are no hardware users for reset API.
        }

        if cycle_failed {
            dev_err!(self.pdev.as_ref(), "GPU reset cycle failed.\n");
        } else {
            dev_info!(self.pdev.as_ref(), "GPU reset completed.\n");
        }
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

impl ResetHandle {
    /// Creates [`ResetHandle`].
    pub(crate) fn new(pdev: ARef<platform::Device>, iomem: Arc<Devres<IoMem>>) -> Result<Self> {
        Ok(Self {
            controller: Controller::new(pdev, iomem)?,
            wq: Queue::new_ordered().build(c"tyr-reset-wq")?,
        })
    }

    /// Schedules a GPU reset on the dedicated workqueue.
    ///
    /// If a reset is already pending or in progress the call is a no-op.
    #[expect(dead_code)]
    pub(crate) fn schedule(&self) {
        // TODO: Similar to `panthor_device_schedule_reset()` in Panthor, add a
        // power management check once Tyr supports it.

        // Keep only one reset request running or queued. If one is already pending,
        // we ignore new schedule requests.
        if self.controller.hw.begin_reset() {
            if self.wq.enqueue(self.controller.clone()).is_err() {
                // Roll back the reservation made by `begin_reset()`.
                self.controller.hw.cancel_reset();
            } else {
                self.controller.hw.finish_enqueue();
            }
        }
    }
}

impl Drop for ResetHandle {
    fn drop(&mut self) {
        // Stop new reset requests before draining queued/running work.
        self.controller.hw.begin_teardown();

        // Not required for safety because `wq` will drain on drop, but keep
        // cancellation of `controller.work` explicit before fields are dropped.
        let _ = self.controller.work.cancel_sync();
    }
}

/// Issues a soft reset command and waits for reset-complete IRQ status.
fn issue_soft_reset(dev: &Device<Bound>, iomem: &Devres<IoMem>) -> Result {
    let io = (*iomem).access(dev)?;

    // Clear any stale reset-complete IRQ state before issuing a new soft reset.
    io.write_reg(GPU_IRQ_CLEAR::zeroed().with_reset_completed(true));

    io.write_reg(GPU_COMMAND::reset(ResetMode::SoftReset));

    poll::read_poll_timeout(
        || {
            let io = (*iomem).access(dev)?;
            Ok(io.read(GPU_IRQ_RAWSTAT))
        },
        |status| status.reset_completed(),
        time::Delta::from_millis(1),
        time::Delta::from_millis(100),
    )
    .inspect_err(|_| dev_err!(dev, "GPU reset timed out."))?;

    Ok(())
}

/// Runs one synchronous GPU reset pass.
///
/// Its visibility is `pub(super)` only so the probe path can run an
/// initial reset; it is not part of this module's public API.
///
/// On success, the GPU is left in a state suitable for reinitialization.
///
/// The sequence is as follows:
///   - Trigger a GPU soft reset.
///   - Wait for the reset-complete IRQ status.
///   - Power L2 back on.
pub(super) fn run_reset(dev: &Device<Bound>, iomem: &Devres<IoMem>) -> Result {
    issue_soft_reset(dev, iomem)?;
    gpu::l2_power_on(dev, iomem)?;
    Ok(())
}
