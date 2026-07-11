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

mod hw_gate;

use kernel::{
    device::Device,
    io::{
        mem::DevresIoMem,
        poll,
        Io, //
    },
    platform,
    prelude::*,
    sizes::SZ_2M,
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            AtomicType,
            Full,
            Release, //
        },
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
    /// Mapped register space needed for reset operations.
    iomem: Arc<DevresIoMem<SZ_2M>>,
    /// Lifecycle state of the reset worker.
    state: Atomic<ResetState>,
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
    fn new(pdev: ARef<platform::Device>, iomem: Arc<DevresIoMem<SZ_2M>>) -> Result<Arc<Self>> {
        Arc::pin_init(
            try_pin_init!(Self {
                pdev,
                iomem,
                state: Atomic::new(ResetState::Idle),
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
    fn record_request(&self) {
        // A request lands only from Idle. Other states leave the machine as is.
        let _ = self.try_change_state(ResetState::Idle, ResetState::Pending);
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

    /// Processes one scheduled reset request.
    ///
    /// If the pending reset cannot be claimed, the worker returns immediately.
    fn reset_work(self: &Arc<Self>) {
        if !self.claim_pending() {
            return;
        }

        dev_info!(self.pdev.as_ref(), "Starting GPU reset.\n");

        match self
            .iomem
            .try_access()
            .ok_or(ENODEV)
            .and_then(|io| run_reset(self.pdev.as_ref(), &io))
        {
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
/// Dropping the handle stops new reset requests and drains any queued or
/// in-flight reset work.
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
    pub(crate) fn new(
        pdev: ARef<platform::Device>,
        iomem: Arc<DevresIoMem<SZ_2M>>,
    ) -> Result<Self> {
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
        // Keep only one reset request running or queued. If one is already pending,
        // we ignore new schedule requests. An enqueue failure means the work
        // item is already queued. That run claims the pending request.
        self.controller.record_request();
        let _ = self.wq.enqueue(self.controller.clone());
    }
}

/// Issues a soft reset command and waits for reset-complete IRQ status.
fn issue_soft_reset(dev: &Device, iomem: &IoMem<'_>) -> Result {
    // Clear any stale reset-complete IRQ state before issuing a new soft reset.
    iomem.write_reg(GPU_IRQ_CLEAR::zeroed().with_reset_completed(true));

    iomem.write_reg(GPU_COMMAND::reset(ResetMode::SoftReset));

    poll::read_poll_timeout(
        || Ok(iomem.read(GPU_IRQ_RAWSTAT)),
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
pub(super) fn run_reset(dev: &Device, iomem: &IoMem<'_>) -> Result {
    issue_soft_reset(dev, iomem)?;
    gpu::l2_power_on(dev, iomem)?;
    Ok(())
}
