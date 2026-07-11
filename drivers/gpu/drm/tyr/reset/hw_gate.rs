// SPDX-License-Identifier: GPL-2.0 or MIT

//! SRCU based hardware access gate.
//!
//! This module provides [`HwGate`] which is a generic, SRCU based gate
//! that serialises hardware access against asynchronous reset cycles.

use super::{
    ResetState,
    Resettable, //
};

use kernel::{
    prelude::*,
    processor::cpu_relax,
    sync::{
        atomic::{
            Acquire,
            Atomic,
            Full,
            Relaxed, //
        },
        srcu, Srcu,
    },
};

use core::ops::Deref;

macro_rules! try_change_state {
    ($state:expr, $from:expr, $to:expr) => {
        $state.cmpxchg($from, $to, Full).is_ok()
    };
}

/// A gate that coordinates hardware access with asynchronous resets.
#[pin_data]
pub(crate) struct HwGate<T: Resettable> {
    #[pin]
    srcu: Srcu,
    state: Atomic<ResetState>,
    epoch: Atomic<u64>,
    hw: T,
}

impl<T: Resettable> HwGate<T> {
    /// Creates a new gate for the given `hw` in [`ResetState::Idle`] state.
    #[inline]
    pub(super) fn new(hw: T) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            srcu <- kernel::new_srcu!(),
            state: Atomic::new(ResetState::Idle),
            epoch: Atomic::new(0),
            hw,
        })
    }

    /// Tries to acquire the hardware access guard.
    ///
    /// Returns [`EBUSY`] if a reset is pending or in progress.
    #[inline]
    pub(crate) fn try_access(&self) -> Result<HwGuard<'_, T>> {
        let srcu = self.srcu.read_lock();

        if self.state.load(Acquire) != ResetState::Idle {
            return Err(EBUSY);
        }

        let epoch = self.epoch.load(Relaxed);

        Ok(HwGuard {
            hw: &self.hw,
            epoch,
            _srcu: srcu,
        })
    }

    /// Runs `callback` with [`HwGuard`], failing fast with [`EBUSY`] if a reset is
    /// pending or in progress.
    #[expect(dead_code)]
    #[inline]
    pub(crate) fn with_hw<R>(
        &self,
        callback: impl FnOnce(&HwGuard<'_, T>) -> Result<R>,
    ) -> Result<R> {
        let guard = self.try_access()?;
        callback(&guard)
    }

    /// Reserves a reset request and transitions from [`ResetState::Idle`] to
    /// [`ResetState::Enqueueing`].
    ///
    /// Returns `true` if the transition succeeded (i.e. no reset was already
    /// scheduled).
    #[inline]
    pub(super) fn begin_reset(&self) -> bool {
        try_change_state!(self.state, ResetState::Idle, ResetState::Enqueueing)
    }

    /// Marks the reset work item as queued.
    #[inline]
    pub(super) fn finish_enqueue(&self) {
        let _ = try_change_state!(self.state, ResetState::Enqueueing, ResetState::Pending);
    }

    /// Blocks future reset scheduling and hardware access during teardown.
    #[inline]
    pub(super) fn begin_teardown(&self) {
        loop {
            match self.state.load(Acquire) {
                ResetState::Idle => {
                    // No reset is active. Teardown can stop new access now.
                    if try_change_state!(self.state, ResetState::Idle, ResetState::ShuttingDown) {
                        return;
                    }
                }
                ResetState::Enqueueing => {
                    // Wait for `schedule()` to move to `Pending` or back to `Idle` then
                    // try again.
                    cpu_relax()
                }
                ResetState::Pending => {
                    // A reset is queued. Teardown blocks it from running.
                    if try_change_state!(self.state, ResetState::Pending, ResetState::ShuttingDown)
                    {
                        return;
                    }
                }
                ResetState::InProgress => {
                    // A reset is already running. Teardown blocks anything that comes after it.
                    if try_change_state!(
                        self.state,
                        ResetState::InProgress,
                        ResetState::ShuttingDown
                    ) {
                        return;
                    }
                }
                ResetState::ShuttingDown => {
                    // Teardown already started.
                    return;
                }
            }
        }
    }

    /// Transitions from [`ResetState::Pending`] or [`ResetState::Enqueueing`] to
    /// [`ResetState::InProgress`].
    #[inline]
    pub(super) fn start_reset(&self) -> Option<Resetting<'_, T>> {
        (try_change_state!(self.state, ResetState::Pending, ResetState::InProgress)
            || try_change_state!(self.state, ResetState::Enqueueing, ResetState::InProgress))
        .then_some(Resetting { gate: self })
    }

    /// Completes a reset cycle and publishes the next hardware-access epoch.
    ///
    /// This must only be called while dropping [`Done`] after the reset phases are completed.
    #[inline]
    fn finish_reset(&self) {
        // Reaching `Done` means the reset completed so advance the epoch. This must happen
        // before a successful transition to `Idle` publishes a new hardware-access window.
        self.epoch.fetch_add(1, Relaxed);
        let _ = try_change_state!(self.state, ResetState::InProgress, ResetState::Idle);
    }

    /// Transitions from [`ResetState::Pending`] to [`ResetState::Idle`].
    #[inline]
    pub(super) fn cancel_reset(&self) {
        if !try_change_state!(self.state, ResetState::Enqueueing, ResetState::Idle) {
            let _ = try_change_state!(self.state, ResetState::Pending, ResetState::Idle);
        }
    }

    /// Waits for all pre-existing SRCU readers to complete.
    ///
    /// This must only be called from the reset worker after the state has left
    /// [`ResetState::Idle`], so that no new readers can enter.
    #[inline]
    pub(super) fn synchronize(&self) {
        self.srcu.synchronize();
    }
}

impl<T: Resettable> Resettable for HwGate<T> {
    fn pre_reset(&self) {
        self.hw.pre_reset()
    }

    fn post_reset(&self, reset_failed: bool) -> Result {
        self.hw.post_reset(reset_failed)
    }
}

/// Reset is in progress and existing hardware access has not been drained.
#[must_use = "must continue to completion"]
pub(super) struct Resetting<'a, T: Resettable> {
    gate: &'a HwGate<T>,
}

/// Existing hardware access has been drained.
#[must_use = "must continue to completion"]
pub(super) struct Drained<'a, T: Resettable> {
    gate: &'a HwGate<T>,
}

/// Hardware is quiesced and ready to be reset.
#[must_use = "must continue to completion"]
pub(super) struct Quiesced<'a, T: Resettable> {
    gate: &'a HwGate<T>,
}

/// Hardware reset has run and post-reset work remains.
#[must_use = "must continue to completion"]
pub(super) struct Finishing<'a, T: Resettable> {
    gate: &'a HwGate<T>,
}

/// Reset and post-reset work have completed.
///
/// Dropping this state completes the cycle and makes hardware accessible.
#[must_use = "must remain alive until completion"]
pub(super) struct Done<'a, T: Resettable> {
    gate: &'a HwGate<T>,
}

impl<'a, T: Resettable> Resetting<'a, T> {
    /// Waits for all pre-existing SRCU readers to complete.
    #[inline]
    pub(super) fn synchronize(self) -> Drained<'a, T> {
        self.gate.synchronize();
        Drained { gate: self.gate }
    }
}

impl<'a, T: Resettable> Drained<'a, T> {
    /// Runs the pre-reset hook after earlier hardware accesses have drained.
    #[inline]
    pub(super) fn pre_reset(self) -> Quiesced<'a, T> {
        self.gate.pre_reset();
        Quiesced { gate: self.gate }
    }
}

impl<'a, T: Resettable> Quiesced<'a, T> {
    /// Runs the reset body while the gate is held in reset state.
    #[inline]
    pub(super) fn run(self, callback: impl FnOnce() -> Result) -> (Finishing<'a, T>, Result) {
        (Finishing { gate: self.gate }, callback())
    }
}

impl<'a, T: Resettable> Finishing<'a, T> {
    /// Runs the post-reset hook and returns the final token that completes the cycle on drop.
    #[inline]
    pub(super) fn post_reset(self, reset_failed: bool) -> (Done<'a, T>, Result) {
        (Done { gate: self.gate }, self.gate.post_reset(reset_failed))
    }
}

impl<T: Resettable> Drop for Done<'_, T> {
    fn drop(&mut self) {
        self.gate.finish_reset();
    }
}

/// A hardware guard that is only present when the hardware is accessible.
///
/// Holding a [`HwGuard`] means the hardware is still in use and prevents
/// the reset path from proceeding. The reset worker waits for all active
/// guards to be dropped before it continues with the reset.
#[must_use = "the hardware guard must be kept alive while using reset-sensitive state"]
pub(crate) struct HwGuard<'a, T> {
    hw: &'a T,
    epoch: u64,
    _srcu: srcu::Guard<'a>,
}

impl<T> HwGuard<'_, T> {
    /// Returns the epoch at which this guard was acquired.
    ///
    /// This is a snapshot of [`HwGate`]'s epoch counter taken when the guard
    /// was acquired. The gate increments that counter each time a reset cycle
    /// completes. Callers can compare epochs from separate access windows to
    /// detect whether a reset happened in between.
    #[expect(dead_code)]
    #[inline]
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl<T> Deref for HwGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.hw
    }
}
