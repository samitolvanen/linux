// SPDX-License-Identifier: GPL-2.0 or MIT

//! Code to wait on GPU events.

use kernel::{
    new_condvar,
    prelude::*,
    sync::{
        lock::{
            mutex::MutexBackend,
            Lock, //
        },
        Arc,
        CondVar,
        CondVarTimeoutResult,
        Mutex, //
    },
    time::msecs_to_jiffies, //
};

/// Creates a new [`Wait`] instance with a call-site-specific lockdep class key.
///
/// Always prefer this macro over [`Wait::new_with_lock`] when the [`Wait`] instance has
/// unique locking behaviour that could otherwise trigger false-positive lockdep
/// warnings.
#[macro_export]
macro_rules! new_wait {
    () => {{
        let lock = new_mutex!(());
        $crate::wait::Wait::new_with_lock(lock)
    }};
}

/// A convenience type to wait for GPU events.
///
/// Wraps a [`CondVar`] and [`Mutex`] pair. The mutex synchronizes predicate checks
/// with wait/wake operations; the condvar provides the sleep/wake mechanism.
#[pin_data]
pub(crate) struct Wait {
    /// The actual wait/signal mechanism.
    #[pin]
    cond: CondVar,
    /// Synchronizes waiters with notifications.
    #[pin]
    lock: Mutex<()>,
}

impl Wait {
    /// Creates a new [`Wait`] with a caller-supplied lock instance.
    ///
    /// Use [`new_wait!`] instead of calling this directly; the macro ensures a
    /// per-call-site lockdep class key is registered.
    pub(crate) fn new_with_lock(lock: impl PinInit<Lock<(), MutexBackend>>) -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(Self {
                cond <- new_condvar!(),
                lock <- lock,
            }),
            GFP_KERNEL,
        )
    }

    /// Waits until a GPU event condition is met or the timeout elapses.
    ///
    /// Calls `on_woken` before sleeping and after each wakeup. If `on_woken`
    /// returns [`WaitResult::Retry`], the wait continues; [`WaitResult::Done`]
    /// returns success.
    ///
    /// `on_woken` is called while the internal wait lock is held, so it must be
    /// cheap and must not call back into code that can notify this wait object.
    ///
    /// Returns [`ETIMEDOUT`] if the deadline is reached without the condition
    /// becoming true, or [`ERESTARTSYS`] if interrupted by a signal.
    pub(crate) fn wait_interruptible_timeout<F>(&self, timeout_ms: u32, mut on_woken: F) -> Result
    where
        F: FnMut() -> Result<WaitResult>,
    {
        let mut guard = self.lock.lock();
        let mut remaining_time = msecs_to_jiffies(timeout_ms);

        loop {
            // Check the condition before sleeping to avoid missing a wakeup
            // that arrived between the caller's last check and acquiring the
            // lock here.
            if let WaitResult::Done = on_woken()? {
                return Ok(());
            }

            match self
                .cond
                .wait_interruptible_timeout(&mut guard, remaining_time)
            {
                CondVarTimeoutResult::Woken { jiffies } => match on_woken()? {
                    WaitResult::Done => return Ok(()),
                    WaitResult::Retry => remaining_time = jiffies,
                },
                CondVarTimeoutResult::Timeout => {
                    // One final check before giving up.
                    if let WaitResult::Done = on_woken()? {
                        return Ok(());
                    }
                    return Err(ETIMEDOUT);
                }
                CondVarTimeoutResult::Signal { .. } => return Err(ERESTARTSYS),
            }
        }
    }

    /// Wakes all waiters.
    ///
    /// Takes the internal lock so notifications are serialized against waiters
    /// checking the condition and entering the sleep state.
    pub(crate) fn notify_all(&self) {
        let _guard = self.lock.lock();
        self.cond.notify_all();
    }
}

/// The result of a wait operation.
pub(crate) enum WaitResult {
    /// The condition was met.
    Done,
    /// The wakeup was spurious or for an unrelated event; retry.
    Retry,
}
