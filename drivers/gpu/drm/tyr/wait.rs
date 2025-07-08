// SPDX-License-Identifier: GPL-2.0 or MIT

//! Code to wait on CSF responses.

use kernel::new_condvar;
use kernel::new_mutex;
use kernel::prelude::*;
use kernel::sync::lock::mutex::MutexBackend;
use kernel::sync::lock::Lock;
use kernel::sync::Arc;
use kernel::sync::CondVar;
use kernel::sync::Mutex;
use kernel::time::msecs_to_jiffies;

/// Creates a new `Wait<T>` instance with call-site-specific lockdep class key.
///
/// # Usage
/// - `new_wait!()`                 → creates `Wait<()>`
/// - `new_wait!(data)`             → creates `Wait<T>` with `data: T`
/// - `new_wait!(data, "name")`     → creates `Wait<T>` with named lock class
///
/// This macro ensures proper per-call-site lock tracking.
///
/// The underlying `Wait::new_with_lock()` function should **not** be
/// used directly; it is only provided to support this macro's expansion.
///
/// Always prefer this macro to construct `Wait` object for cases when
/// the object is expected to have rather unique locking behaviour, that
/// might otherwise trigger false-positive lockdep warnings.
/// In other cases, 'Wait::new()' is expected to be used.
///
/// ### Example
/// ```
/// let wait = new_wait!()?;
/// let wait = new_wait!(data)?;
/// let wait = new_wait!(false, "named_lock")?;
/// ```
#[macro_export]
macro_rules! new_wait {
    () => {{
        let lock = new_mutex!(());
        $crate::wait::Wait::new_with_lock(lock)
    }};
    ($data:expr) => {{
        let lock = new_mutex!($data);
        $crate::wait::Wait::new_with_lock(lock)
    }};
    ($data:expr, $name:literal) => {{
        let lock = new_mutex!($data, $name);
        $crate::wait::Wait::new_with_lock(lock)
    }};
}

pub(crate) use new_wait;

#[pin_data]
/// A convenience type to wait for GPU responses.
pub(crate) struct Wait<T = ()> {
    /// The actual wait/signal mechanism.
    #[pin]
    cond: CondVar,

    /// Serializes the waking up process.
    ///
    /// All waiters will attempt to reacquire this lock, thereby providing
    /// mutual exclusion between themselves.
    ///
    /// Any other locks can be acquired through the variables captured by the
    /// closure in [`Self::wait_interruptible_timeout`].
    #[pin]
    lock: Mutex<T>,
}

impl Wait<()> {
    /// A convenience function to initialize the `Wait` struct.
    pub(crate) fn new() -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(Self {
                cond <- new_condvar!(),
                lock <- new_mutex!(()),
            }),
            GFP_KERNEL,
        )
    }
}

impl<T> Wait<T> {
    /// A convenience function to initialize the `Wait` struct.
    ///
    /// `data` is automatically protected by the Wait instance.
    pub(crate) fn new_with_data(data: T) -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(Self {
                cond <- new_condvar!(),
                lock <- new_mutex!(data),
            }),
            GFP_KERNEL,
        )
    }

    /// A convenience function to initilaize the `Wait` struct
    /// with provided Lock instance
    ///
    /// Use [`new_wait!`] instead.
    pub(crate) fn new_with_lock(lock: impl PinInit<Lock<T, MutexBackend>>) -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(Self {
                cond <- new_condvar!(),
                lock <- lock,
            }),
            GFP_KERNEL,
        )
    }

    /// Wait until the GPU responds.
    ///
    /// This will trigger on all responses and it is up to the caller to react
    /// using the passed-in closure `on_woken`.
    ///
    /// If the wakeup is spurious, or caused by an unrelated response, return [`WaitResult::Retry`].
    pub(crate) fn wait_interruptible_timeout<F>(
        &self,
        timeout_ms: u32,
        mut on_woken: F,
    ) -> Result<()>
    where
        F: FnMut(&mut T) -> Result<WaitResult>,
    {
        let mut guard = self.lock.lock();
        let mut remaining_time = msecs_to_jiffies(timeout_ms);

        loop {
            // Before going to sleep, we must give the caller one final opportunity
            // to check if the condition is true while holding the lock.
            //
            // Skipping this step could lead to a race condition where another
            // thread has already signaled us, but we missed it because we had not
            // yet gone to sleep.
            //
            // With the lock held at this point, such a race condition is no longer
            // possible.
            if let WaitResult::Ok = on_woken(&mut guard)? {
                return Ok(());
            }

            match self
                .cond
                .wait_interruptible_timeout(&mut guard, remaining_time)
            {
                kernel::sync::CondVarTimeoutResult::Woken { jiffies } => {
                    match on_woken(&mut guard)? {
                        WaitResult::Ok => return Ok(()),
                        WaitResult::Retry => {
                            remaining_time =
                                remaining_time.saturating_sub(jiffies)
                        }
                    }
                }
                kernel::sync::CondVarTimeoutResult::Timeout => {
                    // Try one last time before giving up.
                    if let WaitResult::Ok = on_woken(&mut guard)? {
                        return Ok(());
                    }
                    return Err(ETIMEDOUT);
                }
                kernel::sync::CondVarTimeoutResult::Signal { .. } => {
                    return Err(ERESTARTSYS)
                }
            }
        }
    }

    pub(crate) fn notify_one(&self) {
        let _guard = self.lock.lock();
        self.cond.notify_one();
    }

    pub(crate) fn notify_all(&self) {
        let _guard = self.lock.lock();
        self.cond.notify_all();
    }

    /// Provides mutable access to the data protected by the lock.
    pub(crate) fn with_locked_data<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut T) -> Result<R>,
    {
        let mut data = self.lock.lock();
        f(&mut data)
    }
}

/// The result of a wait operation.
///
/// Use [`WaitResult::Ok`] to indicate that the wait was successful.
///
/// If the wakeup is spurious, or caused by an unrelated response, use
/// [`WaitResult::Retry`].
pub(crate) enum WaitResult {
    Ok,
    Retry,
}
