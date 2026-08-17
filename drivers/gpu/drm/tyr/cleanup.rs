// SPDX-License-Identifier: GPL-2.0 or MIT

//! Module-wide cleanup workqueue.
//!
//! Carries deferred drops from objects whose `Drop` would otherwise run
//! inside a dma-fence signalling section. The queue is deliberately not
//! a `DmaFenceWorkqueue`. Without the `dma_fence_map` lockdep token,
//! cleanup work may take `dma_resv_lock` and the per-VM gpuvm mutex,
//! and allocate with `GFP_KERNEL`.
//!
//! The queue lock is a plain spinlock, so every entry point must be
//! called from process context.
//!
//! A queued item may drop the last reference to a device, and destroying
//! a workqueue from one of its own workers deadlocks, so no device owns
//! the queue. The module creates it before the platform driver registers
//! and destroys it after the driver has unregistered, which drains the
//! drops deferred after unbind.

use core::mem::MaybeUninit;

use kernel::{
    prelude::*,
    sync::global_lock,
    workqueue, //
};

global_lock! {
    // SAFETY: Initialized by `Registration::new` before any other use.
    unsafe(uninit) static CLEANUP_WQ: SpinLock<Option<workqueue::OwnedQueue>> = None;
}

/// Registration of the module-wide cleanup workqueue.
///
/// Creating it builds the queue and publishes it to `try_spawn_owned` and
/// `enqueue`. Dropping it destroys the queue, which drains every item still
/// queued.
pub(crate) struct Registration(());

impl Registration {
    /// Creates the cleanup workqueue.
    ///
    /// # Safety
    ///
    /// Must be called at most once per module load, before any other use of
    /// the cleanup workqueue.
    pub(crate) unsafe fn new() -> Result<Self> {
        // SAFETY: The caller calls this at most once, before any other use.
        unsafe { CLEANUP_WQ.init() };
        let wq = workqueue::Queue::new_unbound().build(c"tyr-cleanup")?;
        *CLEANUP_WQ.lock() = Some(wq);
        Ok(Self(()))
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // Destroying the queue sleeps and runs items that may enqueue again,
        // so take it out of the static first.
        let wq = CLEANUP_WQ.lock().take();
        drop(wq);
    }
}

/// Why a cleanup item was not queued.
///
/// `T` is the value that did not make it onto the queue.
pub(crate) enum SpawnError<T = ()> {
    /// The work item allocation failed.
    NoMemory(T),
    /// The module has destroyed the queue. That only happens after the
    /// driver has unregistered, so the caller is outside any dma-fence
    /// signalling section and may run its cleanup inline.
    QueueGone(T),
}

impl SpawnError<()> {
    /// Rebuilds the error around the value that was not handed over.
    fn with_value<T>(self, value: T) -> SpawnError<T> {
        match self {
            Self::NoMemory(()) => SpawnError::NoMemory(value),
            Self::QueueGone(()) => SpawnError::QueueGone(value),
        }
    }
}

/// Queues `func` on the cleanup workqueue.
///
/// `func` is dropped with the queue lock held when it cannot be queued, so
/// it must not carry a destructor. Its only caller is `try_spawn_owned`,
/// whose closure captures only an `OwnedPtr<T>` and an `fn`.
fn try_spawn<T: 'static + Send + FnOnce()>(func: T) -> Result<(), SpawnError> {
    let wq = CLEANUP_WQ.lock();
    match wq.as_ref() {
        Some(wq) => wq
            .try_spawn(GFP_NOWAIT, func)
            .map_err(|_| SpawnError::NoMemory(())),
        None => Err(SpawnError::QueueGone(())),
    }
}

/// `Send` wrapper for the pointer to the value `try_spawn_owned` parks on
/// the heap.
struct OwnedPtr<T>(*mut T);

// SAFETY: `T: Send`, so the value may cross to the worker, and the pointer
// is turned back into a `KBox` exactly once, by the worker when the item was
// queued and by `try_spawn_owned` otherwise, so the two never alias it.
unsafe impl<T: Send> Send for OwnedPtr<T> {}

/// Runs `f` on the cleanup workqueue with ownership of `value`.
///
/// `value` and the work item are allocated with `GFP_NOWAIT`, so the call is
/// safe from a dma-fence signalling section. Must not be called before the
/// module has created the `Registration`.
///
/// `value` is parked on the heap and handed over by pointer, so dropping the
/// closure under the queue lock does not run its destructor. `value` comes
/// back inside the error when the work cannot be queued.
pub(crate) fn try_spawn_owned<T: 'static + Send>(value: T, f: fn(T)) -> Result<(), SpawnError<T>> {
    let slot: KBox<MaybeUninit<T>> = match KBox::new_uninit(GFP_NOWAIT) {
        Ok(slot) => slot,
        Err(_) => return Err(SpawnError::NoMemory(value)),
    };
    let ptr = KBox::into_raw(KBox::write(slot, value));
    let owned = OwnedPtr(ptr);

    let res = try_spawn(move || {
        // Capturing the pointer field on its own would leave the closure
        // non-`Send`.
        let owned = owned;
        // SAFETY: `try_spawn` runs the closure only when the item was
        // queued, in which case nothing else reclaims the box.
        f(KBox::into_inner(unsafe { KBox::from_raw(owned.0) }));
    });

    if let Err(e) = res {
        // SAFETY: `try_spawn` failed, so it dropped the closure without
        // running it and the box is still owned here.
        let value = KBox::into_inner(unsafe { KBox::from_raw(ptr) });
        return Err(e.with_value(value));
    }

    Ok(())
}

/// Enqueues a work item on the cleanup workqueue.
///
/// Must not be called before the module has created the `Registration`.
/// The item comes back in the error when it is already pending or the
/// module has destroyed the queue.
pub(crate) fn enqueue<W, const ID: u64>(w: W) -> Result<(), W>
where
    W: workqueue::RawWorkItem<ID, EnqueueOutput = Result<(), W>> + Send + 'static,
{
    match CLEANUP_WQ.lock().as_ref() {
        Some(wq) => wq.enqueue(w),
        None => Err(w),
    }
}
