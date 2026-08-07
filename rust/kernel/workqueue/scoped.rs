// SPDX-License-Identifier: GPL-2.0

//! Lifetime-scoped workqueues.
//!
//! Provides [`ScopedQueue`] for work items that may borrow data with some
//! non-`'static` lifetime.
//!
//! Unlike [`Queue`] which only accepts `'static` work items, [`ScopedQueue`]
//! owns its underlying queue and relies on that queue being dropped to drain
//! pending and running work before borrowed data can go out of scope.
//!
//! TODO: Remove `ignore` once KUnit supports `compile_fail` on doc-tests.
//! ```compile_fail,ignore
//! use kernel::prelude::*;
//! use kernel::workqueue::ScopedQueue;
//!
//! /// # Safety
//! ///
//! /// Returned queue must not be leaked.
//! unsafe fn new_queue<'bound>(_: &'bound ()) -> Result<ScopedQueue<'bound>> {
//!     // SAFETY: Caller guarantees that the returned queue is not leaked.
//!     unsafe { ScopedQueue::new(c"scoped_queue") }
//! }
//!
//! fn queue_outlives_borrowed_data() -> Result {
//!     let queue;
//!
//!     {
//!         let data = ();
//!         // SAFETY: Queue is not leaked.
//!         queue = unsafe { new_queue(&data)? };
//!     }
//!     // Here the `compile_fail` is fulfilled as `queue` would be dropped
//!     // after `data`.
//!     Ok(())
//! }
//! ```
//!
//! TODO: Remove `ignore` once KUnit supports `compile_fail` on doc-tests.
//! ```compile_fail,ignore
//! use kernel::prelude::*;
//! use kernel::sync::Arc;
//! use kernel::workqueue::{
//!     impl_has_work,
//!     new_work,
//!     ScopedQueue,
//!     Work,
//!     WorkItem,
//! };
//!
//! #[pin_data]
//! struct BorrowedWork<'bound> {
//!     data: &'bound (),
//!     #[pin]
//!     work: Work<BorrowedWork<'bound>>,
//! }
//!
//! impl_has_work! {
//!     impl{'bound} HasWork<BorrowedWork<'bound>> for BorrowedWork<'bound> { self.work }
//! }
//!
//! impl<'bound> WorkItem for BorrowedWork<'bound> {
//!     type Pointer = Arc<Self>;
//!
//!     fn run(_this: Arc<Self>) {}
//! }
//!
//! impl<'bound> BorrowedWork<'bound> {
//!     fn new(data: &'bound ()) -> Result<Arc<Self>> {
//!         Arc::pin_init(
//!             pin_init!(Self {
//!                 data,
//!                 work <- new_work!("BorrowedWork::work"),
//!             }),
//!             GFP_KERNEL,
//!         )
//!     }
//! }
//!
//! struct Handle<'bound> {
//!     work: Arc<BorrowedWork<'bound>>,
//!     wq: ScopedQueue<'bound>,
//! }
//!
//! impl<'bound> Handle<'bound> {
//!     /// # Safety
//!     ///
//!     /// Returned handle must not be leaked.
//!     unsafe fn new(data: &'bound ()) -> Result<Self> {
//!         Ok(Self {
//!             work: BorrowedWork::new(data)?,
//!             // SAFETY: Caller guarantees that the returned handle is not leaked.
//!             wq: unsafe { ScopedQueue::new(c"handle_wq")? },
//!         })
//!     }
//! }
//!
//! fn handle_outlives_borrowed_data() -> Result {
//!     let handle;
//!
//!     {
//!         let data = ();
//!         // SAFETY: Handle is not leaked.
//!         handle = unsafe { Handle::new(&data)? };
//!
//!         let _ = handle.wq.enqueue(handle.work.clone());
//!     }
//!     // Here the `compile_fail` is fulfilled as `handle` would be dropped
//!     // after `data`.
//!     Ok(())
//! }
//! ```

use super::{
    OwnedQueue,
    Queue,
    RawWorkItem, //
};

use crate::{
    bindings,
    ffi,
    prelude::*, //
};

use core::marker::PhantomData;

/// An owned workqueue that can enqueue work items borrowing from `'scope`.
///
/// A `ScopedQueue` must not outlive data borrowed by its work items.
pub struct ScopedQueue<'scope> {
    inner: OwnedQueue,
    _scope: PhantomData<&'scope mut &'scope ()>,
}

impl<'scope> ScopedQueue<'scope> {
    /// Creates an ordered scoped workqueue.
    ///
    /// # Safety
    ///
    /// The caller must not leak the returned queue or otherwise prevent its
    /// [`Drop`] implementation from running since dropping the queue drains
    /// pending and running work that may borrow from `'scope`.
    #[inline]
    pub unsafe fn new(name: &'static CStr) -> Result<Self> {
        Ok(Self {
            inner: Queue::new_ordered().build(name)?,
            _scope: PhantomData,
        })
    }

    /// Enqueues a work item on this scoped queue.
    #[inline]
    pub fn enqueue<W, const ID: u64>(&self, work: W) -> W::EnqueueOutput
    where
        W: RawWorkItem<ID> + Send + 'scope,
    {
        let queue_ptr = self.inner.0.get();

        // SAFETY:
        // - Closure returns `false` only if `queue_work_on` returns `false`
        //   and that means `work_ptr` is already in a workqueue.
        //
        // - `W: 'scope` and dropck keep borrowed data alive until this queue is
        //   dropped. The constructor requires that the queue is not leaked and
        //   dropping `inner` drains pending and running work so the function
        //   pointer is not called after any lifetime in `W` expires.
        //
        // - The last requirement of `__enqueue` is not relevant here because `W`
        //   is `Send`.
        unsafe {
            work.__enqueue(move |work_ptr| {
                bindings::queue_work_on(
                    bindings::wq_misc_consts_WORK_CPU_UNBOUND as ffi::c_int,
                    queue_ptr,
                    work_ptr,
                )
            })
        }
    }
}

impl Drop for ScopedQueue<'_> {
    #[inline]
    fn drop(&mut self) {
        // This impl makes dropck require `'scope` to outlive `OwnedQueue`.
        // See: https://doc.rust-lang.org/nomicon/phantom-data.html#generic-parameters-and-drop-checking
        let _ = &self._scope;
    }
}
