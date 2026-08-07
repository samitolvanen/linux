// SPDX-License-Identifier: GPL-2.0

//! Lifetime-scoped workqueues and work items.
//!
//! Provides [`ScopedQueue`] and [`ScopedWork`] for work items that may borrow
//! data with some non-`'static` lifetime.
//!
//! [`ScopedQueue`] owns its underlying queue and relies on that queue being
//! dropped to drain pending and running work before borrowed data can go out
//! of scope.
//!
//! [`ScopedWork`] wraps a work item whose destructor calls `cancel_work_sync()`,
//! so ownership of the data is not transferred to the workqueue. This allows the
//! inner data to carry non-`'static` lifetimes.
//!
//! Drivers should prefer [`ScopedWork`] with either a [`ScopedQueue`] or a
//! system queue over [`Work`]-based items. When used with a [`ScopedQueue`],
//! the work item must already outlive the queue, making [`Work`]'s separate
//! allocation and reference count unnecessary.
//!
//! # Examples
//!
//! Enqueue on the system workqueue (unsafe, caller must not forget the work):
//!
//! ```
//! # use kernel::time::{Delta, delay::fsleep};
//! use kernel::workqueue::{
//!     self,
//!     new_scoped_work,
//!     ScopedWork,
//!     ScopedWorkItem,
//!     ScopedWorkRef,
//! };
//!
//! struct MyWork {
//!     value: u32,
//! }
//!
//! impl ScopedWorkItem for MyWork {
//!     fn run(work: &ScopedWorkRef<Self>) {
//!         pr_info!("value = {}\n", work.value);
//!     }
//! }
//!
//! let work = KBox::pin_init(
//!     new_scoped_work!("MyWork", MyWork { value: 42 }),
//!     GFP_KERNEL,
//! )?;
//!
//! // SAFETY: `work` is not forgotten.
//! unsafe { workqueue::system_dfl().enqueue_scoped(&*work) };
//! # fsleep(Delta::from_millis(100));
//! # Ok::<(), Error>(())
//! ```
//!
//! Enqueue on a [`ScopedQueue`] using the safe path (work outlives the queue):
//!
//! ```
//! use kernel::workqueue::{
//!     new_scoped_work,
//!     ScopedQueue,
//!     ScopedWork,
//!     ScopedWorkItem,
//!     ScopedWorkRef,
//! };
//!
//! struct MyWork {
//!     value: u32,
//! }
//!
//! impl ScopedWorkItem for MyWork {
//!     fn run(work: &ScopedWorkRef<Self>) {
//!         pr_info!("value = {}\n", work.value);
//!     }
//! }
//!
//! let work = KBox::pin_init(
//!     new_scoped_work!("MyWork", MyWork { value: 42 }),
//!     GFP_KERNEL,
//! )?;
//!
//! // SAFETY: The queue is not forgotten.
//! let queue = unsafe { ScopedQueue::new(c"example_wq")? };
//!
//! // Safe since `work` outlives `queue`.
//! queue.enqueue(&*work);
//! # Ok::<(), Error>(())
//! ```
//!
//! [`ScopedQueue`] can also be used with regular [`Work`]-based items. The
//! following `compile_fail` examples demonstrate the lifetime enforcement that
//! [`ScopedQueue`] provides in that case.
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
    impl_has_work,
    HasWork,
    OwnedQueue,
    Queue,
    RawWorkItem,
    Work,
    WorkItem,
    WorkItemPointer, //
};

use crate::{
    bindings,
    prelude::*,
    sync::LockClassKey,
    types::Opaque, //
};

use pin_init::Wrapper;

use core::{
    marker::PhantomData,
    ops::Deref,
    ptr::NonNull, //
};

/// An owned workqueue that can enqueue work items borrowing from `'scope`.
///
/// A `ScopedQueue` must not outlive data borrowed by its work items.
pub struct ScopedQueue<'scope> {
    inner: OwnedQueue,
    _scope: PhantomData<&'scope mut &'scope ()>,
}

impl Deref for ScopedQueue<'_> {
    type Target = Queue;

    #[inline]
    fn deref(&self) -> &Queue {
        &self.inner
    }
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
        // SAFETY: `W: 'scope` and dropck keep borrowed data alive until this queue
        // is dropped. The constructor requires that the queue is not leaked and
        // dropping `inner` drains pending and running work, so the function pointer
        // is not called after any lifetime in `W` expires.
        unsafe { self.enqueue_scoped(work) }
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

/// Trait for types that can be used as scoped work items.
///
/// Implementers define the work function that executes when the item is dequeued by a workqueue
/// thread. The callback receives a reference to the containing [`ScopedWorkRef`], which provides
/// access to the inner data via [`Deref`] and can be used to re-enqueue the work item.
pub trait ScopedWorkItem: Sized {
    /// Called when the work item is executed.
    fn run(work: &ScopedWorkRef<Self>);
}

/// The work function's view of a [`ScopedWork`] item.
///
/// The work function callback receives `&ScopedWorkRef<T>`, which [`Deref`]s to `&T` and can be
/// passed to queue enqueue methods for re-enqueueing from within the work function.
#[pin_data]
pub struct ScopedWorkRef<T: ScopedWorkItem> {
    #[pin]
    work: Work<Self>,
    #[pin]
    data: T,
}

impl_has_work! {
    impl{T: ScopedWorkItem} HasWork<ScopedWorkRef<T>> for ScopedWorkRef<T> { self.work }
}

impl<T: ScopedWorkItem> Deref for ScopedWorkRef<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.data
    }
}

impl<T: ScopedWorkItem> WorkItem for ScopedWorkRef<T> {
    type Pointer = NonNull<Self>;

    #[inline]
    fn run(this: NonNull<Self>) {
        // SAFETY: `this` points to a valid, pinned `ScopedWorkRef`. `cancel_work_sync()` in
        // `ScopedWork`'s `PinnedDrop` prevents use-after-drop.
        let work = unsafe { &*this.as_ptr() };

        T::run(work);
    }
}

// SAFETY: The `run` callback uses the `work_struct` pointer to recover a pointer to
// `ScopedWorkRef<T>` via `HasWork`, wraps it in `NonNull`, and calls `WorkItem::run`.
unsafe impl<T: ScopedWorkItem, const ID: u64> WorkItemPointer<ID> for NonNull<ScopedWorkRef<T>>
where
    ScopedWorkRef<T>: WorkItem<ID, Pointer = Self>,
    ScopedWorkRef<T>: HasWork<ScopedWorkRef<T>, ID>,
{
    unsafe extern "C" fn run(ptr: *mut bindings::work_struct) {
        let ptr = ptr.cast::<Work<ScopedWorkRef<T>, ID>>();

        // SAFETY: The `work_struct` is embedded in `ScopedWorkRef<T>` via `HasWork`.
        let ptr =
            unsafe { <ScopedWorkRef<T> as HasWork<ScopedWorkRef<T>, ID>>::work_container_of(ptr) };

        // SAFETY: `work_container_of` returns a valid, non-null pointer.
        let nn = unsafe { NonNull::new_unchecked(ptr) };

        <ScopedWorkRef<T> as WorkItem<ID>>::run(nn);
    }
}

// Required because `WorkItemPointer<ID>: RawWorkItem<ID>` is a supertrait bound. This `__enqueue`
// is never called; the enqueue path goes through the `RawWorkItem` impl for `&ScopedWork<T>` or
// `&ScopedWorkRef<T>` instead.
//
// SAFETY: `__enqueue` is unreachable.
unsafe impl<T: ScopedWorkItem, const ID: u64> RawWorkItem<ID> for NonNull<ScopedWorkRef<T>>
where
    ScopedWorkRef<T>: HasWork<ScopedWorkRef<T>, ID>,
{
    type EnqueueOutput = bool;

    unsafe fn __enqueue<F>(self, _queue_work_on: F) -> Self::EnqueueOutput
    where
        F: FnOnce(*mut bindings::work_struct) -> bool,
    {
        unreachable!()
    }
}

// SAFETY: `&ScopedWorkRef<T>` points to a valid `ScopedWorkRef` with a valid `work_struct`.
// The pointer remains valid until `cancel_work_sync()` completes in `ScopedWork`'s drop.
unsafe impl<'a, T: ScopedWorkItem + Sync, const ID: u64> RawWorkItem<ID> for &'a ScopedWorkRef<T>
where
    ScopedWorkRef<T>: HasWork<ScopedWorkRef<T>, ID>,
{
    type EnqueueOutput = bool;

    unsafe fn __enqueue<F>(self, queue_work_on: F) -> Self::EnqueueOutput
    where
        F: FnOnce(*mut bindings::work_struct) -> bool,
    {
        let self_ptr = core::ptr::from_ref(self);

        // SAFETY: `self_ptr` points to a valid `ScopedWorkRef` with a `Work` field.
        let work_ptr = unsafe {
            <ScopedWorkRef<T> as HasWork<ScopedWorkRef<T>, ID>>::raw_get_work(self_ptr.cast_mut())
        };

        // SAFETY: `work_ptr` points to a valid `Work`.
        let work_ptr = unsafe { Work::raw_get(work_ptr) };

        queue_work_on(work_ptr)
    }
}

// SAFETY: `&ScopedWork<T>` accesses the inner `ScopedWorkRef` through `Opaque::get()`.
// The pointer remains valid until `cancel_work_sync()` completes in `ScopedWork`'s drop.
unsafe impl<'a, T: ScopedWorkItem + Sync, const ID: u64> RawWorkItem<ID> for &'a ScopedWork<T>
where
    ScopedWorkRef<T>: HasWork<ScopedWorkRef<T>, ID>,
{
    type EnqueueOutput = bool;

    unsafe fn __enqueue<F>(self, queue_work_on: F) -> Self::EnqueueOutput
    where
        F: FnOnce(*mut bindings::work_struct) -> bool,
    {
        // SAFETY: The inner ScopedWorkRef is valid and initialized.
        let inner: &ScopedWorkRef<T> = unsafe { &*self.inner.get() };

        // SAFETY: Delegates to the `&ScopedWorkRef<T>` impl.
        unsafe { inner.__enqueue(queue_work_on) }
    }
}

/// A scoped work item that cancels synchronously on drop.
///
/// `ScopedWork<T>` contains a `work_struct` and the user data `T`. Its destructor calls
/// `cancel_work_sync()`, guaranteeing the work function is not running when the data is dropped.
///
/// This allows `T` to carry non-`'static` lifetimes.
///
/// Construct via [`new_scoped_work!`] which returns an `impl PinInit` suitable for embedding
/// in-place inside other pinned structs.
///
/// # Examples
///
/// Self-re-enqueueing from within the work function:
///
/// ```
/// # use kernel::sync::atomic::{Atomic, Relaxed};
/// # use kernel::time::{Delta, delay::fsleep};
/// use kernel::workqueue::{
///     new_scoped_work,
///     Queue,
///     ScopedQueue,
///     ScopedWork,
///     ScopedWorkItem,
///     ScopedWorkRef,
/// };
///
/// struct RequeueWork<'a> {
///     counter: Atomic<u32>,
///     queue: &'a Queue,
/// }
///
/// impl ScopedWorkItem for RequeueWork<'_> {
///     fn run(work: &ScopedWorkRef<Self>) {
///         if work.counter.fetch_add(1u32, Relaxed) < 2 {
///             // SAFETY: The `ScopedWork` is not forgotten.
///             unsafe { work.queue.enqueue_scoped(work) };
///         }
///     }
/// }
///
/// // SAFETY: The queue is not forgotten.
/// let queue = unsafe { ScopedQueue::new(c"requeue_wq")? };
///
/// let work = KBox::pin_init(
///     new_scoped_work!("RequeueWork", RequeueWork { counter: Atomic::new(0u32), queue: &queue }),
///     GFP_KERNEL,
/// )?;
///
/// // SAFETY: `work` is not forgotten.
/// unsafe { queue.enqueue_scoped(&*work) };
/// # fsleep(Delta::from_millis(300));
///
/// assert_eq!(work.counter.load(Relaxed), 3);
/// # Ok::<(), Error>(())
/// ```
#[pin_data(PinnedDrop)]
pub struct ScopedWork<T: ScopedWorkItem> {
    #[pin]
    inner: Opaque<ScopedWorkRef<T>>,
}

// SAFETY: `&ScopedWork<T>` only provides `&ScopedWorkRef<T>` (via `Deref`), which is safe to share
// when `T: Sync`.
unsafe impl<T: ScopedWorkItem + Sync> Sync for ScopedWork<T> {}

// SAFETY: ScopedWork can be sent to another thread when T: Send.
unsafe impl<T: ScopedWorkItem + Send> Send for ScopedWork<T> {}

impl<T: ScopedWorkItem> Deref for ScopedWork<T> {
    type Target = ScopedWorkRef<T>;

    #[inline]
    fn deref(&self) -> &ScopedWorkRef<T> {
        // SAFETY: The inner `ScopedWorkRef` is always valid and initialized.
        unsafe { &*self.inner.get() }
    }
}

impl<T: ScopedWorkItem> ScopedWork<T> {
    /// Creates a pin-initializer for a new scoped work item.
    ///
    /// Use [`new_scoped_work!`] to automatically provide the lock class key.
    #[inline]
    pub fn new<E>(
        name: &'static CStr,
        key: Pin<&'static LockClassKey>,
        init: impl PinInit<T, E>,
    ) -> impl PinInit<Self, Error>
    where
        Error: From<E>,
    {
        try_pin_init!(Self {
            inner <- Opaque::pin_init(try_pin_init!(ScopedWorkRef::<T> {
                work <- Work::new(name, key),
                data <- init,
            })),
        })
    }
}

#[pinned_drop]
impl<T: ScopedWorkItem> PinnedDrop for ScopedWork<T> {
    #[inline]
    fn drop(self: Pin<&mut Self>) {
        let inner = self.inner.get();

        // SAFETY: `inner` points to a valid `ScopedWorkRef`. After `cancel_work_sync()` returns,
        // the work function is guaranteed to not be running.
        unsafe { bindings::cancel_work_sync(Work::raw_get(&raw const (*inner).work)) };
    }
}

/// Creates a [`ScopedWork`] pin-initializer with a new lock class.
///
/// # Examples
///
/// ```
/// use kernel::workqueue::{
///     new_scoped_work,
///     ScopedWork,
///     ScopedWorkItem,
///     ScopedWorkRef,
/// };
///
/// struct MyWork {
///     value: u32,
/// }
///
/// impl ScopedWorkItem for MyWork {
///     fn run(work: &ScopedWorkRef<Self>) {
///         pr_info!("value = {}\n", work.value);
///     }
/// }
///
/// #[pin_data]
/// struct MyData {
///     #[pin]
///     work: ScopedWork<MyWork>,
/// }
///
/// fn init_data() -> impl PinInit<MyData, Error> {
///     try_pin_init!(MyData {
///         work <- new_scoped_work!("MyWork", MyWork { value: 7 }),
///     })
/// }
/// ```
#[macro_export]
macro_rules! new_scoped_work {
    ($name:literal, $init:expr) => {
        $crate::workqueue::ScopedWork::new(
            $crate::c_str!($name),
            $crate::static_lock_class!(),
            $init,
        )
    };
}
pub use new_scoped_work;
