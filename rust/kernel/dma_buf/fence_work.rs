// SPDX-License-Identifier: GPL-2.0

//! Work items and workqueues for code on the dma-fence signalling path.
//!
//! The work items run inside a [`SignallingSection`](super::SignallingSection),
//! so lockdep checks their bodies against the dma-fence locking rules.
//! [`DmaFenceWorkqueue`] is always created with `WQ_MEM_RECLAIM` and only
//! accepts these work items.
//!
//! C header: [`include/linux/workqueue.h`](srctree/include/linux/workqueue.h)

use crate::{
    alloc::AllocError,
    prelude::*,
    sync::{
        aref::{
            ARef,
            AlwaysRefCounted, //
        },
        Arc,
        LockClassKey, //
    },
    time::Jiffies,
    workqueue::{
        DelayedWork,
        HasDelayedWork,
        HasWork,
        OwnedQueue,
        Queue,
        RawDelayedWorkItem,
        RawWorkItem,
        SupportsCancel,
        Work,
        WorkItem,
        WorkItemPointer, //
    },
};

/// DMA-fence constrained work item.
///
/// This is a wrapper around [`Work`] allowing us to re-use the existing workqueue
/// infrastructure while adding constraints on the type of workqueue such work items
/// can be scheduled on.
#[pin_data]
pub struct DmaFenceWork<T: ?Sized, const ID: u64 = 0> {
    #[pin]
    /// The underlying work item constrained to DMA-fence-safe queues.
    pub inner: Work<T, ID>,
}

impl<T: ?Sized + WorkItem<ID>, const ID: u64> DmaFenceWork<T, ID> {
    /// Creates an initialiser for a [`DmaFenceWork`] with the given name and lock class.
    pub fn new(name: &'static CStr, key: Pin<&'static LockClassKey>) -> impl PinInit<Self> {
        pin_init!(Self {
            inner <- Work::new(name, key),
        })
    }

    /// Cancels this work item if it is pending and waits for any running execution to finish.
    ///
    /// The wait means this must not be called from inside a dma-fence signalling section or from
    /// a work item on the same [`DmaFenceWorkqueue`]. See [`Work::cancel_sync`].
    #[inline]
    pub fn cancel_sync(&self) -> Option<T::Pointer>
    where
        T::Pointer: SupportsCancel<ID>,
    {
        self.inner.cancel_sync()
    }
}

/// Used to safely implement the `HasDmaFenceWork` trait.
///
/// # Examples
///
/// ```ignore
/// use kernel::sync::Arc;
/// use kernel::dma_fence::{impl_has_dma_fence_work, DmaFenceWork};
///
/// struct MyStruct {
///     work_field: DmaFenceWork<MyStruct>,
/// }
///
/// impl_has_dma_fence_work! {
///     impl HasDmaFenceWork<MyStruct>
///     for MyStruct { self.work_field }
/// }
/// ```
#[macro_export]
macro_rules! impl_has_dma_fence_work {
    ($(impl$({$($generics:tt)*})?
       HasDmaFenceWork<$work_type:ty $(, $id:tt)?>
       for $self:ty
       { self.$field:ident }
    )*) => {$(
        // SAFETY: The implementation of `raw_get_work` only compiles if the field has the right
        // type.
        unsafe impl$(<$($generics)+>)? $crate::workqueue::HasWork<$work_type $(, $id)?> for $self {
            #[inline]
            unsafe fn raw_get_work(
                ptr: *mut Self,
            ) -> *mut $crate::workqueue::Work<$work_type $(, $id)?> {
                // SAFETY: The caller promises that the pointer is not dangling.
                unsafe { &raw mut (*ptr).$field.inner }
            }

            #[inline]
            unsafe fn work_container_of(
                ptr: *mut $crate::workqueue::Work<$work_type $(, $id)?>,
            ) -> *mut Self {
                // SAFETY: The caller promises that the pointer points at a field of the right type
                // in the right kind of struct.
                unsafe { $crate::container_of!(ptr, Self, $field.inner) }
            }
        }

        impl$(<$($generics)+>)? $crate::workqueue::WorkItem<$($id)?> for $self {
            type Pointer =
                <Self as $crate::dma_buf::fence_work::DmaFenceWorkItem<$($id)?>>::Pointer;

            fn run(this: Self::Pointer) {
                let _section = $crate::dma_buf::SignallingSection::begin();

                <Self as $crate::dma_buf::fence_work::DmaFenceWorkItem<$($id)?>>::run(this)
            }
        }
    )*};
}
pub use impl_has_dma_fence_work;

/// Creates a [`DmaFenceWork`] initialiser with the given name and a newly-created lock class.
#[macro_export]
macro_rules! new_dma_fence_work {
    ($($name:literal)?) => {
        $crate::dma_buf::fence_work::DmaFenceWork::new(
            $crate::optional_name!($($name)?),
            $crate::static_lock_class!(),
        )
    };
}
pub use new_dma_fence_work;

/// DMA-fence constrained delayed work item.
///
/// This is a wrapper around [`DelayedWork`] allowing us to re-use the existing workqueue
/// infrastructure while adding constraints on the type of workqueue such work items
/// can be scheduled on, and ensuring the work item runs inside a
/// [`SignallingSection`](super::SignallingSection).
#[pin_data]
pub struct DmaFenceDelayedWork<T: ?Sized, const ID: u64 = 0> {
    #[pin]
    /// The underlying delayed work item constrained to DMA-fence-safe queues.
    pub inner: DelayedWork<T, ID>,
}

impl<T: ?Sized + WorkItem<ID>, const ID: u64> DmaFenceDelayedWork<T, ID> {
    /// Creates an initialiser for a [`DmaFenceDelayedWork`] with the given names and lock
    /// classes.
    pub fn new(
        work_name: &'static CStr,
        work_key: Pin<&'static LockClassKey>,
        timer_name: &'static CStr,
        timer_key: Pin<&'static LockClassKey>,
    ) -> impl PinInit<Self> {
        pin_init!(Self {
            inner <- DelayedWork::new(work_name, work_key, timer_name, timer_key),
        })
    }

    /// Cancels this delayed work item if it is pending and waits for any running execution to
    /// finish.
    ///
    /// The wait means this must not be called from inside a dma-fence signalling section or from
    /// a work item on the same [`DmaFenceWorkqueue`]. See [`DelayedWork::cancel_sync`].
    #[inline]
    pub fn cancel_sync(&self) -> Option<T::Pointer>
    where
        T::Pointer: SupportsCancel<ID>,
    {
        self.inner.cancel_sync()
    }
}

/// Used to safely implement the `HasDmaFenceDelayedWork` trait.
#[macro_export]
macro_rules! impl_has_dma_fence_delayed_work {
    ($(impl$({$($generics:tt)*})?
       HasDmaFenceDelayedWork<$work_type:ty $(, $id:tt)?>
       for $self:ty
       { self.$field:ident }
    )*) => {$(
        // SAFETY: The `HasWork` impl below uses `DelayedWork::raw_as_work`, returning a
        // pointer to the `work` field of a `delayed_work`.
        unsafe impl$(<$($generics)+>)?
            $crate::workqueue::HasDelayedWork<$work_type $(, $id)?> for $self {}

        // SAFETY: The implementation of `raw_get_work` only compiles if the field has the right
        // type.
        unsafe impl$(<$($generics)+>)? $crate::workqueue::HasWork<$work_type $(, $id)?> for $self {
            #[inline]
            unsafe fn raw_get_work(
                ptr: *mut Self,
            ) -> *mut $crate::workqueue::Work<$work_type $(, $id)?> {
                // SAFETY: The caller promises that the pointer is not dangling.
                let ptr: *mut $crate::workqueue::DelayedWork<$work_type $(, $id)?> =
                    // SAFETY: `ptr` points at a valid `$self`, so accessing
                    // the embedded delayed-work field is sound.
                    unsafe { &raw mut (*ptr).$field.inner };
                // SAFETY: The caller promises that the pointer is not dangling.
                unsafe { $crate::workqueue::DelayedWork::raw_as_work(ptr) }
            }

            #[inline]
            unsafe fn work_container_of(
                ptr: *mut $crate::workqueue::Work<$work_type $(, $id)?>,
            ) -> *mut Self {
                // SAFETY: The caller promises that the pointer points at a field of the
                // right type in the right kind of struct.
                let ptr = unsafe { $crate::workqueue::Work::raw_get(ptr) };
                // SAFETY: The caller promises that the pointer points at a field of the
                // right type in the right kind of struct.
                let delayed_work = unsafe {
                    $crate::container_of!(ptr, $crate::bindings::delayed_work, work)
                };
                let delayed_work: *mut $crate::workqueue::DelayedWork<$work_type $(, $id)?> =
                    delayed_work.cast();
                // SAFETY: The caller promises that the pointer points at a field of the
                // right type in the right kind of struct.
                unsafe { $crate::container_of!(delayed_work, Self, $field.inner) }
            }
        }

        impl$(<$($generics)+>)? $crate::workqueue::WorkItem<$($id)?> for $self {
            type Pointer =
                <Self as $crate::dma_buf::fence_work::DmaFenceDelayedWorkItem<$($id)?>>::Pointer;

            fn run(this: Self::Pointer) {
                let _section = $crate::dma_buf::SignallingSection::begin();
                <Self as $crate::dma_buf::fence_work::DmaFenceDelayedWorkItem<$($id)?>>::run(this)
            }
        }
    )*};
}
pub use impl_has_dma_fence_delayed_work;

/// Creates a [`DmaFenceDelayedWork`] initialiser with the given name and a newly-created
/// lock class.
#[macro_export]
macro_rules! new_dma_fence_delayed_work {
    () => {
        $crate::dma_buf::fence_work::DmaFenceDelayedWork::new(
            $crate::optional_name!(),
            $crate::static_lock_class!(),
            $crate::c_str!(::core::concat!(
                ::core::file!(),
                ":",
                ::core::line!(),
                "_timer"
            )),
            $crate::static_lock_class!(),
        )
    };
    ($name:literal) => {
        $crate::dma_buf::fence_work::DmaFenceDelayedWork::new(
            $crate::c_str!($name),
            $crate::static_lock_class!(),
            $crate::c_str!(::core::concat!($name, "_timer")),
            $crate::static_lock_class!(),
        )
    };
}
pub use new_dma_fence_delayed_work;

/// Defines the method that should be called when this DMA-fence constrained
/// work item is executed.
pub trait DmaFenceWorkItem<const ID: u64 = 0> {
    /// The pointer type that this struct is wrapped in. This will typically be `Arc<Self>` or
    /// `Pin<KBox<Self>>`.
    type Pointer: WorkItemPointer<ID>;

    /// The method that should be called when this work item is executed.
    fn run(this: Self::Pointer);
}

/// A raw DMA-fence constrained work item.
///
/// # Safety
///
/// Implementations must satisfy all the safety requirements of [`RawWorkItem`].
pub unsafe trait RawDmaFenceWorkItem<const ID: u64>: RawWorkItem<ID> {}

// SAFETY: [`RawWorkItem`] provides all the guarantees we need.
unsafe impl<T, const ID: u64> RawDmaFenceWorkItem<ID> for Arc<T>
where
    T: DmaFenceWorkItem<ID, Pointer = Self>,
    T: WorkItem<ID, Pointer = Self>,
    T: HasWork<T, ID>,
{
}

// SAFETY: [`RawWorkItem`] provides all the guarantees we need.
unsafe impl<T, const ID: u64> RawDmaFenceWorkItem<ID> for Pin<KBox<T>>
where
    T: DmaFenceWorkItem<ID, Pointer = Self>,
    T: WorkItem<ID, Pointer = Self>,
    T: HasWork<T, ID>,
{
}

// SAFETY: The [`RawWorkItem`] impl for [`ARef<T>`] gives the ownership model
// `RawDmaFenceWorkItem` requires. The queue holds one reference for the
// duration of the run callback.
unsafe impl<T, const ID: u64> RawDmaFenceWorkItem<ID> for ARef<T>
where
    T: AlwaysRefCounted,
    T: DmaFenceWorkItem<ID, Pointer = Self>,
    T: WorkItem<ID, Pointer = Self>,
    T: HasWork<T, ID>,
{
}

/// Defines the method that should be called when this DMA-fence constrained
/// delayed work item is executed.
pub trait DmaFenceDelayedWorkItem<const ID: u64 = 0> {
    /// The pointer type that this struct is wrapped in. This will typically be `Arc<Self>`.
    type Pointer: WorkItemPointer<ID>;

    /// The method that should be called when this work item is executed.
    fn run(this: Self::Pointer);
}

/// A raw DMA-fence constrained delayed work item.
///
/// # Safety
///
/// Implementations must satisfy all the safety requirements of [`RawDelayedWorkItem`].
pub unsafe trait RawDmaFenceDelayedWorkItem<const ID: u64>: RawDelayedWorkItem<ID> {}

// SAFETY: The underlying `RawDelayedWorkItem` impl provides all guarantees.
unsafe impl<T, const ID: u64> RawDmaFenceDelayedWorkItem<ID> for Arc<T>
where
    T: DmaFenceDelayedWorkItem<ID, Pointer = Self>,
    T: WorkItem<ID, Pointer = Self>,
    T: HasDelayedWork<T, ID>,
{
}

// SAFETY: The [`RawDelayedWorkItem`] impl for [`ARef<T>`] gives the ownership
// model `RawDmaFenceDelayedWorkItem` requires. The queue holds one reference
// for the duration of the run callback.
unsafe impl<T, const ID: u64> RawDmaFenceDelayedWorkItem<ID> for ARef<T>
where
    T: AlwaysRefCounted,
    T: DmaFenceDelayedWorkItem<ID, Pointer = Self>,
    T: WorkItem<ID, Pointer = Self>,
    T: HasDelayedWork<T, ID>,
{
}

/// Workqueue that can only be used to schedule [`DmaFenceWork`] items.
pub struct DmaFenceWorkqueue(OwnedQueue);

impl DmaFenceWorkqueue {
    /// Allocates a new unbound DMA-fence constrained workqueue.
    #[inline]
    pub fn new_unbound(name: &CStr) -> Result<DmaFenceWorkqueue, AllocError> {
        Ok(Self(Queue::new_unbound().mem_reclaim().build(name)?))
    }

    /// Allocates a new high-priority per-cpu DMA-fence constrained workqueue.
    #[inline]
    pub fn new_highpri(name: &CStr) -> Result<DmaFenceWorkqueue, AllocError> {
        Ok(Self(
            Queue::new_percpu().highpri().mem_reclaim().build(name)?,
        ))
    }

    /// Flushes this workqueue.
    ///
    /// See [`OwnedQueue::flush`] for the contract.
    #[inline]
    pub fn flush(&self) {
        self.0.flush()
    }

    /// Enqueues a work item.
    pub fn enqueue<W, const ID: u64>(&self, w: W) -> W::EnqueueOutput
    where
        W: RawDmaFenceWorkItem<ID> + Send + 'static,
    {
        self.0.enqueue(w)
    }

    /// Enqueues a delayed work item.
    ///
    /// This may fail if the work item is already enqueued in a workqueue.
    ///
    /// The work item will be submitted using `WORK_CPU_UNBOUND`.
    ///
    /// The queue must not be dropped from a work item running on it.
    ///
    /// # Safety
    ///
    /// The caller must keep this [`DmaFenceWorkqueue`] alive until the delayed work item has run
    /// or been canceled. Dropping it destroys the backing [`OwnedQueue`], whose drop does not
    /// wait for an item still on its timer.
    pub unsafe fn enqueue_delayed<W, const ID: u64>(&self, w: W, delay: Jiffies) -> W::EnqueueOutput
    where
        W: RawDmaFenceDelayedWorkItem<ID> + Send + 'static,
    {
        // SAFETY: The caller keeps this workqueue alive until the work item has run or been
        // canceled.
        unsafe { self.0.enqueue_delayed_unchecked(w, delay) }
    }
}
