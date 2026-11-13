// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026 Red Hat Inc.
 * Author: Philipp Stanner <pstanner@redhat.com>
 */

//! DMA Fence support.
//!
//! Reference: <https://docs.kernel.org/driver-api/dma-buf.html#c.dma_fence>
//!
//! header: [`include/linux/dma-fence.h`](srctree/include/linux/dma-fence.h)

use crate::{
    alloc::AllocError,
    bindings,
    container_of,
    error::to_result,
    prelude::*,
    types::ForeignOwnable,
    types::NotThreadSafe,
    types::Opaque, //
};

use core::{
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::Deref,
    ptr,
    ptr::{
        drop_in_place,
        NonNull, //
    }, //
};

use kernel::{
    str::CString,
    sync::{
        aref::{
            ARef,
            AlwaysRefCounted, //
        },
        atomic::{
            Atomic,
            Relaxed, //
        },
        rcu::synchronize_rcu, //
    }, //
    time::Jiffies,
};

/// VTable for dma_fence backend_ops callbacks.
//
// Mandatory dma_fence backend_ops are implemented implicitly through
// [`FenceContext`]. Additional ones shall get implemented on this trait.
pub trait FenceContextOps {
    /// The generic payload data for [`DriverFence`]s created on this fctx.
    type FenceDataType: Send + Sync;
}

/// A dma-fence context. A fence context takes care of associating related fences
/// with each other, providing each with raising sequence numbers and a common
/// identifier.
///
/// A FenceContext must drop in non-atomic context.
#[pin_data(PinnedDrop)]
pub struct FenceContext<T: FenceContextOps + Send + Sync> {
    /// The fence context number.
    nr: u64,
    /// The sequence number for the next fence created.
    seqno: Atomic<u64>,
    // The name parameters can be accessed by the dma_fence backend_ops. UAF
    // errors are prevented by `synchronize_rcu()`.
    /// The name of the driver this FenceContext's fences belong to.
    driver_name: CString,
    /// The name of the timeline this FenceContext's fences belong to.
    timeline_name: CString,
    /// The number of all unsignaled fences on this context.
    // Used to prevent bugs due to forgotten fences.
    //
    // The lifetime on `DriverFence`s should typically prevent this from
    // happening.
    //
    // However, we cannot fully guarantee in Rust that `DriverFence`s will not
    // be forgotten, e.g., through `core::mem::forget()`. This could circumvent
    // the lifetime which intends to enforce that all fences disappear before
    // their context.
    nr_of_unsignaled_fences: Atomic<usize>,
    /// The user's data.
    #[pin]
    data: T,
}

impl<T: Send + Sync + FenceContextOps> Deref for FenceContext<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<'a, T: Send + Sync + FenceContextOps> FenceContext<T> {
    // This can later be extended as a vtable in case other parties need support
    // for the more "exotic" callbacks.
    const OPS: bindings::dma_fence_ops = bindings::dma_fence_ops {
        get_driver_name: Some(Self::get_driver_name),
        get_timeline_name: Some(Self::get_timeline_name),
        enable_signaling: None,
        signaled: None,
        // Deprecated.
        wait: None,
        // Must never be implemented for these abstractions.
        release: None,
        set_deadline: None,
    };

    /// Create a new `FenceContext`.
    pub fn new<E>(
        initial_seqno: u64,
        driver_name: &CStr,
        timeline_name: &CStr,
        data: impl PinInit<T, E>,
    ) -> impl PinInit<Self, Error>
    where
        Error: From<E>,
    {
        let driver_name = CString::try_from(driver_name);
        let timeline_name = CString::try_from(timeline_name);
        try_pin_init!(Self {
            // SAFETY: `dma_fence_context_alloc()` merely works on a global
            // atomic. Parameter `1` is the number of contexts we want to
            // allocate.
            nr: unsafe { bindings::dma_fence_context_alloc(1) },
            seqno: Atomic::new(initial_seqno),
            driver_name: driver_name?,
            timeline_name: timeline_name?,
            nr_of_unsignaled_fences: Atomic::new(0),
            data <- data,
        })
    }

    /// Obtain the FenceContext's ID number.
    #[inline]
    pub fn id(&self) -> u64 {
        self.nr
    }

    fn next_seqno(&self) -> u64 {
        self.seqno.fetch_add(1, Relaxed)
    }

    /// Allocate the memory for a [`DriverFence`] and already store `data` inside.
    ///
    /// This is needed because many times, creation of a [`DriverFence`] must not
    /// fail, and allocating might deadlock in some situations.
    ///
    /// If `data` needs to be dropped, dropping the [`DriverFence`] waits for an
    /// RCU grace period before dropping `data`, so it must happen in a context
    /// that can sleep.
    pub fn new_fence_allocation(
        &self,
        data: T::FenceDataType,
    ) -> Result<DriverFenceAllocation<'_, T>> {
        let fence_data = DriverFenceData {
            // `inner` remains uninitialized until a `DriverFence` takes over.
            inner: Fence {
                inner: Opaque::uninit(),
            },
            fctx: self,
            data,
        };

        // In order to support the C dma_fence callbacks, it is necessary for
        // a `Fence` and a `DriverFence` to live in the same allocation,
        // because the C backend passes a dma_fence, from which the driver most
        // likely wants to be able to access its `data` in `DriverFence`.
        //
        // Hence, we need the manage the memory manually. It will be freed by the
        // C backend automatically once the refcount within `Fence` drops to 0.
        let data = KBox::new(fence_data, GFP_KERNEL | __GFP_ZERO)?;

        Ok(DriverFenceAllocation {
            data,
            ops: &Self::OPS,
        })
    }

    extern "C" fn get_driver_name(ptr: *mut bindings::dma_fence) -> *const c_char {
        // SAFETY: The C backend only invokes this callback with `ptr` pointing
        // to a valid, unsignaled `bindings::dma_fence`. All fences created in
        // this module always reside within `Fence` which always resides in a
        // `DriverFenceData`, thus satisfying the function's safety
        // requirements.
        let fctx = unsafe { Self::from_raw_fence(ptr) };

        fctx.driver_name.as_char_ptr()
    }

    extern "C" fn get_timeline_name(ptr: *mut bindings::dma_fence) -> *const c_char {
        // SAFETY: The C backend only invokes this callback with `ptr` pointing
        // to a valid, unsignaled `bindings::dma_fence`. All fences created in
        // this module always reside within `Fence` which always resides in a
        // `DriverFenceData`, thus satisfying the function's safety
        // requirements.
        let fctx = unsafe { Self::from_raw_fence(ptr) };

        fctx.timeline_name.as_char_ptr()
    }

    /// Create a [`FenceContext`] from an associated [`bindings::dma_fence`].
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid pointer to a [`bindings::dma_fence`] which resides
    /// within a [`Fence`], which in turn resides in a [`DriverFenceData`].
    unsafe fn from_raw_fence(ptr: *mut bindings::dma_fence) -> &'a Self {
        let opaque_fence = Opaque::cast_from(ptr);

        // SAFETY: Safe due to the function's overall safety requirements.
        let fence_ptr = unsafe { container_of!(opaque_fence, Fence, inner) };

        // CAST: `DriverFenceData` is `repr(C)` and a `Fence` is its first member.
        let fence_data_ptr: *const DriverFenceData<'a, T> = fence_ptr.cast();

        // SAFETY: Safe because of the comments directly above.
        let fence_data = unsafe { &*fence_data_ptr };

        fence_data.fctx
    }
}

#[pinned_drop]
impl<T: FenceContextOps + Send + Sync> PinnedDrop for FenceContext<T> {
    fn drop(self: Pin<&mut Self>) {
        // Fence ops callbacks can be called on unsignaled fences. Since these
        // callbacks can access the fence context and its data, it needs to be
        // guaranteed that a context only drops after all associated
        // `DriverFence`s have been dropped. This is unlikely to occur, but
        // would result in silent UAF. Throw a panic to prevent that.
        //
        // TODO:
        // It would be better if the fence context signals all forgotten fences
        // itself. To do so, it would keep a list of unsignaled fences. That
        // list's members would have to be pre-allocated (see
        // `FenceCallback::new_fence_allocation()`).
        if self.nr_of_unsignaled_fences.load(Relaxed) != 0 {
            panic!("Forgotten fences in FenceContext.");
        }

        // If a DriverFence signals without doing a synchronize_rcu(), and a
        // fctx drops immediately afterwards, then backend_ops still accessing
        // the fctx might run into UAF if we don't wait for them here.
        synchronize_rcu();
    }
}

/// Error type for fence callback registration.
///
/// Generic over `T` so that `AlreadySignaled` can return the callback to the
/// caller, allowing it to reclaim any resources owned by the callback (e.g.,
/// a fence handle that needs to be signaled).
#[derive(Debug)]
pub enum CallbackError<T> {
    /// The fence was already signaled. The callback is returned so the caller
    /// can extract owned resources without losing them.
    AlreadySignaled(T),
    /// Some other error occurred during registration.
    Other(Error),
}

impl<T> From<CallbackError<T>> for Error {
    #[inline]
    fn from(err: CallbackError<T>) -> Self {
        match err {
            CallbackError::AlreadySignaled(_) => ENOENT,
            CallbackError::Other(e) => e,
        }
    }
}

impl<T> From<AllocError> for CallbackError<T> {
    #[inline]
    fn from(e: AllocError) -> Self {
        CallbackError::Other(Error::from(e))
    }
}

/// Trait for callbacks that can be registered on fences.
///
/// When the fence signals, the callback will be invoked.
///
/// # Example
///
/// ```rust
/// use kernel::dma_buf::FenceCallback;
///
/// struct MyCallback {
///     // Your callback state here
/// }
///
/// impl FenceCallback for MyCallback {
///     fn on_signal(&mut self, status: Result) {
///         if status.is_ok() {
///             pr_info!("Fence signaled!\n");
///         } else {
///             pr_err!("Fence signaled with an error!\n");
///         }
///     }
/// }
/// ```
pub trait FenceCallback: Send {
    /// Called when the fence is signaled.
    ///
    /// This is called from the fence signaling path, which may be in interrupt
    /// context or with locks held, which is why `self` is only borrowed, so that
    /// it cannot drop. Implementations must not sleep or perform
    /// long-running operations.
    ///
    /// An implementation likely wants to inform itself (e.g., through a work item)
    /// within this callback that the associated [`FenceCallbackRegistration`]
    /// can now be dropped.
    fn on_signal(&mut self, status: Result);
}

/// A callback registration on a fence.
///
/// When this object is dropped, the callback is automatically removed if it
/// hasn't been called yet.
#[pin_data(PinnedDrop)]
pub struct FenceCallbackRegistration<T: FenceCallback> {
    #[pin]
    callback_foreign: Opaque<bindings::dma_fence_cb>,
    callback: ManuallyDrop<T>,
    fence: ARef<Fence>,
}

impl<T: FenceCallback> FenceCallbackRegistration<T> {
    /// Create a [`PinInit`] closure for registering a callback on a fence.
    ///
    /// The actual attempt at registering the callback will take place once you
    /// call an allocator's `pin_init()` function.
    ///
    /// On success the callback is pinned in place and will fire when the fence
    /// signals. On `AlreadySignaled` the callback is returned to the caller so
    /// that owned resources can be reclaimed.
    ///
    /// # Safety
    ///
    /// The callback registration must not be forgotten.
    pub unsafe fn new<'a>(
        fence: &'a Fence,
        callback: T,
    ) -> impl PinInit<Self, CallbackError<T>> + 'a
    where
        T: 'a,
    {
        try_pin_init!(Self {
            // We need to fully initialize the fence because after
            // `dma_fence_add_callback()` ran, the callback might immediately
            // get invoked.
            callback: ManuallyDrop::new(callback),
            fence: ARef::from(fence),
            callback_foreign <- Opaque::try_ffi_init(|ptr| {
                // SAFETY: `fence.inner.get()` is a valid, initialized `struct
                // dma_fence`. `ptr` points to the `struct dma_fence_cb` field
                // within the pinned allocation, so it remains valid until
                // `dma_fence_remove_callback()` in `PinnedDrop` or until the
                // callback fires.
                let ret = unsafe {
                    to_result(bindings::dma_fence_add_callback(
                        fence.inner.get(),
                        ptr,
                        Some(Self::dma_fence_callback),
                    ))
                };
                match ret {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        // SAFETY: We could not register the callback. Thus,
                        // C will not use it. So we can just take it back
                        // and pass it to the user again.
                        let cb_back = unsafe { ManuallyDrop::take(callback) };
                        if e == ENOENT {
                            Err(CallbackError::AlreadySignaled(cb_back))
                        } else {
                            Err(CallbackError::Other(e))
                        }
                    },
                }
            }),
        }? CallbackError<T>)
    }

    /// Raw dma fence callback that is called by the C code.
    ///
    /// # Safety
    ///
    /// This is only called by the dma_fence subsystem with valid pointers.
    unsafe extern "C" fn dma_fence_callback(
        _fence: *mut bindings::dma_fence,
        callback_foreign: *mut bindings::dma_fence_cb,
    ) {
        let ptr = Opaque::cast_from(callback_foreign).cast_mut();

        // SAFETY: All callbacks we can receive here have been created in such a way that they are
        // embedded into a `FenceCallbackRegistration`.
        let reg: *mut Self = unsafe { container_of!(ptr, Self, callback_foreign) };

        // SAFETY: `reg` was created validly above. The fence is guaranteed to be
        // signaled since this here is a fence callback.
        let fence_result = unsafe { (*reg).fence.__status() };

        // SAFETY: `reg` is a valid `Self` pointer.
        //
        // The backend ensures synchronisation so whoever holds the registration object cannot drop
        // it while this code is running. See `FenceCallbackRegistration::drop`.
        unsafe { (*reg).callback.on_signal(fence_result) };
    }

    /// Returns a reference to the fence this callback is registered on.
    #[inline]
    pub fn fence(&self) -> &Fence {
        &self.fence
    }
}

#[pinned_drop]
impl<T: FenceCallback> PinnedDrop for FenceCallbackRegistration<T> {
    fn drop(self: Pin<&mut Self>) {
        // Always call `dma_fence_remove_callback()`, even if the callback
        // already ran. This is necessary for synchronization:
        // `dma_fence_remove_callback()` acquires `fence->lock`, which ensures
        // that any in-flight `dma_fence_signal()` (which calls our callback
        // while holding the same lock) has completed before we free the struct.
        //
        // Without this, Drop can race with a concurrent signal:
        //   CPU0 (signal, lock held): take() -> on_signal(fence_ref) (in progress)
        //   CPU1 (drop): skips lock -> frees struct
        //   CPU0: accesses fence_ref -> use-after-free
        //
        // When the callback has already fired, the signal path detached the
        // list node via `INIT_LIST_HEAD()`, so dma_fence_remove_callback just
        // sees an empty node and returns false — the lock acquisition is the
        // only thing that matters.
        //
        // SAFETY: The fence pointer is valid and the cb was initialized by
        // `dma_fence_add_callback()` during construction.
        unsafe {
            bindings::dma_fence_remove_callback(self.fence.as_raw(), self.callback_foreign.get())
        };

        // SAFETY: This is literally the drop implementation, so no one has
        // dropped this so far; so we can do it now.
        unsafe { ManuallyDrop::<T>::drop(self.project().callback) };
    }
}

// SAFETY: FenceCallbackRegistration can be sent between threads.
unsafe impl<T: FenceCallback> Send for FenceCallbackRegistration<T> {}

// SAFETY: &FenceCallbackRegistration can be shared between threads if &T can.
unsafe impl<T: FenceCallback> Sync for FenceCallbackRegistration<T> where T: Sync {}

/// The receiving counterpart of a [`DriverFence`].
///
/// The Rust DMA fence implementation has a dualistic design: [`DriverFence`]s
/// are the producer-side, intended to be always owned by only one party. That
/// party has the monopoly on signaling the fence.
///
/// A [`Fence`] is the counterpart for consumers. Thus, [`Fence`]s are always
/// refcounted and can shared with an arbitrary number of parties, including
/// userspace. A [`Fence`] can only be used for actions such as checking the
/// fence's status or for registering callbacks on it.
///
/// Once the associated [`DriverFence`] signals, all
/// [`FenceCallbackRegistration`]s registered on the [`Fence`] will be executed.
///
/// A [`Fence`] can arbitrarily outlive its [`DriverFence`] and the
/// [`FenceContext`]. Signaling a [`DriverFence`] decouples it from its
/// [`Fence`]s.
#[repr(transparent)]
pub struct Fence {
    /// The actual dma_fence passed to C.
    inner: Opaque<bindings::dma_fence>,
}

/// Guard helper for locking within this module.
///
/// Its only purpose for now is to avoid a number of unsafe lock-unlock cycles.
/// It is never used outside of this module.
// TODO: This should be made more canonical, probably by basing it on a
// SpinLockIrqGuard once available.
struct FenceGuard<'a> {
    inner: &'a Fence,
    flags: usize,
}

impl<'a> Deref for FenceGuard<'a> {
    type Target = &'a Fence;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for FenceGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: `fence` is valid because `self` is valid. `flag_ptr` is
        // merely a pointer to an integer, which lives as long as this function.
        // When a `FenceGuard` exists, the lock has been taken by definition.
        unsafe { bindings::dma_fence_unlock_irqrestore(self.as_raw(), &raw mut self.flags) };
    }
}

// SAFETY: Fences are literally designed to be shared between threads.
unsafe impl Send for Fence {}
// SAFETY: Fences are literally designed to be shared between threads.
unsafe impl Sync for Fence {}

/// Fence-Status queried through [`Fence::status()`].
#[derive(Debug)]
pub enum FenceStatus {
    /// The fence is not yet signaled.
    Unsignaled,
    /// The fence is signaled. Might have been signaled with an error.
    Signaled(Result),
}

/// The result of [`Fence::wait_timeout`].
#[derive(Debug, PartialEq, Eq)]
pub enum FenceWaitResult {
    /// The fence was signaled before the timeout elapsed.
    Signaled,
    /// The timeout elapsed before the fence was signaled.
    TimedOut,
}

/// The result of [`Fence::for_each_unsignaled`].
#[must_use]
pub enum FenceWalk {
    /// The walk visited every unsignaled link. Holds the number of links
    /// visited.
    Complete(usize),
    /// The walk stopped after `max` links. Holds the first link not visited.
    /// It signals once the fences of every link not visited have signaled.
    Truncated(ARef<Fence>),
}

impl Fence {
    /// Query a fence's error code and turn it into a [`Result`].
    ///
    /// # Safety
    ///
    /// The caller must only call this on fences that are already signaled.
    unsafe fn __status(&self) -> Result {
        // SAFETY: Safe by the function's safety requirements.
        let res = unsafe { (*self.as_raw()).error };

        to_result(res)
    }

    /// Query a fence's status at the moment of the function call.
    ///
    /// If it is signaled, return the fence's result, i.e., determine if it was
    /// signaled with an error.
    pub fn status(&self) -> FenceStatus {
        // The C backend provides `dma_fence_is_signaled()`. However, this is
        // currently racy and could lead to misordering with our reading of the
        // fence error code. Take the lock to prevent that.
        let fence = self.lock();
        // SAFETY: `fence` is valid because `self` is valid. The lock was
        // taken above.
        let signaled = unsafe { bindings::dma_fence_is_signaled_locked(fence.as_raw()) };

        if signaled {
            // SAFETY: The fence is signaled.
            let status = unsafe { fence.__status() };

            return FenceStatus::Signaled(status);
        }

        FenceStatus::Unsignaled
    }

    /// Lock the fence. A helper only to be used internally in this module.
    fn lock(&self) -> FenceGuard<'_> {
        let mut guard = FenceGuard {
            inner: self,
            flags: 0,
        };

        // SAFETY: `fence` is valid because `self` is valid. `flag_ptr` is
        // merely a pointer to an integer, whose lifetime is tied to the guard
        // object.
        unsafe { bindings::dma_fence_lock_irqsave(self.as_raw(), &raw mut guard.flags) };

        guard
    }

    /// Get the fence's sequence number.
    #[inline]
    pub fn seqno(&self) -> u64 {
        // SAFETY: Valid because `self` is valid.
        unsafe { (*self.as_raw()).seqno }
    }

    /// Get the id of the context the fence belongs to.
    ///
    /// The fences of a [`FenceContext`] carry its [`FenceContext::id`].
    #[inline]
    pub fn context_id(&self) -> u64 {
        // SAFETY: Valid because `self` is valid. `dma_fence_init()` sets
        // `context` before the fence is shared.
        unsafe { (*self.as_raw()).context }
    }

    /// Calls `f` on each unsignaled fence that `self` waits for, newest first.
    ///
    /// A `dma_fence_chain` waits for the fence in each of its links. Any other
    /// fence is visited as one fence. Unlike its C counterpart
    /// `dma_fence_unwrap_for_each()`, the walk does not unwrap a
    /// `dma_fence_array`. The walk stops at the first error `f` returns. `f`
    /// may sleep.
    ///
    /// The walk visits at most `max` links, see [`FenceWalk`].
    ///
    /// To skip signaled links, the walk calls `dma_fence_is_signaled()`, which
    /// can signal a fence and run its callbacks. The caller must not hold a
    /// lock that a fence callback takes.
    pub fn for_each_unsignaled(
        &self,
        max: usize,
        mut f: impl FnMut(&Fence) -> Result,
    ) -> Result<FenceWalk> {
        let mut link = ARef::from(self);
        for visited in 1..=max {
            let fence = link.chain_contained();
            // SAFETY: `fence.as_raw()` is a valid fence.
            if !unsafe { bindings::dma_fence_test_signaled_flag(fence.as_raw()) } {
                f(fence)?;
            }
            let raw = ARef::into_raw(link).as_ptr().cast();
            // SAFETY: `raw` is a valid fence, and `dma_fence_chain_walk()`
            // takes over the reference that `link` gave up.
            let next = unsafe { bindings::dma_fence_chain_walk(raw) };
            let Some(next) = NonNull::new(next) else {
                return Ok(FenceWalk::Complete(visited));
            };
            // SAFETY: `dma_fence_chain_walk()` returns the next link with a
            // reference for the caller, which the `ARef` takes over. `Fence`
            // is a transparent wrapper of a `struct dma_fence`.
            link = unsafe { ARef::from_raw(next.cast()) };
        }
        Ok(FenceWalk::Truncated(link))
    }

    /// Returns the fence in a `dma_fence_chain` link, or `self` for any other
    /// fence.
    #[inline]
    fn chain_contained(&self) -> &Fence {
        // SAFETY: `self.as_raw()` is a valid fence. The result is `self` or the
        // fence a chain link holds a reference to and never replaces, so it
        // lives as long as `self`. `Fence` is a transparent wrapper of a
        // `struct dma_fence`.
        unsafe { Fence::from_raw(bindings::dma_fence_chain_contained(self.as_raw())) }
    }

    /// Wait until the fence is signaled.
    ///
    /// The wait is not interruptible. It returns `Ok(())` once the fence is
    /// signaled, also when it was signaled with an error.
    pub fn wait(&self) -> Result {
        // SAFETY: `self.as_raw()` is a valid fence. `isize::MAX` is
        // `MAX_SCHEDULE_TIMEOUT`, which waits without a timeout.
        let ret = unsafe { bindings::dma_fence_wait_timeout(self.as_raw(), false, isize::MAX) };

        // A successful wait returns the remaining timeout, which does not fit
        // in an `i32`. Only a negative value is an error.
        if ret < 0 {
            Err(Error::from_errno(ret as i32))
        } else {
            Ok(())
        }
    }

    /// Wait until the fence is signaled, for at most `timeout` jiffies.
    ///
    /// The wait is not interruptible. A fence signaled with an error counts as
    /// signaled.
    pub fn wait_timeout(&self, timeout: Jiffies) -> Result<FenceWaitResult> {
        let timeout = isize::try_from(timeout).unwrap_or(isize::MAX);

        // SAFETY: `self.as_raw()` is a valid fence.
        let ret = unsafe { bindings::dma_fence_wait_timeout(self.as_raw(), false, timeout) };

        if ret < 0 {
            Err(Error::from_errno(ret as i32))
        } else if ret == 0 {
            Ok(FenceWaitResult::TimedOut)
        } else {
            Ok(FenceWaitResult::Signaled)
        }
    }

    /// Returns a raw pointer to the underlying C `struct dma_fence`.
    ///
    /// The pointer is valid for as long as `self` is.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::dma_fence {
        self.inner.get()
    }

    /// Create a [`Fence`] from a raw C [`bindings::dma_fence`].
    ///
    /// # Safety
    ///
    /// `ptr` must point to an initialized fence that is embedded into a [`Fence`].
    #[inline]
    pub unsafe fn from_raw<'a>(ptr: *mut bindings::dma_fence) -> &'a Self {
        // SAFETY: Safe as per the function's overall safety requirements.
        unsafe { &*ptr.cast() }
    }
}

// SAFETY: These implement the C backends refcounting methods which are proven
// to work correctly.
unsafe impl AlwaysRefCounted for Fence {
    fn inc_ref(&self) {
        // SAFETY: `self.as_raw()` is a pointer to a valid `struct dma_fence`.
        unsafe { bindings::dma_fence_get(self.as_raw()) }
    }

    unsafe fn dec_ref(ptr: NonNull<Self>) {
        // SAFETY: `ptr` is never a NULL pointer; and when `dec_ref()` is called
        // the fence is by definition still valid.
        let fence = unsafe { (*ptr.as_ptr()).inner.get() };

        // SAFETY: `fence` was created validly above. When `dec_ref()` is called,
        // there is by definition still a reference alive that can be put.
        unsafe { bindings::dma_fence_put(fence) }
    }
}

/// A dma-fence signalling critical section on the current task.
///
/// All code needed to signal a [`DriverFence`] must run in such a section,
/// from the point where its [`Fence`] becomes visible to other threads up to
/// [`DriverFence::signal`]. With `CONFIG_LOCKDEP`, lockdep checks the locks
/// taken and the memory allocated inside the section against the
/// [DMA Fence Cross-Driver Contract], as described in
/// [DMA Fence Signalling Annotations]. Without it, the section has no effect.
///
/// A function that is part of the signalling path can take a
/// `&SignallingSection` to require that its caller opened one. Sections nest.
///
/// [DMA Fence Cross-Driver Contract]: https://docs.kernel.org/driver-api/dma-buf.html#dma-fence-cross-driver-contract
/// [DMA Fence Signalling Annotations]: https://docs.kernel.org/driver-api/dma-buf.html#dma-fence-signalling-annotations
///
/// # Examples
///
/// ```
/// use kernel::dma_buf::SignallingSection;
///
/// // Code on the signalling path takes the section as proof that one is open.
/// fn on_signalling_path(_section: &SignallingSection) {}
///
/// let section = SignallingSection::begin();
/// on_signalling_path(&section);
/// ```
///
/// # Invariants
///
/// `cookie` was returned by `dma_fence_begin_signalling()` on the current task
/// and has not been passed to `dma_fence_end_signalling()` yet.
#[must_use = "the signalling section ends immediately when the value is unused"]
pub struct SignallingSection {
    cookie: bool,
    _not_send: NotThreadSafe,
}

impl SignallingSection {
    /// Begins a signalling section on the current task.
    #[inline]
    pub fn begin() -> Self {
        // SAFETY: `dma_fence_begin_signalling()` has no preconditions.
        let cookie = unsafe { bindings::dma_fence_begin_signalling() };

        // INVARIANT: `cookie` was just returned by `dma_fence_begin_signalling()`
        // on the current task.
        Self {
            cookie,
            _not_send: NotThreadSafe,
        }
    }
}

impl Drop for SignallingSection {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: By the type invariants, `cookie` comes from
        // `dma_fence_begin_signalling()` on the current task and has not been
        // passed to `dma_fence_end_signalling()` yet.
        unsafe { bindings::dma_fence_end_signalling(self.cookie) };
    }
}

// Necessary to guarantee that `inner` always comes first and can be freed by C.
// Also useful for using casts instead of container_of().
#[repr(C)]
#[pin_data]
struct DriverFenceData<'a, T: Send + Sync + FenceContextOps> {
    #[pin]
    /// The inner fence.
    // Must always be the first member so that unsafe casting works; but also
    // necessary so that the C backend can free the allocation (coming from our
    // Rust code) with kfree_rcu().
    inner: Fence,
    /// Reference to access the FenceContext.
    fctx: &'a FenceContext<T>,
    /// The API user's data, dropped by [`DriverFence`]'s [`Drop`] after an RCU
    /// grace period.
    #[pin]
    data: T::FenceDataType,
}

/// A synchronization primitive mainly for GPU drivers.
///
/// The Rust DMA fence implementation has a dualistic design: [`DriverFence`]s
/// are the producer-side, intended to be always owned by only one party. That
/// party has the monopoly on signaling the fence.
///
/// A [`Fence`] is the counterpart for consumers. Thus, [`Fence`]s are always
/// refcounted and can be shared with an arbitrary number of parties, including
/// userspace. A [`Fence`] can only be used for actions such as checking the
/// fence's status or for registering callbacks on it.
///
/// Once the associated [`DriverFence`] signals, all
/// [`FenceCallbackRegistration`]s registered on a [`Fence`] will be executed.
///
/// A [`Fence`] can arbitrarily outlive its [`DriverFence`] and the
/// [`FenceContext`]. Signaling a [`DriverFence`] decouples it from its
/// [`Fence`]s.
///
/// It is crucial that a [`DriverFence`] always correctly represents the state
/// of the associated job on the hardware. Especially, it is strictly necessary
/// that the owner ensures that all [`DriverFence`]s eventually get signaled.
/// As a last resort, a [`DriverFence`] will signal itself if it drops
/// unsignaled and print a warning.
///
/// This design intends to implement the [`bindings::dma_fence_ops`] in such a
/// way that the driver-data necessary to implement the callback's functionality
/// resides in the [`FenceContext`]. Thus, a [`DriverFence`] contains a
/// reference to the context, which can be accessed in the callbacks. The
/// implementation, therefore, ensures that a [`DriverFence`] cannot outlive its
/// [`FenceContext`]. Unfortunately, this can be circumvented under certain
/// circumstances in Rust (e.g., usage of [`core::mem::forget`]).
///
/// In the unlikely case of such violations, a panic is thrown.
///
/// A DriverFence must drop in non-atomic context.
///
/// # Examples
///
/// ```
/// use kernel::{
///     dma_buf::{
///         DriverFence,
///         FenceContext,
///         FenceContextOps,
///         FenceCallback,
///         FenceCallbackRegistration,
///         FenceStatus,
///         SignallingSection, //
///     },
///     str::CString,
///     sync::aref::ARef, //
/// };
/// use core::fmt::Display;
///
/// struct CallbackData { }
///
/// impl FenceCallback for CallbackData {
///     fn on_signal(&mut self, status: Result) {
///         if status.is_ok() {
///             pr_info!("DmaFence callback executed.\n");
///         } else {
///             pr_err!("DmaFence callback executed, but fence has an error.\n");
///         }
///     }
/// }
///
/// #[pin_data]
/// struct FenceContextData {}
///
/// impl FenceContextData {
///     fn new() -> impl PinInit<Self> {
///         pin_init!(Self {})
///     }
/// }
///
/// impl FenceContextOps for FenceContextData {
///     type FenceDataType = FenceData;
/// }
///
/// let fctx_data = FenceContextData::new();
///
///
/// let mut fctx = KBox::pin_init(
///     FenceContext::new(0, c"dummy_driver", c"dummy_timeline", fctx_data),
///     GFP_KERNEL
/// )?;
///
/// struct FenceData {
///     data: CString,
/// }
///
/// let fence_data = FenceData { data: c"dummy_data".try_into()? };
///
/// let fence_alloc = fctx.new_fence_allocation(fence_data)?;
/// let mut fence = fence_alloc.new_fence();
///
/// let cb_data = CallbackData { };
/// let waiting_fence = ARef::from(fence.as_fence());
/// // SAFETY: `cb_data` is not forgotten.
/// let cb_reg = unsafe { FenceCallbackRegistration::new(&waiting_fence, cb_data) };
/// let cb_reg = KBox::pin_init(cb_reg, GFP_KERNEL)?;
///
/// // TODO: add support for `assert_matches!()`.
/// if let FenceStatus::Signaled(_) = waiting_fence.status() {
///      return Err(ENOMSG);
/// }
/// let section = SignallingSection::begin();
/// fence.signal(Ok(()));
/// drop(section);
/// if let FenceStatus::Unsignaled = waiting_fence.status() {
///     return Err(ENOENT);
/// }
///
/// Ok::<(), Error>(())
/// ```
pub struct DriverFence<'a, T: Send + Sync + FenceContextOps> {
    /// The actual content of the fence. Lives in a [`NonNull`] so that its
    /// memory can be managed independently. Valid until both the [`DriverFence`]
    /// and all associated [`Fence`]s have disappeared.
    data: NonNull<DriverFenceData<'a, T>>,
}

/// A pre-prepared DMA fence, carrying the user's data and the memory it and the
/// fence reside in. Only useful for creating a [`DriverFence`]. Splitting
/// allocation and full initialization is necessary because fences cannot be
/// allocated dynamically in some circumstances (deadlock).
pub struct DriverFenceAllocation<'a, T: Send + Sync + FenceContextOps> {
    /// The memory for the actual content of the fence.
    /// Handed over to a [`DriverFence`], or deallocated once the
    /// [`DriverFenceAllocation`] drops.
    data: KBox<DriverFenceData<'a, T>>,
    /// Reference for the ops for the associated [`FenceContext`]
    ops: &'static bindings::dma_fence_ops,
}

impl<'a, T: Send + Sync + FenceContextOps> DriverFenceAllocation<'a, T> {
    /// Create a new [`DriverFence`], the signalable counterpart of a [`Fence`].
    ///
    /// This increments the sequence number in the associated [`FenceContext`].
    pub fn new_fence(self) -> DriverFence<'a, T> {
        // We feed the C dma_fence backend a NULL for the spinlock so that it
        // uses per-fence locks automatically.
        let null_ptr: *mut bindings::spinlock = ptr::null_mut();
        let seqno = self.data.fctx.next_seqno();
        let fence_ptr = self.as_raw();
        // SAFETY: `fence_ptr` has been created directly above. It will live
        // at least as long as `Self`. The same applies to `&Self::OPS`.
        unsafe {
            bindings::dma_fence_init(fence_ptr, self.ops, null_ptr, self.data.fctx.nr, seqno)
        };

        self.data.fctx.nr_of_unsignaled_fences.fetch_add(1, Relaxed);

        // A `DriverFenceAllocation`'s purpose is to carry allocated memory, so
        // that `DriverFence`s can always be created without allocating. In this
        // method, ownership over that memory is transferred to the new
        // `DriverFence` and managed through refcounting. The C dma_fence
        // backend will ultimately free the memory once the refcount reaches 0.
        let ptr = KBox::into_raw(self.data);
        // SAFETY: `ptr` was just created validly directly above.
        let ptr = unsafe { NonNull::new_unchecked(ptr) };

        DriverFence { data: ptr }
    }

    fn as_raw(&self) -> *mut bindings::dma_fence {
        self.data.inner.inner.get()
    }
}

impl<'a, T: Send + Sync + FenceContextOps> DriverFence<'a, T> {
    /// Drops the fence without waiting for an RCU grace period.
    ///
    /// [`Drop`] waits for one grace period per fence before it drops the
    /// fence's data. A caller that drops many fences can instead wait once,
    /// with [`synchronize_rcu()`], after all of them were signaled, and then
    /// drop each with this function.
    ///
    /// # Safety
    ///
    /// The fence is signaled, and a full RCU grace period has elapsed since.
    pub unsafe fn drop_after_grace_period(self) {
        let this = ManuallyDrop::new(self);

        // `as_raw()` references the whole `DriverFenceData`, so take the
        // pointer before the payload is dropped.
        let fence = this.as_raw();

        // SAFETY: `this.data` points to a valid `DriverFenceData`. The fence
        // is signaled and a grace period has elapsed since, so no
        // dma_fence_ops caller can reach the payload any more.
        unsafe { drop_in_place(&raw mut (*this.data.as_ptr()).data) };

        // SAFETY: `this` owns one reference to `fence`, which it gives up
        // here.
        unsafe { bindings::dma_fence_put(fence) };
    }

    fn as_raw(&self) -> *mut bindings::dma_fence {
        // SAFETY: Valid because `self` is valid.
        let fence_data = unsafe { &*self.data.as_ptr() };

        fence_data.inner.inner.get()
    }

    /// Create a [`DriverFence`] from a raw pointer to a [`bindings::dma_fence`].
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid pointer to a `dma_fence` that was obtained through
    /// a [`DriverFence`] with matching generic data for both fence and associated
    /// [`FenceContext`].
    unsafe fn from_raw(ptr: *mut bindings::dma_fence) -> Self {
        let opaque_fence = Opaque::cast_from(ptr);

        // SAFETY: Safe due to the function's overall safety requirements.
        let fence_ptr = unsafe { container_of!(opaque_fence, Fence, inner) };

        // DriverFenceData is `repr(C)` and a Fence is its first member.
        let fence_data_ptr = fence_ptr as *mut DriverFenceData<'a, T>;

        // SAFETY: `fence_data_ptr` was created validly above.
        let data = unsafe { NonNull::new_unchecked(fence_data_ptr) };

        Self { data }
    }

    /// Return the underlying [`Fence`].
    #[inline]
    pub fn as_fence(&self) -> &Fence {
        // SAFETY: `self` is by definition still valid, and it cannot drop until
        // this new reference is gone.
        unsafe { Fence::from_raw(self.as_raw()) }
    }

    /// Signal the fence. This will invoke all registered callbacks.
    pub fn signal(&self, res: Result) {
        let fence = self.as_fence().lock();

        // SAFETY: `fence` is valid because `self` is valid. The lock must be
        // held, which we acquired directly above.
        if !unsafe { bindings::dma_fence_test_signaled_flag(fence.as_raw()) } {
            if let Err(err) = res {
                // SAFETY: `fence` is valid because `self` is valid. The fence
                // must not have been signaled yet, which we check directly above.
                unsafe { bindings::dma_fence_set_error(fence.as_raw(), err.to_errno()) };
            }

            // SAFETY: `self.data` is valid because `self` is valid.
            let fctx = unsafe { self.data.as_ref().fctx };
            let _ = fctx.nr_of_unsignaled_fences.fetch_sub(1, Relaxed);

            // SAFETY: `fence` is valid because `self` is valid. The lock must
            // be held, which we acquired above.
            unsafe { bindings::dma_fence_signal_locked(fence.as_raw()) };
        }
    }
}

// SAFETY: Fences are literally designed to be shared between threads.
unsafe impl<'a, T: Send + Sync + FenceContextOps> Send for DriverFence<'a, T> {}
// SAFETY: Fences are literally designed to be shared between threads.
unsafe impl<'a, T: Send + Sync + FenceContextOps> Sync for DriverFence<'a, T> {}

impl<'a, T: Send + Sync + FenceContextOps> Deref for DriverFence<'a, T> {
    type Target = T::FenceDataType;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Thanks to refcounting, `data` is always valid as long as `self` is.
        let data = unsafe { &*self.data.as_ptr() };

        &data.data
    }
}

/// A borrow wrapper for [`DriverFence`]. Implements [`Deref`].
pub struct DriverFenceBorrow<'a, T: Send + Sync + FenceContextOps> {
    driver_fence: ManuallyDrop<DriverFence<'a, T>>,
    _lifetime: PhantomData<&'a T>,
}

impl<'a, T: Send + Sync + FenceContextOps> Deref for DriverFenceBorrow<'a, T> {
    type Target = DriverFence<'a, T>;

    fn deref(&self) -> &Self::Target {
        self.driver_fence.deref()
    }
}

// SAFETY: The Rust dma_fence abstractions are already designed around the inner
// C `dma_fence`, which can serve safely as the identification point when being
// owned by C. Moreover, safety is ensured by not dropping `DriverFence` and by
// only allowing operations without side effects on the Borrowed type.
unsafe impl<T: Send + Sync + FenceContextOps> ForeignOwnable for DriverFence<'_, T> {
    type Borrowed<'a>
        = DriverFenceBorrow<'a, T>
    where
        Self: 'a;
    type BorrowedMut<'a>
        = DriverFenceBorrow<'a, T>
    where
        Self: 'a;

    const FOREIGN_ALIGN: usize = core::mem::align_of::<bindings::dma_fence>();

    fn into_foreign(self) -> *mut c_void {
        let fence = self;

        let ptr = fence.as_raw();

        // DriverFence must not drop.
        let _ = ManuallyDrop::new(fence);

        ptr.cast()
    }

    unsafe fn from_foreign(ptr: *mut c_void) -> Self {
        // SAFETY: Safe because the trait implementation only invokes this with
        // a valid `ptr`, associated to a `DriverFence` with matching generic data.
        unsafe { Self::from_raw(ptr.cast()) }
    }

    unsafe fn borrow<'a>(ptr: *mut c_void) -> Self::Borrowed<'a>
    where
        Self: 'a,
    {
        // SAFETY: The trait implementation ensures that `ptr` always resides
        // within a [`Fence`] within a [`DriverFenceData`].
        let driver_fence = unsafe { Self::from_raw(ptr.cast()) };

        let driver_fence = ManuallyDrop::new(driver_fence);

        DriverFenceBorrow {
            driver_fence,
            _lifetime: PhantomData,
        }
    }

    unsafe fn borrow_mut<'a>(ptr: *mut c_void) -> Self::BorrowedMut<'a>
    // FIXME: The bound below and the one above in `borrow` should actually be
    // unnecessary since the compiler should be able to completely derive all
    // necessary information automatically. There is currently a compiler bug
    // preventing that, though:
    //
    // https://github.com/rust-lang/rust/issues/155430.
    //
    // (Help to) fix the compiler bug and remove the bounds afterwards.
    where
        Self: 'a,
    {
        // SAFETY: The trait implementation ensures that `ptr` always resides
        // within a [`Fence`] within a [`DriverFenceData`].
        let driver_fence = unsafe { Self::from_raw(ptr.cast()) };

        let driver_fence = ManuallyDrop::new(driver_fence);

        DriverFenceBorrow {
            driver_fence,
            _lifetime: PhantomData,
        }
    }
}

impl<'a, T: Send + Sync + FenceContextOps> Drop for DriverFence<'a, T> {
    fn drop(&mut self) {
        let guard = self.as_fence().lock();

        // Use dma_fence_test_signaled_flag() instead of
        // dma_fence_is_signaled_locked() because the C backend wants to get rid
        // of the latter.

        // SAFETY: `guard` is valid.
        let signaled: bool = unsafe { bindings::dma_fence_test_signaled_flag(guard.as_raw()) };
        if !signaled {
            pr_err!("DriverFence drops unsignaled. Danger of memory corruption!\n");
            // SAFETY: `guard` is valid. The fence must not have been signaled
            // yet, which we check directly above.
            unsafe { bindings::dma_fence_set_error(guard.as_raw(), ECANCELED.to_errno()) };
            // SAFETY: `guard` is valid. The lock must be held, which we
            // acquired above.
            unsafe { bindings::dma_fence_signal_locked(guard.as_raw()) };

            // SAFETY: `self.data` is valid because `self` is valid.
            let fctx = unsafe { self.data.as_ref().fctx };
            let _ = fctx.nr_of_unsignaled_fences.fetch_sub(1, Relaxed);
        }
        drop(guard);

        // `DriverFenceData` could be accessed through some dma_fence
        // callbacks right now. Access is being revoked in principle above by
        // signaling the fence, but since the C backend does not guarantee
        // perfect full synchronization, we have to wait for one grace period to
        // ensure that all accessors of `DriverFenceData` (through the
        // dma_fence_ops accessible through a `Fence`) are gone.

        if !core::mem::needs_drop::<T::FenceDataType>() {
            // SAFETY: Once a `DriverFence` is initialized, the inner `fence` is
            // valid and initialized. It is valid until the refcount drops to 0,
            // which can earliest happen once we drop the `DriverFence`'s
            // reference here.
            unsafe { bindings::dma_fence_put(self.as_raw()) };
            return;
        }

        // Make sure none of the fence backend_ops can access fence-data anymore.
        //
        // TODO:
        // This would not be necessary if the C dma_fence backend were using a
        // spinlock to properly synchronize its signaled state. Fix it in C and
        // then remove synchronize_rcu().
        synchronize_rcu();

        // `as_raw()` references the whole `DriverFenceData`, so take the
        // pointer before the payload is dropped.
        let fence = self.as_raw();

        // SAFETY: `self.data` points to a valid `DriverFenceData` because
        // `self` is valid. The `synchronize_rcu()` above ensures that no one
        // accesses the payload any more, and nothing drops it after this.
        unsafe { drop_in_place(&raw mut (*self.data.as_ptr()).data) };

        // SAFETY: `fence` is valid until this reference is put. The
        // `synchronize_rcu()` above ensures all accessors are gone.
        unsafe { bindings::dma_fence_put(fence) };
    }
}
