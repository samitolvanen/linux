// SPDX-License-Identifier: GPL-2.0

//! DMA fence abstraction.
//!
//! This module provides safe Rust abstractions for the kernel's DMA fence
//! synchronization primitive (`struct dma_fence`).
//!
//! C header: [`include/linux/dma-fence.h`](srctree/include/linux/dma-fence.h)

use core::{
	marker::PhantomData,
	mem::ManuallyDrop,
	ops::{
		Deref,
		DerefMut,
	},
	ptr::NonNull,
	sync::atomic::{
		AtomicU64,
		Ordering,
	},
};

use pin_init::pin_init_from_closure;

use crate::{
    alloc::AllocError,
	bindings,
	c_str,
    device::{
        Bound,
        Device,
    },
	error::to_result,
    irq::{
        IrqReturn,
        ThreadedHandler,
        ThreadedIrqReturn,
    },
	prelude::*,
    sync::{
        aref::{
            ARef,
            AlwaysRefCounted,
        },
        Arc,
        LockClassKey,
	},
	time::Jiffies,
	types::{
		ForeignOwnable,
		NotThreadSafe,
		Opaque,
	},
    workqueue::{
        DelayedWork,
        HasDelayedWork,
        HasWork,
        OwnedQueue,
        RawDelayedWorkItem,
        RawWorkItem,
        Work,
        WorkItem,
        WorkItemPointer,
        WqFlags,
    },
};

/// The return type of [`PublicDmaFence::wait_timeout`].
#[derive(Debug, PartialEq, Eq)]
pub enum FenceWaitResult {
	/// The fence was signaled before the timeout elapsed.
	Signaled,
	/// The timeout elapsed before the fence was signaled.
	TimedOut,
}

/// A wrapper around a `dma_fence_chain` object.
///
/// # Invariants
///
/// - `ptr` is a valid, non-null pointer to a dma_fence_chain which we own.
pub struct FenceChain {
	ptr: NonNull<bindings::dma_fence_chain>,
}

impl FenceChain {
	/// Create a new `FenceChain` object.
	pub fn new() -> Result<Self> {
		// SAFETY: This function is safe to call and takes no arguments.
		let ptr = unsafe { bindings::dma_fence_chain_alloc() };

		let ptr = NonNull::new(ptr).ok_or(ENOMEM)?;
		Ok(Self { ptr })
	}

	/// Convert the `FenceChain` into the underlying raw pointer.
	///
	/// This transfers ownership of the allocation to the caller.
	pub(crate) fn into_raw(self) -> *mut bindings::dma_fence_chain {
		let ptr = self.ptr.as_ptr();
		core::mem::forget(self);
		ptr
	}
}

impl Drop for FenceChain {
	fn drop(&mut self) {
		// SAFETY: We own this dma_fence_chain allocation.
		unsafe { bindings::dma_fence_chain_free(self.ptr.as_ptr()) };
	}
}

/// A public DMA fence reference.
///
/// This is a reference-counted handle to a `dma_fence` that can be shared with
/// userspace and other kernel subsystems. It exposes read-only state queries
/// and waiting operations.
///
/// # Invariants
///
/// The contained `Opaque<bindings::dma_fence>` refers to a valid,
/// initialized `dma_fence` that is always reference-counted.
#[repr(transparent)]
#[pin_data]
pub struct PublicDmaFence {
	#[pin]
	inner: Opaque<bindings::dma_fence>,
}

// SAFETY: DMA fences are designed to be shared across threads.
unsafe impl Send for PublicDmaFence {}
// SAFETY: DMA fences are designed to be shared across threads.
unsafe impl Sync for PublicDmaFence {}

// SAFETY: We correctly implement inc_ref/dec_ref via dma_fence_get/put, which
// keep the underlying dma_fence alive as long as any reference exists.
unsafe impl AlwaysRefCounted for PublicDmaFence {
	fn inc_ref(&self) {
		// SAFETY: `self.inner.get()` is a pointer to a valid `struct dma_fence`.
		unsafe { bindings::dma_fence_get(self.inner.get()) };
	}

	unsafe fn dec_ref(obj: NonNull<Self>) {
		// SAFETY: `obj` is non-null and still refers to a valid fence while
		// the final reference is being dropped.
		unsafe {
			let raw_fence = (*obj.as_ptr()).inner.get();
			bindings::dma_fence_put(raw_fence);
		}
	}
}

impl From<*mut bindings::dma_fence> for ARef<PublicDmaFence> {
	fn from(value: *mut bindings::dma_fence) -> Self {
		// SAFETY: `value` is a pointer to a valid `struct dma_fence` with a
		// non-zero refcount. `PublicDmaFence` is `repr(transparent)` over
		// `Opaque<bindings::dma_fence>`.
		unsafe { ARef::from(&*value.cast_const().cast::<PublicDmaFence>()) }
	}
}

impl PublicDmaFence {
	/// Create an [`ARef<PublicDmaFence>`] from a raw pointer, taking ownership
	/// of one reference.
	///
	/// # Safety
	///
	/// `ptr` must be a valid, non-null pointer to a `dma_fence` and the caller
	/// must transfer one owned reference to the returned [`ARef`].
	pub unsafe fn from_raw(ptr: *mut bindings::dma_fence) -> ARef<Self> {
		// SAFETY: `ptr` is valid and non-null per the safety contract.
		unsafe { ARef::from_raw(NonNull::new_unchecked(ptr.cast())) }
	}

	/// Create an [`ARef<PublicDmaFence>`] from a raw pointer, incrementing the
	/// refcount first.
	///
	/// # Safety
	///
	/// `ptr` must be a valid, non-null pointer to a `dma_fence`.
	pub unsafe fn get_raw(ptr: *mut bindings::dma_fence) -> ARef<Self> {
		// SAFETY: The pointer is valid per the safety contract.
		unsafe { bindings::dma_fence_get(ptr) };
		// SAFETY: We just acquired an additional reference.
		unsafe { Self::from_raw(ptr) }
	}

	/// Returns the raw `struct dma_fence` pointer.
	pub fn raw(&self) -> *mut bindings::dma_fence {
		self.inner.get()
	}

	/// Check if the fence has been signaled.
	pub fn is_signaled(&self) -> bool {
		// SAFETY: The pointer is valid per the type invariant.
		unsafe { bindings::dma_fence_is_signaled(self.inner.get()) }
	}

	/// Get the error from the fence, if any.
	pub fn error(&self) -> Result {
		// SAFETY: The pointer is valid per the type invariant.
		let err = unsafe { (*self.inner.get()).error };
		if err == 0 {
			Ok(())
		} else {
			Err(Error::from_errno(err))
		}
	}

	/// Wait for the fence to be signaled, blocking indefinitely.
	pub fn wait(&self) -> Result {
		// SAFETY: The pointer is valid. We pass `false` for a non-interruptible
		// wait and `isize::MAX` to request an indefinite timeout.
		let ret = unsafe { bindings::dma_fence_wait_timeout(self.inner.get(), false, isize::MAX) };
		to_result(ret as i32)
	}

	/// Wait for the fence to be signaled, with a timeout.
	pub fn wait_timeout(&self, timeout: Jiffies) -> Result<FenceWaitResult> {
		// SAFETY: The pointer is valid and the timeout is passed through as
		// jiffies.
		let ret = unsafe {
			bindings::dma_fence_wait_timeout(self.inner.get(), false, timeout as isize)
		};

		if ret < 0 {
			Err(Error::from_errno(ret as i32))
		} else if ret > 0 {
			Ok(FenceWaitResult::Signaled)
		} else {
			Ok(FenceWaitResult::TimedOut)
		}
	}

	/// Returns the fence sequence number.
	pub fn seqno(&self) -> u64 {
		// SAFETY: The pointer is valid per the type invariant.
		unsafe { (*self.inner.get()).seqno }
	}
}

/// A DMA fence context plus a monotonically increasing sequence number.
///
/// # Invariants
///
/// - `ctx` is a valid DMA fence context allocated via
///   `dma_fence_context_alloc`.
/// - `seqno` only ever increases.
pub struct DmaFenceContext {
	ctx: u64,
	seqno: AtomicU64,
}

impl DmaFenceContext {
	/// Allocate a new DMA fence context.
	pub fn new(initial_seqno: u64) -> Self {
		// SAFETY: `dma_fence_context_alloc` is always safe to call.
		let ctx = unsafe { bindings::dma_fence_context_alloc(1) };

		Self {
			ctx,
			seqno: AtomicU64::new(initial_seqno),
		}
	}

	/// Claim the next sequence number.
	pub fn next_seqno(&self) -> (u64, u64) {
		let seqno = self.seqno.fetch_add(1, Ordering::Relaxed) + 1;
		(self.ctx, seqno)
	}

	/// Return the context ID.
	pub fn ctx(&self) -> u64 {
		self.ctx
	}

	/// Return the last allocated sequence number.
	pub fn last_seqno(&self) -> u64 {
		self.seqno.load(Ordering::Relaxed)
	}
}

/// DMA fence signalling guard used to annotate a section of code responsible
/// for signaling `dma_fence` objects.
pub struct DmaFenceSignallingAnnotation {
	/// The cookie returned by `dma_fence_begin_signalling()`.
	cookie: bool,

	/// Keep the annotation on the current thread.
	_not_send: NotThreadSafe,
}

impl DmaFenceSignallingAnnotation {
	/// Begin a DMA-fence signalling section.
	#[inline]
	pub fn new() -> Self {
		Self {
			// SAFETY: Drop always pairs this with a matching
			// `dma_fence_end_signalling()` call.
			cookie: unsafe { bindings::dma_fence_begin_signalling() },
			_not_send: NotThreadSafe,
		}
	}
}

impl Default for DmaFenceSignallingAnnotation {
	fn default() -> Self {
		Self::new()
	}
}

impl Drop for DmaFenceSignallingAnnotation {
	#[inline]
	fn drop(&mut self) {
		// SAFETY: The cookie was returned by `dma_fence_begin_signalling()`.
		unsafe { bindings::dma_fence_end_signalling(self.cookie) };
	}
}

/// Trait for driver-specific DMA fence operations.
#[vtable]
pub trait DriverDmaFenceOps: Sized + Send + Sync {
	/// Returns the driver name. This is a callback to allow drivers to
	/// compute the name at runtime, without having it to store permanently
	/// for each fence, or build a cache of some sort.
	fn driver_name(&self) -> &'static CStr;

	/// Return the name of the context this fence belongs to. This is a
	/// callback to allow drivers to compute the name at runtime, without
	/// having it to store permanently for each fence, or build a cache of
	/// some sort.
	fn timeline_name(&self) -> &'static CStr;
}

/// The in-memory representation of a driver-specific DMA fence.
///
/// Contains the raw `dma_fence`, its per-fence spinlock, and the driver's
/// private data of type `T`.
///
/// # Invariants
///
/// The `fence` field is always a valid, initialized `dma_fence` whose `ops`
/// pointer refers to `Self::OPS`.
#[repr(C)]
#[pin_data]
pub struct DriverDmaFenceInner<T: DriverDmaFenceOps> {
	#[pin]
	fence: Opaque<bindings::dma_fence>,
	#[pin]
	lock: Opaque<bindings::spinlock>,
	data: T,
}

// SAFETY: These implement the C backend's refcounting methods which are
// proven to work correctly.
unsafe impl<T: DriverDmaFenceOps> AlwaysRefCounted for DriverDmaFenceInner<T> {
	fn inc_ref(&self) {
		// SAFETY: `self.fence.get()` is a pointer to a valid `struct dma_fence`.
		unsafe { bindings::dma_fence_get(self.fence.get()) };
	}

	unsafe fn dec_ref(obj: NonNull<Self>) {
		// SAFETY: `obj` is never NULL, and when `dec_ref()` is called the fence
		// is still valid and has a non-zero refcount.
		unsafe {
			let raw_fence = (*obj.as_ptr()).fence.get();
			bindings::dma_fence_put(raw_fence);
		}
	}
}

#[allow(dead_code)]
impl<T: DriverDmaFenceOps> DriverDmaFenceInner<T> {
	const OPS: bindings::dma_fence_ops = bindings::dma_fence_ops {
		get_driver_name: Some(Self::get_driver_name_cb),
		get_timeline_name: Some(Self::get_timeline_name_cb),
		enable_signaling: None,
		signaled: None,
		wait: None,
		release: None,
		set_deadline: None,
	};

	/// Create a [`PinInit`] that initializes a `DriverDmaFenceInner<T>` with
	/// the given driver data, context ID, and sequence number.
	fn new_init(data: T, ctx: u64, seqno: u64) -> impl PinInit<Self> {
		// SAFETY: All three fields (`lock`, `fence`, `data`) are fully
		// initialized inside the closure before it returns `Ok(())`.
		// `dma_fence_init` runs after `__spin_lock_init`, so the lock pointer is
		// valid. Initialization is infallible, so there is no partially
		// initialized state to unwind.
		unsafe {
			pin_init_from_closure(move |slot: *mut Self| {
				(&raw mut (*slot).data).write(data);

				bindings::__spin_lock_init(
					Opaque::cast_into((&raw mut (*slot).lock).cast_const()),
					c_str!("drv_dma_fence").as_char_ptr(),
					crate::static_lock_class!().as_ptr(),
				);

				bindings::dma_fence_init(
					Opaque::cast_into((&raw mut (*slot).fence).cast_const()),
					&Self::OPS,
					Opaque::cast_into((&raw mut (*slot).lock).cast_const()),
					ctx,
					seqno,
				);

				Ok(())
			})
		}
	}

	/// Allocate and initialize a new `DriverDmaFenceInner<T>`.
	///
	/// Returns an `ARef` owning the initial reference created by
	/// `dma_fence_init`.
	fn new(data: T, ctx: u64, seqno: u64) -> Result<ARef<Self>> {
		let boxed = KBox::pin_init(Self::new_init(data, ctx, seqno), GFP_KERNEL)?;

		// Leak the KBox. From this point the C dma_fence refcounting owns the
		// allocation and the pin guarantee is upheld by that subsystem.
		// SAFETY: The allocation was just pinned by `KBox::pin_init`, and the
		// dma_fence backend owns the stable allocation after we leak it.
		let raw = KBox::into_raw(unsafe { Pin::into_inner_unchecked(boxed) });

		// SAFETY: `raw` is valid and we own the one reference created by
		// `dma_fence_init`, so take ownership without bumping the refcount.
		Ok(unsafe { ARef::from_raw(NonNull::new_unchecked(raw)) })
	}

	/// Recover a `&DriverDmaFenceInner<T>` from a raw `*mut dma_fence`.
	///
	/// # Safety
	///
	/// `raw_fence` must point at a `dma_fence` embedded in a
	/// `DriverDmaFenceInner<T>`.
	unsafe fn from_raw<'a>(raw_fence: *mut bindings::dma_fence) -> &'a Self {
		// SAFETY: `raw_fence` points at the embedded `fence` field of a valid
		// `DriverDmaFenceInner<T>` per the function contract.
		unsafe {
			&*crate::container_of!(raw_fence.cast::<Opaque<bindings::dma_fence>>(), Self, fence)
		}
	}

	/// Returns a pointer to the raw `dma_fence`.
	pub(crate) fn raw(&self) -> *mut bindings::dma_fence {
		self.fence.get()
	}

	/// Returns the fence's sequence number.
	pub fn seqno(&self) -> u64 {
		// SAFETY: The fence is initialized per the type invariant.
		unsafe { (*self.fence.get()).seqno }
	}

	/// # Safety
	///
	/// `fence` must have been initialized by `DriverDmaFenceInner::new_init`
	/// and therefore belong to a live `DriverDmaFenceInner<T>`.
	unsafe extern "C" fn get_driver_name_cb(
		fence: *mut bindings::dma_fence,
	) -> *const crate::ffi::c_char {
		// SAFETY: The fence was created by `DriverDmaFenceInner::new_init`.
		let fence = unsafe { Self::from_raw(fence) };
		fence.data.driver_name().as_char_ptr()
	}

	/// # Safety
	///
	/// `fence` must have been initialized by `DriverDmaFenceInner::new_init`
	/// and therefore belong to a live `DriverDmaFenceInner<T>`.
	unsafe extern "C" fn get_timeline_name_cb(
		fence: *mut bindings::dma_fence,
	) -> *const crate::ffi::c_char {
		// SAFETY: The fence was created by `DriverDmaFenceInner::new_init`.
		let fence = unsafe { Self::from_raw(fence) };
		fence.data.timeline_name().as_char_ptr()
	}
}

impl<T: DriverDmaFenceOps> Deref for DriverDmaFenceInner<T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.data
	}
}

impl<T: DriverDmaFenceOps> DerefMut for DriverDmaFenceInner<T> {
	fn deref_mut(&mut self) -> &mut T {
		&mut self.data
	}
}

/// Trait for DMA fence visibility states.
///
/// Implemented by [`Private`] and [`Published`].
pub trait DriverDmaFenceVisibility {
    /// Whether fences in this state have been published (shared with the
    /// outside world).
    const PUBLISHED: bool;
}

/// A fence that has not yet been published. It can still be freely mutated
/// and has not been shared with any external consumer.
pub struct Private;
impl DriverDmaFenceVisibility for Private {
    const PUBLISHED: bool = false;
}

/// A fence that has been published. An [`ARef<PublicDmaFence>`] has been
/// handed out and the fence may be waited on by external consumers. The
/// only remaining operation is to signal it.
pub struct Published;
impl DriverDmaFenceVisibility for Published {
    const PUBLISHED: bool = true;
}

/// A driver-owned handle to a DMA fence with type-state visibility tracking.
///
/// - [`DriverDmaFence<T, Private>`]: a freshly allocated fence that has not
///   been shared. Can be published via [`publish`](DriverDmaFence::publish).
/// - [`DriverDmaFence<T, Published>`]: a fence that has been shared with
///   external consumers. Can be signaled via
///   [`signal`](DriverDmaFence::signal), which consumes the handle. If
///   dropped without signaling, the fence is automatically signaled with
///   `ECANCELED`.
///
/// # Invariants
///
/// `inner` contains a valid `ARef<DriverDmaFenceInner<T>>`.
pub struct DriverDmaFence<T: DriverDmaFenceOps, V: DriverDmaFenceVisibility = Private> {
    inner: ManuallyDrop<ARef<DriverDmaFenceInner<T>>>,
    visibility: PhantomData<V>,
}

// SAFETY: The underlying dma_fence is thread-safe.
unsafe impl<T: DriverDmaFenceOps, V: DriverDmaFenceVisibility> Send for DriverDmaFence<T, V> {}
// SAFETY: The underlying dma_fence is thread-safe.
unsafe impl<T: DriverDmaFenceOps, V: DriverDmaFenceVisibility> Sync for DriverDmaFence<T, V> {}

impl<T: DriverDmaFenceOps> DriverDmaFence<T, Private> {
    /// Allocate a new private DMA fence.
    ///
    /// The fence is initialized with the given context ID and sequence number
    /// but is not yet visible to any external consumer.
    pub fn new(data: T, ctx: u64, seqno: u64) -> Result<Self> {
        let fence = DriverDmaFenceInner::new(data, ctx, seqno)?;

        Ok(Self {
            inner: ManuallyDrop::new(fence),
            visibility: PhantomData,
        })
    }

    /// Publish the fence, making it visible to external consumers.
    ///
    /// Returns the published driver fence handle and an [`ARef<PublicDmaFence>`]
    /// that can be shared with waiters.
    pub fn publish(self) -> (DriverDmaFence<T, Published>, ARef<PublicDmaFence>) {
        let mut fence = self;

        // Create a new public reference by incrementing the refcount.
        let pub_fence: ARef<PublicDmaFence> = fence.inner.fence.get().into();

        // SAFETY: We are consuming `fence` and transferring the ARef to the
        // new Published handle. `core::mem::forget` prevents double-drop.
        let drv_fence = unsafe { ManuallyDrop::take(&mut fence.inner) };
        core::mem::forget(fence);

        (
            DriverDmaFence {
                inner: ManuallyDrop::new(drv_fence),
                visibility: PhantomData,
            },
            pub_fence,
        )
    }
}

impl<T: DriverDmaFenceOps, V: DriverDmaFenceVisibility> DriverDmaFence<T, V> {
    /// Access the inner fence object.
    pub fn inner(&self) -> &DriverDmaFenceInner<T> {
        &self.inner
    }
}

impl<T: DriverDmaFenceOps> DriverDmaFence<T, Published> {
    /// Signal the fence with the given result.
    ///
    /// Consumes `self`, enforcing at the type level that a fence can only be
    /// signaled once.
    ///
    /// - `Ok(())` signals successful completion.
    /// - `Err(e)` sets the error on the fence before signaling.
    pub fn signal(self, result: Result) {
        let raw_fence = self.inner.fence.get();

		// SAFETY: `raw_fence` is owned by this handle and remains valid for the
		// duration of the signaling sequence.
        unsafe {
            if let Err(e) = result {
                bindings::dma_fence_set_error(raw_fence, e.to_errno());
            }
            bindings::dma_fence_signal(raw_fence);
        }

        // `self` is dropped here. Since the fence is now signaled, Drop
        // won't signal ECANCELED.
    }
}

impl<T: DriverDmaFenceOps, V: DriverDmaFenceVisibility> Drop for DriverDmaFence<T, V> {
    fn drop(&mut self) {
        // SAFETY: Take the ARef — this is only called on drop, so it's the
        // final use of `self.inner`. Wrap in ManuallyDrop to prevent
        // ARef::drop from running — we manage the put manually below.
        let drv_fence = ManuallyDrop::new(unsafe { ManuallyDrop::take(&mut self.inner) });
        let raw_fence = drv_fence.fence.get();

        if V::PUBLISHED {
            // Safety net: if a published fence is dropped without being
            // signaled, signal it with ECANCELED so waiters don't hang.
			// SAFETY: `raw_fence` remains valid while this handle still owns the
			// final driver reference.
            if !unsafe { bindings::dma_fence_is_signaled(raw_fence) } {
				// SAFETY: The fence is still valid and we are setting the terminal
				// error immediately before signaling it.
                unsafe { bindings::dma_fence_set_error(raw_fence, -(bindings::ECANCELED as i32)) };
				// SAFETY: The fence is valid and still owned by this handle.
				unsafe { bindings::dma_fence_signal(raw_fence) };
            }
        }

        // SAFETY: We are the sole owner of the DriverDmaFence handle, so no
        // one else can access T. The pointer is valid — drv_fence is alive
        // (ManuallyDrop prevents ARef::drop).
        unsafe { core::ptr::drop_in_place((&raw const drv_fence.data).cast_mut()) };

        // Release our reference. When the refcount reaches 0, C calls
        // dma_fence_free directly (ops->release is NULL) to free the
        // allocation. T is already dropped above.
        //
        // SAFETY: `raw_fence` is valid and has a non-zero refcount since we own
        // the ARef.
        unsafe { bindings::dma_fence_put(raw_fence) };
    }
}

impl<T: DriverDmaFenceOps> DriverDmaFenceInner<T> {
    /// Allocate a `DriverDmaFenceInner<T>` and initialize `data` and `lock` but
    /// not `fence` (i.e., `dma_fence_init` is not called and no seqno is
    /// assigned, so no signal obligation is created).
    ///
    /// Returns an [`UninitDriverDmaFenceInner<T>`] that owns the allocation.
    /// The caller must eventually either call [`UninitDmaFence::init`] (which
    /// calls `dma_fence_init`) or drop the [`UninitDmaFence`] (which drops
    /// `data` and frees the allocation).
	fn new_uninit(
		data: T,
		key: ::core::pin::Pin<&'static LockClassKey>,
	) -> Result<UninitDriverDmaFenceInner<T>> {
        // SAFETY: All three fields are correctly handled:
        // - `data` is written via raw pointer (plain move, no drop issue).
        // - `lock` is initialized by `__spin_lock_init`.
        // - `fence` is intentionally left uninitialized; its type
        // `Opaque<dma_fence>` contains a `MaybeUninit` and has a no-op Drop, so
        // this is safe.
        let boxed = KBox::pin_init(
            unsafe {
                pin_init_from_closure(
                    move |slot: *mut Self|
                          -> ::core::result::Result<(), ::core::convert::Infallible> {
                        (&raw mut (*slot).data).write(data);

                        bindings::__spin_lock_init(
                            Opaque::cast_into(
                                (&raw mut (*slot).lock).cast_const(),
                            ),
                            c_str!("drv_dma_fence").as_char_ptr(),
							key.as_ptr(),
                        );
                        // (*slot).fence intentionally not initialized.
                        Ok(())
                    },
                )
            },
            GFP_KERNEL,
        )?;

        // SAFETY: This wraps a pointer on the heap, we do not move it in the
        // kernel crate and driver code cannot access it directly.
        let raw = KBox::into_raw(unsafe { Pin::into_inner_unchecked(boxed) });
        // SAFETY: `KBox::into_raw` always returns a non-null pointer.
        Ok(UninitDriverDmaFenceInner(unsafe {
            NonNull::new_unchecked(raw)
        }))
    }
}

/// Owns a heap-allocated [`DriverDmaFenceInner<T>`] whose `data` and `lock`
/// are initialized but whose `fence` field is not (i.e., `dma_fence_init` has
/// not been called).  Private to this module; exposed to callers only through
/// [`UninitDmaFence`].
struct UninitDriverDmaFenceInner<T: DriverDmaFenceOps>(NonNull<DriverDmaFenceInner<T>>);

// SAFETY: The underlying allocation is heap memory; no thread-local state.
unsafe impl<T: DriverDmaFenceOps> Send for UninitDriverDmaFenceInner<T> {}
// SAFETY: No interior mutability through a shared reference.
unsafe impl<T: DriverDmaFenceOps> Sync for UninitDriverDmaFenceInner<T> {}

/// A fence allocation whose `data` and spinlock are initialized but for which
/// [`dma_fence_init`] has not been called yet.
///
/// This is the pre-commit form of a driver DMA fence.  Because no seqno has
/// been assigned yet, dropping an `UninitDmaFence` is a simple `kfree` plus
/// a call to `T::drop` — no `ECANCELED` signal, no hole in the seqno
/// sequence, as if the fence never existed.
///
/// Obtain one via [`UninitDmaFence::new`] and convert it into a live, published
/// fence via [`UninitDmaFence::init`].
///
/// # Invariants
///
/// `inner` wraps a heap-allocated `DriverDmaFenceInner<T>` whose `data` and
/// `lock` fields are fully initialized and whose `fence` field has NOT been
/// initialized (i.e., `dma_fence_init` has not been called).
pub struct UninitDmaFence<T: DriverDmaFenceOps> {
    inner: UninitDriverDmaFenceInner<T>,
}

// SAFETY: The underlying allocation is heap memory; no thread-local state.
unsafe impl<T: DriverDmaFenceOps> Send for UninitDmaFence<T> {}
// SAFETY: `&UninitDmaFence` provides no interior mutability.
unsafe impl<T: DriverDmaFenceOps> Sync for UninitDmaFence<T> {}

impl<T: DriverDmaFenceOps> UninitDmaFence<T> {
    /// Allocate and partially initialize a new fence.
    ///
    /// Initializes the driver `data` and the per-fence spinlock, but does
    /// not call `dma_fence_init`.
	pub fn new(data: T, key: ::core::pin::Pin<&'static LockClassKey>) -> Result<Self> {
		let inner = DriverDmaFenceInner::new_uninit(data, key)?;
        Ok(Self { inner })
    }

    /// Assign a seqno and publish the fence.
    ///
    /// Calls `dma_fence_init` with the given `ctx` and `seqno`, which assigns
    /// the seqno and establishes the signal obligation.  From this point on the
    /// fence **must** be signaled (either by the caller via
    /// [`DriverDmaFence::signal`] or automatically with `ECANCELED` on drop).
    ///
    /// Returns the driver-owned handle and a public reference that can be
    /// shared with waiters.
    ///
    /// Consumes `self` to make clear that the allocation is now owned by the
    /// `dma_fence` refcounting machinery.
    pub fn init(
        self,
        ctx: u64,
        seqno: u64,
    ) -> (DriverDmaFence<T, Published>, ARef<PublicDmaFence>) {
        let ptr = self.inner.0.as_ptr();
        // Prevent our Drop from running — ownership is transferred to the
        // dma_fence refcount established by dma_fence_init below.
        core::mem::forget(self);

        // SAFETY: `ptr` is valid and exclusively owned (we just forgot `self`).
        // `fence` and `lock` are at valid locations within the allocation.
        // `lock` was initialized by `new_uninit`.
        unsafe {
            bindings::dma_fence_init(
                Opaque::cast_into((&raw mut (*ptr).fence).cast_const()),
                &DriverDmaFenceInner::<T>::OPS,
                Opaque::cast_into((&raw mut (*ptr).lock).cast_const()),
                ctx,
                seqno,
            );
        }

        // After dma_fence_init the refcount is 1.  Create the public ARef by
        // calling dma_fence_get (refcount = 2), then own the original count
        // (refcount stays at 2: one for drv_fence, one for pub_fence).
        //
        // SAFETY: `dma_fence_init` initialized the fence; the fence field is
        // valid and lives at the correct offset within the allocation.
        let raw_fence: *mut bindings::dma_fence = unsafe { (*ptr).fence.get() };
        let pub_fence: ARef<PublicDmaFence> = raw_fence.into();

        // SAFETY: refcount is now 2; take ownership of one count for drv_fence.
        let aref: ARef<DriverDmaFenceInner<T>> =
            unsafe { ARef::from_raw(NonNull::new_unchecked(ptr)) };

        (
            DriverDmaFence {
                inner: ManuallyDrop::new(aref),
                visibility: PhantomData::<Published>,
            },
            pub_fence,
        )
    }
}

impl<T: DriverDmaFenceOps> Drop for UninitDmaFence<T> {
    fn drop(&mut self) {
        let ptr = self.inner.0.as_ptr();

        // Drop `data: T` (it was fully initialized by `new_uninit`).
        // SAFETY: `data` is at a valid, initialized location in the allocation.
        unsafe { core::ptr::drop_in_place(&raw mut (*ptr).data) };

        // Free the allocation without re-running T's destructor.
        // We cast to `ManuallyDrop<DriverDmaFenceInner<T>>` so that the KBox
        // drop glue is a no-op for the inner type (ManuallyDrop prevents it),
        // and only the allocator `dealloc` runs.
        //
        // SAFETY:
        // - `ptr` was obtained from `KBox::into_raw` in `new_uninit`
        //   using the same kernel allocator.
        // - `ManuallyDrop<X>` is `repr(transparent)`, so size and alignment
        //   match; the allocation is valid for this type.
        // - `data: T` has already been dropped above; the ManuallyDrop cast
        //   ensures it is not dropped again by KBox.
        drop(unsafe {
            KBox::<core::mem::ManuallyDrop<DriverDmaFenceInner<T>>>::from_raw(
                ptr.cast::<core::mem::ManuallyDrop<DriverDmaFenceInner<T>>>(),
            )
        });
    }
}

/// A borrowed reference to a [`DriverDmaFence`].
///
/// This is used by the [`ForeignOwnable`] implementation to provide borrowed
/// access to a `DriverDmaFence`.
pub struct DriverDmaFenceBorrow<'a, T: DriverDmaFenceOps, V: DriverDmaFenceVisibility> {
    // We just borrow the DriverDmaFenceInner, so we don't want Drop to be
    // called on the DriverDmaFence.
    inner: ManuallyDrop<DriverDmaFence<T, V>>,
    _p: PhantomData<&'a ()>,
}

impl<T: DriverDmaFenceOps, V: DriverDmaFenceVisibility> Deref for DriverDmaFenceBorrow<'_, T, V> {
    type Target = DriverDmaFence<T, V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// A mutably borrowed reference to a [`DriverDmaFence`].
///
/// This is used by the [`ForeignOwnable`] implementation to provide mutably borrowed
/// access to a `DriverDmaFence`.
pub struct DriverDmaFenceBorrowMut<'a, T: DriverDmaFenceOps, V: DriverDmaFenceVisibility> {
    // We just borrow the DriverDmaFenceInner, so we don't want Drop to be
    // called on the DriverDmaFence.
    inner: ManuallyDrop<DriverDmaFence<T, V>>,
    _p: PhantomData<&'a mut ()>,
}

impl<T: DriverDmaFenceOps, V: DriverDmaFenceVisibility> Deref
    for DriverDmaFenceBorrowMut<'_, T, V>
{
    type Target = DriverDmaFence<T, V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: DriverDmaFenceOps, V: DriverDmaFenceVisibility> DerefMut
    for DriverDmaFenceBorrowMut<'_, T, V>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

// SAFETY: `DriverDmaFence` wraps a refcounted `ARef<DriverDmaFenceInner<T>>`, so
// the raw pointer roundtrip through `into_foreign`/`from_foreign` preserves all
// invariants.
unsafe impl<T: DriverDmaFenceOps + 'static, V: DriverDmaFenceVisibility> ForeignOwnable
    for DriverDmaFence<T, V>
{
    const FOREIGN_ALIGN: usize = core::mem::align_of::<DriverDmaFenceInner<T>>();

    type Borrowed<'a> = DriverDmaFenceBorrow<'a, T, V>;
    type BorrowedMut<'a> = DriverDmaFenceBorrowMut<'a, T, V>;

    fn into_foreign(self) -> *mut crate::ffi::c_void {
        let mut fence = self;
        // SAFETY: We're consuming self, so taking the ARef is safe.
        let drv_fence = unsafe { ManuallyDrop::take(&mut fence.inner) };
        core::mem::forget(fence);

        ARef::into_raw(drv_fence).as_ptr().cast()
    }

    unsafe fn from_foreign(ptr: *mut crate::ffi::c_void) -> Self {
        // SAFETY: The safety requirements of this method ensure that `ptr` is a
        // valid pointer to a `DriverDmaFenceInner<T>` that was created by a
        // previous call to `into_foreign`.
        let inner = unsafe {
            ARef::from_raw(NonNull::<DriverDmaFenceInner<T>>::new_unchecked(ptr.cast()))
        };

        Self {
            inner: ManuallyDrop::new(inner),
            visibility: PhantomData,
        }
    }

    unsafe fn borrow<'a>(ptr: *mut crate::ffi::c_void) -> Self::Borrowed<'a> {
        // SAFETY: The safety requirements of this method ensure that `ptr` is a
        // valid pointer to a `DriverDmaFenceInner<T>` that was created by a
        // previous call to `into_foreign`.
        let inner = unsafe {
            ARef::from_raw(NonNull::<DriverDmaFenceInner<T>>::new_unchecked(ptr.cast()))
        };

        DriverDmaFenceBorrow {
            inner: ManuallyDrop::new(DriverDmaFence {
                inner: ManuallyDrop::new(inner),
                visibility: PhantomData,
            }),
            _p: PhantomData,
        }
    }

    unsafe fn borrow_mut<'a>(ptr: *mut crate::ffi::c_void) -> Self::BorrowedMut<'a> {
        // SAFETY: The safety requirements of this method ensure that `ptr` is a
        // valid pointer to a `DriverDmaFenceInner<T>` that was created by a
        // previous call to `into_foreign`.
        let inner = unsafe {
            ARef::from_raw(NonNull::<DriverDmaFenceInner<T>>::new_unchecked(ptr.cast()))
        };

        DriverDmaFenceBorrowMut {
            inner: ManuallyDrop::new(DriverDmaFence {
                inner: ManuallyDrop::new(inner),
                visibility: PhantomData,
            }),
            _p: PhantomData,
        }
    }
}
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
            unsafe fn raw_get_work(ptr: *mut Self) -> *mut $crate::workqueue::Work<$work_type $(, $id)?> {
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
            type Pointer = <Self as $crate::dma_buf::dma_fence::DmaFenceWorkItem<$($id)?>>::Pointer;

            fn run(this: Self::Pointer) {
                let _annotation = $crate::dma_buf::dma_fence::DmaFenceSignallingAnnotation::new();

                <Self as $crate::dma_buf::dma_fence::DmaFenceWorkItem<$($id)?>>::run(this)
            }
        }
    )*};
}
pub use impl_has_dma_fence_work;

/// Creates a [`DmaFenceWork`] initialiser with the given name and a newly-created lock class.
#[macro_export]
macro_rules! new_dma_fence_work {
    ($($name:literal)?) => {
        $crate::dma_buf::dma_fence::DmaFenceWork::new(
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
/// [`DmaFenceSignallingAnnotation`] section.
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
                <Self as $crate::dma_buf::dma_fence::DmaFenceDelayedWorkItem<$($id)?>>::Pointer;

            fn run(this: Self::Pointer) {
                let _annotation = $crate::dma_buf::dma_fence::DmaFenceSignallingAnnotation::new();
                <Self as $crate::dma_buf::dma_fence::DmaFenceDelayedWorkItem<$($id)?>>::run(this)
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
        $crate::dma_buf::dma_fence::DmaFenceDelayedWork::new(
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
        $crate::dma_buf::dma_fence::DmaFenceDelayedWork::new(
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

/// Workqueue that can only be used to schedule [`DmaFenceWork`] items.
pub struct DmaFenceWorkqueue(OwnedQueue);

impl DmaFenceWorkqueue {
    /// Allocates a new DMA-fence constrained workqueue.
    #[inline]
    pub fn new(
        name: &CStr,
        flags: WqFlags,
        max_active: usize,
    ) -> Result<DmaFenceWorkqueue, AllocError> {
        let flags = flags | WqFlags::MEM_RECLAIM;
        let queue = OwnedQueue::new(name, flags, max_active)?;
        Ok(Self(queue))
    }

    /// Allocates a new DMA-fence constrained workqueue with a formatted name.
    #[inline]
    pub fn new_fmt(
        name: core::fmt::Arguments<'_>,
        flags: WqFlags,
        max_active: usize,
    ) -> Result<DmaFenceWorkqueue, AllocError> {
        let flags = flags | WqFlags::MEM_RECLAIM;
        let queue = OwnedQueue::new_fmt(name, flags, max_active)?;
        Ok(Self(queue))
    }

    /// Enqueues a work item.
    pub fn enqueue<W, const ID: u64>(&self, w: W) -> W::EnqueueOutput
    where
        W: RawDmaFenceWorkItem<ID> + Send + 'static,
    {
        self.0.enqueue(w)
    }

    /// Enqueues a delayed work item.
    pub fn enqueue_delayed<W, const ID: u64>(&self, w: W, delay: Jiffies) -> W::EnqueueOutput
    where
        W: RawDmaFenceDelayedWorkItem<ID> + Send + 'static,
    {
        self.0.enqueue_delayed(w, delay)
    }
}

/// Trait used for drivers signalling their DMA-fences from a threaded IRQ handler.
pub trait DmaFenceIrqThreadedHandler: Sync {
    /// The hard IRQ handler.
    #[expect(unused_variables)]
    fn handle(&self, device: &Device<Bound>) -> ThreadedIrqReturn {
        ThreadedIrqReturn::WakeThread
    }

    /// The threaded IRQ handler, called within a [`DmaFenceSignallingAnnotation`] section.
    fn handle_dma_fence_threaded(&self, device: &Device<Bound>) -> IrqReturn;
}

/// Adapter that wraps a [`DmaFenceIrqThreadedHandler`] to implement [`ThreadedHandler`].
pub struct DmaFenceIrqAdapter<T: DmaFenceIrqThreadedHandler>(pub T);

impl<T: DmaFenceIrqThreadedHandler + Send + 'static> ThreadedHandler for DmaFenceIrqAdapter<T> {
    fn handle(&self, device: &Device<Bound>) -> ThreadedIrqReturn {
        self.0.handle(device)
    }

    fn handle_threaded(&self, device: &Device<Bound>) -> IrqReturn {
        let _annotation = DmaFenceSignallingAnnotation::new();
        self.0.handle_dma_fence_threaded(device)
    }
}

/// Trait for callbacks that can be registered on fences.
///
/// When the fence signals, the callback will be invoked.
pub trait FenceCallback: Sync + Send {
    /// Called when the fence is signaled, consuming the callback.
    ///
    /// This is called from the fence signaling path, which may be in interrupt
    /// context or with locks held. Implementations must not sleep or perform
    /// long-running operations.
    ///
    /// Takes `self` because each callback fires at most once. This allows the
    /// callback to own resources (e.g., a fence handle) and transfer them out
    /// without interior mutability or locking.
    fn signaled(self, fence: &ARef<PublicDmaFence>);
}

/// Error type for fence callback registration.
///
/// Generic over `T` so that `AlreadySignaled` can return the callback to the
/// caller, allowing it to reclaim any resources owned by the callback (e.g.,
/// a fence handle that needs to be signaled).
#[derive(Debug)]
pub enum CallbackError<T = ()> {
    /// The fence was already signaled. The callback is returned so the caller
    /// can extract owned resources without losing them.
    AlreadySignaled(T),
    /// Some other error occurred during registration.
    Other(Error),
}

impl<T> From<CallbackError<T>> for Error {
    fn from(err: CallbackError<T>) -> Self {
        match err {
            CallbackError::AlreadySignaled(_) => ENOENT,
            CallbackError::Other(e) => e,
        }
    }
}

impl<T> From<AllocError> for CallbackError<T> {
    fn from(e: AllocError) -> Self {
        CallbackError::Other(Error::from(e))
    }
}

/// A callback registration on a fence.
///
/// When this object is dropped, the callback is automatically removed if it
/// hasn't been called yet.
///
/// # Invariants
///
/// If `callback` is `Some`, then `cb` is registered with the fence and the
/// callback hasn't been invoked yet. If `None`, the callback has been invoked
/// or the fence was already signaled when we tried to register.
#[pin_data(PinnedDrop)]
pub struct FenceCallbackRegistration<T: FenceCallback> {
    #[pin]
    cb: Opaque<bindings::dma_fence_cb>,
    callback: Option<T>,
    fence: ARef<PublicDmaFence>,
}

impl<T: FenceCallback> FenceCallbackRegistration<T> {
    /// Register a callback on a fence.
    ///
    /// On success the callback is pinned in place and will fire when the fence
    /// signals. On `AlreadySignaled` the callback is returned to the caller so
    /// that owned resources can be reclaimed.
    pub fn new<'a>(
        fence: &'a ARef<PublicDmaFence>,
        callback: T,
    ) -> impl PinInit<Self, CallbackError<T>> + 'a
    where
        T: 'a,
    {
        // SAFETY: On `Ok(())` the slot is fully initialized. On `Err(_)` the
        // slot is left clean (no partially-initialized fields remain).
        unsafe {
            pin_init_from_closure(move |slot: *mut Self| {
                let slot_callback = &raw mut (*slot).callback;
                let slot_fence = &raw mut (*slot).fence;
                let slot_cb = &raw mut (*slot).cb;

                core::ptr::write(slot_callback, Some(callback));
                core::ptr::write(slot_fence, fence.clone());

                let ret = to_result(bindings::dma_fence_add_callback(
                    fence.inner.get(),
                    Opaque::cast_into(slot_cb),
                    Some(Self::dma_fence_callback),
                ));

                match ret {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        let cb_back = core::ptr::read(slot_callback)
                            .expect("callback was just written as Some");
                        let _fence_back = core::ptr::read(slot_fence);

                        if e.to_errno() == ENOENT.to_errno() {
                            Err(CallbackError::AlreadySignaled(cb_back))
                        } else {
                            Err(CallbackError::Other(e))
                        }
                    }
                }
            })
        }
    }

    /// Raw dma fence callback invoked by the C subsystem.
    ///
    /// # Safety
    ///
    /// This is only called by the dma_fence subsystem with valid pointers.
    unsafe extern "C" fn dma_fence_callback(
        _fence: *mut bindings::dma_fence,
        cb: *mut bindings::dma_fence_cb,
    ) {
		// SAFETY: The dma_fence subsystem invokes this with a valid callback
		// pointer that was registered from a live `FenceCallbackRegistration`.
        unsafe {
            let ptr = cb.cast::<Opaque<bindings::dma_fence_cb>>();
            let reg: *mut Self = crate::container_of!(ptr, Self, cb).cast();

            let callback = (*reg).callback.take();

            if let Some(callback) = callback {
                let fence_ref = &(*reg).fence;
                callback.signaled(fence_ref);
            }
        }
    }

    /// Remove the callback registration.
    ///
    /// Returns `true` if the callback was successfully removed (meaning it hasn't
    /// been called yet), or `false` if the callback was already invoked or removed.
    pub fn remove(mut self: Pin<&mut Self>) -> bool {
        if self.callback.is_some() {
            // SAFETY: The fence pointer is valid and the callback is registered.
            let removed = unsafe {
                bindings::dma_fence_remove_callback(self.fence.inner.get(), self.cb.get())
            };

            if removed {
                // SAFETY: `callback` is not structurally pinned (only `cb` is).
                unsafe {
                    self.as_mut().get_unchecked_mut().callback = None;
                }
                return true;
            }
        }
        false
    }

    /// Remove the callback and return it if it hasn't fired yet.
    pub fn take(mut self: Pin<&mut Self>) -> Option<T> {
        if self.callback.is_some() {
            // SAFETY: The fence pointer is valid and the callback is registered.
            let removed = unsafe {
                bindings::dma_fence_remove_callback(self.fence.inner.get(), self.cb.get())
            };

            if removed {
                // SAFETY: The `callback` field is not structurally pinned.
                return unsafe { self.as_mut().get_unchecked_mut().callback.take() };
            }
        }
        None
    }

    /// Check if the callback is still active (has not been invoked yet).
    pub fn is_active(self: Pin<&Self>) -> bool {
        self.callback.is_some()
    }

    /// Returns a reference to the fence this callback is registered on.
    pub fn fence(self: Pin<&Self>) -> &ARef<PublicDmaFence> {
        &self.get_ref().fence
    }
}

#[pinned_drop]
impl<T: FenceCallback> PinnedDrop for FenceCallbackRegistration<T> {
    fn drop(self: Pin<&mut Self>) {
        // Always call dma_fence_remove_callback even if `callback` is already
        // None. This acquires `fence->lock` and ensures any in-flight signal
        // path has completed before we free the struct.
        //
        // SAFETY: The fence pointer is valid and `cb` was initialized by
        // dma_fence_add_callback during construction.
        unsafe {
            bindings::dma_fence_remove_callback(self.fence.inner.get(), self.cb.get());
        }
    }
}

// SAFETY: FenceCallbackRegistration can be sent between threads.
unsafe impl<T: FenceCallback> Send for FenceCallbackRegistration<T> {}

// SAFETY: &FenceCallbackRegistration can be shared between threads if &T can.
unsafe impl<T: FenceCallback> Sync for FenceCallbackRegistration<T> where T: Sync {}
