// SPDX-License-Identifier: GPL-2.0

//! DMA fence abstraction.
//!
//! This module provides safe Rust abstractions for the kernel's DMA fence
//! synchronization primitive (`struct dma_fence`).
//!
//! C header: [`include/linux/dma-fence.h`](srctree/include/linux/dma-fence.h)

use core::{
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
	bindings,
	c_str,
	error::to_result,
	prelude::*,
	sync::aref::{
		ARef,
		AlwaysRefCounted,
	},
	time::Jiffies,
	types::{
		NotThreadSafe,
		Opaque,
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
