// SPDX-License-Identifier: GPL-2.0

//! XArray abstraction.
//!
//! C header: [`include/linux/xarray.h`](srctree/include/linux/xarray.h)

use crate::{
    alloc, bindings, build_assert,
    error::{Error, Result},
    ffi::c_void,
    types::{ForeignOwnable, NotThreadSafe, Opaque},
};
use core::{iter, marker::PhantomData, pin::Pin, ptr::NonNull};
use pin_init::{pin_data, pin_init, pinned_drop, PinInit};

/// `XA_ZERO_ENTRY` — the XArray sentinel for reserved-but-empty slots.
///
/// Defined in C as `xa_mk_internal(257)` which expands to `(257 << 2) | 2`.
const XA_ZERO_ENTRY: *mut c_void = 1030usize as *mut c_void;

/// An XArray index that has been reserved but not yet populated.
///
/// Returned by [`Guard::alloc_cyclic_reserve`]. Must be passed to either
/// [`Guard::store_reserved`] (to commit a value) or [`Guard::release`] (to
/// undo the reservation). Carries no Drop impl intentionally, i.e.: callers are
/// responsible for not leaking reserved slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservedIndex(pub u32);

impl ReservedIndex {
    /// Returns the raw index value.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// An array which efficiently maps sparse integer indices to owned objects.
///
/// This is similar to a [`crate::alloc::kvec::Vec<Option<T>>`], but more efficient when there are
/// holes in the index space, and can be efficiently grown.
///
/// # Invariants
///
/// `self.xa` is always an initialized and valid [`bindings::xarray`] whose entries are either
/// `XA_ZERO_ENTRY` or came from `T::into_foreign`.
///
/// # Examples
///
/// ```rust
/// use kernel::alloc::KBox;
/// use kernel::xarray::{AllocKind, XArray};
///
/// let xa = KBox::pin_init(XArray::new(AllocKind::Alloc1), GFP_KERNEL)?;
///
/// let dead = KBox::new(0xdead, GFP_KERNEL)?;
/// let beef = KBox::new(0xbeef, GFP_KERNEL)?;
///
/// let mut guard = xa.lock();
///
/// assert_eq!(guard.get(0), None);
///
/// assert_eq!(guard.store(0, dead, GFP_KERNEL)?.as_deref(), None);
/// assert_eq!(guard.get(0).copied(), Some(0xdead));
///
/// *guard.get_mut(0).unwrap() = 0xffff;
/// assert_eq!(guard.get(0).copied(), Some(0xffff));
///
/// assert_eq!(guard.store(0, beef, GFP_KERNEL)?.as_deref().copied(), Some(0xffff));
/// assert_eq!(guard.get(0).copied(), Some(0xbeef));
///
/// guard.remove(0);
/// assert_eq!(guard.get(0), None);
///
/// # Ok::<(), Error>(())
/// ```
#[pin_data(PinnedDrop)]
pub struct XArray<T: ForeignOwnable> {
    #[pin]
    xa: Opaque<bindings::xarray>,
    _p: PhantomData<T>,
}

#[pinned_drop]
impl<T: ForeignOwnable> PinnedDrop for XArray<T> {
    fn drop(self: Pin<&mut Self>) {
        self.iter().for_each(|ptr| {
            let ptr = ptr.as_ptr();
            // SAFETY: `ptr` came from `T::into_foreign`.
            //
            // INVARIANT: we own the only reference to the array which is being dropped so the
            // broken invariant is not observable on function exit.
            drop(unsafe { T::from_foreign(ptr) })
        });

        // SAFETY: `self.xa` is always valid by the type invariant.
        unsafe { bindings::xa_destroy(self.xa.get()) };
    }
}

/// Flags passed to [`XArray::new`] to configure the array's allocation tracking behavior.
pub enum AllocKind {
    /// Consider the first element to be at index 0.
    Alloc,
    /// Consider the first element to be at index 1.
    Alloc1,
}

/// Represents a range of valid allocation IDs for XArray allocation functions.
///
/// Wraps the C `struct xa_limit`.
pub struct XaLimit {
    // This is just two integers. The overhead of wrapping this in Opaque<T> is
    // not worth it IMHO.
    inner: bindings::xa_limit,
}

impl XaLimit {
    /// The full 32-bit range `[0, u32::MAX]`.
    pub const LIMIT_32B: Self = Self {
        inner: bindings::xa_limit {
            min: 0,
            max: u32::MAX,
        },
    };

    /// Create a custom range.
    pub const fn new(min: u32, max: u32) -> Self {
        Self {
            inner: bindings::xa_limit { min, max },
        }
    }
}

impl<T: ForeignOwnable> XArray<T> {
    /// Creates a new initializer for this type.
    pub fn new(kind: AllocKind) -> impl PinInit<Self> {
        let flags = match kind {
            AllocKind::Alloc => bindings::XA_FLAGS_ALLOC,
            AllocKind::Alloc1 => bindings::XA_FLAGS_ALLOC1,
        };
        pin_init!(Self {
            // SAFETY: `xa` is valid while the closure is called.
            //
            // INVARIANT: `xa` is initialized here to an empty, valid [`bindings::xarray`].
            xa <- Opaque::ffi_init(|xa| unsafe {
                bindings::xa_init_flags(xa, flags)
            }),
            _p: PhantomData,
        })
    }

    fn iter(&self) -> impl Iterator<Item = NonNull<c_void>> + '_ {
        let mut index = 0;

        // SAFETY: `self.xa` is always valid by the type invariant.
        iter::once(unsafe {
            bindings::xa_find(self.xa.get(), &mut index, usize::MAX, bindings::XA_PRESENT)
        })
        .chain(iter::from_fn(move || {
            // SAFETY: `self.xa` is always valid by the type invariant.
            Some(unsafe {
                bindings::xa_find_after(self.xa.get(), &mut index, usize::MAX, bindings::XA_PRESENT)
            })
        }))
        .map_while(|ptr| NonNull::new(ptr.cast()))
    }

    /// Attempts to lock the [`XArray`] for exclusive access.
    pub fn try_lock(&self) -> Option<Guard<'_, T>> {
        // SAFETY: `self.xa` is always valid by the type invariant.
        if (unsafe { bindings::xa_trylock(self.xa.get()) } != 0) {
            Some(Guard {
                xa: self,
                _not_send: NotThreadSafe,
            })
        } else {
            None
        }
    }

    /// Locks the [`XArray`] for exclusive access.
    pub fn lock(&self) -> Guard<'_, T> {
        // SAFETY: `self.xa` is always valid by the type invariant.
        unsafe { bindings::xa_lock(self.xa.get()) };

        Guard {
            xa: self,
            _not_send: NotThreadSafe,
        }
    }
}

/// A lock guard.
///
/// The lock is unlocked when the guard goes out of scope.
#[must_use = "the lock unlocks immediately when the guard is unused"]
pub struct Guard<'a, T: ForeignOwnable> {
    xa: &'a XArray<T>,
    _not_send: NotThreadSafe,
}

impl<T: ForeignOwnable> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        // SAFETY:
        // - `self.xa.xa` is always valid by the type invariant.
        // - The caller holds the lock, so it is safe to unlock it.
        unsafe { bindings::xa_unlock(self.xa.xa.get()) };
    }
}

/// The error returned by [`store`](Guard::store).
///
/// Contains the underlying error and the value that was not stored.
pub struct StoreError<T> {
    /// The error that occurred.
    pub error: Error,
    /// The value that was not stored.
    pub value: T,
}

impl<T> From<StoreError<T>> for Error {
    fn from(value: StoreError<T>) -> Self {
        value.error
    }
}

impl<'a, T: ForeignOwnable> Guard<'a, T> {
    fn load<F, U>(&self, index: usize, f: F) -> Option<U>
    where
        F: FnOnce(NonNull<c_void>) -> U,
    {
        // SAFETY: `self.xa.xa` is always valid by the type invariant.
        let ptr = unsafe { bindings::xa_load(self.xa.xa.get(), index) };
        let ptr = NonNull::new(ptr.cast())?;
        Some(f(ptr))
    }

    /// Provides a reference to the element at the given index.
    pub fn get(&self, index: usize) -> Option<T::Borrowed<'_>> {
        self.load(index, |ptr| {
            // SAFETY: `ptr` came from `T::into_foreign`.
            unsafe { T::borrow(ptr.as_ptr()) }
        })
    }

    /// Provides a mutable reference to the element at the given index.
    pub fn get_mut(&mut self, index: usize) -> Option<T::BorrowedMut<'_>> {
        self.load(index, |ptr| {
            // SAFETY: `ptr` came from `T::into_foreign`.
            unsafe { T::borrow_mut(ptr.as_ptr()) }
        })
    }

    /// Removes and returns the element at the given index.
    pub fn remove(&mut self, index: usize) -> Option<T> {
        // SAFETY:
        // - `self.xa.xa` is always valid by the type invariant.
        // - The caller holds the lock.
        let ptr = unsafe { bindings::__xa_erase(self.xa.xa.get(), index) }.cast();
        // SAFETY:
        // - `ptr` is either NULL or came from `T::into_foreign`.
        // - `&mut self` guarantees that the lifetimes of [`T::Borrowed`] and [`T::BorrowedMut`]
        // borrowed from `self` have ended.
        unsafe { T::try_from_foreign(ptr) }
    }

    /// Allocates an unused index and stores the element there.
    ///
    /// The index is allocated within the given `limit` range.
    ///
    /// On success, returns the allocated index.
    ///
    /// On failure, returns the element which was not stored.
    pub fn alloc(
        &mut self,
        value: T,
        limit: XaLimit,
        gfp: alloc::Flags,
    ) -> Result<u32, StoreError<T>> {
        build_assert!(
            T::FOREIGN_ALIGN >= 4,
            "pointers stored in XArray must be 4-byte aligned"
        );
        let new = value.into_foreign();
        let mut id: u32 = 0;

        // SAFETY:
        // - `self.xa.xa` is always valid by the type invariant.
        // - The caller holds the lock.
        //
        // INVARIANT: `new` came from `T::into_foreign`.
        let ret = unsafe {
            bindings::__xa_alloc(
                self.xa.xa.get(),
                &mut id,
                new.cast(),
                limit.inner,
                gfp.as_raw(),
            )
        };

        if ret < 0 {
            // SAFETY: `new` came from `T::into_foreign` and `__xa_alloc` does not take
            // ownership of the value on error.
            let value = unsafe { T::from_foreign(new) };
            Err(StoreError {
                value,
                error: Error::from_errno(ret),
            })
        } else {
            Ok(id)
        }
    }

    /// Allocates an unused index cyclically and stores the element there.
    ///
    /// The index is allocated within the given `limit` range, starting from `*next`.
    /// On success, `*next` is updated to the value after the allocated index, ready
    /// for the next call.
    ///
    /// Returns the allocated index on success, or the element on failure.
    ///
    /// The XArray should be initialized with [`AllocKind::Alloc`].
    pub fn alloc_cyclic(
        &mut self,
        value: T,
        limit: XaLimit,
        next: &mut u32,
        gfp: alloc::Flags,
    ) -> Result<u32, StoreError<T>> {
        build_assert!(
            T::FOREIGN_ALIGN >= 4,
            "pointers stored in XArray must be 4-byte aligned"
        );
        let new = value.into_foreign();
        let mut id: u32 = 0;

        // SAFETY:
        // - `self.xa.xa` is always valid by the type invariant.
        // - The caller holds the lock.
        //
        // INVARIANT: `new` came from `T::into_foreign`.
        let ret = unsafe {
            bindings::__xa_alloc_cyclic(
                self.xa.xa.get(),
                &mut id,
                new.cast(),
                limit.inner,
                next,
                gfp.as_raw(),
            )
        };

        if ret < 0 {
            // SAFETY: `new` came from `T::into_foreign` and `__xa_alloc_cyclic` does not take
            // ownership of the value on error.
            let value = unsafe { T::from_foreign(new) };
            Err(StoreError {
                value,
                error: Error::from_errno(ret),
            })
        } else {
            Ok(id)
        }
    }

    /// Cyclically allocates an index and marks it as reserved (no value stored yet).
    ///
    /// Works like [`alloc_cyclic`](Guard::alloc_cyclic) but stores `XA_ZERO_ENTRY`
    /// instead of a real value. The slot is invisible to normal lookups but prevents
    /// the cyclic allocator from reusing the index until it is either filled with
    /// [`store_reserved`](Guard::store_reserved) or freed with
    /// [`release`](Guard::release).
    pub fn alloc_cyclic_reserve(
        &mut self,
        limit: XaLimit,
        next: &mut u32,
        gfp: alloc::Flags,
    ) -> Result<ReservedIndex> {
        build_assert!(
            core::mem::align_of::<u32>() >= 4,
            "XArray alloc requires 4-byte aligned entries"
        );
        let mut id: u32 = 0;

        // SAFETY: `self.xa.xa` is valid by the type invariant, the caller
        // holds the lock, and `XA_ZERO_ENTRY` is a valid XArray sentinel.
        let ret = unsafe {
            bindings::__xa_alloc_cyclic(
                self.xa.xa.get(),
                &mut id,
                XA_ZERO_ENTRY,
                limit.inner,
                next,
                gfp.as_raw(),
            )
        };

        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ReservedIndex(id))
        }
    }
    /// [`alloc_cyclic_reserve`](Guard::alloc_cyclic_reserve).
    ///
    /// The `XA_ZERO_ENTRY` sentinel left by the reservation is silently discarded
    /// (it is not a `T`). Use the ordinary [`store`](Guard::store) when replacing
    /// an existing `T` value.
    ///
    /// On failure the element is returned inside [`StoreError`].
    pub fn store_reserved(
        &mut self,
        index: ReservedIndex,
        value: T,
        gfp: alloc::Flags,
    ) -> Result<(), StoreError<T>> {
        build_assert!(
            T::FOREIGN_ALIGN >= 4,
            "pointers stored in XArray must be 4-byte aligned"
        );
        let new = value.into_foreign();

        let old = {
            // SAFETY:
            // - `self.xa.xa` is always valid by the type invariant.
            // - The caller holds the lock.
            // - `new` came from `T::into_foreign`.
            unsafe {
                bindings::__xa_store(self.xa.xa.get(), index.index(), new.cast(), gfp.as_raw())
            }
        };

        // SAFETY: `__xa_store` returns `xa_err(…)` on error, 0 on success.
        let errno = unsafe { bindings::xa_err(old) };
        if errno != 0 {
            // SAFETY: `new` came from `T::into_foreign`; `__xa_store` does not take
            // ownership on error.
            let value = unsafe { T::from_foreign(new) };
            Err(StoreError {
                value,
                error: Error::from_errno(errno),
            })
        } else {
            // `old` is XA_ZERO_ENTRY — an internal marker, not a `T`. Discard it.
            Ok(())
        }
    }

    /// Releases a slot previously reserved with
    /// [`alloc_cyclic_reserve`](Guard::alloc_cyclic_reserve) without storing a value.
    ///
    /// Uses `__xa_cmpxchg` to atomically replace `XA_ZERO_ENTRY` with `NULL`, making
    /// the slot available for future allocations. If the slot no longer contains
    /// `XA_ZERO_ENTRY` (e.g. it was already committed or concurrently modified) this
    /// is a no-op.
    pub fn release(&mut self, index: ReservedIndex) {
        // SAFETY: `self.xa.xa` is valid by the type invariant, the caller
        // holds the lock, and both XA_ZERO_ENTRY and NULL are valid cmpxchg
        // arguments.
        unsafe {
            bindings::__xa_cmpxchg(
                self.xa.xa.get(),
                index.index(),
                XA_ZERO_ENTRY,
                core::ptr::null_mut(),
                0,
            );
        }
    }

    /// Stores an element at the given index.
    ///
    /// May drop the lock if needed to allocate memory, and then reacquire it afterwards.
    ///
    /// On success, returns the element which was previously at the given index.
    ///
    /// On failure, returns the element which was attempted to be stored.
    pub fn store(
        &mut self,
        index: usize,
        value: T,
        gfp: alloc::Flags,
    ) -> Result<Option<T>, StoreError<T>> {
        build_assert!(
            T::FOREIGN_ALIGN >= 4,
            "pointers stored in XArray must be 4-byte aligned"
        );
        let new = value.into_foreign();

        let old = {
            let new = new.cast();
            // SAFETY:
            // - `self.xa.xa` is always valid by the type invariant.
            // - The caller holds the lock.
            //
            // INVARIANT: `new` came from `T::into_foreign`.
            unsafe { bindings::__xa_store(self.xa.xa.get(), index, new, gfp.as_raw()) }
        };

        // SAFETY: `__xa_store` returns the old entry at this index on success or `xa_err` if an
        // error happened.
        let errno = unsafe { bindings::xa_err(old) };
        if errno != 0 {
            // SAFETY: `new` came from `T::into_foreign` and `__xa_store` does not take
            // ownership of the value on error.
            let value = unsafe { T::from_foreign(new) };
            Err(StoreError {
                value,
                error: Error::from_errno(errno),
            })
        } else {
            let old = old.cast();
            // SAFETY: `ptr` is either NULL or came from `T::into_foreign`.
            //
            // NB: `XA_ZERO_ENTRY` is never returned by functions belonging to the Normal XArray
            // API; such entries present as `NULL`.
            Ok(unsafe { T::try_from_foreign(old) })
        }
    }
}

// SAFETY: `XArray<T>` has no shared mutable state so it is `Send` iff `T` is `Send`.
unsafe impl<T: ForeignOwnable + Send> Send for XArray<T> {}

// SAFETY: `XArray<T>` serialises the interior mutability it provides so it is `Sync` iff `T` is
// `Send`.
unsafe impl<T: ForeignOwnable + Send> Sync for XArray<T> {}
