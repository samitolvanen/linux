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
    /// Consider the first element to be at index 0, suitable for cyclic allocation.
    AllocCyclic,
}

impl<T: ForeignOwnable> XArray<T> {
    /// Creates a new initializer for this type.
    pub fn new(kind: AllocKind) -> impl PinInit<Self> {
        let flags = match kind {
            AllocKind::Alloc | AllocKind::AllocCyclic => bindings::XA_FLAGS_ALLOC,
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
    #[inline]
    fn from(value: StoreError<T>) -> Self {
        value.error
    }
}

/// A range of valid indices for XArray allocation.
///
/// Used with [`Guard::alloc_cyclic`] to constrain which indices are allocated.
/// Wraps the C `struct xa_limit`.
#[derive(Copy, Clone)]
pub struct XaLimit {
    inner: bindings::xa_limit,
}

impl XaLimit {
    /// Create a new limit with the given inclusive min/max bounds.
    pub const fn new(min: u32, max: u32) -> Self {
        Self {
            inner: bindings::xa_limit { min, max },
        }
    }

    /// Limit to 32-bit indices: `[0, u32::MAX]`.
    pub const LIMIT_32B: Self = Self::new(0, u32::MAX);

    /// Limit to 31-bit indices: `[0, i32::MAX as u32]`.
    pub const LIMIT_31B: Self = Self::new(0, i32::MAX as u32);

    /// Limit to 16-bit indices: `[0, u16::MAX as u32]`.
    pub const LIMIT_16B: Self = Self::new(0, u16::MAX as u32);
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

    /// Allocates the next available index cyclically and stores the given value there.
    ///
    /// Starting from `*next`, wraps around within `limit`, and stores `value` at the
    /// allocated index. On success, returns the allocated index and updates `*next`.
    ///
    /// May drop the lock if needed to allocate memory, and then reacquire it afterwards.
    pub fn alloc_cyclic(
        &mut self,
        value: T,
        limit: XaLimit,
        next: &mut u32,
        gfp: alloc::Flags,
    ) -> Result<usize, StoreError<T>> {
        build_assert!(
            T::FOREIGN_ALIGN >= 4,
            "pointers stored in XArray must be 4-byte aligned"
        );
        let new = value.into_foreign();
        let mut id: u32 = 0;

        // SAFETY:
        // - `self.xa.xa` is always valid by the type invariant.
        // - The caller holds the lock.
        // - `new` came from `T::into_foreign` and satisfies alignment requirements.
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
            // SAFETY: `new` came from `T::into_foreign` and `__xa_alloc_cyclic` does not
            // take ownership on error.
            let value = unsafe { T::from_foreign(new) };
            Err(StoreError {
                value,
                error: Error::from_errno(ret),
            })
        } else {
            Ok(id as usize)
        }
    }
}

// SAFETY: `XArray<T>` has no shared mutable state so it is `Send` iff `T` is `Send`.
unsafe impl<T: ForeignOwnable + Send> Send for XArray<T> {}

// SAFETY: `XArray<T>` serialises the interior mutability it provides so it is `Sync` iff `T` is
// `Send`.
unsafe impl<T: ForeignOwnable + Send> Sync for XArray<T> {}
