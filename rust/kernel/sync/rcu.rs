// SPDX-License-Identifier: GPL-2.0

//! RCU support.
//!
//! C header: [`include/linux/rcupdate.h`](srctree/include/linux/rcupdate.h)

use crate::bindings;
use crate::{
    sync::atomic::{Atomic, Relaxed, Release},
    types::{ForeignOwnable, NotThreadSafe},
};
use core::{marker::PhantomData, pin::Pin, ptr::NonNull};

/// Evidence that the RCU read side lock is held on the current thread/CPU.
///
/// The type is explicitly not `Send` because this property is per-thread/CPU.
///
/// # Invariants
///
/// The RCU read side lock is actually held while instances of this guard exist.
pub struct Guard(NotThreadSafe);

impl Guard {
    /// Acquires the RCU read side lock and returns a guard.
    #[inline]
    pub fn new() -> Self {
        // SAFETY: An FFI call with no additional requirements.
        unsafe { bindings::rcu_read_lock() };
        // INVARIANT: The RCU read side lock was just acquired above.
        Self(NotThreadSafe)
    }

    /// Explicitly releases the RCU read side lock.
    #[inline]
    pub fn unlock(self) {}
}

impl Default for Guard {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Guard {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: By the type invariants, the RCU read side is locked, so it is ok to unlock it.
        unsafe { bindings::rcu_read_unlock() };
    }
}

/// Acquires the RCU read side lock.
#[inline]
pub fn read_lock() -> Guard {
    Guard::new()
}

/// An RCU protected pointer, the pointed object is protected by RCU.
///
/// # Invariants
///
/// Either the pointer is null, or it points to a return value of [`P::into_foreign`] and the atomic
/// variable exclusively owns the pointer.
pub struct Rcu<P: ForeignOwnable>(Atomic<*mut crate::ffi::c_void>, PhantomData<P>);

/// A pointer that has been unpublished, but hasn't waited for a grace period yet.
///
/// The pointed object may still have an existing RCU reader. Therefore a grace period is needed to
/// free the object.
///
/// # Invariants
///
/// The pointer has to be a return value of [`P::into_foreign`] and [`Self`] exclusively owns the
/// pointer.
pub struct RcuOld<P: ForeignOwnable>(NonNull<crate::ffi::c_void>, PhantomData<P>);

impl<P: ForeignOwnable> Drop for RcuOld<P> {
    fn drop(&mut self) {
        // SAFETY: As long as called in a sleepable context, which should be checked by klint,
        // `synchronize_rcu()` is safe to call.
        unsafe {
            bindings::synchronize_rcu();
        }

        // SAFETY: `self.0` is a return value of `P::into_foreign()`, so it's safe to call
        // `from_foreign()` on it. Plus, the above `synchronize_rcu()` guarantees no existing
        // `ForeignOwnable::borrow()` anymore.
        let p: P = unsafe { P::from_foreign(self.0.as_ptr().cast()) };
        drop(p);
    }
}

impl<P: ForeignOwnable> Rcu<P> {
    /// Creates a new RCU pointer.
    pub fn new(p: P) -> Self {
        // INVARIANTS: The return value of `p.into_foreign()` is directly stored in the atomic
        // variable.
        Self(Atomic::new(p.into_foreign().cast()), PhantomData)
    }

    /// Creates a null RCU pointer.
    pub const fn null() -> Self {
        Self(Atomic::new(core::ptr::null_mut()), PhantomData)
    }

    /// Dereferences the protected object.
    ///
    /// Returns `Some(b)`, where `b` is a reference-like borrowed type, if the pointer is not null,
    /// otherwise returns `None`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use kernel::alloc::{flags, KBox};
    /// use kernel::sync::rcu::{self, Rcu};
    ///
    /// let x = Rcu::new(KBox::new(100i32, flags::GFP_KERNEL)?);
    ///
    /// let g = rcu::read_lock();
    /// // Read in under RCU read lock protection.
    /// let v = x.dereference(&g);
    ///
    /// assert_eq!(v, Some(&100i32));
    ///
    /// # Ok::<(), Error>(())
    /// ```
    ///
    /// Note the borrowed access can outlive the reference of the [`Rcu<P>`], this is because as
    /// long as the RCU read lock is held, the pointed object should remain valid.
    ///
    /// In the following case, the main thread is responsible for the ownership of `shared`, i.e. it
    /// will drop it eventually, and a work item can temporarily access the `shared` via `cloned`,
    /// but the use of the dereferenced object doesn't depend on `cloned`'s existence.
    ///
    /// ```rust
    /// # use kernel::alloc::{flags, KBox};
    /// # use kernel::workqueue::system;
    /// # use kernel::sync::{Arc, atomic::{Atomic, Acquire, Release}};
    /// use kernel::sync::rcu::{self, Rcu};
    ///
    /// struct Config {
    ///     a: i32,
    ///     b: i32,
    ///     c: i32,
    /// }
    ///
    /// let config = KBox::new(Config { a: 1, b: 2, c: 3 }, flags::GFP_KERNEL)?;
    ///
    /// let shared = Arc::new(Rcu::new(config), flags::GFP_KERNEL)?;
    /// let cloned = shared.clone();
    ///
    /// // Use atomic to simulate a special refcounting.
    /// static FLAG: Atomic<i32> = Atomic::new(0);
    ///
    /// system().try_spawn(flags::GFP_KERNEL, move || {
    ///     let g = rcu::read_lock();
    ///     let v = cloned.dereference(&g).unwrap();
    ///     drop(cloned); // release reference to `shared`.
    ///     FLAG.store(1, Release);
    ///
    ///     // but still need to access `v`.
    ///     assert_eq!(v.a, 1);
    ///     drop(g);
    /// });
    ///
    /// // Wait until `cloned` dropped.
    /// while FLAG.load(Acquire) == 0 {
    ///     // SAFETY: Sleep should be safe.
    ///     unsafe { kernel::bindings::schedule(); }
    /// }
    ///
    /// drop(shared);
    ///
    /// # Ok::<(), Error>(())
    /// ```
    pub fn dereference<'rcu>(&self, _rcu_guard: &'rcu Guard) -> Option<P::Borrowed<'rcu>> {
        // Ordering: Address dependency pairs with the `store(Release)` in read_copy_update().
        let ptr = self.0.load(Relaxed);

        if !ptr.is_null() {
            // SAFETY:
            // - Since `ptr` is not null, so it has to be a return value of `P::into_foreign()`.
            // - The returned `Borrowed<'rcu>` cannot outlive the RCU Guar, this guarantees the
            //   return value will only be used under RCU read lock, and the RCU read lock prevents
            //   the pass of a grace period that the drop of `RcuOld` or `Rcu` is waiting for,
            //   therefore no `from_foreign()` will be called for `ptr` as long as `Borrowed` exists.
            //
            //      CPU 0                                       CPU 1
            //      =====                                       =====
            //      { `x` is a reference to Rcu<Box<i32>> }
            //      let g = rcu::read_lock();
            //
            //      if let Some(b) = x.dereference(&g) {
            //      // drop(g); cannot be done, since `b` is still alive.
            //
            //                                              if let Some(old) = x.replace(...) {
            //                                                  // `x` is null now.
            //          println!("{}", b);
            //      }
            //                                                  drop(old):
            //                                                    synchronize_rcu();
            //      drop(g);
            //                                                    // a grace period passed.
            //                                                    // No `Borrowed` exists now.
            //                                                    from_foreign(...);
            //                                              }
            Some(unsafe { P::borrow(ptr.cast()) })
        } else {
            None
        }
    }

    /// Read, copy and update the pointer with new value.
    ///
    /// Returns `None` if the pointer's old value is null, otherwise returns `Some(old)`, where old
    /// is a [`RcuOld`] which can be used to free the old object eventually.
    ///
    /// The `Pin<&mut Self>` is needed because this function needs the exclusive access to
    /// [`Rcu<P>`], otherwise two `read_copy_update()`s may get the same old object and double free.
    /// Using `Pin<&mut Self>` provides the exclusive access that C side requires with the type
    /// system checking.
    ///
    /// Also this has to be `Pin` because a `&mut Self` may allow users to `swap()` safely, that
    /// will break the atomicity. A [`Rcu<P>`] should be structurally pinned in the struct that
    /// contains it.
    ///
    /// Note that `Pin<&mut Self>` cannot assume noalias here because [`Atomic<T>`] is a
    /// [`Opaque<T>`] which has the same effect on aliasing rules as [`UnsafePinned`].
    ///
    /// [`UnsafePinned`]: https://rust-lang.github.io/rfcs/3467-unsafe-pinned.html
    pub fn read_copy_update<F>(self: Pin<&mut Self>, f: F) -> Option<RcuOld<P>>
    where
        F: FnOnce(Option<P::Borrowed<'_>>) -> Option<P>,
    {
        // step 1: READ.
        // Ordering: Address dependency pairs with the `store(Release)` in read_copy_update().
        let old_ptr = NonNull::new(self.0.load(Relaxed));

        let old = old_ptr.map(|nonnull| {
            // SAFETY: Per type invariants `old_ptr` has to be a value return by a previous
            // `into_foreign()`, and the exclusive reference `self` guarantees that `from_foreign()`
            // has not been called.
            unsafe { P::borrow(nonnull.as_ptr().cast()) }
        });

        // step 2: COPY, or more generally, initializing `new` based on `old`.
        let new = f(old);

        // step 3: UPDATE.
        if let Some(new) = new {
            let new_ptr = new.into_foreign();
            // Ordering: Pairs with the address dependency in `dereference()` and
            // `read_copy_update()`.
            // INVARIANTS: `new.into_foreign()` is directly store into the atomic variable.
            self.0.store(new_ptr.cast(), Release);
        } else {
            // Ordering: Setting to a null pointer doesn't need to be Release.
            // INVARIANTS: The atomic variable is set to be null.
            self.0.store(core::ptr::null_mut(), Relaxed);
        }

        // INVARIANTS: The exclusive reference guarantess that the ownership of a previous
        // `into_foreign()` transferred to the `RcuOld`.
        Some(RcuOld(old_ptr?, PhantomData))
    }

    /// Replaces the pointer with new value.
    ///
    /// Returns `None` if the pointer's old value is null, otherwise returns `Some(old)`, where old
    /// is a [`RcuOld`] which can be used to free the old object eventually.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::pin::pin;
    /// # use kernel::alloc::{flags, KBox};
    /// use kernel::sync::rcu::{self, Rcu};
    ///
    /// let mut x = pin!(Rcu::new(KBox::new(100i32, flags::GFP_KERNEL)?));
    /// let q = KBox::new(101i32, flags::GFP_KERNEL)?;
    ///
    /// // Read in under RCU read lock protection.
    /// let g = rcu::read_lock();
    /// let v = x.dereference(&g);
    ///
    /// // Replace with a new object.
    /// let old = x.as_mut().replace(q);
    ///
    /// assert!(old.is_some());
    ///
    /// // `v` should still read the old value.
    /// assert_eq!(v, Some(&100i32));
    ///
    /// // New readers should get the new value.
    /// assert_eq!(x.dereference(&g), Some(&101i32));
    ///
    /// drop(g);
    ///
    /// // Can free the object outside the read-side critical section.
    /// drop(old);
    /// # Ok::<(), Error>(())
    /// ```
    pub fn replace(self: Pin<&mut Self>, new: P) -> Option<RcuOld<P>> {
        self.read_copy_update(|_| Some(new))
    }
}

impl<P: ForeignOwnable> Drop for Rcu<P> {
    fn drop(&mut self) {
        let ptr = *self.0.get_mut();
        if !ptr.is_null() {
            // SAFETY: As long as called in a sleepable context, which should be checked by klint,
            // `synchronize_rcu()` is safe to call.
            unsafe {
                bindings::synchronize_rcu();
            }

            // SAFETY: `self.0` is a return value of `P::into_foreign()`, so it's safe to call
            // `from_foreign()` on it. Plus, the above `synchronize_rcu()` guarantees no existing
            // `ForeignOwnable::borrow()` anymore.
            drop(unsafe { P::from_foreign(ptr.cast()) });
        }
    }
}
