// SPDX-License-Identifier: GPL-2.0 OR MIT

//! LRU lists of GEM objects.
//!
//! A shrinker keeps the objects whose memory it can reclaim on LRU lists, and scans the lists to
//! reclaim memory. The GEM LRU mutex of the DRM device protects all LRU lists of the device.
//!
//! C header: [`include/drm/drm_gem.h`](srctree/include/drm/drm_gem.h)

use crate::{
    bindings,
    drm::{
        self,
        driver::AllocImpl,
        gem::{
            IntoGEMObject,
            ResvGuard, //
        }, //
    },
    prelude::*,
    sync::{
        aref::ARef,
        MutexGuard, //
    },
    types::Opaque, //
};
use core::{
    marker::PhantomData,
    ptr, //
};

/// An LRU list of GEM objects.
///
/// An object is on at most one list. Moving an object to the tail of a list removes it from the
/// list it was on, and freeing an object removes it from its list.
///
/// The list holds a reference to its DRM device, so storing it in the private data of the device
/// would create a reference cycle. Device-wide lists belong in data that is dropped when the
/// device is unbound, such as data owned by a [`Devres`]. Dropping the list takes the GEM LRU
/// mutex of the device and removes the objects that remain on it.
///
/// [`Devres`]: crate::devres::Devres
///
/// # Invariants
///
/// - `lru` is an initialized `struct drm_gem_lru`, protected by the GEM LRU mutex of `dev`.
/// - Every object on the list is an `O` that belongs to `dev`.
#[pin_data(PinnedDrop)]
pub struct Lru<O: AllocImpl> {
    #[pin]
    lru: Opaque<bindings::drm_gem_lru>,
    dev: ARef<drm::Device<O::Driver>>,
    _p: PhantomData<O>,
}

// SAFETY: It is safe to send an `Lru` to another thread because the GEM LRU mutex serializes all
// accesses to the list, and the objects that a scan shares and may drop are `Send + Sync`.
unsafe impl<O: AllocImpl + Send + Sync> Send for Lru<O> {}

// SAFETY: It is safe to share an `Lru` with other threads because the GEM LRU mutex serializes all
// accesses to the list, and the objects that a scan shares and may drop are `Send + Sync`.
unsafe impl<O: AllocImpl + Send + Sync> Sync for Lru<O> {}

impl<O: AllocImpl> Lru<O> {
    /// Creates an empty list for the objects of `dev`.
    pub fn new(dev: &drm::Device<O::Driver>) -> impl PinInit<Self> {
        let dev = dev.into();

        // INVARIANT: The list is initialized empty, and `dev` is its device.
        pin_init!(Self {
            // SAFETY: `drm_gem_lru_init()` initializes the list at `slot`.
            lru <- Opaque::ffi_init(|slot| unsafe { bindings::drm_gem_lru_init(slot) }),
            dev,
            _p: PhantomData,
        })
    }

    /// Moves `obj` to the tail of the list.
    ///
    /// Takes the GEM LRU mutex of the device. Returns [`EINVAL`] if `obj` belongs to another
    /// device.
    #[inline]
    pub fn move_tail(&self, obj: &O) -> Result {
        self.check_obj(obj)?;

        // INVARIANT: `obj` is an `O` of `dev`, as checked above.
        // SAFETY: The list is initialized, and `obj` belongs to the device whose GEM LRU mutex
        // protects the list. `drm_gem_lru_move_tail()` takes that mutex.
        unsafe { bindings::drm_gem_lru_move_tail(self.lru.get(), obj.as_raw()) };

        Ok(())
    }

    /// Moves `obj` to the tail of the list, with the GEM LRU mutex of the device held.
    ///
    /// Returns [`EINVAL`] if `guard` does not hold the GEM LRU mutex of the device, or if `obj`
    /// belongs to another device.
    #[inline]
    pub fn move_tail_locked(&self, guard: &mut MutexGuard<'_, ()>, obj: &O) -> Result {
        self.check_guard(guard)?;
        self.check_obj(obj)?;

        // INVARIANT: `obj` is an `O` of `dev`, as checked above.
        // SAFETY: The list is initialized, and `guard` holds the GEM LRU mutex that protects the
        // list and the LRU state of `obj`.
        unsafe { bindings::drm_gem_lru_move_tail_locked(self.lru.get(), obj.as_raw()) };

        Ok(())
    }

    /// Returns the total number of pages of the objects on the list.
    ///
    /// Returns [`EINVAL`] if `guard` does not hold the GEM LRU mutex of the device.
    #[inline]
    pub fn count(&self, guard: &MutexGuard<'_, ()>) -> Result<usize> {
        self.check_guard(guard)?;

        // SAFETY: `guard` holds the GEM LRU mutex that protects the list.
        let count = unsafe { (*self.lru.get()).count };

        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// Scans the list from its head and tries to reclaim the memory of its objects with `S`.
    ///
    /// The scan skips objects whose reservation lock is held, and stops once it has reclaimed
    /// `nr_to_scan` pages. It adds the pages of the objects that remain reclaimable to
    /// `remaining`, and returns the number of pages it reclaimed.
    ///
    /// The scan takes the GEM LRU mutex of the device, and releases it while `S` runs.
    pub fn scan<S: Shrink<O>>(&self, nr_to_scan: usize, remaining: &mut usize) -> usize {
        let nr_to_scan = u32::try_from(nr_to_scan).unwrap_or(u32::MAX);

        // SAFETY: The list is initialized and protected by the GEM LRU mutex of `dev`, which
        // `drm_gem_lru_scan()` takes. The objects on the list are `O`s, and the scan holds a
        // reference to each object and its reservation lock while it calls `shrink_callback`.
        unsafe {
            bindings::drm_gem_lru_scan(
                self.dev.as_raw(),
                self.lru.get(),
                nr_to_scan,
                remaining,
                Some(shrink_callback::<O, S>),
                ptr::null_mut(),
            )
        }
    }

    /// Checks that `obj` belongs to the device of the list.
    fn check_obj(&self, obj: &O) -> Result {
        // SAFETY: `obj` is a valid GEM object.
        let dev = unsafe { (*obj.as_raw()).dev };

        if dev == self.dev.as_raw() {
            Ok(())
        } else {
            Err(EINVAL)
        }
    }

    /// Checks that `guard` holds the GEM LRU mutex of the device of the list.
    fn check_guard(&self, guard: &MutexGuard<'_, ()>) -> Result {
        if ptr::eq(guard.lock_ref(), self.dev.gem_lru_mutex()) {
            Ok(())
        } else {
            Err(EINVAL)
        }
    }
}

/// Removes `obj` from the [`Lru`] it is on, if any.
///
/// Takes the GEM LRU mutex of the device of `obj`.
#[inline]
pub fn remove<O: IntoGEMObject>(obj: &O) {
    // SAFETY: `obj` is a valid GEM object. `drm_gem_lru_remove()` takes the GEM LRU mutex of its
    // device, which protects any list that `obj` is on.
    unsafe { bindings::drm_gem_lru_remove(obj.as_raw()) };
}

#[pinned_drop]
impl<O: AllocImpl> PinnedDrop for Lru<O> {
    fn drop(self: Pin<&mut Self>) {
        let lru = self.lru.get();
        let _guard = self.dev.gem_lru_mutex().lock();

        // SAFETY: The list is initialized.
        let head = unsafe { &raw mut (*lru).list };

        loop {
            // SAFETY: We hold the GEM LRU mutex that protects the list.
            let node = unsafe { (*head).next };
            if node == head {
                break;
            }

            // SAFETY: We hold the GEM LRU mutex that protects the list and the LRU state of the
            // objects on it. `node` is the `lru_node` of the first object on the list.
            unsafe {
                let obj = crate::container_of!(node, bindings::drm_gem_object, lru_node);

                bindings::list_del_init(node);
                (*obj).lru = ptr::null_mut();
            }
        }

        // SAFETY: We hold the GEM LRU mutex that protects the list.
        unsafe { (*lru).count = 0 };
    }
}

/// A way to reclaim the memory of the objects on an [`Lru`].
pub trait Shrink<O: IntoGEMObject> {
    /// Tries to reclaim the memory of the object whose reservation lock `guard` holds.
    ///
    /// This runs with the reservation lock of the object trylocked, possibly from memory reclaim,
    /// so it may only trylock other reservation locks. The GEM LRU mutex is not held.
    ///
    /// Returns `true` if the memory was reclaimed. The object must then no longer be on the
    /// scanned list, for example because it was moved to another list.
    fn shrink(guard: &mut ResvGuard<'_, O>) -> bool;
}

/// Calls [`Shrink::shrink()`] for an object that [`Lru::scan()`] has locked.
///
/// # Safety
///
/// `obj` must be an `O`. The caller must hold a reference to `obj` and its reservation lock for
/// the duration of the call, and must have taken the lock without a guard.
unsafe extern "C" fn shrink_callback<O: AllocImpl, S: Shrink<O>>(
    obj: *mut bindings::drm_gem_object,
    _ticket: *mut bindings::ww_acquire_ctx,
) -> bool {
    // SAFETY: Per the safety requirements, `obj` is a valid `O` for the duration of the call.
    let obj = unsafe { O::from_raw(obj) };

    // SAFETY: Per the safety requirements, the caller holds the reservation lock of `obj` for the
    // duration of the call, and no other guard of it exists.
    let mut guard = unsafe { ResvGuard::assume_locked(obj) };

    S::shrink(&mut guard)
}

#[kunit_tests(rust_drm_gem_lru)]
mod tests {
    use super::*;
    use crate::{
        drm::{
            gem::{
                self,
                BaseObject, //
            },
            DeviceContext, //
        },
        faux,
        page::PAGE_SIZE,
        sync::LockedBy, //
    };

    #[pin_data]
    struct KunitData {}
    struct KunitDriver;
    struct KunitFile;
    #[pin_data]
    struct KunitObject {}

    type KunitGem = gem::Object<KunitObject>;

    impl drm::file::DriverFile for KunitFile {
        type Driver = KunitDriver;

        fn open(_dev: &drm::Device<KunitDriver>) -> Result<Pin<KBox<Self>>> {
            Ok(KBox::new(Self, GFP_KERNEL)?.into())
        }
    }

    impl gem::DriverObject for KunitObject {
        type Driver = KunitDriver;
        type Args = ();

        fn new<Ctx: DeviceContext>(
            _dev: &drm::Device<KunitDriver, Ctx>,
            _size: usize,
            _args: Self::Args,
        ) -> impl PinInit<Self, Error> {
            try_pin_init!(KunitObject {})
        }

        fn create_imported(
            _dev: &drm::Device<KunitDriver>,
            _size: usize,
        ) -> impl PinInit<Self, Error> {
            try_pin_init!(KunitObject {})
        }
    }

    #[vtable]
    impl drm::Driver for KunitDriver {
        type Data = KunitData;
        type File = KunitFile;
        type Object<Ctx: DeviceContext> = KunitGem;

        const INFO: drm::DriverInfo = drm::DriverInfo {
            major: 0,
            minor: 0,
            patchlevel: 0,
            name: c"kunit",
            desc: c"Kunit",
        };
        const IOCTLS: &'static [drm::ioctl::DrmIoctlDescriptor] = &[];
    }

    fn create_drm_dev(reg: &faux::Registration) -> Result<&drm::Device<KunitDriver>> {
        let drm = drm::device::UnregisteredDevice::<KunitDriver>::new(reg.as_ref())?;

        // SAFETY: The faux device is created and registered, so it is bound for the lifetime of
        // the test.
        let dev = unsafe { reg.as_ref().as_bound() };

        drm::driver::Registration::new_foreign_owned(drm, dev, try_pin_init!(KunitData {}), 0)
    }

    /// Reclaims every object by removing it from its list.
    struct Remove;

    impl Shrink<KunitGem> for Remove {
        fn shrink(guard: &mut ResvGuard<'_, KunitGem>) -> bool {
            remove(guard.obj());
            true
        }
    }

    /// Reclaims nothing.
    struct Keep;

    impl Shrink<KunitGem> for Keep {
        fn shrink(_guard: &mut ResvGuard<'_, KunitGem>) -> bool {
            false
        }
    }

    #[test]
    fn move_and_count() -> Result {
        let reg = faux::Registration::new(c"Kunit", None)?;
        let drm = create_drm_dev(&reg)?;
        let other_reg = faux::Registration::new(c"KunitOther", None)?;
        let other = create_drm_dev(&other_reg)?;

        let small = KunitGem::new(drm, PAGE_SIZE, ())?;
        let large = KunitGem::new(drm, 2 * PAGE_SIZE, ())?;
        let foreign = KunitGem::new(other, PAGE_SIZE, ())?;

        let a = KBox::pin_init(Lru::<KunitGem>::new(drm), GFP_KERNEL)?;
        let b = KBox::pin_init(Lru::<KunitGem>::new(drm), GFP_KERNEL)?;

        a.move_tail(&small)?;
        a.move_tail(&large)?;
        assert_eq!(a.move_tail(&foreign).err(), Some(EINVAL));

        let mut guard = drm.gem_lru_mutex().lock();
        assert_eq!(a.count(&guard)?, 3);
        b.move_tail_locked(&mut guard, &large)?;
        assert_eq!(a.count(&guard)?, 1);
        assert_eq!(b.count(&guard)?, 2);
        drop(guard);

        let mut other_guard = other.gem_lru_mutex().lock();
        assert_eq!(a.count(&other_guard).err(), Some(EINVAL));
        assert_eq!(
            a.move_tail_locked(&mut other_guard, &small).err(),
            Some(EINVAL)
        );
        drop(other_guard);

        remove(&*small);
        let guard = drm.gem_lru_mutex().lock();
        assert_eq!(a.count(&guard)?, 0);
        assert_eq!(b.count(&guard)?, 2);

        Ok(())
    }

    #[test]
    fn scan() -> Result {
        let reg = faux::Registration::new(c"Kunit", None)?;
        let drm = create_drm_dev(&reg)?;

        let objs = [
            KunitGem::new(drm, PAGE_SIZE, ())?,
            KunitGem::new(drm, PAGE_SIZE, ())?,
            KunitGem::new(drm, PAGE_SIZE, ())?,
        ];

        let lru = KBox::pin_init(Lru::<KunitGem>::new(drm), GFP_KERNEL)?;
        for obj in &objs {
            lru.move_tail(obj)?;
        }

        let mut remaining = 0;
        assert_eq!(lru.scan::<Keep>(3, &mut remaining), 0);
        assert_eq!(remaining, 3);

        let resv = objs[1].lock_resv();
        let mut remaining = 0;
        assert_eq!(lru.scan::<Remove>(3, &mut remaining), 2);
        assert_eq!(remaining, 1);
        drop(resv);

        assert_eq!(lru.count(&drm.gem_lru_mutex().lock())?, 1);

        lru.move_tail(&objs[0])?;
        let mut remaining = 0;
        assert_eq!(lru.scan::<Remove>(1, &mut remaining), 1);
        assert_eq!(lru.count(&drm.gem_lru_mutex().lock())?, 1);

        Ok(())
    }

    #[test]
    fn locked_by() -> Result {
        let reg = faux::Registration::new(c"Kunit", None)?;
        let drm = create_drm_dev(&reg)?;

        let value = LockedBy::new(drm.gem_lru_mutex(), 0u32);

        let mut guard = drm.gem_lru_mutex().lock();
        *value.access_with_guard_mut(&mut guard) += 1;
        assert_eq!(*value.access_with_guard(&guard), 1);

        Ok(())
    }

    #[test]
    fn drop_removes_objects() -> Result {
        let reg = faux::Registration::new(c"Kunit", None)?;
        let drm = create_drm_dev(&reg)?;

        let obj = KunitGem::new(drm, PAGE_SIZE, ())?;

        let lru = KBox::pin_init(Lru::<KunitGem>::new(drm), GFP_KERNEL)?;
        lru.move_tail(&obj)?;
        drop(lru);

        let lru = KBox::pin_init(Lru::<KunitGem>::new(drm), GFP_KERNEL)?;
        lru.move_tail(&obj)?;
        assert_eq!(lru.count(&drm.gem_lru_mutex().lock())?, 1);

        remove(&*obj);
        assert_eq!(lru.count(&drm.gem_lru_mutex().lock())?, 0);

        Ok(())
    }
}
