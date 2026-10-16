// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DRM GEM API
//!
//! C header: [`include/drm/drm_gem.h`](srctree/include/drm/drm_gem.h)

use crate::{
    bindings,
    drm::{
        self,
        device::{
            DeviceContext,
            Registered, //
        },
        driver::{
            AllocImpl,
            AllocOps, //
        },
    },
    error::to_result,
    prelude::*,
    sync::aref::{
        ARef,
        AlwaysRefCounted, //
    },
    types::{
        NotThreadSafe,
        Opaque, //
    },
};
use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    ops::Deref,
    ptr::{
        self,
        NonNull, //
    },
};

pub mod lru;
#[cfg(CONFIG_RUST_DRM_GEM_SHMEM_HELPER)]
pub mod shmem;

/// A macro for implementing [`AlwaysRefCounted`] for any GEM object type.
///
/// Since all GEM objects use the same refcounting scheme.
#[macro_export]
macro_rules! impl_aref_for_gem_obj {
    (
        impl $( <$( $tparam_id:ident ),+> )? for $type:ty
        $(
            where
                $( $bind_param:path : $bind_trait:path ),+
        )?
    ) => {
        // SAFETY: All GEM objects are refcounted.
        unsafe impl $( <$( $tparam_id ),+> )? $crate::sync::aref::AlwaysRefCounted for $type
        where
            Self: IntoGEMObject,
            $( $( $bind_param : $bind_trait ),+ )?
        {
            fn inc_ref(&self) {
                // SAFETY: The existence of a shared reference guarantees that the refcount is
                // non-zero.
                unsafe { bindings::drm_gem_object_get(self.as_raw()) };
            }

            unsafe fn dec_ref(obj: core::ptr::NonNull<Self>) {
                // SAFETY: `obj` is a valid pointer to an `Object<T>`.
                let obj = unsafe { obj.as_ref() }.as_raw();

                // SAFETY: The safety requirements guarantee that the refcount is non-zero.
                unsafe { bindings::drm_gem_object_put(obj) };
            }
        }
    };
}
#[cfg_attr(not(CONFIG_RUST_DRM_GEM_SHMEM_HELPER), allow(unused))]
pub(crate) use impl_aref_for_gem_obj;

/// A type alias for retrieving a [`Driver`]s [`DriverFile`] implementation from its
/// [`DriverObject`] implementation.
///
/// [`Driver`]: drm::Driver
/// [`DriverFile`]: drm::file::DriverFile
pub type DriverFile<T> = drm::File<<<T as DriverObject>::Driver as drm::Driver>::File>;

/// A type alias for retrieving the current [`AllocImpl`] for a given [`DriverObject`].
///
/// [`Driver`]: drm::Driver
pub type DriverAllocImpl<T, Ctx = Registered> =
    <<T as DriverObject>::Driver as drm::Driver>::Object<Ctx>;

/// The state of a GEM object, as reported to fdinfo.
///
/// Mirrors `enum drm_gem_object_status`. Flags can be combined with the `|`,
/// `&`, and `!` operators. The empty set is the default.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ObjectStatus(c_int);

impl ObjectStatus {
    /// The object is resident in memory (i.e. not unpinned).
    pub const RESIDENT: ObjectStatus =
        ObjectStatus(bindings::drm_gem_object_status::DRM_GEM_OBJECT_RESIDENT.0);

    /// The object is marked as purgeable by userspace.
    pub const PURGEABLE: ObjectStatus =
        ObjectStatus(bindings::drm_gem_object_status::DRM_GEM_OBJECT_PURGEABLE.0);

    /// The object is in use by an active submission.
    pub const ACTIVE: ObjectStatus =
        ObjectStatus(bindings::drm_gem_object_status::DRM_GEM_OBJECT_ACTIVE.0);

    /// Returns the empty set of flags.
    pub const fn empty() -> ObjectStatus {
        ObjectStatus(0)
    }

    /// Returns whether all of the flags in `flags` are set in `self`.
    pub fn contains(self, flags: ObjectStatus) -> bool {
        (self & flags) == flags
    }

    pub(crate) fn as_raw(self) -> bindings::drm_gem_object_status {
        bindings::drm_gem_object_status(self.0)
    }
}

impl core::ops::BitOr for ObjectStatus {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for ObjectStatus {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::Not for ObjectStatus {
    type Output = Self;
    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

/// GEM object functions, which must be implemented by drivers.
pub trait DriverObject: Sync + Send + Sized {
    /// Parent `Driver` for this object.
    type Driver: drm::Driver;

    /// The data type to use for passing arguments to [`DriverObject::new`].
    type Args;

    /// Create a new driver data object for a GEM object of a given size.
    fn new<Ctx: DeviceContext>(
        dev: &drm::Device<Self::Driver, Ctx>,
        size: usize,
        args: Self::Args,
    ) -> impl PinInit<Self, Error>;

    /// Create a new driver data object for a GEM object that is being imported
    /// from another driver (e.g. via dma-buf).
    ///
    /// Imported objects are allocated by the importing helper, which only
    /// provides the device and size; there is no driver-supplied
    /// [`DriverObject::Args`]. Drivers must initialise the per-object state
    /// without those arguments.
    fn create_imported(dev: &drm::Device<Self::Driver>, size: usize) -> impl PinInit<Self, Error>;

    /// Open a new handle to an existing object, associated with a File.
    fn open(_obj: &DriverAllocImpl<Self>, _file: &DriverFile<Self>) -> Result {
        Ok(())
    }

    /// Close a handle to an existing object, associated with a File.
    fn close(_obj: &DriverAllocImpl<Self>, _file: &DriverFile<Self>) {}

    /// Notifies the driver that the object is about to be freed.
    ///
    /// Called from the free path once the last reference drops and before any
    /// backing storage is released, so the object is still fully valid. The
    /// core still performs the free. This is only a notification.
    ///
    /// This can run before the device finishes registering, for an object
    /// created on an unregistered device and freed on a probe-error path, so
    /// the driver data reached through [`dev()`] may be absent. Use
    /// [`Device::data`] rather than the `Registered` deref to reach it.
    ///
    /// It can also run while the device data is being dropped, when a data
    /// field releasing its objects triggers this hook. A hook that reaches
    /// device data through [`Device::data`] then observes partially-dropped
    /// data, so a driver must drop the objects a hook frees before the data
    /// fields that hook reads.
    ///
    /// For a [`RECLAIMABLE`] object, it can run in memory reclaim, when a
    /// shrinker drops the last reference. The hook then must not take a lock
    /// that is held while memory is allocated with reclaim allowed.
    ///
    /// [`RECLAIMABLE`]: Self::RECLAIMABLE
    /// [`dev()`]: crate::drm::gem::Object::dev
    /// [`Device::data`]: crate::drm::device::Device::data
    fn free(_obj: &DriverAllocImpl<Self>) {}

    /// Report the state of the object for fdinfo memory accounting.
    ///
    /// Called by `drm_show_memory_stats` while holding `file->table_lock`, so
    /// the implementation runs in atomic context and must not sleep, allocate,
    /// or acquire any locks.
    fn status(_obj: &DriverAllocImpl<Self>) -> ObjectStatus {
        ObjectStatus::empty()
    }

    /// Called when userspace exports the object to a dma-buf.
    ///
    /// Returning an error rejects the export. On success the object is
    /// exported through the default `drm_gem_prime_export()` path, or, for
    /// shmem-backed objects with [`Self::EXPORT_CPU_ACCESS_SYNC`] set, with
    /// CPU access synchronization.
    fn export(_obj: &DriverAllocImpl<Self>, _flags: c_int) -> Result {
        Ok(())
    }

    /// Called before a shmem-backed object is mapped into a userspace
    /// address space. Imported objects also reach this hook.
    ///
    /// The hook runs with the mmap lock held for writing. It may take the
    /// object's reservation lock and allocate with [`GFP_KERNEL`], but must
    /// not take the mmap lock or fault in user memory.
    ///
    /// Returning an error rejects the mapping. An [`EINTR`] or
    /// [`ERESTARTSYS`] error restarts the mmap(2) call instead.
    ///
    /// Objects that are not shmem-backed cannot be mapped and never reach
    /// this hook. The hook also does not run when fork, a VMA split or
    /// mremap duplicates an existing mapping.
    fn mmap(_obj: &DriverAllocImpl<Self>) -> Result {
        Ok(())
    }

    /// Called when a shmem-backed object with [`Self::RECLAIMABLE`] set gains
    /// or loses its pages, its pins, or its userspace mappings.
    ///
    /// The hook runs with the object's reservation lock held, and must not
    /// take that lock again.
    fn residency_changed(_guard: &ResvGuard<'_, DriverAllocImpl<Self>>) {}

    /// Whether dma-bufs exported from this driver's GEM objects synchronize
    /// CPU caches around CPU access.
    ///
    /// When `true`, dma-bufs exported from shmem-backed objects perform CPU
    /// cache maintenance on the exporter's and all importers' DMA mappings
    /// around CPU accesses, making `DMA_BUF_IOCTL_SYNC` work for buffers with
    /// cached CPU mappings. This also installs an import hook, so that
    /// self-imports of these exports still resolve to the original GEM
    /// object. Objects that are not shmem-backed ignore this constant and
    /// always use the default export path.
    const EXPORT_CPU_ACCESS_SYNC: bool = false;

    /// Whether the dumb-buffer creation ioctl is exposed for this driver's
    /// shmem-backed GEM objects.
    ///
    /// When `true`, `DRM_IOCTL_MODE_CREATE_DUMB` allocates a shmem object
    /// through the generic helper. Objects that are not shmem-backed ignore
    /// this constant.
    const EXPOSE_DUMB_CREATE: bool = true;

    /// Whether the pages of this driver's shmem-backed objects may be released
    /// while the objects are alive.
    ///
    /// When `true`, a userspace mapping does not hold the pages of an object.
    /// The first fault allocates them, and the object's scatter-gather table
    /// holds them. Objects that are not shmem-backed ignore this constant.
    const RECLAIMABLE: bool = false;
}

/// Trait that represents a GEM object subtype
pub trait IntoGEMObject: Sized + super::private::Sealed + AlwaysRefCounted {
    /// Returns a reference to the raw `drm_gem_object` structure, which must be valid as long as
    /// this owning object is valid.
    fn as_raw(&self) -> *mut bindings::drm_gem_object;

    /// Converts a pointer to a `struct drm_gem_object` into a reference to `Self`.
    ///
    /// # Safety
    ///
    /// - `self_ptr` must be a valid pointer to `Self`.
    /// - The caller promises that holding the immutable reference returned by this function does
    ///   not violate rust's data aliasing rules and remains valid throughout the lifetime of `'a`.
    unsafe fn from_raw<'a>(self_ptr: *mut bindings::drm_gem_object) -> &'a Self;
}

extern "C" fn open_callback<T: DriverObject>(
    raw_obj: *mut bindings::drm_gem_object,
    raw_file: *mut bindings::drm_file,
) -> core::ffi::c_int {
    // SAFETY: `open_callback` is only ever called with a valid pointer to a `struct drm_file`.
    let file = unsafe { DriverFile::<T>::from_raw(raw_file) };

    // SAFETY:
    // * `open_callback` is specified in the AllocOps structure for `DriverObject`, ensuring that
    //   `raw_obj` is contained within a `DriverAllocImpl<T>`
    // * It is only possible for `open_callback` to be called after device registration, ensuring
    //   that the object's device is in the `Registered` state.
    let obj: &DriverAllocImpl<T> = unsafe { IntoGEMObject::from_raw(raw_obj) };

    match T::open(obj, file) {
        Err(e) => e.to_errno(),
        Ok(()) => 0,
    }
}

extern "C" fn close_callback<T: DriverObject>(
    raw_obj: *mut bindings::drm_gem_object,
    raw_file: *mut bindings::drm_file,
) {
    // SAFETY: `open_callback` is only ever called with a valid pointer to a `struct drm_file`.
    let file = unsafe { DriverFile::<T>::from_raw(raw_file) };

    // SAFETY: `close_callback` is specified in the AllocOps structure for `Object<T>`, ensuring
    // that `raw_obj` is indeed contained within a `Object<T>`.
    let obj: &DriverAllocImpl<T> = unsafe { IntoGEMObject::from_raw(raw_obj) };

    T::close(obj, file);
}

pub(crate) extern "C" fn status_callback<T: DriverObject>(
    raw_obj: *mut bindings::drm_gem_object,
) -> bindings::drm_gem_object_status {
    // SAFETY: `status_callback` is installed in `OBJECT_FUNCS` (`drm_gem_object_funcs`) for
    // `Object<T>`, so `raw_obj` is always contained within an `Object<T>`.
    let obj: &DriverAllocImpl<T> = unsafe { IntoGEMObject::from_raw(raw_obj) };

    T::status(obj).as_raw()
}

extern "C" fn export_callback<T: DriverObject>(
    raw_obj: *mut bindings::drm_gem_object,
    flags: c_int,
) -> *mut bindings::dma_buf {
    // SAFETY:
    // * `export_callback` is specified in the AllocOps structure for `DriverObject`, ensuring
    //   that `raw_obj` is contained within a `DriverAllocImpl<T>`
    // * It is only possible for `export_callback` to be called after device registration,
    //   ensuring that the object's device is in the `Registered` state.
    let obj: &DriverAllocImpl<T> = unsafe { IntoGEMObject::from_raw(raw_obj) };

    match T::export(obj, flags) {
        // SAFETY: `raw_obj` is a valid GEM object (see above);
        // `drm_gem_prime_export()` is the default the DRM core uses when no
        // export hook is installed.
        Ok(()) => unsafe { bindings::drm_gem_prime_export(raw_obj, flags) },
        Err(e) => e.to_ptr(),
    }
}

impl<T: DriverObject, Ctx: DeviceContext> IntoGEMObject for Object<T, Ctx> {
    fn as_raw(&self) -> *mut bindings::drm_gem_object {
        self.obj.get()
    }

    unsafe fn from_raw<'a>(self_ptr: *mut bindings::drm_gem_object) -> &'a Self {
        // SAFETY: `obj` is guaranteed to be in an `Object<T>` via the safety contract of this
        // function
        unsafe { &*crate::container_of!(Opaque::cast_from(self_ptr), Object<T, Ctx>, obj) }
    }
}

/// Base operations shared by all GEM object classes
pub trait BaseObject: IntoGEMObject {
    /// Returns the size of the object in bytes.
    fn size(&self) -> usize {
        // SAFETY: `self.as_raw()` is guaranteed to be a pointer to a valid `struct drm_gem_object`.
        unsafe { (*self.as_raw()).size }
    }

    /// Returns whether the object's backing buffer is imported from another
    /// driver.
    fn is_imported(&self) -> bool {
        // SAFETY: `self.as_raw()` is guaranteed to be a pointer to a valid `struct drm_gem_object`.
        unsafe { bindings::drm_gem_is_imported(self.as_raw()) }
    }

    /// Returns whether the object holds a dma-buf reference.
    ///
    /// The reference is present when the object has been exported or imported
    /// through PRIME.
    fn has_dma_buf(&self) -> bool {
        // SAFETY: `self.as_raw()` is guaranteed to be a pointer to a valid `struct drm_gem_object`.
        !unsafe { (*self.as_raw()).dma_buf }.is_null()
    }

    /// Returns the current reference count of the object.
    fn refcount(&self) -> u32 {
        // SAFETY: `self.as_raw()` is guaranteed to be a pointer to a valid `struct drm_gem_object`,
        // whose `refcount` is initialized for its whole lifetime.
        unsafe { bindings::kref_read(&raw const (*self.as_raw()).refcount) }
    }

    /// Returns the object's global (flink) name, or `0` if it has none.
    fn global_name(&self) -> c_int {
        // SAFETY: `self.as_raw()` is guaranteed to be a pointer to a valid `struct drm_gem_object`.
        unsafe { (*self.as_raw()).name }
    }

    /// Returns the start of the object's fake mmap offset in page units.
    fn vma_node_start(&self) -> u64 {
        // SAFETY: `self.as_raw()` is guaranteed to be a pointer to a valid `struct drm_gem_object`,
        // whose `vma_node` is embedded and valid for the object's lifetime.
        unsafe { bindings::drm_vma_node_start(&raw const (*self.as_raw()).vma_node) as u64 }
    }

    /// Creates a new handle for the object associated with a given `File`
    /// (or returns an existing one).
    fn create_handle<D, F>(&self, file: &drm::File<F>) -> Result<u32>
    where
        Self: AllocImpl<Driver = D>,
        D: drm::Driver<Object<Registered> = Self, File = F>,
        F: drm::file::DriverFile<Driver = D>,
    {
        let mut handle: u32 = 0;
        // SAFETY: The arguments are all valid per the type invariants.
        to_result(unsafe {
            bindings::drm_gem_handle_create(file.as_raw().cast(), self.as_raw(), &mut handle)
        })?;
        Ok(handle)
    }

    /// Looks up an object by its handle for a given `File`.
    fn lookup_handle<D, F>(file: &drm::File<F>, handle: u32) -> Result<ARef<Self>>
    where
        Self: AllocImpl<Driver = D>,
        D: drm::Driver<Object<Registered> = Self, File = F>,
        F: drm::file::DriverFile<Driver = D>,
    {
        // SAFETY: The arguments are all valid per the type invariants.
        let ptr = unsafe { bindings::drm_gem_object_lookup(file.as_raw().cast(), handle) };
        if ptr.is_null() {
            return Err(ENOENT);
        }

        // SAFETY:
        // - A `drm::Driver` can only have a single `File` implementation.
        // - `file` uses the same `drm::Driver` as `Self`.
        // - Therefore, we're guaranteed that `ptr` must be a gem object embedded within `Self`.
        // - And we check if the pointer is null befoe calling from_raw(), ensuring that `ptr` is a
        //   valid pointer to an initialized `Self`.
        let obj = unsafe { Self::from_raw(ptr) };

        // SAFETY:
        // - We take ownership of the reference of `drm_gem_object_lookup()`.
        // - Our `NonNull` comes from an immutable reference, thus ensuring it is a valid pointer to
        //   `Self`.
        Ok(unsafe { ARef::from_raw(obj.into()) })
    }

    /// Creates an mmap offset to map the object from userspace.
    fn create_mmap_offset(&self) -> Result<u64> {
        // SAFETY: The arguments are valid per the type invariant.
        to_result(unsafe { bindings::drm_gem_create_mmap_offset(self.as_raw()) })?;

        // SAFETY: The arguments are valid per the type invariant.
        Ok(unsafe { bindings::drm_vma_node_offset_addr(&raw mut (*self.as_raw()).vma_node) })
    }

    /// Acquires the reservation lock of the object, sleeping until it is available.
    #[inline]
    fn lock_resv(&self) -> ResvGuard<'_, Self> {
        // SAFETY: The reservation object is valid for the lifetime of `self`. Without an acquire
        // context, `dma_resv_lock()` cannot fail.
        unsafe { bindings::dma_resv_lock(self.raw_dma_resv(), ptr::null_mut()) };

        // INVARIANT: The lock was acquired above.
        ResvGuard {
            obj: self,
            unlock: true,
            _not_send: NotThreadSafe,
        }
    }

    /// Acquires the reservation lock of the object, sleeping interruptibly until it is available.
    ///
    /// Returns [`EINTR`] if a signal interrupts the wait.
    #[inline]
    fn lock_resv_interruptible(&self) -> Result<ResvGuard<'_, Self>> {
        // SAFETY: The reservation object is valid for the lifetime of `self`.
        to_result(unsafe {
            bindings::dma_resv_lock_interruptible(self.raw_dma_resv(), ptr::null_mut())
        })?;

        // INVARIANT: The lock was acquired above.
        Ok(ResvGuard {
            obj: self,
            unlock: true,
            _not_send: NotThreadSafe,
        })
    }

    /// Tries to acquire the reservation lock of the object without sleeping.
    ///
    /// Returns `None` if the lock is already held.
    #[inline]
    fn try_lock_resv(&self) -> Option<ResvGuard<'_, Self>> {
        // SAFETY: The reservation object is valid for the lifetime of `self`.
        if !unsafe { bindings::dma_resv_trylock(self.raw_dma_resv()) } {
            return None;
        }

        // INVARIANT: The lock was acquired above.
        Some(ResvGuard {
            obj: self,
            unlock: true,
            _not_send: NotThreadSafe,
        })
    }
}

impl<T: IntoGEMObject> BaseObject for T {}

/// A guard that holds the reservation lock of a GEM object.
///
/// The lock is released when the guard is dropped.
///
/// # Invariants
///
/// The current thread holds the reservation lock of `obj` for the lifetime of the guard. If
/// `unlock` is set, nothing else releases the lock.
#[must_use = "the lock unlocks immediately when the guard is unused"]
pub struct ResvGuard<'a, O: IntoGEMObject> {
    obj: &'a O,
    /// Whether dropping the guard releases the lock.
    unlock: bool,
    _not_send: NotThreadSafe,
}

impl<'a, O: IntoGEMObject> ResvGuard<'a, O> {
    /// Creates a guard for a reservation lock that the caller already holds.
    ///
    /// Dropping the returned guard does not release the lock.
    ///
    /// # Safety
    ///
    /// The current thread holds the reservation lock of `obj` for `'a`, and no other guard of it
    /// is used while the returned guard exists.
    pub(crate) unsafe fn assume_locked(obj: &'a O) -> Self {
        // INVARIANT: The caller holds the lock for `'a`.
        Self {
            obj,
            unlock: false,
            _not_send: NotThreadSafe,
        }
    }

    /// Returns the object whose reservation lock is held.
    #[inline]
    pub fn obj(&self) -> &'a O {
        self.obj
    }
}

impl<O: IntoGEMObject> Drop for ResvGuard<'_, O> {
    #[inline]
    fn drop(&mut self) {
        if self.unlock {
            // SAFETY: By the type invariants, the current thread holds the lock, and nothing else
            // releases it.
            unsafe { bindings::dma_resv_unlock(self.obj.raw_dma_resv()) };
        }
    }
}

/// Data protected by the reservation lock of the GEM object that contains it.
///
/// A [`ResvLocked`] must be stored inline in a GEM object, for example in the driver's object
/// data. Access requires a [`ResvGuard`] of that object. A guard of any other object is rejected
/// with [`EINVAL`].
pub struct ResvLocked<T> {
    data: UnsafeCell<T>,
}

// SAFETY: `ResvLocked` serializes the interior mutability it provides with the reservation lock,
// so it is `Sync` as long as the data it protects is `Send`.
unsafe impl<T: Send> Sync for ResvLocked<T> {}

impl<T> ResvLocked<T> {
    /// Creates a new [`ResvLocked`] holding `data`.
    #[inline]
    pub const fn new(data: T) -> Self {
        Self {
            data: UnsafeCell::new(data),
        }
    }

    /// Returns a reference to the data, given a guard of the object that contains `self`.
    pub fn access<'a, O: IntoGEMObject>(&'a self, guard: &'a ResvGuard<'_, O>) -> Result<&'a T> {
        self.check_owner(guard.obj)?;

        // SAFETY: `self` lies within the object of `guard`, as checked above.
        Ok(unsafe { self.access_unchecked(guard) })
    }

    /// Returns a mutable reference to the data, given a guard of the object that contains `self`.
    pub fn access_mut<'a, O: IntoGEMObject>(
        &'a self,
        guard: &'a mut ResvGuard<'_, O>,
    ) -> Result<&'a mut T> {
        self.check_owner(guard.obj)?;

        // SAFETY: `self` lies within the object of `guard`, as checked above.
        Ok(unsafe { self.access_unchecked_mut(guard) })
    }

    /// Returns a reference to the data without checking the object of the guard.
    ///
    /// # Safety
    ///
    /// `self` lies within the object of the guard.
    #[inline]
    pub(crate) unsafe fn access_unchecked<'a, O: IntoGEMObject>(
        &'a self,
        _guard: &'a ResvGuard<'_, O>,
    ) -> &'a T {
        // SAFETY: Per the safety requirements, the guard holds the reservation lock of the object
        // that contains `self`. Mutable access needs a mutable borrow of that guard, so the data
        // is not mutated while the returned reference exists.
        unsafe { &*self.data.get() }
    }

    /// Returns a mutable reference to the data without checking the object of the guard.
    ///
    /// # Safety
    ///
    /// `self` lies within the object of the guard.
    #[inline]
    pub(crate) unsafe fn access_unchecked_mut<'a, O: IntoGEMObject>(
        &'a self,
        _guard: &'a mut ResvGuard<'_, O>,
    ) -> &'a mut T {
        // SAFETY: Per the safety requirements, the guard holds the reservation lock of the object
        // that contains `self`, and is mutably borrowed for the lifetime of the returned
        // reference, so no other reference to the data exists.
        unsafe { &mut *self.data.get() }
    }

    /// Returns a mutable reference to the data.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Checks that `self` lies within `obj`.
    fn check_owner<O>(&self, obj: &O) -> Result {
        let end = ptr::from_ref(self)
            .addr()
            .checked_sub(ptr::from_ref(obj).addr())
            .and_then(|offset| offset.checked_add(size_of::<Self>()));

        match end {
            Some(end) if end <= size_of::<O>() => Ok(()),
            _ => Err(EINVAL),
        }
    }
}

/// Crate-private base operations shared by all GEM object classes.
pub(crate) trait BaseObjectPrivate: IntoGEMObject {
    /// Return a pointer to this object's dma_resv.
    fn raw_dma_resv(&self) -> *mut bindings::dma_resv {
        // SAFETY: `self.as_raw()` always returns a valid pointer to the base DRM GEM object.
        unsafe { (*self.as_raw()).resv }
    }
}

impl<T: IntoGEMObject> BaseObjectPrivate for T {}

/// A base GEM object.
///
/// # Invariants
///
/// * `self.obj` is a valid instance of a `struct drm_gem_object`.
/// * Any type invariants of `Ctx` apply to the parent DRM device for this GEM object.
#[repr(C)]
#[pin_data]
pub struct Object<T: DriverObject + Send + Sync, Ctx: DeviceContext = Registered> {
    obj: Opaque<bindings::drm_gem_object>,
    #[pin]
    data: T,
    _ctx: PhantomData<Ctx>,
}

impl<T: DriverObject, Ctx: DeviceContext> Object<T, Ctx> {
    const OBJECT_FUNCS: bindings::drm_gem_object_funcs = bindings::drm_gem_object_funcs {
        free: Some(Self::free_callback),
        open: Some(open_callback::<T>),
        close: Some(close_callback::<T>),
        print_info: None,
        export: Some(export_callback::<T>),
        pin: None,
        unpin: None,
        get_sg_table: None,
        vmap: None,
        vunmap: None,
        mmap: None,
        status: Some(status_callback::<T>),
        vm_ops: core::ptr::null_mut(),
        evict: None,
        rss: None,
    };

    /// Create a new GEM object.
    pub fn new(
        dev: &drm::Device<T::Driver, Ctx>,
        size: usize,
        args: T::Args,
    ) -> Result<ARef<Self>> {
        let obj: Pin<KBox<Self>> = KBox::pin_init(
            try_pin_init!(Self {
                obj: Opaque::new(bindings::drm_gem_object::default()),
                data <- T::new(dev, size, args),
                _ctx: PhantomData,
            }),
            GFP_KERNEL,
        )?;

        // SAFETY: `obj.as_raw()` is guaranteed to be valid by the initialization above.
        unsafe { (*obj.as_raw()).funcs = &Self::OBJECT_FUNCS };

        // SAFETY: The arguments are all valid per the type invariants.
        // INVARIANT: `dev` and the GEM object are in the same state at the moment, and upgrading
        // the typestate in `dev` will not carry over to the GEM object.
        to_result(unsafe { bindings::drm_gem_object_init(dev.as_raw(), obj.obj.get(), size) })?;

        // SAFETY: We will never move out of `Self` as `ARef<Self>` is always treated as pinned.
        let ptr = KBox::into_raw(unsafe { Pin::into_inner_unchecked(obj) });

        // SAFETY: `ptr` comes from `KBox::into_raw` and hence can't be NULL.
        let ptr = unsafe { NonNull::new_unchecked(ptr) };

        // SAFETY: We take over the initial reference count from `drm_gem_object_init()`.
        Ok(unsafe { ARef::from_raw(ptr) })
    }

    /// Returns the `Device` that owns this GEM object.
    pub fn dev(&self) -> &drm::Device<T::Driver, Ctx> {
        // SAFETY:
        // - `struct drm_gem_object.dev` is initialized and valid for as long as the GEM
        //   object lives.
        // - The device we used for creating the gem object is passed as &drm::Device<T::Driver> to
        //   Object::<T>::new(), so we know that `T::Driver` is the right generic parameter to use
        //   here.
        // - Any type invariants of `Ctx` are upheld by using the same `Ctx` for the `Device` we
        //   return.
        unsafe { drm::Device::from_raw((*self.as_raw()).dev) }
    }

    fn as_raw(&self) -> *mut bindings::drm_gem_object {
        self.obj.get()
    }

    extern "C" fn free_callback(obj: *mut bindings::drm_gem_object) {
        // Notify the driver before any teardown, while the object is still valid.
        // SAFETY: The core passes a valid gem object contained in a `DriverAllocImpl<T>`.
        let driver_obj: &DriverAllocImpl<T> = unsafe { IntoGEMObject::from_raw(obj) };
        T::free(driver_obj);

        let ptr: *mut Opaque<bindings::drm_gem_object> = obj.cast();

        // SAFETY: All of our objects are of type `Object<T>`.
        let this = unsafe { crate::container_of!(ptr, Self, obj) };

        // SAFETY: The C code only ever calls this callback with a valid pointer to a `struct
        // drm_gem_object`.
        unsafe { bindings::drm_gem_object_release(obj) };

        // SAFETY: All of our objects are allocated via `KBox`, and we're in the
        // free callback which guarantees this object has zero remaining references,
        // so we can drop it.
        let _ = unsafe { KBox::from_raw(this) };
    }
}

impl_aref_for_gem_obj!(impl<T, Ctx> for Object<T, Ctx> where T: DriverObject, Ctx: DeviceContext);

impl<T: DriverObject, Ctx: DeviceContext> super::private::Sealed for Object<T, Ctx> {}

impl<T: DriverObject, Ctx: DeviceContext> Deref for Object<T, Ctx> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: DriverObject, Ctx: DeviceContext> AllocImpl for Object<T, Ctx> {
    type Driver = T::Driver;

    const ALLOC_OPS: AllocOps = AllocOps {
        gem_create_object: None,
        prime_handle_to_fd: None,
        prime_fd_to_handle: None,
        gem_prime_import: None,
        gem_prime_import_sg_table: None,
        dumb_create: None,
        dumb_map_offset: None,
    };
}

pub(super) const fn create_fops(owner: *mut bindings::module) -> bindings::file_operations {
    let mut fops: bindings::file_operations = pin_init::zeroed();

    fops.owner = owner;
    fops.open = Some(bindings::drm_open);
    fops.release = Some(bindings::drm_release);
    fops.unlocked_ioctl = Some(bindings::drm_ioctl);
    #[cfg(CONFIG_COMPAT)]
    {
        fops.compat_ioctl = Some(bindings::drm_compat_ioctl);
    }
    fops.poll = Some(bindings::drm_poll);
    fops.read = Some(bindings::drm_read);
    fops.llseek = Some(bindings::noop_llseek);
    #[cfg(CONFIG_MMU)]
    {
        fops.get_unmapped_area = Some(bindings::drm_gem_get_unmapped_area);
    }
    fops.mmap = Some(bindings::drm_gem_mmap);
    fops.fop_flags = bindings::FOP_UNSIGNED_OFFSET;

    fops
}
