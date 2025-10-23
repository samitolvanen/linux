// SPDX-License-Identifier: GPL-2.0

//! DRM GEM shmem helper objects
//!
//! C header: [`include/linux/drm/drm_gem_shmem_helper.h`](srctree/include/linux/drm/drm_gem_shmem_helper.h)

// TODO:
// - There are a number of spots here that manually acquire/release the DMA reservation lock using
//   dma_resv_(un)lock(). In the future we should add support for ww mutex, expose a method to
//   acquire a reference to the WwMutex, and then use that directly instead of the C functions here.

use crate::{
    container_of,
    drm::{device, driver, gem, private::Sealed},
    error::{from_err_ptr, to_result},
    iosys_map::*,
    prelude::*,
    scatterlist,
    transmute::*,
    types::{ARef, Opaque},
};
use core::{
    mem::{self, MaybeUninit},
    ops::{Deref, DerefMut},
    ptr::NonNull,
};
use gem::{BaseObject, BaseObjectPrivate, DriverObject, IntoGEMObject};

/// A struct for controlling the creation of shmem-backed GEM objects.
///
/// This is used with [`Object::new()`] to control various properties that can only be set when
/// initially creating a shmem-backed GEM object.
#[derive(Default)]
pub struct ObjectConfig<'a, T: DriverObject> {
    /// Whether to set the write-combine map flag.
    pub map_wc: bool,

    /// Reuse the DMA reservation from another GEM object.
    ///
    /// The newly created [`Object`] will hold an owned refcount to `parent_resv_obj` if specified.
    pub parent_resv_obj: Option<&'a Object<T>>,
}

/// A shmem-backed GEM object.
///
/// # Invariants
///
/// `obj` contains a valid initialized `struct drm_gem_shmem_object` for the lifetime of this
/// object.
#[repr(C)]
#[pin_data]
pub struct Object<T: DriverObject> {
    #[pin]
    obj: Opaque<bindings::drm_gem_shmem_object>,
    // Parent object that owns this object's DMA reservation object
    parent_resv_obj: Option<ARef<Object<T>>>,
    #[pin]
    inner: T,
}

super::impl_aref_for_gem_obj!(impl<T> for Object<T> where T: DriverObject);

impl<T: DriverObject> Object<T> {
    /// `drm_gem_object_funcs` vtable suitable for GEM shmem objects.
    const VTABLE: bindings::drm_gem_object_funcs = bindings::drm_gem_object_funcs {
        free: Some(Self::free_callback),
        open: Some(super::open_callback::<T>),
        close: Some(super::close_callback::<T>),
        print_info: Some(bindings::drm_gem_shmem_object_print_info),
        export: None,
        pin: Some(bindings::drm_gem_shmem_object_pin),
        unpin: Some(bindings::drm_gem_shmem_object_unpin),
        get_sg_table: Some(bindings::drm_gem_shmem_object_get_sg_table),
        vmap: Some(bindings::drm_gem_shmem_object_vmap),
        vunmap: Some(bindings::drm_gem_shmem_object_vunmap),
        mmap: Some(bindings::drm_gem_shmem_object_mmap),
        status: None,
        rss: None,
        // SAFETY: `drm_gem_shmem_vm_ops` is static const on the C side, so immutable references are
        // safe here and such references shall be valid forever
        vm_ops: unsafe { &bindings::drm_gem_shmem_vm_ops },
        evict: None,
    };

    /// Return a raw pointer to the embedded drm_gem_shmem_object.
    fn as_shmem(&self) -> *mut bindings::drm_gem_shmem_object {
        self.obj.get()
    }

    /// Create a new shmem-backed DRM object of the given size.
    ///
    /// Additional config options can be specified using `config`.
    pub fn new(
        dev: &device::Device<T::Driver>,
        size: usize,
        config: ObjectConfig<'_, T>,
        args: T::Args,
    ) -> Result<ARef<Self>> {
        let new: Pin<KBox<Self>> = KBox::try_pin_init(
            try_pin_init!(Self {
                obj <- Opaque::init_zeroed(),
                parent_resv_obj: config.parent_resv_obj.map(|p| p.into()),
                inner <- T::new(dev, size, args),
            }),
            GFP_KERNEL,
        )?;

        // SAFETY: `obj.as_raw()` is guaranteed to be valid by the initialization above.
        unsafe { (*new.as_raw()).funcs = &Self::VTABLE };

        // SAFETY: The arguments are all valid via the type invariants.
        to_result(unsafe { bindings::drm_gem_shmem_init(dev.as_raw(), new.as_shmem(), size) })?;

        // SAFETY: We never move out of `self`.
        let new = KBox::into_raw(unsafe { Pin::into_inner_unchecked(new) });

        // SAFETY: We're taking over the owned refcount from `drm_gem_shmem_init`.
        let obj = unsafe { ARef::from_raw(NonNull::new_unchecked(new)) };

        // Start filling out values from `config`
        if let Some(parent_resv) = config.parent_resv_obj {
            // SAFETY: We have yet to expose the new gem object outside of this function, so it is
            // safe to modify this field.
            unsafe { (*obj.obj.get()).base.resv = parent_resv.raw_dma_resv() };
        }

        // SAFETY: We have yet to expose this object outside of this function, so we're guaranteed
        // to have exclusive access - thus making this safe to hold a mutable reference to.
        let shmem = unsafe { &mut *obj.as_shmem() };
        shmem.set_map_wc(config.map_wc);

        Ok(obj)
    }

    /// Returns the `Device` that owns this GEM object.
    pub fn dev(&self) -> &device::Device<T::Driver> {
        // SAFETY: `dev` will have been initialized in `Self::new()` by `drm_gem_shmem_init()`.
        unsafe { device::Device::from_raw((*self.as_raw()).dev) }
    }

    extern "C" fn free_callback(obj: *mut bindings::drm_gem_object) {
        // SAFETY:
        // - DRM always passes a valid gem object here
        // - We used drm_gem_shmem_create() in our create_gem_object callback, so we know that
        //   `obj` is contained within a drm_gem_shmem_object
        let this = unsafe { container_of!(obj, bindings::drm_gem_shmem_object, base) };

        // SAFETY:
        // - We're in free_callback - so this function is safe to call.
        // - We won't be using the gem resources on `this` after this call.
        unsafe { bindings::drm_gem_shmem_release(this) };

        // SAFETY:
        // - We verified above that `obj` is valid, which makes `this` valid
        // - This function is set in AllocOps, so we know that `this` is contained within a
        //   `Object<T>`
        let this = unsafe { container_of!(Opaque::cast_from(this), Self, obj) }.cast_mut();

        // SAFETY: We're recovering the Kbox<> we created in gem_create_object()
        let _ = unsafe { KBox::from_raw(this) };
    }

    /// Creates (if necessary) and returns an immutable reference to a scatter-gather table of DMA
    /// pages for this object.
    ///
    /// This will pin the object in memory.
    #[inline]
    pub fn sg_table(&self) -> Result<&scatterlist::SGTable> {
        // SAFETY:
        // - drm_gem_shmem_get_pages_sgt is thread-safe.
        // - drm_gem_shmem_get_pages_sgt returns either a valid pointer to a scatterlist, or an
        //   error pointer.
        let sgt = from_err_ptr(unsafe { bindings::drm_gem_shmem_get_pages_sgt(self.as_shmem()) })?;

        // SAFETY: We checked above that `sgt` is not an error pointer, so it must be a valid
        // pointer to a scatterlist
        Ok(unsafe { scatterlist::SGTable::from_raw(sgt) })
    }

    /// Creates (if necessary) and returns an owned reference to a scatter-gather table of DMA pages
    /// for this object.
    ///
    /// This is the same as [`sg_table`](Self::sg_table), except that it instead returns an
    /// [`shmem::SGTable`] which holds a reference to the associated gem object, instead of a
    /// reference to an [`scatterlist::SGTable`].
    ///
    /// This will pin the object in memory.
    ///
    /// [`shmem::SGTable`]: SGTable
    pub fn owned_sg_table(&self) -> Result<SGTable<T>> {
        Ok(SGTable {
            sgt: self.sg_table()?.into(),
            // INVARIANT: We take an owned refcount to `self` here, ensuring that `sgt` remains
            // valid for as long as this `SGTable`.
            _owner: self.into(),
        })
    }

    /// Attempt to create a [`RawIoSysMap`] from the gem object.
    fn raw_vmap<U: AsBytes + FromBytes>(&self) -> Result<RawIoSysMap<U>> {
        build_assert!(
            mem::size_of::<U>() > 0,
            "It doesn't make sense for the mapping type to be a ZST"
        );

        let mut map: MaybeUninit<bindings::iosys_map> = MaybeUninit::uninit();

        // SAFETY: drm_gem_shmem_vmap can be called with the DMA reservation lock held
        to_result(unsafe {
            // TODO: see top of file
            bindings::dma_resv_lock(self.raw_dma_resv(), core::ptr::null_mut());
            let ret = bindings::drm_gem_shmem_vmap_locked(self.as_shmem(), map.as_mut_ptr());
            bindings::dma_resv_unlock(self.raw_dma_resv());
            ret
        })?;

        // SAFETY: if drm_gem_shmem_vmap did not fail, map is initialized now
        Ok(unsafe { RawIoSysMap::from_raw(map.assume_init()) })
    }

    /// Unmap a [`RawIoSysMap`] from the gem object.
    ///
    /// # Safety
    ///
    /// - The caller promises that `map` came from a prior call to [`Self::raw_vmap`] on this gem
    ///   object.
    /// - The caller promises that the memory pointed to by `map` will no longer be accesed through
    ///   this instance.
    unsafe fn raw_vunmap<U: AsBytes + FromBytes>(&self, map: &mut RawIoSysMap<U>) {
        let resv = self.raw_dma_resv();

        // SAFETY:
        // - This function is safe to call with the DMA reservation lock held
        // - Our `ARef` is proof that the underlying gem object here is initialized and thus safe to
        //   dereference.
        unsafe {
            // TODO: see top of file
            bindings::dma_resv_lock(resv, core::ptr::null_mut());
            bindings::drm_gem_shmem_vunmap_locked(self.as_shmem(), map.as_raw_mut());
            bindings::dma_resv_unlock(resv);
        }
    }

    /// Creates and returns a virtual kernel memory mapping for this object.
    pub fn vmap<U: AsBytes + FromBytes>(&self) -> Result<VMapRef<'_, T, U>> {
        let map = self.raw_vmap()?;

        Ok(VMapRef {
            // SAFETY:
            // - The size of the vmap is the same as the size of the gem
            // - The vmap will remain alive until this object is dropped.
            map: unsafe { IoSysMapRef::new(map, self.size()) },
            owner: self,
        })
    }

    /// Creates and returns an owned reference to a virtual kernel memory mapping for this object.
    pub fn owned_vmap<U: AsBytes + FromBytes>(&self) -> Result<VMap<T, U>> {
        Ok(VMap {
            map: self.raw_vmap()?,
            owner: self.into(),
        })
    }
}

impl<T: DriverObject> Deref for Object<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: DriverObject> DerefMut for Object<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: DriverObject> Sealed for Object<T> {}

impl<T: DriverObject> gem::IntoGEMObject for Object<T> {
    fn as_raw(&self) -> *mut bindings::drm_gem_object {
        // SAFETY:
        // - Our immutable reference is proof that this is safe to dereference.
        // - `obj` is always a valid drm_gem_shmem_object via our type invariants.
        unsafe { &raw mut (*self.obj.get()).base }
    }

    unsafe fn from_raw<'a>(obj: *mut bindings::drm_gem_object) -> &'a Object<T> {
        // SAFETY: The safety contract of from_gem_obj() guarantees that `obj` is contained within
        // `Self`
        unsafe {
            let obj = Opaque::cast_from(container_of!(obj, bindings::drm_gem_shmem_object, base));

            &*container_of!(obj, Object<T>, obj)
        }
    }
}

impl<T: DriverObject> driver::AllocImpl for Object<T> {
    type Driver = T::Driver;

    const ALLOC_OPS: driver::AllocOps = driver::AllocOps {
        gem_create_object: None,
        prime_handle_to_fd: None,
        prime_fd_to_handle: None,
        gem_prime_import: None,
        gem_prime_import_sg_table: Some(bindings::drm_gem_shmem_prime_import_sg_table),
        dumb_create: Some(bindings::drm_gem_shmem_dumb_create),
        dumb_map_offset: None,
    };
}

/// A borrowed reference to a virtual mapping for a shmem-based GEM object in kernel address space.
pub struct VMapRef<'a, D: DriverObject, T: AsBytes + FromBytes> {
    map: IoSysMapRef<'a, T>,
    owner: &'a Object<D>,
}

impl<'a, D: DriverObject, T: AsBytes + FromBytes> Clone for VMapRef<'a, D, T> {
    fn clone(&self) -> Self {
        // SAFETY: We have a successful vmap already, so this can't fail
        unsafe { self.owner.vmap().unwrap_unchecked() }
    }
}

impl<'a, D: DriverObject, T: AsBytes + FromBytes> Deref for VMapRef<'a, D, T> {
    type Target = IoSysMapRef<'a, T>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<'a, D: DriverObject, T: AsBytes + FromBytes> DerefMut for VMapRef<'a, D, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

impl<'a, D: DriverObject, T: AsBytes + FromBytes> Drop for VMapRef<'a, D, T> {
    fn drop(&mut self) {
        // SAFETY: Our existence is proof that this map was previously created using self.owner.
        unsafe { self.owner.raw_vunmap(&mut self.map) };
    }
}

/// An owned reference to a virtual mapping for a shmem-based GEM object in kernel address space.
///
/// # Invariants
///
/// - The memory pointed to by `map` is at least as large as `T`.
/// - The memory pointed to by `map` remains valid at least until this object is dropped.
pub struct VMap<D: DriverObject, T: AsBytes + FromBytes> {
    map: RawIoSysMap<T>,
    owner: ARef<Object<D>>,
}

impl<D: DriverObject, T: AsBytes + FromBytes> Clone for VMap<D, T> {
    fn clone(&self) -> Self {
        // SAFETY: We have a successful vmap already, so this can't fail
        unsafe { self.owner.owned_vmap().unwrap_unchecked() }
    }
}

impl<'a, D: DriverObject, T: AsBytes + FromBytes> From<VMapRef<'a, D, T>> for VMap<D, T> {
    fn from(value: VMapRef<'a, D, T>) -> Self {
        let this = Self {
            map: value.map.clone(),
            owner: value.owner.into(),
        };

        mem::forget(value);
        this
    }
}

impl<D: DriverObject, T: AsBytes + FromBytes> VMap<D, T> {
    /// Return a reference to the iosys map for this `VMap`.
    pub fn get(&self) -> IoSysMapRef<'_, T> {
        // SAFETY: The size of the iosys_map is equivalent to the size of the gem object.
        unsafe { IoSysMapRef::new(self.map.clone(), self.owner.size()) }
    }

    /// Borrows a reference to the object that owns this virtual mapping.
    pub fn owner(&self) -> &Object<D> {
        &self.owner
    }
}

impl<D: DriverObject, T: AsBytes + FromBytes> Drop for VMap<D, T> {
    fn drop(&mut self) {
        // SAFETY: Our existence is proof that this map was previously created using self.owner
        unsafe { self.owner.raw_vunmap(&mut self.map) };
    }
}

/// SAFETY: `iosys_map` objects are safe to send across threads.
unsafe impl<D: DriverObject, T: AsBytes + FromBytes> Send for VMap<D, T> {}
/// SAFETY: `iosys_map` objects are safe to send across threads.
unsafe impl<D: DriverObject, T: AsBytes + FromBytes> Sync for VMap<D, T> {}

/// An owned reference to a scatter-gather table of DMA address spans for a GEM shmem object.
///
/// This object holds an owned reference to the underlying GEM shmem object, ensuring that the
/// [`scatterlist::SGTable`] referenced by this type remains valid for the lifetime of this object.
///
/// # Invariants
///
/// - `sgt` is kept alive by `_owner`, ensuring it remains valid for as long as `Self`.
/// - `sgt` corresponds to the owned object in `_owner`.
/// - This object is only exposed in situations where we know the underlying `SGTable` will not be
///   modified for the lifetime of this object. Thus, it is safe to send/access this type across
///   threads.
pub struct SGTable<T: DriverObject> {
    sgt: NonNull<scatterlist::SGTable>,
    _owner: ARef<Object<T>>,
}

// SAFETY: This object is thread-safe via our type invariants.
unsafe impl<T: DriverObject> Send for SGTable<T> {}
// SAFETY: This object is thread-safe via our type invariants.
unsafe impl<T: DriverObject> Sync for SGTable<T> {}

impl<T: DriverObject> Deref for SGTable<T> {
    type Target = scatterlist::SGTable;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Creating an immutable reference to this is safe via our type invariants.
        unsafe { self.sgt.as_ref() }
    }
}
