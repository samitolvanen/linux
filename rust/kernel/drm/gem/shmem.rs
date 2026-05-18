// SPDX-License-Identifier: GPL-2.0

//! DRM GEM shmem helper objects
//!
//! C header: [`include/linux/drm/drm_gem_shmem_helper.h`](srctree/include/drm/drm_gem_shmem_helper.h)

// TODO:
// - There are a number of spots here that manually acquire/release the DMA reservation lock using
//   dma_resv_(un)lock(). In the future we should add support for ww mutex, expose a method to
//   acquire a reference to the WwMutex, and then use that directly instead of the C functions here.

use crate::{
    container_of,
    device::{
        self,
        Bound, //
    },
    devres::*,
    drm::{
        driver,
        gem,
        private::Sealed,
        Device,
        DeviceContext, //
    },
    error::{
        from_err_ptr,
        to_result, //
    },
    io::{
        Io,
        IoCapable,
        IoKnownSize, //
    },
    prelude::*,
    scatterlist,
    sync::aref::ARef,
    types::Opaque, //
};
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    mem::{
        self,
        MaybeUninit, //
    },
    ops::{
        Deref,
        DerefMut, //
    },
    ptr::{
        self,
        NonNull, //
    },
};
use gem::{
    BaseObject,
    BaseObjectPrivate,
    DriverObject,
    IntoGEMObject, //
};

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
    /// Embedded `drm_gem_shmem_object`.
    ///
    /// Must remain the first field so the allocation address coincides with the embedded
    /// `drm_gem_shmem_object`. The DRM shmem helper's `__drm_gem_shmem_create()` error path calls
    /// `kfree()` on the returned `drm_gem_object` pointer, which is only sound when it points at
    /// the start of the allocation.
    #[pin]
    obj: Opaque<bindings::drm_gem_shmem_object>,
    /// Devres object for unmapping any SGTable on driver-unbind.
    ///
    /// This is protected by the object's dma_resv lock. `Opaque<drm_gem_shmem_object>` has no
    /// `Drop`, so declaring `obj` first does not affect the SGTable teardown order: the
    /// underlying memory remains valid until the whole [`Object`] allocation is freed.
    sgt_res: UnsafeCell<Option<Devres<SGTableMap<T>>>>,
    /// Parent object that owns this object's DMA reservation object.
    parent_resv_obj: Option<ARef<Object<T>>>,
    #[pin]
    inner: T,
}

super::impl_aref_for_gem_obj!(impl<T> for Object<T> where T: DriverObject);

// SAFETY: All GEM objects are thread-safe.
unsafe impl<T: DriverObject> Send for Object<T> {}

// SAFETY: All GEM objects are thread-safe.
unsafe impl<T: DriverObject> Sync for Object<T> {}

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
        #[allow(unused_unsafe, reason = "Safe since Rust 1.82.0")]
        // SAFETY: `drm_gem_shmem_vm_ops` is a valid, static const on the C side.
        vm_ops: unsafe { &raw const bindings::drm_gem_shmem_vm_ops },
        evict: None,
    };

    /// Return a raw pointer to the embedded drm_gem_shmem_object.
    fn as_raw_shmem(&self) -> *mut bindings::drm_gem_shmem_object {
        self.obj.get()
    }

    /// Create a new shmem-backed DRM object of the given size.
    ///
    /// Additional config options can be specified using `config`.
    pub fn new<Ctx: DeviceContext>(
        dev: &Device<T::Driver, Ctx>,
        size: usize,
        config: ObjectConfig<'_, T>,
        args: T::Args,
    ) -> Result<ARef<Self>> {
        let new: Pin<KBox<Self>> = KBox::try_pin_init(
            try_pin_init!(Self {
                obj <- Opaque::init_zeroed(),
                parent_resv_obj: config.parent_resv_obj.map(|p| p.into()),
                sgt_res: UnsafeCell::new(None),
                inner <- T::new(dev, size, args),
            }),
            GFP_KERNEL,
        )?;

        // SAFETY: `obj.as_raw()` is guaranteed to be valid by the initialization above.
        unsafe { (*new.as_raw()).funcs = &Self::VTABLE };

        // SAFETY: The arguments are all valid via the type invariants.
        to_result(unsafe { bindings::drm_gem_shmem_init(dev.as_raw(), new.as_raw_shmem(), size) })?;

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
        let shmem = unsafe { &mut *obj.as_raw_shmem() };
        shmem.set_map_wc(config.map_wc);

        Ok(obj)
    }

    /// Returns the `Device` that owns this GEM object.
    pub fn dev(&self) -> &Device<T::Driver> {
        // SAFETY: `dev` will have been initialized in `Self::new()` by `drm_gem_shmem_init()`.
        unsafe { Device::from_raw((*self.as_raw()).dev) }
    }

    /// Allocates the full [`Object<T>`] wrapper and zero-initialises the embedded shmem object;
    /// the helper's `__drm_gem_shmem_init` fills it in after we return.
    extern "C" fn gem_create_object_callback(
        raw_dev: *mut bindings::drm_device,
        size: usize,
    ) -> *mut bindings::drm_gem_object {
        const_assert!(
            core::mem::offset_of!(Self, obj) == 0,
            "Object<T>::obj must be at offset 0 so drm_gem_shmem_helper's kfree(obj) error path \
             frees the wrapper allocation, not the middle of it"
        );

        // SAFETY: The DRM shmem helper only invokes this callback for a registered DRM device of
        // type `T::Driver`, which is `Self`'s driver per the `AllocImpl` impl below.
        let dev: &Device<T::Driver> = unsafe { Device::from_raw(raw_dev) };

        let new: Pin<KBox<Self>> = match KBox::try_pin_init(
            try_pin_init!(Self {
                obj <- Opaque::init_zeroed(),
                parent_resv_obj: None,
                sgt_res: UnsafeCell::new(None),
                inner <- T::create_imported(dev, size),
            }),
            GFP_KERNEL,
        ) {
            Ok(new) => new,
            Err(e) => return e.to_ptr(),
        };

        // SAFETY: `new.as_raw()` is guaranteed to be valid by the initialization above.
        unsafe { (*new.as_raw()).funcs = &Self::VTABLE };

        // SAFETY: We never move out of `self`; ownership of the allocation is transferred to the
        // C side, which will run `__drm_gem_shmem_init()` next and later free us via
        // `free_callback` (or `kfree()` on the `__drm_gem_shmem_init()` error path, matching the
        // C kzalloc fallback contract).
        let new = KBox::into_raw(unsafe { Pin::into_inner_unchecked(new) });

        // SAFETY: `new` was just produced by `KBox::into_raw` and so is a valid pointer to an
        // initialized `Self`; `obj.base` is the embedded `drm_gem_object` the caller expects.
        unsafe { &raw mut (*(*new).obj.get()).base }
    }

    extern "C" fn free_callback(obj: *mut bindings::drm_gem_object) {
        // SAFETY:
        // - DRM always passes a valid gem object here
        // - We used drm_gem_shmem_create() in our create_gem_object callback, so we know that
        //   `obj` is contained within a drm_gem_shmem_object
        let this = unsafe { container_of!(obj, bindings::drm_gem_shmem_object, base) };

        // SAFETY:
        // - We verified above that `obj` is valid, which makes `this` valid.
        // - This function is set in AllocOps, so we know that `this` is contained within an
        //   `Object<T>`.
        let rust_this = unsafe { container_of!(Opaque::cast_from(this), Self, obj) }.cast_mut();

        // Drop any SGTableMap before calling drm_gem_shmem_release(). Otherwise the release path
        // can clear `shmem->sgt` first, and the subsequent SGTableMap drop will try to free it a
        // second time.
        // SAFETY: `free_callback()` runs when the last GEM reference is dropped, so we have
        // exclusive access to the object state while taking the optional devres out.
        let sgt_res = unsafe { (*(*rust_this).sgt_res.get()).take() };
        drop(sgt_res);

        // SAFETY:
        // - We're in free_callback - so this function is safe to call.
        // - We won't be using the gem resources on `this` after this call.
        unsafe { bindings::drm_gem_shmem_release(this) };

        // SAFETY: We're recovering the Kbox<> we created in gem_create_object()
        let _ = unsafe { KBox::from_raw(rust_this) };
    }

    // If necessary, create an SGTable for the gem object and register a Devres for it to ensure
    // that it is unmapped on driver unbind.
    fn get_sg_table<'a>(
        &'a self,
        dev: &'a device::Device<Bound>,
    ) -> Result<&'a Devres<SGTableMap<T>>> {
        let sgt_res_ptr = self.sgt_res.get();

        // SAFETY: This lock is initialized throughout the lifetime of the gem object
        unsafe { bindings::dma_resv_lock(self.raw_dma_resv(), ptr::null_mut()) };

        // SAFETY: We just grabbed the lock required for reading this data above.
        let sgt_res = unsafe { (*sgt_res_ptr).as_ref() };

        let ret = if let Some(sgt_res) = sgt_res {
            pr_err!("shmem DBG get_sg_table: CACHED path\n");
            // We already have a Devres object for this sg table, return it
            Ok(sgt_res)
        } else {
            pr_err!(
                "shmem DBG get_sg_table: COLD path -> calling drm_gem_shmem_get_pages_sgt_locked\n"
            );
            // SAFETY: We grabbed the lock required for calling this function above */
            let sgt = from_err_ptr(unsafe {
                bindings::drm_gem_shmem_get_pages_sgt_locked(self.as_raw_shmem())
            });

            if let Err(e) = &sgt {
                pr_err!(
                    "shmem DBG get_sg_table: COLD path get_pages_sgt_locked FAIL err={:?}\n",
                    e,
                );
            } else {
                pr_err!("shmem DBG get_sg_table: COLD path get_pages_sgt_locked OK\n");
            }

            if let Err(e) = sgt {
                Err(e)
            } else {
                // INVARIANT:
                // - We called drm_gem_shmem_get_pages_sgt_locked above and checked that it
                //   succeeded, fulfilling the invariant of SGTableRef that the object's `sgt` field
                //   is initialized.
                // - We store this Devres in the object itself and don't move it, ensuring that the
                //   object it points to remains valid for the lifetime of the SGTableRef.
                let devres = Devres::new(dev, init!(SGTableMap { obj: self.into() }));
                match devres {
                    Ok(devres) => {
                        pr_err!("shmem DBG get_sg_table: COLD path Devres::new OK\n");
                        // SAFETY: We acquired the lock protecting this data above, making it safe
                        // to write into here
                        unsafe { (*sgt_res_ptr) = Some(devres) };

                        // SAFETY: We just write Some() into *sgt_res_ptr above
                        Ok(unsafe { (&*sgt_res_ptr).as_ref().unwrap_unchecked() })
                    }
                    Err(e) => {
                        pr_err!(
                            "shmem DBG get_sg_table: COLD path Devres::new FAIL err={:?}\n",
                            e,
                        );
                        // We can't make sure that the pages for this object are unmapped on
                        // driver-unbind, so we need to release the sgt
                        // SAFETY:
                        // - We grabbed the lock required for calling this function above
                        // - We checked above that get_pages_sgt_locked() was successful
                        unsafe { bindings::__drm_gem_shmem_free_sgt_locked(self.as_raw_shmem()) };

                        Err(e)
                    }
                }
            }
        };

        // SAFETY: We're releasing the lock that we grabbed above.
        unsafe { bindings::dma_resv_unlock(self.raw_dma_resv()) };

        ret
    }

    /// Creates (if necessary) and returns an immutable reference to a scatter-gather table of DMA
    /// pages for this object.
    ///
    /// This will pin the object in memory.
    #[inline]
    pub fn sg_table<'a>(
        &'a self,
        dev: &'a device::Device<Bound>,
    ) -> Result<&'a scatterlist::SGTable> {
        let sgt = self.get_sg_table(dev)?;

        match sgt.access(dev) {
            Ok(guard) => {
                pr_err!("shmem DBG sg_table: access OK\n");
                Ok(guard.deref())
            }
            Err(e) => {
                pr_err!(
                    "shmem DBG sg_table: access FAIL err={:?} (Devres dev mismatch?)\n",
                    e,
                );
                Err(e)
            }
        }
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
    pub fn owned_sg_table(&self, dev: &device::Device<Bound>) -> Result<SGTable<T>> {
        self.get_sg_table(dev)?;

        // INVARIANT: We just ensured above that `self.sgt_res` is initialized with
        // `Some(Devres<SGTableMap<T>>)`.
        Ok(SGTable(self.into()))
    }

    /// Attempt to create a vmap from the gem object, and confirm the size of said vmap.
    fn raw_vmap(&self, min_size: usize) -> Result<*mut c_void> {
        if self.size() < min_size {
            return Err(ENOSPC);
        }

        let mut map: MaybeUninit<bindings::iosys_map> = MaybeUninit::uninit();

        // SAFETY: drm_gem_shmem_vmap can be called with the DMA reservation lock held
        to_result(unsafe {
            // TODO: see top of file
            bindings::dma_resv_lock(self.raw_dma_resv(), ptr::null_mut());
            let ret = bindings::drm_gem_shmem_vmap_locked(self.as_raw_shmem(), map.as_mut_ptr());
            bindings::dma_resv_unlock(self.raw_dma_resv());
            ret
        })?;

        // SAFETY: The call to drm_gem_shmem_vmap_locked succeeded above, so we are guaranteed that
        // map is properly initialized.
        let map = unsafe { map.assume_init() };

        // XXX: We don't currently support iomem allocations
        if map.is_iomem {
            // SAFETY:
            // - The vmap operation above succeeded, guaranteeing that `map` points to a valid
            //   memory mapping.
            // - We checked that this is an iomem allocation, making it safe to read vaddr_iomem
            unsafe { self.raw_vunmap(map) };

            Err(ENOTSUPP)
        } else {
            // SAFETY: We checked that this is not an iomem allocation, making it safe to read vaddr
            Ok(unsafe { map.__bindgen_anon_1.vaddr })
        }
    }

    /// Unmap a vmap from the gem object.
    ///
    /// # Safety
    ///
    /// - The caller promises that `map` is a valid vmap on this gem object.
    /// - The caller promises that the memory pointed to by map will no longer be accesed through
    ///   this instance.
    unsafe fn raw_vunmap(&self, mut map: bindings::iosys_map) {
        let resv = self.raw_dma_resv();

        // SAFETY:
        // - This function is safe to call with the DMA reservation lock held
        // - Our `ARef` is proof that the underlying gem object here is initialized and thus safe to
        //   dereference.
        unsafe {
            // TODO: see top of file
            bindings::dma_resv_lock(resv, ptr::null_mut());
            bindings::drm_gem_shmem_vunmap_locked(self.as_raw_shmem(), &mut map);
            bindings::dma_resv_unlock(resv);
        }
    }

    /// Creates and returns a virtual kernel memory mapping for this object.
    #[inline]
    pub fn vmap<const SIZE: usize>(&self) -> Result<VMapRef<'_, T, SIZE>> {
        Ok(VMap {
            // INVARIANT: `raw_vmap()` checks that the gem object is at least as large as `SIZE`.
            addr: self.raw_vmap(SIZE)?,
            owner: self,
        })
    }

    /// Creates and returns an owned reference to a virtual kernel memory mapping for this object.
    #[inline]
    pub fn owned_vmap<const SIZE: usize>(&self) -> Result<VMapOwned<T, SIZE>> {
        Ok(VMap {
            // INVARIANT: `raw_vmap()` checks that the gem object is at least as large as `SIZE`.
            addr: self.raw_vmap(SIZE)?,
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
        gem_create_object: Some(Self::gem_create_object_callback),
        prime_handle_to_fd: None,
        prime_fd_to_handle: None,
        gem_prime_import: None,
        gem_prime_import_sg_table: Some(bindings::drm_gem_shmem_prime_import_sg_table),
        dumb_create: Some(bindings::drm_gem_shmem_dumb_create),
        dumb_map_offset: None,
    };
}

/// A reference to a GEM object that is known to have a mapped [`SGTable`].
///
/// This is used by the Rust bindings with [`Devres`] in order to ensure that mappings for SGTables
/// on GEM shmem objects are revoked on driver-unbind.
///
/// # Invariants
///
/// - `self.obj` always points to a valid GEM object.
/// - This object is proof that `self.0.owner.sgt` has an initialized and valid SGTable.
pub struct SGTableMap<T: DriverObject> {
    obj: NonNull<Object<T>>,
}

impl<T: DriverObject> Deref for SGTableMap<T> {
    type Target = scatterlist::SGTable;

    fn deref(&self) -> &Self::Target {
        // SAFETY:
        // - The NonNull is guaranteed to be valid via our type invariants.
        // - The sgt field is guaranteed to be initialized and valid via our type invariants.
        unsafe { scatterlist::SGTable::from_raw((*self.obj.as_ref().as_raw_shmem()).sgt) }
    }
}

impl<T: DriverObject> Drop for SGTableMap<T> {
    fn drop(&mut self) {
        // SAFETY: `obj` is always valid via our type invariants
        let obj = unsafe { self.obj.as_ref() };

        // SAFETY: The dma_resv for GEM objects is initialized throughout its lifetime
        unsafe { bindings::dma_resv_lock(obj.raw_dma_resv(), ptr::null_mut()) };

        // SAFETY: We acquired the lock needed for calling this function above
        unsafe { bindings::__drm_gem_shmem_free_sgt_locked(obj.as_raw_shmem()) };

        // SAFETY: We are releasing the lock we acquired above.
        unsafe { bindings::dma_resv_unlock(obj.raw_dma_resv()) };
    }
}

// SAFETY: The NonNull in SGTableRef is guaranteed valid by our type invariants, and the GEM object
// it points to is guaranteed to be thread-safe.
unsafe impl<T: DriverObject> Send for SGTableMap<T> {}
// SAFETY: The NonNull in SGTableRef is guaranteed valid by our type invariants, and the GEM object
// it points to is guaranteed to be thread-safe.
unsafe impl<T: DriverObject> Sync for SGTableMap<T> {}

macro_rules! impl_vmap_io_capable {
    ($impl:ident, $ty:ty) => {
        impl<D, R, const SIZE: usize> IoCapable<$ty> for $impl<D, R, SIZE>
        where
            D: DriverObject,
            R: Deref<Target = Object<D>>,
        {
            #[inline(always)]
            unsafe fn io_read(&self, address: usize) -> $ty {
                let ptr = address as *mut $ty;

                // SAFETY: The safety contract of `io_read` guarantees that address is a valid
                // address within the bounds of `Self` of at least the size of $ty, and is properly
                // aligned.
                unsafe { ptr::read(ptr) }
            }

            #[inline(always)]
            unsafe fn io_write(&self, value: $ty, address: usize) {
                let ptr = address as *mut $ty;

                // SAFETY: The safety contract of `io_write` guarantees that address is a valid
                // address within the bounds of `Self` of at least the size of $ty, and is properly
                // aligned.
                unsafe { ptr::write(ptr, value) }
            }
        }
    };
}

/// A reference to a virtual mapping for an shmem-based GEM object in kernel address space.
///
/// # Invariants
///
/// - The size of `owner` is >= SIZE.
/// - The memory pointed to by addr remains valid at least until this object is dropped.
pub struct VMap<D, R, const SIZE: usize = 0>
where
    D: DriverObject,
    R: Deref<Target = Object<D>>,
{
    addr: *mut c_void,
    owner: R,
}

/// An alias type for a reference to a shmem-based GEM object's VMap.
pub type VMapRef<'a, D, const SIZE: usize = 0> = VMap<D, &'a Object<D>, SIZE>;

/// An alias type for an owned reference to a shmem-based GEM object's VMap.
pub type VMapOwned<D, const SIZE: usize = 0> = VMap<D, ARef<Object<D>>, SIZE>;

impl<D, R, const SIZE: usize> VMap<D, R, SIZE>
where
    D: DriverObject,
    R: Deref<Target = Object<D>>,
{
    /// Borrows a reference to the object that owns this virtual mapping.
    #[inline(always)]
    pub fn owner(&self) -> &Object<D> {
        &self.owner
    }
}

impl<D, R, const SIZE: usize> Drop for VMap<D, R, SIZE>
where
    D: DriverObject,
    R: Deref<Target = Object<D>>,
{
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY:
        // - Our existence is proof that this map was previously created using self.owner.
        // - Since we are in Drop, we are guaranteed that no one will access the memory
        //   through this mapping after calling this.
        unsafe {
            self.owner.raw_vunmap(bindings::iosys_map {
                is_iomem: false,
                __bindgen_anon_1: bindings::iosys_map__bindgen_ty_1 { vaddr: self.addr },
            })
        };
    }
}

impl<D, R, const SIZE: usize> Io for VMap<D, R, SIZE>
where
    D: DriverObject,
    R: Deref<Target = Object<D>>,
{
    #[inline(always)]
    fn addr(&self) -> usize {
        self.addr as usize
    }

    #[inline(always)]
    fn maxsize(&self) -> usize {
        self.owner.size()
    }
}

impl<D, R, const SIZE: usize> IoKnownSize for VMap<D, R, SIZE>
where
    D: DriverObject,
    R: Deref<Target = Object<D>>,
{
    const MIN_SIZE: usize = SIZE;
}

impl_vmap_io_capable!(VMap, u8);
impl_vmap_io_capable!(VMap, u16);
impl_vmap_io_capable!(VMap, u32);
#[cfg(CONFIG_64BIT)]
impl_vmap_io_capable!(VMap, u64);

impl<D: DriverObject, const SIZE: usize> Clone for VMapOwned<D, SIZE> {
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: We have a successful vmap already, so this can't fail.
        unsafe { self.owner.owned_vmap().unwrap_unchecked() }
    }
}

impl<'a, D: DriverObject, const SIZE: usize> Clone for VMapRef<'a, D, SIZE> {
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: We have a successful vmap already, so this can't fail.
        unsafe { self.owner.vmap().unwrap_unchecked() }
    }
}

impl<'a, D: DriverObject, const SIZE: usize> From<VMapRef<'a, D, SIZE>> for VMapOwned<D, SIZE> {
    #[inline]
    fn from(value: VMapRef<'a, D, SIZE>) -> Self {
        let this = Self {
            addr: value.addr,
            owner: value.owner.into(),
        };

        mem::forget(value);
        this
    }
}

// SAFETY: VMap is thread-safe, and the fact that this VMap has an owned reference to the object
// means this object will remain valid until dropped.
unsafe impl<D: DriverObject, const SIZE: usize> Send for VMapOwned<D, SIZE> {}
// SAFETY: VMap is thread-safe, and the fact that this VMap has an owned reference to the object
// means this object will remain valid until dropped.
unsafe impl<D: DriverObject, const SIZE: usize> Sync for VMapOwned<D, SIZE> {}

/// An owned reference to a scatter-gather table of DMA address spans for a GEM shmem object.
///
/// This object holds an owned reference to the underlying GEM shmem object, ensuring that the
/// [`scatterlist::SGTable`] referenced by this type remains valid for the lifetime of this object.
///
/// # Invariants
///
/// - This type is proof that `self.0.sgt_res` is initialized with a `Some(Devres<SGTableMap<T>>)`.
/// - This object is only exposed in situations where we know the underlying `SGTable` will not be
///   modified for the lifetime of this object. Thus, it is safe to send/access this type across
///   threads.
pub struct SGTable<T: DriverObject>(ARef<Object<T>>);

// SAFETY: This object is thread-safe via our type invariants.
unsafe impl<T: DriverObject> Send for SGTable<T> {}
// SAFETY: This object is thread-safe via our type invariants.
unsafe impl<T: DriverObject> Sync for SGTable<T> {}

impl<T: DriverObject> Deref for SGTable<T> {
    type Target = Devres<SGTableMap<T>>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `self.owner.sgt_res` is guaranteed to be initialized with
        // `Some(Devres<SGTableMap<T>>)` via our type invariants
        unsafe { (*self.0.sgt_res.get()).as_ref().unwrap_unchecked() }
    }
}

#[kunit_tests(rust_drm_gem_shmem)]
mod tests {
    use super::*;
    use crate::{
        drm,
        faux,
        page::PAGE_SIZE, //
    };

    // The bare minimum needed to create a fake drm driver for kunit

    #[pin_data]
    struct KunitData {}
    struct KunitDriver;
    struct KunitFile;
    #[pin_data]
    struct KunitObject {}

    const INFO: drm::DriverInfo = drm::DriverInfo {
        major: 0,
        minor: 0,
        patchlevel: 0,
        name: c"kunit",
        desc: c"Kunit",
    };

    impl drm::file::DriverFile for KunitFile {
        type Driver = KunitDriver;

        fn open(_dev: &drm::Device<KunitDriver>) -> Result<Pin<KBox<Self>>> {
            Ok(KBox::new(Self, GFP_KERNEL)?.into())
        }
    }

    impl gem::DriverObject for KunitObject {
        type Driver = KunitDriver;
        type Args = ();

        fn new<Ctx: drm::DeviceContext>(
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
        type Object<Ctx: drm::DeviceContext> = Object<KunitObject>;

        const INFO: drm::DriverInfo = INFO;
        const IOCTLS: &'static [drm::ioctl::DrmIoctlDescriptor] = &[];
    }

    fn create_drm_dev<'a>(dev: &'a faux::Registration) -> Result<&'a drm::Device<KunitDriver>> {
        // Create a faux DRM device so we can test gem object creation.
        let data = try_pin_init!(KunitData {});
        let drm_unregistered = drm::device::UnregisteredDevice::<KunitDriver>::new(dev.as_ref())?;

        // SAFETY: The faux device is created and registered, so it's safe to treat as bound for the
        // lifetime of the test.
        let dev_bound = unsafe { dev.as_ref().as_bound() };

        let drm =
            drm::driver::Registration::new_foreign_owned(drm_unregistered, dev_bound, data, 0)?;

        Ok(drm)
    }

    #[test]
    fn compile_time_vmap_sizes() -> Result {
        let dev = faux::Registration::new(c"Kunit", None)?;
        let drm = create_drm_dev(&dev)?;

        // Create a gem object to test with
        let cfg_ = ObjectConfig::<KunitObject> {
            map_wc: false,
            parent_resv_obj: None,
        };
        let obj = Object::<KunitObject>::new(drm, PAGE_SIZE, cfg_, ())?;

        // Try creating a normal vmap
        obj.vmap::<PAGE_SIZE>()?;

        // Try creating a vmap that's smaller then the size we specified
        obj.vmap::<{ PAGE_SIZE - 100 }>()?;

        // Make sure creating a vmap that's too large fails
        assert!(obj.vmap::<{ PAGE_SIZE + 200 }>().is_err());

        Ok(())
    }

    #[test]
    fn vmap_io() -> Result {
        let dev = faux::Registration::new(c"Kunit", None)?;
        let drm = create_drm_dev(&dev)?;

        // Create a gem object to test with
        let cfg_ = ObjectConfig::<KunitObject> {
            map_wc: false,
            parent_resv_obj: None,
        };
        let obj = Object::<KunitObject>::new(drm, PAGE_SIZE, cfg_, ())?;

        let vmap = obj.vmap::<PAGE_SIZE>()?;

        vmap.write8(0xDE, 0x0);
        assert_eq!(vmap.read8(0x0), 0xDE);
        vmap.write32(0xFFFFFFFF, 0x20);

        assert_eq!(vmap.read32(0x20), 0xFFFFFFFF);

        assert_eq!(vmap.read8(0x20), 0xFF);
        assert_eq!(vmap.read8(0x21), 0xFF);
        assert_eq!(vmap.read8(0x22), 0xFF);
        assert_eq!(vmap.read8(0x23), 0xFF);

        Ok(())
    }
}
