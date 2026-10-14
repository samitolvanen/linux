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
    dma,
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
    highmem,
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
    ffi::c_void,
    mem::{
        self,
        ManuallyDrop,
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
    IntoGEMObject,
    ResvGuard,
    ResvLocked, //
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
    /// Parent object that owns this object's DMA reservation object.
    parent_resv_obj: Option<ARef<Object<T>>>,
    /// Devres object for unmapping the SGTable on driver-unbind, set when the table is created.
    sgt_res: ManuallyDrop<ResvLocked<Option<Devres<SgtDma>>>>,
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
        export: Some(Self::export_callback),
        pin: Some(bindings::drm_gem_shmem_object_pin),
        unpin: Some(bindings::drm_gem_shmem_object_unpin),
        get_sg_table: Some(bindings::drm_gem_shmem_object_get_sg_table),
        vmap: Some(bindings::drm_gem_shmem_object_vmap),
        vunmap: Some(bindings::drm_gem_shmem_object_vunmap),
        mmap: Some(Self::mmap_callback),
        status: Some(super::status_callback::<T>),
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

    /// Returns whether the object's backing pages are currently present, i.e.
    /// [`drm_gem_shmem_object::pages`] is non-NULL.
    ///
    /// This is a lockless read. The value may change concurrently, so a stale
    /// result is possible. That is acceptable for the fdinfo memory accounting
    /// this serves, where the read must not sleep or take a lock.
    ///
    /// [`drm_gem_shmem_object::pages`]: srctree/include/drm/drm_gem_shmem_helper.h
    #[inline]
    pub fn pages_present(&self) -> bool {
        let shmem = self.as_raw_shmem();

        // SAFETY: `shmem` points to the embedded `drm_gem_shmem_object`, which
        // is valid for the lifetime of `self` per the type invariant. The
        // volatile read tolerates a concurrent write from the page put path.
        !unsafe { core::ptr::read_volatile(&raw const (*shmem).pages) }.is_null()
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
                sgt_res: ManuallyDrop::new(ResvLocked::new(None)),
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

    /// Returns whether the object's CPU mappings are write-combined.
    #[inline]
    pub fn map_wc(&self) -> bool {
        // SAFETY: `as_raw_shmem()` returns a valid pointer to this object's shmem object for the
        // lifetime of `&self`.
        unsafe { bindings::drm_gem_shmem_object::map_wc_raw(self.as_raw_shmem()) }
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
                sgt_res: ManuallyDrop::new(ResvLocked::new(None)),
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
        // Notify the driver before any teardown, while the object is still valid.
        // SAFETY: The core passes a valid gem object contained in a `DriverAllocImpl<T>`.
        let driver_obj: &gem::DriverAllocImpl<T> = unsafe { IntoGEMObject::from_raw(obj) };
        T::free(driver_obj);

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

        // Dropping `sgt_res` unmaps the table, so it must happen before the table is freed.
        // SAFETY:
        // - We verified above that `rust_this` is valid.
        // - We are in free_callback, guaranteeing we have exclusive access to `rust_this` and that
        //   `sgt_res` will not be used after dropping it here.
        unsafe { ManuallyDrop::drop(&mut (*rust_this).sgt_res) };

        // `drm_gem_shmem_release()` would unmap the table a second time, so free it here.
        // SAFETY: We have exclusive access to `rust_this`, and the table is unmapped once `sgt_res`
        // is dropped.
        unsafe { (*rust_this).free_sgt() };

        // SAFETY:
        // - We're in free_callback - so this function is safe to call.
        // - We won't be using the gem resources on `this` after this call.
        unsafe { bindings::drm_gem_shmem_release(this) };

        // SAFETY: We're recovering the Kbox<> we created in gem_create_object()
        let _ = unsafe { KBox::from_raw(rust_this) };
    }

    /// Frees the sg table of the object, unless the object is imported.
    ///
    /// # Safety
    ///
    /// The caller holds the reservation lock or has exclusive access to the object, the table is
    /// not DMA-mapped unless the object is imported, and no table reference from
    /// [`ResvGuard::sg_table()`] is alive.
    unsafe fn free_sgt(&self) {
        if self.is_imported() {
            return;
        }

        let shmem = self.as_raw_shmem();

        // SAFETY: Per the safety requirements, nothing else accesses `sgt`. The shmem helper
        // allocates the table with `kmalloc()`.
        unsafe {
            let sgt = (*shmem).sgt;
            if !sgt.is_null() {
                bindings::sg_free_table(sgt);
                bindings::kfree(sgt.cast());
                (*shmem).sgt = ptr::null_mut();
            }
        }
    }

    /// Exports the GEM object as a dma-buf, after running the driver's `export` hook.
    extern "C" fn export_callback(
        raw_obj: *mut bindings::drm_gem_object,
        flags: c_int,
    ) -> *mut bindings::dma_buf {
        // SAFETY:
        // * `export_callback` is only installed in the vtable of `Self`, ensuring that `raw_obj`
        //   is contained within a `DriverAllocImpl<T>`.
        // * It is only possible for `export_callback` to be called after device registration,
        //   ensuring that the object's device is in the `Registered` state.
        let obj: &gem::DriverAllocImpl<T> = unsafe { IntoGEMObject::from_raw(raw_obj) };

        match T::export(obj, flags) {
            Ok(()) if T::EXPORT_CPU_ACCESS_SYNC => {
                // SAFETY: `raw_obj` is a valid GEM object (see above), so its `dev`, `size` and
                // `resv` fields are valid, and every registered DRM device provides
                // `driver->fops`.
                let (dev, exp_name, owner, size, resv) = unsafe {
                    let dev = (*raw_obj).dev;
                    let driver = (*dev).driver;
                    (
                        dev,
                        (*driver).name,
                        (*(*driver).fops).owner,
                        (*raw_obj).size,
                        (*raw_obj).resv,
                    )
                };

                let mut exp_info = bindings::dma_buf_export_info {
                    exp_name,
                    owner,
                    ops: &CPU_SYNC_DMA_BUF_OPS,
                    size,
                    flags,
                    resv,
                    priv_: raw_obj.cast(),
                };

                // SAFETY: `dev` is the device of a valid GEM object, and `exp_info` is fully
                // initialized above.
                unsafe { bindings::drm_gem_dmabuf_export(dev, &mut exp_info) }
            }
            // SAFETY: `raw_obj` is a valid GEM object (see above).
            Ok(()) => unsafe { bindings::drm_gem_prime_export(raw_obj, flags) },
            Err(e) => e.to_ptr(),
        }
    }

    /// Maps the GEM object into userspace, after running the driver's `mmap` hook.
    extern "C" fn mmap_callback(
        raw_obj: *mut bindings::drm_gem_object,
        vma: *mut bindings::vm_area_struct,
    ) -> c_int {
        // SAFETY:
        // * `mmap_callback` is only installed in the vtable of `Self`, ensuring that `raw_obj` is
        //   contained within a `DriverAllocImpl<T>`.
        // * It is only possible for `mmap_callback` to be called after device registration,
        //   ensuring that the object's device is in the `Registered` state.
        let obj: &gem::DriverAllocImpl<T> = unsafe { IntoGEMObject::from_raw(raw_obj) };

        if let Err(e) = T::mmap(obj) {
            // mmap(2) has no EINTR, so restart it after an interrupted wait.
            if e == EINTR || e == ERESTARTSYS {
                return ERESTARTNOINTR.to_errno();
            }

            return e.to_errno();
        }

        // SAFETY: `raw_obj` is a valid shmem GEM object (see above), and `vma` is the VMA the DRM
        // core is setting up for it.
        unsafe { bindings::drm_gem_shmem_object_mmap(raw_obj, vma) }
    }

    /// Attempt to create a vmap from the gem object, and confirm the size of said vmap.
    fn raw_vmap(&self, min_size: usize) -> Result<*mut c_void> {
        if self.size() < min_size {
            return Err(ENOSPC);
        }

        let mut map: MaybeUninit<bindings::iosys_map> = MaybeUninit::uninit();
        let guard = self.lock_resv();

        // SAFETY: drm_gem_shmem_vmap can be called with the DMA reservation lock held
        to_result(unsafe {
            bindings::drm_gem_shmem_vmap_locked(self.as_raw_shmem(), map.as_mut_ptr())
        })?;

        // Drop the guard explicitly here, since we may need to call `raw_vunmap()` (which
        // re-acquires the lock).
        drop(guard);

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
        let _guard = self.lock_resv();

        // SAFETY:
        // - This function is safe to call with the DMA reservation lock held
        // - Our `ARef` is proof that the underlying gem object here is initialized and thus safe to
        //   dereference.
        unsafe { bindings::drm_gem_shmem_vunmap_locked(self.as_raw_shmem(), &mut map) };
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

impl<T: DriverObject> ResvGuard<'_, Object<T>> {
    /// Creates (if necessary) and returns the scatter-gather table of DMA pages for the object.
    ///
    /// The table holds a reference to the object's pages. `dev` must be the [`device::Device`]
    /// the object belongs to, otherwise this returns [`EINVAL`]. Once driver unbind has unmapped
    /// the table, this returns [`ENODEV`].
    pub fn sg_table<'a>(
        &'a mut self,
        dev: &'a device::Device<Bound>,
    ) -> Result<&'a scatterlist::SGTable> {
        let obj = self.obj();
        let parent: &device::Device = obj.dev().as_ref();
        if dev.as_raw() != parent.as_raw() {
            return Err(EINVAL);
        }

        // SAFETY: `sgt_res` lies within `obj`, whose lock `self` holds.
        let sgt_res = unsafe { obj.sgt_res.access_unchecked_mut(self) };
        if sgt_res
            .as_ref()
            .is_some_and(|sgt_res| sgt_res.try_access().is_none())
        {
            return Err(ENODEV);
        }

        let shmem = obj.as_raw_shmem();

        // SAFETY: We hold the reservation lock of `obj`.
        let sgt = from_err_ptr(unsafe { bindings::drm_gem_shmem_get_pages_sgt_locked(shmem) })?;

        if sgt_res.is_none() && !obj.is_imported() {
            // INVARIANT: The shmem helper mapped the new table for `dev`, and nothing frees it
            // before `dma` is dropped.
            let dma = SgtDma {
                // SAFETY: `drm_gem_shmem_get_pages_sgt_locked()` returns a valid table or an
                // error.
                sgt: unsafe { NonNull::new_unchecked(sgt) },
                dev: dev.into(),
            };

            match Devres::new(dev, dma) {
                Ok(dma) => *sgt_res = Some(dma),
                Err(e) => {
                    // SAFETY: We hold the reservation lock, and `&mut self` excludes live table
                    // references. `Devres::new()` dropped `dma`, which unmapped the table, and
                    // the table holds a reference to the pages.
                    unsafe {
                        obj.free_sgt();
                        bindings::drm_gem_shmem_put_pages_locked(shmem);
                    }
                    return Err(e);
                }
            }
        }

        // SAFETY: The table is freed under the reservation lock, which we hold for `'a`, or once
        // `obj` has no references. Driver unbind does not unmap the table while `dev` is bound.
        Ok(unsafe { scatterlist::SGTable::from_raw(sgt) })
    }

    /// Pins the pages of the object, or does nothing if the object is imported.
    ///
    /// Allocates the pages if needed. The pages of an imported object belong to the exporter.
    pub fn pin(&self) -> Result<PinGuard<T>> {
        let obj = self.obj();
        if !obj.is_imported() {
            // SAFETY: We hold the reservation lock of an object that is not imported.
            to_result(unsafe { bindings::drm_gem_shmem_pin_locked(obj.as_raw_shmem()) })?;
        }

        // INVARIANT: The object was pinned above, unless it is imported.
        Ok(PinGuard { obj: obj.into() })
    }
}

/// A pin on the pages of a shmem-backed GEM object.
///
/// The pages stay in memory until the guard is dropped. Dropping the guard takes the reservation
/// lock of the object.
///
/// # Invariants
///
/// `obj` holds a pin on its pages for the lifetime of the guard, unless it is imported.
pub struct PinGuard<T: DriverObject> {
    obj: ARef<Object<T>>,
}

impl<T: DriverObject> PinGuard<T> {
    /// Returns the pinned object.
    #[inline]
    pub fn obj(&self) -> &Object<T> {
        &self.obj
    }
}

impl<T: DriverObject> Drop for PinGuard<T> {
    fn drop(&mut self) {
        if self.obj.is_imported() {
            return;
        }

        let _resv = self.obj.lock_resv();

        // SAFETY: We hold the reservation lock, and by the type invariants the object holds the
        // pin released here.
        unsafe { bindings::drm_gem_shmem_unpin_locked(self.obj.as_raw_shmem()) };
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
        gem_prime_import: if T::EXPORT_CPU_ACCESS_SYNC {
            Some(prime_import_callback)
        } else {
            None
        },
        gem_prime_import_sg_table: Some(bindings::drm_gem_shmem_prime_import_sg_table),
        dumb_create: if T::EXPOSE_DUMB_CREATE {
            Some(bindings::drm_gem_shmem_dumb_create)
        } else {
            None
        },
        dumb_map_offset: None,
    };
}

/// `dma_buf_ops` used for exports when [`DriverObject::EXPORT_CPU_ACCESS_SYNC`] is set.
///
/// This is a `static` rather than an associated `const` so that [`prime_import_callback`] can
/// identify self-exported buffers by the ops address, since references to an associated `const`
/// are not guaranteed to be unique. The static is shared by every driver that opts in, and
/// [`prime_import_callback`] tells self-imports apart with a device-identity check.
static CPU_SYNC_DMA_BUF_OPS: bindings::dma_buf_ops = bindings::dma_buf_ops {
    attach: Some(bindings::drm_gem_map_attach),
    detach: Some(bindings::drm_gem_map_detach),
    pin: None,
    unpin: None,
    map_dma_buf: Some(map_dma_buf_callback),
    unmap_dma_buf: Some(unmap_dma_buf_callback),
    release: Some(bindings::drm_gem_dmabuf_release),
    begin_cpu_access: Some(begin_cpu_access_callback),
    end_cpu_access: Some(end_cpu_access_callback),
    mmap: Some(bindings::drm_gem_dmabuf_mmap),
    vmap: Some(bindings::drm_gem_dmabuf_vmap),
    vunmap: Some(bindings::drm_gem_dmabuf_vunmap),
};

/// The scatter-gather table is cached in `attach->priv` so the CPU access callbacks can sync
/// importers. `attach->priv` is protected by the buffer's reservation lock, which the dma-buf
/// core holds across `map_dma_buf()`/`unmap_dma_buf()`.
extern "C" fn map_dma_buf_callback(
    attach: *mut bindings::dma_buf_attachment,
    dir: bindings::dma_data_direction,
) -> *mut bindings::sg_table {
    // SAFETY: The dma-buf core calls this with a valid attachment on a buffer exported with
    // `CPU_SYNC_DMA_BUF_OPS`, whose `priv` is a valid GEM object.
    let sgt = unsafe { bindings::drm_gem_map_dma_buf(attach, dir) };

    if let Ok(sgt) = from_err_ptr(sgt) {
        // SAFETY: `attach` is valid (see above), and `attach->priv` is exporter-owned,
        // protected by the reservation lock held by the core.
        unsafe { (*attach).priv_ = sgt.cast() };
    }

    sgt
}

extern "C" fn unmap_dma_buf_callback(
    attach: *mut bindings::dma_buf_attachment,
    sgt: *mut bindings::sg_table,
    dir: bindings::dma_data_direction,
) {
    // SAFETY: `attach` is a valid attachment and `attach->priv` is protected by the reservation
    // lock held by the core.
    unsafe { (*attach).priv_ = ptr::null_mut() };

    // SAFETY: The core passes back the attachment and table produced by
    // `map_dma_buf_callback`, both valid for this call.
    unsafe { bindings::drm_gem_unmap_dma_buf(attach, sgt, dir) };
}

/// Syncs the cached scatter-gather tables of all of the buffer's attachments in `dir`.
///
/// # Safety
///
/// `dma_buf` must be a valid dma-buf exported with [`CPU_SYNC_DMA_BUF_OPS`], and its reservation
/// lock must be held.
unsafe fn sync_attachments(
    dma_buf: *mut bindings::dma_buf,
    dir: dma::DataDirection,
    sync: unsafe fn(&device::Device, &scatterlist::SGTable, dma::DataDirection),
) {
    // SAFETY: `dma_buf` is valid and its attachment list is protected by the reservation lock,
    // held per this function's safety requirements.
    let head = unsafe { &raw const (*dma_buf).attachments };
    // SAFETY: As above.
    let mut pos = unsafe { (*head).next };

    while !ptr::eq(pos.cast_const(), head) {
        // SAFETY: Under the reservation lock, non-head nodes of the attachment list are
        // embedded in valid `struct dma_buf_attachment` instances.
        let attach = unsafe { container_of!(pos, bindings::dma_buf_attachment, node) };

        // SAFETY: `attach` is valid (see above) and this read is under the reservation lock.
        let sgt = unsafe { (*attach).priv_.cast::<bindings::sg_table>() };
        if !sgt.is_null() {
            // SAFETY: A non-NULL `attach->priv` is the table cached by `map_dma_buf_callback`,
            // mapped for `attach->dev`, which stays valid while the attachment exists.
            unsafe {
                sync(
                    device::Device::from_raw((*attach).dev),
                    scatterlist::SGTable::from_raw(sgt),
                    dir,
                )
            };
        }

        // SAFETY: `pos` is a valid list node while the reservation lock is held.
        pos = unsafe { (*pos).next };
    }
}

/// Called by the dma-buf core without the reservation lock held. The core waits for implicit
/// fences afterwards.
extern "C" fn begin_cpu_access_callback(
    dma_buf: *mut bindings::dma_buf,
    dir: bindings::dma_data_direction,
) -> c_int {
    let dir = match dma::DataDirection::try_from(dir) {
        Ok(dir) if dir != dma::DataDirection::None => dir,
        _ => return EINVAL.to_errno(),
    };

    // SAFETY: The core calls this with a valid dma-buf exported with `CPU_SYNC_DMA_BUF_OPS`,
    // whose `priv` is the GEM object embedded in a valid `drm_gem_shmem_object`.
    let obj = unsafe { (*dma_buf).priv_ }.cast::<bindings::drm_gem_object>();
    // SAFETY: As above.
    let shmem = unsafe { container_of!(obj, bindings::drm_gem_shmem_object, base) };

    let mut idx = 0;
    // SAFETY: `obj` is valid, so its DRM device is valid.
    let entered = unsafe { bindings::drm_dev_enter((*obj).dev, &mut idx) };

    // SAFETY: The object's reservation lock is initialized for its whole lifetime.
    unsafe { bindings::dma_resv_lock((*obj).resv, ptr::null_mut()) };

    // SAFETY: `shmem` is valid (see above) and this read is under the reservation lock.
    let sgt = unsafe { (*shmem).sgt };
    if entered && !sgt.is_null() {
        // SAFETY: Under the reservation lock, a non-NULL `shmem->sgt` is a live scatter-gather
        // table. The successful `drm_dev_enter()` keeps the DRM device's parent device bound, so
        // the table stays mapped for it.
        unsafe {
            dma::sync_sgtable_for_cpu(
                device::Device::from_raw((*(*obj).dev).dev),
                scatterlist::SGTable::from_raw(sgt),
                dir,
            )
        };
    }

    // SAFETY: `shmem` is valid (see above) and this read is under the reservation lock.
    let vaddr = unsafe { (*shmem).vaddr };
    if !vaddr.is_null() {
        // SAFETY: `obj` is valid, and under the reservation lock a non-NULL `shmem->vaddr` is a
        // live kernel vmap of the object's pages covering `size` bytes.
        unsafe { highmem::invalidate_kernel_vmap_range(vaddr, (*obj).size) };
    }

    // SAFETY: `dma_buf` is valid and we hold its reservation lock.
    unsafe { sync_attachments(dma_buf, dir, dma::sync_sgtable_for_cpu) };

    // SAFETY: We are releasing the lock acquired above.
    unsafe { bindings::dma_resv_unlock((*obj).resv) };

    if entered {
        // SAFETY: `idx` is from the successful `drm_dev_enter()` above.
        unsafe { bindings::drm_dev_exit(idx) };
    }

    0
}

/// The mirror of [`begin_cpu_access_callback`], returning the mappings to the device in the
/// opposite order.
extern "C" fn end_cpu_access_callback(
    dma_buf: *mut bindings::dma_buf,
    dir: bindings::dma_data_direction,
) -> c_int {
    let dir = match dma::DataDirection::try_from(dir) {
        Ok(dir) if dir != dma::DataDirection::None => dir,
        _ => return EINVAL.to_errno(),
    };

    // SAFETY: The core calls this with a valid dma-buf exported with `CPU_SYNC_DMA_BUF_OPS`,
    // whose `priv` is the GEM object embedded in a valid `drm_gem_shmem_object`.
    let obj = unsafe { (*dma_buf).priv_ }.cast::<bindings::drm_gem_object>();
    // SAFETY: As above.
    let shmem = unsafe { container_of!(obj, bindings::drm_gem_shmem_object, base) };

    let mut idx = 0;
    // SAFETY: `obj` is valid, so its DRM device is valid.
    let entered = unsafe { bindings::drm_dev_enter((*obj).dev, &mut idx) };

    // SAFETY: The object's reservation lock is initialized for its whole lifetime.
    unsafe { bindings::dma_resv_lock((*obj).resv, ptr::null_mut()) };

    // SAFETY: `dma_buf` is valid and we hold its reservation lock.
    unsafe { sync_attachments(dma_buf, dir, dma::sync_sgtable_for_device) };

    // SAFETY: `shmem` is valid (see above) and this read is under the reservation lock.
    let vaddr = unsafe { (*shmem).vaddr };
    if !vaddr.is_null() {
        // SAFETY: `obj` is valid, and under the reservation lock a non-NULL `shmem->vaddr` is a
        // live kernel vmap of the object's pages covering `size` bytes.
        unsafe { highmem::flush_kernel_vmap_range(vaddr, (*obj).size) };
    }

    // SAFETY: `shmem` is valid (see above) and this read is under the reservation lock.
    let sgt = unsafe { (*shmem).sgt };
    if entered && !sgt.is_null() {
        // SAFETY: Under the reservation lock, a non-NULL `shmem->sgt` is a live scatter-gather
        // table. The successful `drm_dev_enter()` keeps the DRM device's parent device bound, so
        // the table stays mapped for it.
        unsafe {
            dma::sync_sgtable_for_device(
                device::Device::from_raw((*(*obj).dev).dev),
                scatterlist::SGTable::from_raw(sgt),
                dir,
            )
        };
    }

    // SAFETY: We are releasing the lock acquired above.
    unsafe { bindings::dma_resv_unlock((*obj).resv) };

    if entered {
        // SAFETY: `idx` is from the successful `drm_dev_enter()` above.
        unsafe { bindings::drm_dev_exit(idx) };
    }

    0
}

/// Importing a buffer that this device itself exported must hand back the original GEM object
/// rather than wrap the dma-buf in a new one. The DRM core only recognizes its own default
/// `dma_buf_ops`, so buffers exported with [`CPU_SYNC_DMA_BUF_OPS`] need the equivalent check
/// here.
extern "C" fn prime_import_callback(
    raw_dev: *mut bindings::drm_device,
    dma_buf: *mut bindings::dma_buf,
) -> *mut bindings::drm_gem_object {
    // SAFETY: The DRM core calls this with a valid dma-buf.
    if unsafe { ptr::eq((*dma_buf).ops, &CPU_SYNC_DMA_BUF_OPS) } {
        // SAFETY: The ops identify the buffer as exported by `Object::export_callback`, so its
        // `priv` is a valid GEM object.
        let obj = unsafe { (*dma_buf).priv_ }.cast::<bindings::drm_gem_object>();

        // SAFETY: As above.
        if unsafe { ptr::eq((*obj).dev, raw_dev) } {
            // SAFETY: `obj` has a non-zero refcount, since the dma-buf holds a reference to it.
            unsafe { bindings::drm_gem_object_get(obj) };
            return obj;
        }
    }

    // SAFETY: `raw_dev` and `dma_buf` are valid.
    unsafe { bindings::drm_gem_prime_import(raw_dev, dma_buf) }
}

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

/// The DMA mapping of the sg table of a shmem object, removed on drop.
///
/// It is kept in a [`Devres`], so that driver unbind unmaps the table. The table itself belongs to
/// the object.
///
/// # Invariants
///
/// `sgt` is a valid table that the shmem helper mapped for `dev`, and it is not freed until this
/// is dropped.
struct SgtDma {
    sgt: NonNull<bindings::sg_table>,
    dev: ARef<device::Device>,
}

impl Drop for SgtDma {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: By the type invariants, `sgt` is valid, and the shmem helper mapped it for `dev`
        // with the same direction and attributes.
        unsafe {
            bindings::dma_unmap_sgtable(
                self.dev.as_raw(),
                self.sgt.as_ptr(),
                dma::DataDirection::Bidirectional.into(),
                0,
            )
        };
    }
}

// SAFETY: It is safe to send `SgtDma` to another thread because the DMA mapping can be removed
// from any thread.
unsafe impl Send for SgtDma {}

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
    struct KunitObject {
        value: gem::ResvLocked<u32>,
    }

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
            try_pin_init!(KunitObject {
                value: gem::ResvLocked::new(0),
            })
        }

        fn create_imported(
            _dev: &drm::Device<KunitDriver>,
            _size: usize,
        ) -> impl PinInit<Self, Error> {
            try_pin_init!(KunitObject {
                value: gem::ResvLocked::new(0),
            })
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

    #[test]
    fn resv_guards() -> Result {
        let dev = faux::Registration::new(c"Kunit", None)?;
        let drm = create_drm_dev(&dev)?;

        let cfg_ = || ObjectConfig::<KunitObject> {
            map_wc: false,
            parent_resv_obj: None,
        };
        let obj = Object::<KunitObject>::new(drm, PAGE_SIZE, cfg_(), ())?;
        let other = Object::<KunitObject>::new(drm, PAGE_SIZE, cfg_(), ())?;

        let mut guard = obj.lock_resv();
        assert!(obj.try_lock_resv().is_none());
        *obj.value.access_mut(&mut guard)? += 1;
        drop(guard);

        // A guard of another object does not give access.
        let other_guard = other.lock_resv();
        assert_eq!(obj.value.access(&other_guard).err(), Some(EINVAL));
        drop(other_guard);

        let guard = obj.try_lock_resv().ok_or(EBUSY)?;
        assert_eq!(*obj.value.access(&guard)?, 1);

        Ok(())
    }

    #[test]
    fn pin_guards() -> Result {
        let dev = faux::Registration::new(c"Kunit", None)?;
        let drm = create_drm_dev(&dev)?;

        let cfg_ = ObjectConfig::<KunitObject> {
            map_wc: false,
            parent_resv_obj: None,
        };
        let obj = Object::<KunitObject>::new(drm, PAGE_SIZE, cfg_, ())?;
        assert!(!obj.pages_present());

        let pin = obj.lock_resv().pin()?;
        assert!(obj.pages_present());

        drop(pin);
        assert!(!obj.pages_present());

        Ok(())
    }
}
