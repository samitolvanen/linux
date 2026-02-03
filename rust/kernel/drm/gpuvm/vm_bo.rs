// SPDX-License-Identifier: GPL-2.0 OR MIT

use super::*;

/// Represents that a given GEM object has at least one mapping on this [`GpuVm`] instance.
///
/// Does not assume that GEM lock is held.
#[repr(C)]
#[pin_data]
pub struct GpuVmBo<T: DriverGpuVm> {
    #[pin]
    inner: Opaque<bindings::drm_gpuvm_bo>,
    #[pin]
    data: T::VmBoData,
}

impl<T: DriverGpuVm> GpuVmBo<T> {
    pub(super) const ALLOC_FN: Option<unsafe extern "C" fn() -> *mut bindings::drm_gpuvm_bo> = {
        use core::alloc::Layout;
        let base = Layout::new::<bindings::drm_gpuvm_bo>();
        let rust = Layout::new::<Self>();
        assert!(base.size() <= rust.size());
        if base.size() != rust.size() || base.align() != rust.align() {
            Some(Self::vm_bo_alloc)
        } else {
            // This causes GPUVM to allocate a `GpuVmBo<T>` with `kzalloc(sizeof(drm_gpuvm_bo))`.
            None
        }
    };

    pub(super) const FREE_FN: Option<unsafe extern "C" fn(*mut bindings::drm_gpuvm_bo)> = {
        if core::mem::needs_drop::<Self>() {
            Some(Self::vm_bo_free)
        } else {
            // This causes GPUVM to free a `GpuVmBo<T>` with `kfree`.
            None
        }
    };

    /// Custom function for allocating a `drm_gpuvm_bo`.
    ///
    /// # Safety
    ///
    /// Always safe to call.
    // Unsafe to match function pointer type in C struct.
    unsafe extern "C" fn vm_bo_alloc() -> *mut bindings::drm_gpuvm_bo {
        KBox::<Self>::new_uninit(GFP_KERNEL | __GFP_ZERO)
            .map(KBox::into_raw)
            .unwrap_or(ptr::null_mut())
            .cast()
    }

    /// Custom function for freeing a `drm_gpuvm_bo`.
    ///
    /// # Safety
    ///
    /// The pointer must have been allocated with [`GpuVmBo::ALLOC_FN`], and must not be used after
    /// this call.
    unsafe extern "C" fn vm_bo_free(ptr: *mut bindings::drm_gpuvm_bo) {
        // SAFETY:
        // * The ptr was allocated from kmalloc with the layout of `GpuVmBo<T>`.
        // * `ptr->inner` has no destructor.
        // * `ptr->data` contains a valid `T::VmBoData` that we can drop.
        drop(unsafe { KBox::<Self>::from_raw(ptr.cast()) });
    }

    /// Access this [`GpuVmBo`] from a raw pointer.
    ///
    /// # Safety
    ///
    /// For the duration of `'a`, the pointer must reference a valid `drm_gpuvm_bo` associated with
    /// a [`GpuVm<T>`].
    #[inline]
    pub unsafe fn from_raw<'a>(ptr: *mut bindings::drm_gpuvm_bo) -> &'a Self {
        // SAFETY: `drm_gpuvm_bo` is first field and `repr(C)`.
        unsafe { &*ptr.cast() }
    }

    /// Returns a raw pointer to underlying C value.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::drm_gpuvm_bo {
        self.inner.get()
    }

    /// The [`GpuVm`] that this GEM object is mapped in.
    #[inline]
    pub fn gpuvm(&self) -> &GpuVm<T> {
        // SAFETY: The `obj` pointer is guaranteed to be valid.
        unsafe { GpuVm::<T>::from_raw((*self.inner.get()).vm) }
    }

    /// The [`drm_gem_object`](crate::gem::Object) for these mappings.
    #[inline]
    pub fn obj(&self) -> &T::Object {
        // SAFETY: The `obj` pointer is guaranteed to be valid.
        unsafe { <T::Object as IntoGEMObject>::from_raw((*self.inner.get()).obj) }
    }

    /// The driver data with this buffer object.
    #[inline]
    pub fn data(&self) -> &T::VmBoData {
        &self.data
    }

    pub(super) fn lock_gpuva(&self) -> crate::sync::MutexGuard<'_, ()> {
        // SAFETY: The GEM object is valid.
        let ptr = unsafe { &raw mut (*self.obj().as_raw()).gpuva.lock };
        // SAFETY: The GEM object is valid, so the mutex is properly initialized.
        let mutex = unsafe { crate::sync::Mutex::from_raw(ptr) };
        mutex.lock()
    }
}

/// A pre-allocated [`GpuVmBo`] object.
///
/// # Invariants
///
/// Points at a `drm_gpuvm_bo` that contains a valid `T::VmBoData`, has a refcount of one, and is
/// absent from any gem, extobj, or evict lists.
pub(super) struct GpuVmBoAlloc<T: DriverGpuVm>(NonNull<GpuVmBo<T>>);

impl<T: DriverGpuVm> GpuVmBoAlloc<T> {
    /// Create a new pre-allocated [`GpuVmBo`].
    ///
    /// It's intentional that the initializer is infallible because `drm_gpuvm_bo_put` will call
    /// drop on the data, so we don't have a way to free it when the data is missing.
    #[inline]
    pub(super) fn new(
        gpuvm: &GpuVm<T>,
        gem: &T::Object,
        value: impl PinInit<T::VmBoData>,
    ) -> Result<GpuVmBoAlloc<T>, AllocError> {
        // CAST: `GpuVmBoAlloc::vm_bo_alloc` ensures that this memory was allocated with the layout
        // of `GpuVmBo<T>`. The type is repr(C), so `container_of` is not required.
        // SAFETY: The provided gpuvm and gem ptrs are valid for the duration of this call.
        let raw_ptr = unsafe {
            bindings::drm_gpuvm_bo_create(gpuvm.as_raw(), gem.as_raw()).cast::<GpuVmBo<T>>()
        };
        let ptr = NonNull::new(raw_ptr).ok_or(AllocError)?;
        // SAFETY: `ptr->data` is a valid pinned location.
        let Ok(()) = unsafe { value.__pinned_init(&raw mut (*raw_ptr).data) };
        // INVARIANTS: We just created the vm_bo so it's absent from lists, and the data is valid
        // as we just initialized it.
        Ok(GpuVmBoAlloc(ptr))
    }

    /// Returns a raw pointer to underlying C value.
    #[inline]
    pub(super) fn as_raw(&self) -> *mut bindings::drm_gpuvm_bo {
        // SAFETY: The pointer references a valid `drm_gpuvm_bo`.
        unsafe { (*self.0.as_ptr()).inner.get() }
    }

    /// Look up whether there is an existing [`GpuVmBo`] for this gem object.
    #[inline]
    pub(super) fn obtain(self) -> GpuVmBoResident<T> {
        let me = ManuallyDrop::new(self);
        // SAFETY: Valid `drm_gpuvm_bo` not already in the lists.
        let ptr = unsafe { bindings::drm_gpuvm_bo_obtain_prealloc(me.as_raw()) };

        // If the vm_bo does not already exist, ensure that it's in the extobj list.
        if ptr::eq(ptr, me.as_raw()) && me.gpuvm().is_extobj(me.obj()) {
            let resv_lock = me.gpuvm().raw_resv_lock();
            // SAFETY: The GPUVM is still alive, so its resv lock is too.
            unsafe { bindings::dma_resv_lock(resv_lock, ptr::null_mut()) };
            // SAFETY: We hold the GPUVMs resv lock.
            unsafe { bindings::drm_gpuvm_bo_extobj_add(ptr) };
            // SAFETY: We took the lock, so we can unlock it.
            unsafe { bindings::dma_resv_unlock(resv_lock) };
        }

        // INVARIANTS: Valid `drm_gpuvm_bo` in the GEM list.
        // SAFETY: `drm_gpuvm_bo_obtain_prealloc` always returns a non-null ptr
        GpuVmBoResident(unsafe { NonNull::new_unchecked(ptr.cast()) })
    }
}

impl<T: DriverGpuVm> Deref for GpuVmBoAlloc<T> {
    type Target = GpuVmBo<T>;
    #[inline]
    fn deref(&self) -> &GpuVmBo<T> {
        // SAFETY: By the type invariants we may deref while `Self` exists.
        unsafe { self.0.as_ref() }
    }
}

impl<T: DriverGpuVm> Drop for GpuVmBoAlloc<T> {
    #[inline]
    fn drop(&mut self) {
        // TODO: Call drm_gpuvm_bo_destroy_not_in_lists() directly.
        // SAFETY: It's safe to perform a deferred put in any context.
        unsafe { bindings::drm_gpuvm_bo_put_deferred(self.as_raw()) };
    }
}

/// A [`GpuVmBo`] object in the GEM list.
///
/// # Invariants
///
/// Points at a `drm_gpuvm_bo` that contains a valid `T::VmBoData` and is present in the gem list.
pub struct GpuVmBoResident<T: DriverGpuVm>(NonNull<GpuVmBo<T>>);

impl<T: DriverGpuVm> GpuVmBoResident<T> {
    /// Returns a raw pointer to underlying C value.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::drm_gpuvm_bo {
        // SAFETY: The pointer references a valid `drm_gpuvm_bo`.
        unsafe { (*self.0.as_ptr()).inner.get() }
    }
}

impl<T: DriverGpuVm> Deref for GpuVmBoResident<T> {
    type Target = GpuVmBo<T>;
    #[inline]
    fn deref(&self) -> &GpuVmBo<T> {
        // SAFETY: By the type invariants we may deref while `Self` exists.
        unsafe { self.0.as_ref() }
    }
}

impl<T: DriverGpuVm> Drop for GpuVmBoResident<T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: It's safe to perform a deferred put in any context.
        unsafe { bindings::drm_gpuvm_bo_put_deferred(self.as_raw()) };
    }
}
