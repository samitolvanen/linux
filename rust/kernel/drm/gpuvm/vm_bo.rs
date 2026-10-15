// SPDX-License-Identifier: GPL-2.0 OR MIT

use super::*;
use crate::{
    interop::list::clist_create,
    sync::{
        Mutex,
        MutexGuard, //
    }, //
};

/// Represents that a given GEM object has at least one mapping on this [`GpuVm`] instance.
///
/// Does not assume that GEM lock is held.
///
/// # Invariants
///
/// * Allocated with `kmalloc` and refcounted via `inner`.
/// * Is present in the gem list.
#[repr(C)]
#[pin_data]
pub struct GpuVmBo<T: DriverGpuVm> {
    #[pin]
    inner: Opaque<bindings::drm_gpuvm_bo>,
    #[pin]
    data: T::VmBoData,
}

// SAFETY: It is safe to send a `GpuVmBo<T>` to another thread: dropping it there drops
// `T::VmBoData` and the GEM `T::Object`, both `Send` by the `DriverGpuVm` bounds.
unsafe impl<T: DriverGpuVm> Send for GpuVmBo<T> {}

// SAFETY: It is safe to share a `&GpuVmBo<T>` between threads: it effectively shares
// `&T::VmBoData` and the GEM `&T::Object` (both `Sync`), and any thread may upgrade to an
// `ARef` and ultimately drop them (both `Send`), per the `DriverGpuVm` bounds.
unsafe impl<T: DriverGpuVm> Sync for GpuVmBo<T> {}

// SAFETY: By type invariants, the allocation is managed by the refcount in `self.inner`.
unsafe impl<T: DriverGpuVm> AlwaysRefCounted for GpuVmBo<T> {
    fn inc_ref(&self) {
        // SAFETY: By type invariants, the allocation is managed by the refcount in `self.inner`.
        unsafe { bindings::drm_gpuvm_bo_get(self.inner.get()) };
    }

    unsafe fn dec_ref(obj: NonNull<Self>) {
        // CAST: `drm_gpuvm_bo` is first field of repr(C) struct.
        // SAFETY: By type invariants, the allocation is managed by the refcount in `self.inner`.
        // This GPUVM instance uses immediate mode, so we may put the refcount using the deferred
        // mechanism.
        unsafe { bindings::drm_gpuvm_bo_put_deferred(obj.as_ptr().cast()) };
    }
}

impl<T: DriverGpuVm> PartialEq for GpuVmBo<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.as_raw(), other.as_raw())
    }
}
impl<T: DriverGpuVm> Eq for GpuVmBo<T> {}

impl<T: DriverGpuVm> GpuVmBo<T> {
    /// The function pointer for allocating a GpuVmBo stored in the gpuvm vtable.
    ///
    /// Allocation is always implemented according to [`Self::vm_bo_alloc`], but it is set to
    /// `None` if the default gpuvm behavior is the same as `vm_bo_alloc`.
    ///
    /// This may be `Some` even if `FREE_FN` is `None`, or vice-versa.
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

    /// The function pointer for freeing a GpuVmBo stored in the gpuvm vtable.
    ///
    /// Freeing is always implemented according to [`Self::vm_bo_free`], but it is set to `None` if
    /// the default gpuvm behavior is the same as `vm_bo_free`.
    ///
    /// This may be `Some` even if `ALLOC_FN` is `None`, or vice-versa.
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
    unsafe extern "C" fn vm_bo_alloc() -> *mut bindings::drm_gpuvm_bo {
        let raw_ptr = KBox::<Self>::new_uninit(GFP_KERNEL | __GFP_ZERO)
            .map(KBox::into_raw)
            .unwrap_or(ptr::null_mut());

        // CAST: `drm_gpuvm_bo` is first field of `Self`.
        raw_ptr.cast()
    }

    /// Custom function for freeing a `drm_gpuvm_bo`.
    ///
    /// # Safety
    ///
    /// The pointer must have been allocated with [`GpuVmBo::ALLOC_FN`], and must not be used after
    /// this call.
    unsafe extern "C" fn vm_bo_free(ptr: *mut bindings::drm_gpuvm_bo) {
        // CAST: `drm_gpuvm_bo` is first field of `Self`.
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
    /// a [`GpuVm<T>`]. The BO must also be present in the GEM list.
    #[inline]
    pub(crate) unsafe fn from_raw<'a>(ptr: *mut bindings::drm_gpuvm_bo) -> &'a Self {
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

    /// The [`drm_gem_object`](DriverGpuVm::Object) for these mappings.
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
        gpuva_mutex(self.obj()).lock()
    }

    /// Returns an iterator over the [`GpuVa`]s of this `vm_bo`.
    ///
    /// Returns [`EINVAL`] if `guard` holds the gpuva lock of another object. An `ARef<GpuVmBo>`
    /// made from the returned `GpuVa`s must not be dropped while `guard` is held. The `GpuVa`s
    /// match the VA tree only while no `sm_map()` or `sm_unmap()` runs on the GPUVM.
    pub fn vas<'a>(
        &'a self,
        guard: &'a GemGpuvaGuard<'_, T>,
    ) -> Result<impl Iterator<Item = &'a GpuVa<T>>>
    where
        T::VaData: Sync,
    {
        if !ptr::eq(guard.obj, self.obj()) {
            return Err(EINVAL);
        }

        // SAFETY: `self` is a valid `drm_gpuvm_bo`.
        let head = unsafe { &raw mut (*self.as_raw()).list.gpuva };

        // SAFETY: By the type invariants of `GemGpuvaGuard`, `guard` holds the gpuva lock of the
        // object of `self`, as checked above, which keeps the list unchanged while `guard` is
        // borrowed. The list links the `drm_gpuva`s of this `vm_bo` through `gem.entry`, and each
        // is the first field of a `repr(C)` `GpuVa<T>`. `T::VaData: Sync` allows sharing their data
        // with the threads of the GPUVM.
        let vas = unsafe { clist_create!(head, GpuVa<T>, bindings::drm_gpuva, gem.entry) };

        Ok(vas.iter())
    }
}

/// Returns the mutex that protects the GPU VA lists of `obj`.
fn gpuva_mutex<O: IntoGEMObject>(obj: &O) -> &Mutex<()> {
    // SAFETY: The GEM object is valid, so its gpuva lock is initialized and lives as long as
    // `obj`.
    unsafe { Mutex::from_raw(&raw mut (*obj.as_raw()).gpuva.lock) }
}

/// A guard that holds the gpuva lock of a GEM object.
///
/// The gpuva lock protects the list of [`GpuVmBo`]s of the object, and the list of [`GpuVa`]s of
/// each of them. Dropping the last reference to a [`GpuVmBo`] takes the gpuva lock of its object,
/// so no `ARef<GpuVmBo>` may be dropped while the guard is held.
///
/// The gpuva locks of all objects share one lockdep class, so two guards must not be nested.
///
/// # Invariants
///
/// `_guard` holds the gpuva lock of `obj`.
#[must_use = "the lock unlocks immediately when the guard is unused"]
pub struct GemGpuvaGuard<'a, T: DriverGpuVm> {
    obj: &'a T::Object,
    _guard: MutexGuard<'a, ()>,
}

impl<'a, T: DriverGpuVm> GemGpuvaGuard<'a, T> {
    /// Takes the gpuva lock of `obj`, sleeping until it is available.
    #[inline]
    pub fn lock(obj: &'a T::Object) -> Self {
        // INVARIANT: The guard holds the gpuva lock of `obj`.
        Self {
            obj,
            _guard: gpuva_mutex(obj).lock(),
        }
    }

    /// Tries to take the gpuva lock of `obj` without sleeping.
    ///
    /// Returns `None` if the lock is held.
    #[inline]
    pub fn try_lock(obj: &'a T::Object) -> Option<Self> {
        // INVARIANT: The guard holds the gpuva lock of `obj`.
        Some(Self {
            obj,
            _guard: gpuva_mutex(obj).try_lock()?,
        })
    }

    /// Returns the object whose gpuva lock is held.
    #[inline]
    pub fn obj(&self) -> &'a T::Object {
        self.obj
    }
}

impl<T: ExclusiveObjects> GemGpuvaGuard<'_, T> {
    /// Returns an iterator over the [`GpuVmBo`]s of the object.
    ///
    /// An `ARef` made from the returned references must not be dropped while the guard is held.
    pub fn vm_bos(&self) -> impl Iterator<Item = &GpuVmBo<T>> {
        // SAFETY: The object is valid.
        let head = unsafe { &raw mut (*self.obj.as_raw()).gpuva.list };

        // SAFETY: By the type invariants, `self` holds the gpuva lock, which keeps the list
        // unchanged while `self` is borrowed. The list links the `drm_gpuvm_bo`s of the object
        // through `list.entry.gem`. By `T: ExclusiveObjects`, each belongs to a `GpuVm<T>`, so it
        // is the first field of a `repr(C)` `GpuVmBo<T>`.
        let vm_bos =
            unsafe { clist_create!(head, GpuVmBo<T>, bindings::drm_gpuvm_bo, list.entry.gem) };

        vm_bos.iter()
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
        unsafe { pin_init::raw_init(&raw mut (*raw_ptr).data, value) };
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
    ///
    /// The caller should not hold the GEM mutex or DMA resv lock.
    #[inline]
    pub(super) fn obtain(self) -> ARef<GpuVmBo<T>> {
        let me = ManuallyDrop::new(self);
        // SAFETY: Valid `drm_gpuvm_bo` not already in the lists. We do not access `me` after this
        // call.
        let ptr = unsafe { bindings::drm_gpuvm_bo_obtain_prealloc(me.as_raw()) };

        // SAFETY: `drm_gpuvm_bo_obtain_prealloc` always returns a non-null ptr
        let nonnull = unsafe { NonNull::new_unchecked(ptr.cast()) };

        // INVARIANTS: `drm_gpuvm_bo_obtain_prealloc` ensures that the bo is in the GEM list.
        // SAFETY: We received one refcount from `drm_gpuvm_bo_obtain_prealloc`.
        let ret = unsafe { ARef::<GpuVmBo<T>>::from_raw(nonnull) };

        // Ensure that external objects are in the extobj list.
        //
        // Note that we must call `extobj_add` even if `ptr != me` to avoid a race condition where
        // we could end up using the extobj before the thread with `ptr == me` calls extobj_add.
        if ret.gpuvm().is_extobj(ret.obj()) {
            let _resv = ret.gpuvm().root_obj().lock_resv();
            // SAFETY: We hold the GPUVMs resv lock.
            unsafe { bindings::drm_gpuvm_bo_extobj_add(ptr) };
        }

        ret
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
