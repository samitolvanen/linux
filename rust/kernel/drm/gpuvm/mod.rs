// SPDX-License-Identifier: GPL-2.0 OR MIT

#![cfg(CONFIG_DRM_GPUVM = "y")]

//! DRM GPUVM in immediate mode
//!
//! Rust abstractions for using GPUVM in immediate mode. This is when the GPUVM state is updated
//! during `run_job()`, i.e., in the DMA fence signalling critical path, to ensure that the GPUVM
//! and the GPU's virtual address space has the same state at all times.
//!
//! C header: [`include/drm/drm_gpuvm.h`](srctree/include/drm/drm_gpuvm.h)

use kernel::{
    alloc::{
        AllocError,
        Flags as AllocFlags, //
    },
    bindings,
    drm,
    drm::gem::IntoGEMObject,
    error::to_result,
    prelude::*,
    sync::aref::{
        ARef,
        AlwaysRefCounted, //
    },
    types::Opaque, //
};

use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    mem::{
        ManuallyDrop,
        MaybeUninit, //
    },
    ops::{
        Deref,
        DerefMut,
        Range, //
    },
    ptr::{
        self,
        NonNull, //
    }, //
};

mod sm_ops;
pub use self::sm_ops::*;

mod vm_bo;
pub use self::vm_bo::*;

mod va;
pub use self::va::*;

/// A DRM GPU VA manager.
///
/// This object is refcounted, but the "core" is only accessible using a special unique handle. The
/// core consists of the `core` field and the GPUVM's interval tree.
///
/// # Invariants
///
/// * Stored in an allocation managed by the refcount in `self.vm`.
/// * Access to `data` and the gpuvm interval tree is controlled via the [`GpuVmCore`] type.
#[pin_data]
pub struct GpuVm<T: DriverGpuVm> {
    #[pin]
    vm: Opaque<bindings::drm_gpuvm>,
    /// Accessed only through the [`GpuVmCore`] reference.
    data: UnsafeCell<T>,
}

// SAFETY: By type invariants, the allocation is managed by the refcount in `self.vm`.
unsafe impl<T: DriverGpuVm> AlwaysRefCounted for GpuVm<T> {
    fn inc_ref(&self) {
        // SAFETY: By type invariants, the allocation is managed by the refcount in `self.vm`.
        unsafe { bindings::drm_gpuvm_get(self.vm.get()) };
    }

    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: By type invariants, the allocation is managed by the refcount in `self.vm`.
        unsafe { bindings::drm_gpuvm_put((*obj.as_ptr()).vm.get()) };
    }
}

impl<T: DriverGpuVm> GpuVm<T> {
    const fn vtable() -> &'static bindings::drm_gpuvm_ops {
        &bindings::drm_gpuvm_ops {
            vm_free: Some(Self::vm_free),
            op_alloc: None,
            op_free: None,
            vm_bo_alloc: GpuVmBo::<T>::ALLOC_FN,
            vm_bo_free: GpuVmBo::<T>::FREE_FN,
            vm_bo_validate: None,
            sm_step_map: Some(Self::sm_step_map),
            sm_step_unmap: Some(Self::sm_step_unmap),
            sm_step_remap: Some(Self::sm_step_remap),
        }
    }

    /// Creates a GPUVM instance.
    #[expect(clippy::new_ret_no_self)]
    pub fn new<E>(
        name: &'static CStr,
        dev: &drm::Device<T::Driver>,
        r_obj: &T::Object,
        range: Range<u64>,
        reserve_range: Range<u64>,
        data: T,
    ) -> Result<GpuVmCore<T>, E>
    where
        E: From<AllocError>,
        E: From<core::convert::Infallible>,
    {
        let obj = KBox::try_pin_init::<E>(
            try_pin_init!(Self {
                data: UnsafeCell::new(data),
                vm <- Opaque::ffi_init(|vm| {
                    // SAFETY: These arguments are valid. `vm` is valid until refcount drops to
                    // zero.
                    unsafe {
                        bindings::drm_gpuvm_init(
                            vm,
                            name.as_char_ptr(),
                            bindings::drm_gpuvm_flags_DRM_GPUVM_IMMEDIATE_MODE
                                | bindings::drm_gpuvm_flags_DRM_GPUVM_RESV_PROTECTED,
                            dev.as_raw(),
                            r_obj.as_raw(),
                            range.start,
                            range.end - range.start,
                            reserve_range.start,
                            reserve_range.end - reserve_range.start,
                            const { Self::vtable() },
                        )
                    }
                }),
            }? E),
            GFP_KERNEL,
        )?;
        // SAFETY: This transfers the initial refcount to the ARef.
        Ok(GpuVmCore(unsafe {
            ARef::from_raw(NonNull::new_unchecked(KBox::into_raw(
                Pin::into_inner_unchecked(obj),
            )))
        }))
    }

    /// Access this [`GpuVm`] from a raw pointer.
    ///
    /// # Safety
    ///
    /// The pointer must reference the `struct drm_gpuvm` in a valid [`GpuVm<T>`] that remains
    /// valid for at least `'a`.
    #[inline]
    pub unsafe fn from_raw<'a>(ptr: *mut bindings::drm_gpuvm) -> &'a Self {
        // SAFETY: Caller passes a pointer to the `drm_gpuvm` in a `GpuVm<T>`. Caller ensures the
        // pointer is valid for 'a.
        unsafe { &*kernel::container_of!(Opaque::cast_from(ptr), Self, vm) }
    }

    /// Returns a raw pointer to the embedded `struct drm_gpuvm`.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::drm_gpuvm {
        self.vm.get()
    }

    /// The start of the VA space.
    #[inline]
    pub fn va_start(&self) -> u64 {
        // SAFETY: The `mm_start` field is immutable.
        unsafe { (*self.as_raw()).mm_start }
    }

    /// The length of the GPU's virtual address space.
    #[inline]
    pub fn va_length(&self) -> u64 {
        // SAFETY: The `mm_range` field is immutable.
        unsafe { (*self.as_raw()).mm_range }
    }

    /// Returns the range of the GPU virtual address space.
    #[inline]
    pub fn va_range(&self) -> Range<u64> {
        let start = self.va_start();
        // OVERFLOW: This reconstructs the Range<u64> passed to the constructor, so it won't fail.
        let end = start + self.va_length();
        Range { start, end }
    }

    /// Get or create the [`GpuVmBo`] for this gem object.
    #[inline]
    pub fn obtain(
        &self,
        obj: &T::Object,
        data: impl PinInit<T::VmBoData>,
    ) -> Result<GpuVmBoResident<T>, AllocError> {
        Ok(GpuVmBoAlloc::new(self, obj, data)?.obtain())
    }

    /// Clean up buffer objects that are no longer used.
    #[inline]
    pub fn deferred_cleanup(&self) {
        // SAFETY: This GPUVM uses immediate mode.
        unsafe { bindings::drm_gpuvm_bo_deferred_cleanup(self.as_raw()) }
    }

    /// Check if this GEM object is an external object for this GPUVM.
    #[inline]
    pub fn is_extobj(&self, obj: &T::Object) -> bool {
        // SAFETY: We may call this with any GPUVM and GEM object.
        unsafe { bindings::drm_gpuvm_is_extobj(self.as_raw(), obj.as_raw()) }
    }

    /// Free this GPUVM.
    ///
    /// # Safety
    ///
    /// Called when refcount hits zero.
    unsafe extern "C" fn vm_free(me: *mut bindings::drm_gpuvm) {
        // SAFETY: Caller passes a pointer to the `drm_gpuvm` in a `GpuVm<T>`.
        let me = unsafe { kernel::container_of!(Opaque::cast_from(me), Self, vm).cast_mut() };
        // SAFETY: By type invariants we can free it when refcount hits zero.
        drop(unsafe { KBox::from_raw(me) })
    }

    #[inline]
    fn raw_resv_lock(&self) -> *mut bindings::dma_resv {
        // SAFETY: `r_obj` is immutable and valid for duration of GPUVM.
        unsafe { (*(*self.as_raw()).r_obj).resv }
    }
}

/// The manager for a GPUVM.
pub trait DriverGpuVm: Sized {
    /// Parent `Driver` for this object.
    type Driver: drm::Driver;

    /// The kind of GEM object stored in this GPUVM.
    type Object: IntoGEMObject;

    /// Data stored with each `struct drm_gpuva`.
    type VaData;

    /// Data stored with each `struct drm_gpuvm_bo`.
    type VmBoData;

    /// The private data passed to callbacks.
    type SmContext<'ctx>;

    /// Indicates that a new mapping should be created.
    fn sm_step_map<'op, 'ctx>(
        &mut self,
        op: OpMap<'op, Self>,
        context: &mut Self::SmContext<'ctx>,
    ) -> Result<OpMapped<'op, Self>, Error>;

    /// Indicates that an existing mapping should be removed.
    fn sm_step_unmap<'op, 'ctx>(
        &mut self,
        op: OpUnmap<'op, Self>,
        context: &mut Self::SmContext<'ctx>,
    ) -> Result<OpUnmapped<'op, Self>, Error>;

    /// Indicates that an existing mapping should be split up.
    fn sm_step_remap<'op, 'ctx>(
        &mut self,
        op: OpRemap<'op, Self>,
        context: &mut Self::SmContext<'ctx>,
    ) -> Result<OpRemapped<'op, Self>, Error>;
}

/// The core of the DRM GPU VA manager.
///
/// This object is a unique reference to the VM that can access the interval tree and the Rust
/// `data` field.
///
/// # Invariants
///
/// Each `GpuVm` instance has at most one `GpuVmCore` reference.
pub struct GpuVmCore<T: DriverGpuVm>(ARef<GpuVm<T>>);

impl<T: DriverGpuVm> GpuVmCore<T> {
    /// Access the core data of this GPUVM.
    #[inline]
    pub fn data(&mut self) -> &mut T {
        // SAFETY: By the type invariants we may access `core`.
        unsafe { &mut *self.0.data.get() }
    }
}

impl<T: DriverGpuVm> Deref for GpuVmCore<T> {
    type Target = GpuVm<T>;

    #[inline]
    fn deref(&self) -> &GpuVm<T> {
        &self.0
    }
}
