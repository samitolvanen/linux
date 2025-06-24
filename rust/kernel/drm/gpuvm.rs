// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DRM GPU VA Manager abstractions.
//!
//! This can be used to manage GPU virtual address spaces, which in turn makes
//! it easier to implement `bind` and `unbind` operations. Notably, using
//! `GpuVm` makes it easier to support Vulkan
//! [Sparse Resources](https://docs.vulkan.org/spec/latest/chapters/sparsemem.html).
//!
//! See [GPUVM](https://docs.kernel.org/gpu/drm-mm.html#gpuvm) for more information.
//!
//! C header: [`include/drm/drm_gpuvm.h`](srctree/include/drm/drm_gpuvm.h)

use core::marker::PhantomData;
use core::marker::PhantomPinned;
use core::ops::Deref;
use core::ops::DerefMut;
use core::ops::Range;
use core::ptr::NonNull;

use pin_init::pin_init_from_closure;

use crate::bindings;
use crate::drm::device;
use crate::drm::driver;
use crate::drm::gem;
use crate::drm::gem::IntoGEMObject;
use crate::error::code::ENOMEM;
use crate::error::from_result;
use crate::error::to_result;
use crate::error::Result;
use crate::prelude::*;
use crate::types::ARef;
use crate::types::AlwaysRefCounted;
use crate::types::Opaque;

/// A convenience type for the driver's GEM object.
type Object<T> =
    <<<T as DriverGpuVm>::Driver as driver::Driver>::Object as gem::DriverObject>::Object;

/// Trait that must be implemented by DRM drivers to represent a DRM [`GpuVm`],
/// i.e. a GPU address space.
///
/// The driver has to provide the hardware-specific implementations to map,
/// unmap and remap GPU virtual addresses as needed.
pub trait DriverGpuVm: Sized {
    /// The parent [`driver::Driver`] implementation for this [`DriverGpuVm`].
    type Driver: driver::Driver;

    /// The driver-specific GpuVa type, repesenting a single VA range within the
    /// GPU.
    type GpuVa: DriverGpuVa;

    /// The driver-specific GpuVmBo type, representing the connection between a
    /// GEM object and [`GpuVm`].
    type GpuVmBo: DriverGpuVmBo;

    /// The driver-specific context that is kept through the map, unmap and
    /// remap steps.
    type StepContext;

    /// Implements the map step for the driver.
    fn step_map(
        gpuvm: &mut GpuVm<Self>,
        op: &mut OpMap<Self>,
        ctx: &mut Self::StepContext,
    ) -> Result;

    /// Implements the unmap step for the driver.
    fn step_unmap(
        gpuvm: &mut GpuVm<Self>,
        op: &mut OpUnMap<Self>,
        ctx: &mut Self::StepContext,
    ) -> Result;

    /// Implements the remap step for the driver.
    fn step_remap(
        gpuvm: &mut GpuVm<Self>,
        op: &mut OpReMap<Self>,
        vm_bo: &GpuVmBo<Self>,
        ctx: &mut Self::StepContext,
    ) -> Result;
}

/// The driver-specific context that is passed through the map, unmap and remap
/// steps.
struct StepContext<'a, T: DriverGpuVm> {
    gpuvm: &'a mut GpuVm<T>,
    ctx: &'a mut T::StepContext,
}

/// Trait that must be implemented by DRM drivers to represent a DRM [`GpuVa`],
/// i.e.: a mapping in GPU address space.
pub trait DriverGpuVa: Sized {}

/// Trait that must be implemented by DRM drivers to represent a DRM
/// [`GpuVmBo`], i.e.: a connection between a BO and a VM.
pub trait DriverGpuVmBo: Sized {
    /// Initializes the GpuVmBo object.
    fn new() -> impl PinInit<Self>;
}

/// Provides a default implementation for trivial types
impl<T: Default> DriverGpuVmBo for T {
    fn new() -> impl PinInit<Self> {
        // SAFETY:
        // - `Ok(())` is always returned.
        // - The slot is never moved.
        unsafe {
            pin_init_from_closure(|slot| {
                *slot = Self::default();
                Ok(())
            })
        }
    }
}

/// A transparent wrapper over
/// [`bindings::drm_gpuva_op_map`](https://docs.kernel.org/gpu/drm-mm.html#c.drm_gpuva_op_map)
///
/// Represents the map operation to be carried out by the driver.
#[repr(transparent)]
pub struct OpMap<T: DriverGpuVm>(Opaque<bindings::drm_gpuva_op_map>, PhantomData<T>);

impl<T: DriverGpuVm> OpMap<T> {
    /// Returns the base address of the new mapping.
    #[inline]
    pub fn addr(&self) -> u64 {
        let ptr = self.0.get();

        // SAFETY: `self.0` is a valid pointer to a `drm_gpuva_op_map` structure,
        unsafe { *ptr }.va.addr
    }

    /// Returns the length of the new mapping.
    #[inline]
    pub fn length(&self) -> u64 {
        let ptr = self.0.get();

        // SAFETY: `self.0` is a valid pointer to a `drm_gpuva_op_map` structure,
        unsafe { *ptr }.va.range
    }

    /// Returns the range of the new mapping.
    #[inline]
    pub fn range(&self) -> Range<u64> {
        let start = self.addr();
        let end = start + self.length();
        Range { start, end }
    }

    /// Returns the offset within the GEM object.
    #[inline]
    pub fn gem_offset(&self) -> u64 {
        let ptr = self.0.get();

        // SAFETY: `self.0` is a valid pointer to a `drm_gpuva_op_map` structure,
        unsafe { *ptr }.gem.offset
    }

    /// Returns the GEM object to map.
    #[inline]
    pub fn object(&self) -> &Object<T> {
        // SAFETY: Safe as per the invariants of `self`.
        let gem = unsafe { *self.0.get() }.gem.obj;

        // SAFETY: The GEM object has an active reference for the lifetime of this op.
        unsafe { <Object<T> as IntoGEMObject>::from_raw(gem) }
    }
}

/// A transparent wrapper over
/// [`bindings::drm_gpuva_op_remap`](https://docs.kernel.org/gpu/drm-mm.html#c.drm_gpuva_op_remap).
///
/// Represents a single remap operation generated by [`GpuVm`].
///
/// A remap operation is generated when an existing [`GpuVa`] mapping is split
/// by inserting a new one or by partially unmapping existing mappings. Hence,
/// it consists of a maximum of two maps and one unmap operation,
///
/// The unmap operation takes care of removing the original existing mapping.
/// The `prev` field is used to remap the preceding part and `next` is used to
/// remap the subsequent part.
///
/// If the start address of the new mapping aligns with the start address of the
/// old mapping, `prev` will be `None`. Similarly, if the end address of the new
/// mapping aligns with the end address of the old mapping, `next` will be
/// `None`.
///
/// Note: the reason for a dedicated remap operation, rather than arbitrary
/// unmap and map operations, is to give drivers the chance of extracting driver
/// specific data for creating the new mappings from the unmap operations's
/// [`GpuVa`] structure which typically is embedded in larger driver specific
/// structures.
#[repr(transparent)]
pub struct OpReMap<T: DriverGpuVm>(bindings::drm_gpuva_op_remap, PhantomData<T>);

/// A transparent wrapper over
/// [`bindings::drm_gpuva_op_unmap`](https://docs.kernel.org/gpu/drm-mm.html#c.drm_gpuva_op_unmap).
///
/// Represents a single unmap operation generated by [`GpuVm`].
#[repr(transparent)]
pub struct OpUnMap<T: DriverGpuVm>(bindings::drm_gpuva_op_unmap, PhantomData<T>);

impl<T: DriverGpuVm> OpUnMap<T> {
    /// Returns the GPU VA to unmap.
    #[inline]
    pub fn va(&self) -> Option<&GpuVa<T>> {
        if self.0.va.is_null() {
            return None;
        }
        // SAFETY: Container invariant is guaranteed for ops structs created for our types.
        let p = unsafe {
            crate::container_of!(
                self.0.va.cast::<Opaque<bindings::drm_gpuva>>(),
                GpuVa<T>,
                gpuva
            )
        };
        // SAFETY: The GpuVa object reference is valid per the op_unmap contract
        Some(unsafe { &*p })
    }

    /// Indicates whether this [`GpuVa`] is physically contiguous with the
    /// original mapping request.
    ///
    /// Optionally, if `keep` is set, drivers may keep the actual page table
    /// mappings for this [`GpuVa`], adding the missing page table entries only and
    /// subsequently updating the VM accordingly.
    #[inline]
    pub fn keep(&self) -> bool {
        self.0.keep
    }
}

impl<T: DriverGpuVm> OpReMap<T> {
    /// Returns the preceding part of a split mapping, if any.
    #[inline]
    pub fn prev_map(&mut self) -> Option<&mut OpMap<T>> {
        // SAFETY: The prev pointer must be valid if not-NULL per the op_remap contract
        unsafe { (self.0.prev as *mut OpMap<T>).as_mut() }
    }

    /// Returns the subsequent part of a split mapping, if any.
    #[inline]
    pub fn next_map(&mut self) -> Option<&mut OpMap<T>> {
        // SAFETY: The next pointer must be valid if not-NULL per the op_remap contract
        unsafe { (self.0.next as *mut OpMap<T>).as_mut() }
    }

    /// Returns the unmap operation for the original existing mapping.
    #[inline]
    pub fn unmap(&mut self) -> &mut OpUnMap<T> {
        // SAFETY: The unmap pointer is always valid per the op_remap contract
        unsafe { (self.0.unmap as *mut OpUnMap<T>).as_mut().unwrap() }
    }
}

/// A GPU VA range.
///
/// Drivers can use `inner` to store additional data.
///
/// # Invariants
///
/// At all times, `gpuva` is safe to dereference, as it's either zeroed or
/// otherwise initialized from an operation.
#[repr(C)]
#[pin_data]
pub struct GpuVa<T: DriverGpuVm> {
    #[pin]
    gpuva: Opaque<bindings::drm_gpuva>,
    #[pin]
    inner: T::GpuVa,
    #[pin]
    _p: PhantomPinned,
}

impl<T: DriverGpuVm> GpuVa<T> {
    /// Creates a new GPU VA.
    pub fn new<E>(inner: impl PinInit<T::GpuVa, E>) -> Result<Pin<KBox<GpuVa<T>>>>
    where
        Error: From<E>,
    {
        KBox::try_pin_init(
            try_pin_init!(Self {
                gpuva <- Opaque::zeroed(),
                inner <- inner,
                _p: PhantomPinned
            }),
            GFP_KERNEL,
        )
    }

    /// Returns the start address of the GPU VA range.
    #[inline]
    pub fn addr(&self) -> u64 {
        // SAFETY: Safe as per the invariants of self.
        unsafe { *self.gpuva.get() }.va.addr
    }

    /// Returns the length of the GPU VA.
    #[inline]
    pub fn length(&self) -> u64 {
        // SAFETY: Safe as per the invariants of self.
        unsafe { *self.gpuva.get() }.va.range
    }

    /// Returns the length of the GPU VA.
    #[inline]
    pub fn range(&self) -> Range<u64> {
        let start = self.addr();
        let end = start + self.length();
        Range { start, end }
    }

    /// Returns the offset within the GEM object.
    #[inline]
    pub fn gem_offset(&self) -> u64 {
        // SAFETY: Safe as per the invariants of self.
        unsafe { *self.gpuva.get() }.gem.offset
    }

    /// Returns the underlying [`GpuVmBo`] object that backs this [`GpuVa`].
    pub fn vm_bo(&self) -> Option<ARef<GpuVmBo<T>>> {
        // SAFETY: Safe by the type invariant of `GpuVa<T>`.
        let vm_bo = unsafe { *self.gpuva.get() }.vm_bo;

        if vm_bo.is_null() {
            return None;
        }

        // SAFETY: Safe by the type invariant of `GpuVmBo<T>`.
        unsafe { bindings::drm_gpuvm_bo_get(vm_bo) };

        // SAFETY: Container invariant is guaranteed for GpuVmBo<T> objects.
        let vm_bo = unsafe {
            crate::container_of!(
                vm_bo.cast::<Opaque<bindings::drm_gpuvm_bo>>(),
                GpuVmBo<T>,
                bo
            )
        };

        // SAFETY: We just incremented the reference count above.
        Some(unsafe { ARef::from_raw(NonNull::new_unchecked(vm_bo)) })
    }
}

/// The connection between a GEM object and a VM.
///
/// # Invariants
///
/// At all times, `bo` is safe to dereference, as it's initialized by the C code
/// on a call to [`GpuVm::obtain_bo`].
#[repr(C)]
#[pin_data]
pub struct GpuVmBo<T: DriverGpuVm> {
    #[pin]
    bo: Opaque<bindings::drm_gpuvm_bo>,
    #[pin]
    inner: T::GpuVmBo,
    #[pin]
    _p: PhantomPinned,
}

impl<T: DriverGpuVm> GpuVmBo<T> {
    /// Returns the underlying GEM object that this [`GpuVmBo`] is connected to.
    pub fn gem(&self) -> &Object<T> {
        // SAFETY: safe as per the invariants of self.
        let bo = unsafe { *self.bo.get() }.obj;

        // SAFETY: The GEM object has an active reference for the lifetime of
        // this GpuVmBo and `obj` was set to a pointer to `BaseObject` in
        // `obtain_bo()`.
        unsafe { <Object<T> as IntoGEMObject>::from_raw(bo) }
    }
}

// SAFETY: DRM GpuVmBo objects are always reference counted and the get/put functions
// satisfy the requirements.
unsafe impl<T: DriverGpuVm> AlwaysRefCounted for GpuVmBo<T> {
    fn inc_ref(&self) {
        // SAFETY: The drm_gpuvm_get function satisfies the requirements for inc_ref().
        unsafe { bindings::drm_gpuvm_bo_get(&self.bo as *const _ as *mut _) };
    }

    unsafe fn dec_ref(mut obj: NonNull<Self>) {
        // SAFETY:
        // - The drm_gpuvm_put function satisfies the requirements for dec_ref().
        // - The `bo` field is valid to dereference for the lifetime of self.
        // - Given the above, and the fact that the reference rules are
        //   respected, it is ok to create a reference from `obj` here
        unsafe {
            // TODO: switch to the locked version of this function once available.
            bindings::drm_gpuvm_bo_put(obj.as_mut().bo.get());
        }
    }
}

impl<T: DriverGpuVm> Deref for GpuVmBo<T> {
    type Target = T::GpuVmBo;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// The DRM GPU VA Manager.
///
/// It keeps track of a GPU's virtual address space by using maple tree
/// structures.
///
/// Typically, an instance of [`GpuVm`] is embedded bigger, driver-specific
/// structures.
///
/// Drivers can pass addresses and ranges in arbitrary units, e.g.: bytes or
/// pages.
///
/// There should be one manager instance per GPU virtual address space.
#[repr(C)]
#[pin_data]
pub struct GpuVm<T: DriverGpuVm> {
    #[pin]
    gpuvm: Opaque<bindings::drm_gpuvm>,
    #[pin]
    inner: T,
    #[pin]
    _p: PhantomPinned,
}

impl<T: DriverGpuVm> GpuVm<T> {
    const OPS: bindings::drm_gpuvm_ops = bindings::drm_gpuvm_ops {
        vm_free: Some(vm_free_callback::<T>),
        op_alloc: None,
        op_free: None,
        vm_bo_alloc: Some(vm_bo_alloc_callback::<T>),
        vm_bo_free: Some(vm_bo_free_callback::<T>),
        vm_bo_validate: None,
        sm_step_map: Some(step_map_callback::<T>),
        sm_step_remap: Some(step_remap_callback::<T>),
        sm_step_unmap: Some(step_unmap_callback::<T>),
    };

    /// Creates a GPUVM instance.
    pub fn new<E>(
        name: &'static CStr,
        dev: &device::Device<T::Driver>,
        r_obj: &Object<T>,
        range: Range<u64>,
        reserve_range: Range<u64>,
        inner: impl PinInit<T, E>,
    ) -> Result<ARef<GpuVm<T>>>
    where
        Error: From<E>,
    {
        let obj: Pin<KBox<Self>> = KBox::try_pin_init(
            try_pin_init!(Self {
                // SAFETY: drm_gpuvm_init cannot fail and always initializes the member.
                gpuvm <- unsafe {
                    pin_init::pin_init_from_closure(move |slot: *mut Opaque<bindings::drm_gpuvm> | {
                        // Zero-init required by drm_gpuvm_init.
                        *slot = core::mem::zeroed();
                        bindings::drm_gpuvm_init(
                            Opaque::cast_into(slot),
                            name.as_char_ptr(),
                            0,
                            dev.as_raw(),
                            r_obj.as_raw(),
                            range.start,
                            range.end - range.start,
                            reserve_range.start,
                            reserve_range.end - reserve_range.start,
                            &Self::OPS
                        );
                        Ok(())
                    })
                },
                inner <- inner,
                _p: PhantomPinned
            }),
            GFP_KERNEL,
        )?;

        // SAFETY: We never move out of the object.
        let vm_ref = unsafe {
            ARef::from_raw(NonNull::new_unchecked(KBox::leak(
                Pin::into_inner_unchecked(obj),
            )))
        };

        Ok(vm_ref)
    }

    /// A helper function to insert a [`GpuVa`] into the the [`GpuVm`].
    ///
    /// This will internally add the [`GpuVa`] to the interval tree.
    pub fn insert_va(
        &mut self,
        op_map: &mut OpMap<T>,
        gpuva: Pin<KBox<GpuVa<T>>>,
    ) -> Result<(), Pin<KBox<GpuVa<T>>>> {
        // SAFETY: It is always safe to initialize a GpuVa from an op.
        unsafe {
            bindings::drm_gpuva_init_from_op(gpuva.gpuva.get(), op_map.0.get());
        }

        // SAFETY:
        // - `gpuvm` is valid by our type invariant.
        // - `gpuva` was initialized above.
        if unsafe { bindings::drm_gpuva_insert(self.gpuvm.get(), gpuva.gpuva.get()) } != 0 {
            // EEXIST, return the GpuVa to the caller as an error
            return Err(gpuva);
        };

        // SAFETY: We are handing off the GpuVa ownership and it will not be moved.
        KBox::leak(unsafe { Pin::into_inner_unchecked(gpuva) });

        Ok(())
    }

    /// Links the given [`MappedGpuVa`] in the given [`GpuVmBo`].
    pub fn link_va(&self, gpuva: ResidentGpuVa<'_, T>, gpuvmbo: &ARef<GpuVmBo<T>>) -> Result {
        // SAFETY:
        // - We make sure that the gpuva has been previously mapped, so it's
        // been initialized from an op.
        // - This takes a new reference to the gpuvmbo.
        // - The gpuvmbo is guaranteed to be valid through ARef.
        unsafe { bindings::drm_gpuva_link(gpuva.gpuva.get(), gpuvmbo.bo.get()) }
        Ok(())
    }

    /// Removes the given [`GpuVa`] from the [`GpuVm`] instance.
    ///
    /// This removes the [`GpuVa`] from the interval tree and returns a special
    /// type that can be used to unlink the [`GpuVa`] later.
    pub fn remove_va(&mut self, gpuva: ResidentGpuVa<'_, T>) -> Result<RemovedGpuVa<T>> {
        // SAFETY: The gpuva is guaranteed to be valid through the type invariant.
        unsafe { bindings::drm_gpuva_remove(gpuva.gpuva.get()) };

        // SAFETY: We are handing off the GpuVa ownership from a previous call
        // to [`KBox::leak`] that was made in [`GpuVm::insert_va`].
        let gpuva = unsafe { KBox::from_raw(gpuva.0) };

        // SAFETY: The `gpuva` instance was pinned when [`GpuVm::insert_va`] was
        // called. It remained pinned by the C GPUVM code.
        Ok(RemovedGpuVa(unsafe { Pin::new_unchecked(gpuva) }))
    }

    /// Unlinks a previously linked [`GpuVa`] from the [`GpuVmBo`].
    pub fn unlink_va(&self, gpuva: &RemovedGpuVa<T>) {
        // SAFETY: Safe as per the type invariant of `GpuVa<T>`.
        unsafe { bindings::drm_gpuva_unlink(gpuva.0.gpuva.get()) };
    }

    /// Finds the [`GpuVmBo`] object that connects `obj` to this VM.
    ///
    /// If found, increases the reference count of the GpuVmBo object
    /// accordingly.
    pub fn find_bo(&mut self, obj: &Object<T>) -> Option<ARef<GpuVmBo<T>>> {
        // SAFETY: LockedGpuVm implies the right locks are held.
        let p = unsafe { bindings::drm_gpuvm_bo_find(self.gpuvm.get(), obj.as_raw()) };

        if p.is_null() {
            return None;
        }

        // SAFETY: All the drm_gpuvm_bo objects in this GpuVm are always
        // allocated by us as GpuVmBo<T>.
        let p = unsafe {
            crate::container_of!(p.cast::<Opaque<bindings::drm_gpuvm_bo>>(), GpuVmBo<T>, bo)
        };
        // SAFETY: We checked for NULL above, and the types ensure that
        // this object was created by vm_bo_alloc_callback<T>.
        Some(unsafe { ARef::from_raw(NonNull::new_unchecked(p)) })
    }

    /// Obtains the [`GpuVmBo`] object that connects `obj` to this VM.
    ///
    /// This connection is unique, so an instane of [`GpuVmBo`] will be
    /// allocated for `obj` once, and that instance will be returned from that
    /// point forward.
    pub fn obtain_bo(&self, obj: &Object<T>) -> Result<ARef<GpuVmBo<T>>> {
        // SAFETY: LockedGpuVm implies the right locks are held.
        let p = unsafe { bindings::drm_gpuvm_bo_obtain(self.gpuvm.get(), obj.as_raw()) };

        if p.is_null() {
            return Err(ENOMEM);
        }

        // SAFETY: Container invariant is guaranteed for GpuVmBo objects for this GpuVm.
        let p = unsafe {
            crate::container_of!(p.cast::<Opaque<bindings::drm_gpuvm_bo>>(), GpuVmBo<T>, bo)
        };
        // SAFETY: We checked for NULL above, and the types ensure that
        // this object was created by vm_bo_alloc_callback<T>.
        Ok(unsafe { ARef::from_raw(NonNull::new_unchecked(p)) })
    }

    /// Instructs the [`GpuVm`] instance to build the necessary operations in
    /// order to map a given range.
    ///
    /// This utilizes [`DriverGpuVm`] to call back into the driver providing the
    /// split and merge steps.
    ///
    /// A sequence of callbacks can contain map, unmap and remap operations, but
    /// the sequence of callbacks might also be empty if no operation is
    /// required, e.g. if the requested mapping already exists in the exact same
    /// way.
    ///
    /// There can be an arbitrary amount of unmap operations, a maximum of two
    /// remap operations and a single map operation. The latter one represents
    /// the original map operation requested by the caller.
    pub fn map(
        &mut self,
        ctx: &mut T::StepContext,
        req_obj: &Object<T>,
        range: Range<u64>,
        gem_offset: u64,
    ) -> Result {
        let gpuvm = self.gpuvm.get();
        let mut ctx = StepContext { ctx, gpuvm: self };
        let req_addr = range.start;
        let req_range = range.end - range.start;

        // SAFETY:
        // - `gpuvm` is guaranteed to be valid by the type invariant of `GpuVm<T>`.
        // - `req_obj` is guaranteed to be a valid GEM object by the type invariant of `Object<T>`.
        to_result(unsafe {
            bindings::drm_gpuvm_sm_map(
                gpuvm,
                &mut ctx as *mut _ as *mut _,
                req_addr,
                req_range,
                req_obj.as_raw(),
                gem_offset,
            )
        })
    }

    /// Instructs the [`GpuVm`] instance to build the necessary operations in
    /// order to unmap a given range.
    ///
    /// This utilizes [`DriverGpuVm`] to call back into the driver providing the
    /// operations to unmap and, if required, split existent mappings.
    ///
    /// A sequence of callbacks can contain unmap and remap operations,
    /// depending on whether there are actual overlapping mappings to split.
    ///
    /// There can be an arbitrary amount of unmap operations and a maximum of
    /// two remap operations.
    pub fn unmap(&mut self, ctx: &mut T::StepContext, range: Range<u64>) -> Result {
        let gpuvm = self.gpuvm.get();
        let mut ctx = StepContext { ctx, gpuvm: self };
        let req_addr = range.start;
        let req_range = range.end - range.start;

        // SAFETY:
        // - `gpuvm` is guaranteed to be valid by the type invariant of `GpuVm<T>`.
        // - `req_obj` is guaranteed to be a valid GEM object by the type invariant of `Object<T>`.
        to_result(unsafe {
            bindings::drm_gpuvm_sm_unmap(gpuvm, &mut ctx as *mut _ as *mut _, req_addr, req_range)
        })
    }

    /// Finds the [`GpuVa`] that covers exactly the given range in this
    /// [`GpuVm`], if any.
    pub fn find_va<R, F>(&mut self, range: Range<u64>, f: F) -> Result<R>
    where
        for<'a> F: FnOnce(&mut GpuVm<T>, Option<ResidentGpuVa<'a, T>>) -> Result<R>,
    {
        // SAFETY: The drm_gpuva_find function is safe to call with a valid
        // gpuvm and range.
        let gpuva = unsafe {
            bindings::drm_gpuva_find(self.gpuvm.get(), range.start, range.end - range.start)
        };

        let resident_va = if gpuva.is_null() {
            None
        } else {
            // SAFETY: Container invariant is guaranteed for GpuVa<T> objects.
            let gpuva = unsafe {
                crate::container_of!(gpuva.cast::<Opaque<bindings::drm_gpuva>>(), GpuVa<T>, gpuva)
            };
            // SAFETY: Safe as per the type invariant of `GpuVa<T>`. Also it is OK
            // to convert to a reference here.
            Some(ResidentGpuVa(unsafe { &mut *gpuva }))
        };

        f(self, resident_va)
    }

    /// Finds the first [`GpuVa`] that covers the given range in this [`GpuVm`],
    /// if any.
    pub fn find_first_va<R, F>(&mut self, range: Range<u64>, f: F) -> Result<R>
    where
        for<'a> F: FnOnce(&mut GpuVm<T>, Option<ResidentGpuVa<'a, T>>) -> Result<R>,
    {
        // SAFETY: `gpuvm` is known to be valid as per the type invariants of
        // `self` and drm_gpuva_find_first is safe to call with a valid gpuvm
        // and range.
        let gpuva = unsafe {
            bindings::drm_gpuva_find_first(self.gpuvm.get(), range.start, range.end - range.start)
        };

        let resident_va = if gpuva.is_null() {
            None
        } else {
            // SAFETY: Container invariant is guaranteed for GpuVa<T> objects.
            let gpuva = unsafe {
                crate::container_of!(gpuva.cast::<Opaque<bindings::drm_gpuva>>(), GpuVa<T>, gpuva)
            };
            // SAFETY: Safe as per the type invariant of `GpuVa<T>`. Also it is OK
            // to convert to a reference here.
            Some(ResidentGpuVa(unsafe { &mut *gpuva }))
        };

        f(self, resident_va)
    }

    /// The start of the VA space.
    #[inline]
    pub fn va_start(&self) -> u64 {
        // SAFETY: Safe by the type invariant of `GpuVm<T>`.
        unsafe { *self.gpuvm.get() }.mm_start
    }

    /// The length of the address space
    #[inline]
    pub fn va_length(&self) -> u64 {
        // SAFETY: Safe by the type invariant of `GpuVm<T>`.
        unsafe { *self.gpuvm.get() }.mm_range
    }

    /// Returns the range of the GPU virtual address space.
    #[inline]
    pub fn va_range(&self) -> Range<u64> {
        let start = self.va_start();
        let end = start + self.va_length();
        Range { start, end }
    }
}

impl<T: DriverGpuVm> Deref for GpuVm<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: DriverGpuVm> DerefMut for GpuVm<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

// SAFETY: DRM GpuVm objects are always reference counted and the get/put functions
// satisfy the requirements.
unsafe impl<T: DriverGpuVm> AlwaysRefCounted for GpuVm<T> {
    fn inc_ref(&self) {
        // SAFETY: The drm_gpuvm_get function satisfies the requirements for inc_ref().
        unsafe { bindings::drm_gpuvm_get(self.gpuvm.get()) };
    }

    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: The drm_gpuvm_put function satisfies the requirements for dec_ref().
        unsafe { bindings::drm_gpuvm_put(Opaque::get(&(*obj.as_ptr()).gpuvm)) };
    }
}

/// A referenfe to a [`GpuVa`] that is guaranteed to be resident in the
/// [`GpuVm`] instance. This means that it was previously inserted with
/// `[`GpuVm::insert_va`].
pub struct ResidentGpuVa<'a, T: DriverGpuVm>(&'a mut GpuVa<T>);

impl<'a, T: DriverGpuVm> Deref for ResidentGpuVa<'a, T> {
    type Target = GpuVa<T>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a, T: DriverGpuVm> DerefMut for ResidentGpuVa<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

/// A [`GpuVa`] that has been removed from the [`GpuVm`] instance.
pub struct RemovedGpuVa<T: DriverGpuVm>(Pin<KBox<GpuVa<T>>>);

impl<T: DriverGpuVm> Deref for RemovedGpuVa<T> {
    type Target = Pin<KBox<GpuVa<T>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: DriverGpuVm> DerefMut for RemovedGpuVa<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// SAFETY: All operations that manipulate the interval tree take `&mut self`. In
// other words, there is no interior mutability allowing mutation from a shared
// reference to GpuVm<T>, so it's OK to send a &GpuVm<T> to another thread.
//
// By definition, this implies that it is safe to implement Sync.
unsafe impl<T: DriverGpuVm> Sync for GpuVm<T> {}

// SAFETY: It is OK to send a GpuVm<T> to another thread.
unsafe impl<T: DriverGpuVm> Send for GpuVm<T> {}

// SAFETY: By the same token, there is no way that a GpuVmBo<T> can be mutated
// from a shared reference. For the cases where the underlying
// [`kernel::gem::Object`] is modified through a [`GpuVmBo`], its VA lock is
// taken. This ensures that it is still thread-safe to modify the underlying BO
// even when it is shared among multiple VMs.
//
// (NOTE: this will be implemented in v4)
unsafe impl<T: DriverGpuVm> Sync for GpuVmBo<T> {}

// SAFETY: It is OK to send a GpuVmBo<T> to another thread.
unsafe impl<T: DriverGpuVm> Send for GpuVmBo<T> {}

/// # Safety
///
/// This function is only safe to be called from the GPUVM C code.
unsafe extern "C" fn vm_bo_free_callback<T: DriverGpuVm>(raw_vm_bo: *mut bindings::drm_gpuvm_bo) {
    // SAFETY: Container invariant is guaranteed for objects using this callback.
    let p = unsafe {
        crate::container_of!(
            raw_vm_bo.cast::<Opaque<bindings::drm_gpuvm_bo>>(),
            GpuVmBo<T>,
            bo
        )
    };

    // SAFETY: p is guaranteed to be valid for drm_gpuvm_bo objects using this callback.
    unsafe { drop(KBox::from_raw(p)) };
}

/// # Safety
///
/// This function is only safe to be called from the GPUVM C code.
unsafe extern "C" fn step_map_callback<T: DriverGpuVm>(
    op: *mut bindings::drm_gpuva_op,
    _priv: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    // SAFETY: We know this is a map op, and OpMap is a transparent wrapper.
    let map = unsafe { (&raw mut (*op).__bindgen_anon_1.map) }.cast(); //as *mut _ as *mut OpMap<T>;

    // SAFETY: It is ok to reborrow the pointer as a mutable reference here.
    let map = unsafe { &mut *map };

    // SAFETY: This is a pointer to a StepContext created inline in sm_map(), which is
    // guaranteed to outlive this function.
    let ctx = unsafe { &mut *(_priv as *mut StepContext<'_, T>) };

    from_result(|| {
        T::step_map(ctx.gpuvm, map, ctx.ctx)?;
        Ok(0)
    })
}

/// # Safety
///
/// This function is only safe to be called from the GPUVM C code.
unsafe extern "C" fn step_remap_callback<T: DriverGpuVm>(
    op: *mut bindings::drm_gpuva_op,
    _priv: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    // SAFETY: We know this is a map op, and OpReMap is a transparent wrapper.
    let remap: *mut OpReMap<T> = unsafe { (&raw mut (*op).__bindgen_anon_1.remap) }.cast(); //as *mut _ as *mut OpMap<T>;

    // SAFETY: It is ok to reborrow the pointer as a mutable reference here.
    let remap = unsafe { &mut *remap };

    // SAFETY: This is a pointer to a StepContext created inline in sm_map(), which is
    // guaranteed to outlive this function.
    let ctx = unsafe { &mut *(_priv as *mut StepContext<'_, T>) };

    // SAFETY: Safe by the type invariants of `GpuVa<T>`
    let p_vm_bo = unsafe { *remap.unmap().va().unwrap().gpuva.get() }.vm_bo;

    let res = {
        // SAFETY: vm_bo pointer must be valid and non-null by the step_remap
        // invariants.
        //
        // Since we , this reference's lifetime is until
        // [`AlwaysRefCounted::dec_ref`] is called.
        let vm_bo_ref = unsafe {
            bindings::drm_gpuvm_bo_get(p_vm_bo);
            &*(crate::container_of!(
                p_vm_bo.cast::<Opaque<bindings::drm_gpuvm_bo>>(),
                GpuVmBo<T>,
                bo
            ))
        };

        from_result(|| {
            T::step_remap(ctx.gpuvm, remap, vm_bo_ref, ctx.ctx)?;
            Ok(0)
        })
    };

    // SAFETY: We incremented the refcount above, and the Rust reference we took is
    // no longer in scope.
    unsafe { bindings::drm_gpuvm_bo_put(p_vm_bo) };

    res
}

/// # Safety
///
/// This function is only safe to be called from the GPUVM C code.
unsafe extern "C" fn step_unmap_callback<T: DriverGpuVm>(
    op: *mut bindings::drm_gpuva_op,
    _priv: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    // SAFETY: We know this is a map op, and OpReMap is a transparent wrapper.
    let unmap = unsafe { (&raw mut (*op).__bindgen_anon_1.unmap) }.cast(); //as *mut _ as *mut OpMap<T>;

    // SAFETY: It is ok to reborrow the pointer as a mutable reference here.
    let unmap = unsafe { &mut *unmap };

    // SAFETY: This is a pointer to a StepContext created inline in sm_map(), which is
    // guaranteed to outlive this function.
    let ctx = unsafe { &mut *(_priv as *mut StepContext<'_, T>) };

    from_result(|| {
        T::step_unmap(ctx.gpuvm, unmap, ctx.ctx)?;
        Ok(0)
    })
}

/// # Safety
///
/// This function is only safe to be called from the GPUVM C code.
unsafe extern "C" fn vm_free_callback<T: DriverGpuVm>(raw_gpuvm: *mut bindings::drm_gpuvm) {
    // SAFETY: `raw_gpuvm` points inside the allocation for `GpuVm<T>`, see [`GpuVm::new`].
    let p = unsafe {
        crate::container_of!(
            raw_gpuvm as *mut Opaque<bindings::drm_gpuvm>,
            GpuVm<T>,
            gpuvm
        )
    };

    // SAFETY: `p` is guaranteed to be valid for [`bindings::drm_gpuvm`] objects
    // using this callback. It was leaked in [`GpuVm::new`].
    unsafe { drop(KBox::from_raw(p)) };
}

/// # Safety
///
/// This function is only safe to be called from the GPUVM C code.
unsafe extern "C" fn vm_bo_alloc_callback<T: DriverGpuVm>() -> *mut bindings::drm_gpuvm_bo {
    let obj: Result<Pin<KBox<GpuVmBo<T>>>, Error> = KBox::pin_init(
        pin_init!(GpuVmBo::<T> {
            bo: Opaque::zeroed(),
            inner <- T::GpuVmBo::new(),
            _p: PhantomPinned
        }),
        GFP_KERNEL,
    );

    match obj {
        Ok(obj) => {
            // SAFETY: The DRM core will keep this object pinned.
            let inner = unsafe { Pin::into_inner_unchecked(obj) };
            let p: &mut GpuVmBo<T> = KBox::leak(inner);
            p.bo.get()
        }

        Err(_) => core::ptr::null_mut(),
    }
}
