// SPDX-License-Identifier: GPL-2.0 OR MIT

#![cfg(CONFIG_RUST_DRM_GPUVM)]

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
    dma_buf::{
        dma_fence::PublicDmaFence,
        DmaResvUsage, //
    },
    drm,
    drm::exec::{
        ExecCtx,
        ExecFlags,
        Prepared, //
    },
    drm::gem::{
        BaseObject,
        IntoGEMObject,
        ResvGuard, //
    },
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

#[cfg(CONFIG_DEBUG_FS)]
use crate::seq_file::SeqFile;

mod sm_ops;
pub use self::sm_ops::*;

mod vm_bo;
pub use self::vm_bo::*;

mod va;
pub use self::va::*;

/// A DRM GPU VA manager.
///
/// This object is refcounted, but the locations of mapped ranges may only be accessed or changed
/// via the special unique handle [`UniqueRefGpuVm`].
///
/// # Invariants
///
/// * Stored in an allocation managed by the refcount in `self.vm`.
/// * Access to `data` and the gpuvm interval tree is controlled via the [`UniqueRefGpuVm`] type.
/// * Does not contain any sparse [`GpuVa<T>`] instances.
/// * `validate` is accessed only with the reservation lock of the GPUVM held. It is null, or
///   points at a `&mut ValidateFn<'_, T>` to the closure of the running
///   [`GpuVmExec::validate()`].
#[pin_data]
pub struct GpuVm<T: DriverGpuVm> {
    #[pin]
    vm: Opaque<bindings::drm_gpuvm>,
    /// Accessed only through the [`UniqueRefGpuVm`] reference.
    data: UnsafeCell<T>,
    /// The closure of a running [`GpuVmExec::validate()`].
    validate: UnsafeCell<*mut c_void>,
}

// SAFETY: It is safe to send a `GpuVm<T>` to another thread: all data reachable through it
// (`T`, `T::VmBoData`, and the GEM `T::Object`) is `Send` by the `DriverGpuVm` bounds.
unsafe impl<T: DriverGpuVm> Send for GpuVm<T> {}
// SAFETY: It is safe to share a `&GpuVm<T>` between threads: `&self` methods only alias data
// that is `Sync` by the `DriverGpuVm` bounds, and any thread may drop that data, or upgrade the
// reference and ultimately drop `T`, which the same bounds make `Send`. Only the thread that holds
// the reservation lock of the GPUVM uses the `validate` closure.
unsafe impl<T: DriverGpuVm> Sync for GpuVm<T> {}

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

impl<T: DriverGpuVm> PartialEq for GpuVm<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.as_raw(), other.as_raw())
    }
}
impl<T: DriverGpuVm> Eq for GpuVm<T> {}

impl<T: DriverGpuVm> GpuVm<T> {
    const fn vtable() -> &'static bindings::drm_gpuvm_ops {
        &bindings::drm_gpuvm_ops {
            vm_free: Some(Self::vm_free),
            op_alloc: None,
            op_free: None,
            vm_bo_alloc: GpuVmBo::<T>::ALLOC_FN,
            vm_bo_free: GpuVmBo::<T>::FREE_FN,
            vm_bo_validate: Some(Self::vm_bo_validate),
            sm_step_map: Some(Self::sm_step_map),
            sm_step_unmap: Some(Self::sm_step_unmap),
            sm_step_remap: Some(Self::sm_step_remap),
        }
    }

    /// Creates a GPUVM instance.
    #[expect(clippy::new_ret_no_self)]
    pub fn new<E, Ctx: drm::DeviceContext>(
        name: &'static CStr,
        dev: &drm::Device<T::Driver, Ctx>,
        r_obj: &T::Object,
        range: Range<u64>,
        reserve_range: Range<u64>,
        data: T,
    ) -> Result<UniqueRefGpuVm<T>, E>
    where
        E: From<AllocError>,
        E: From<core::convert::Infallible>,
    {
        let obj = KBox::try_pin_init::<E>(
            try_pin_init!(Self {
                data: UnsafeCell::new(data),
                validate: UnsafeCell::new(ptr::null_mut()),
                vm <- Opaque::ffi_init(|vm| {
                    // SAFETY: These arguments are valid. `vm` is valid until refcount drops to
                    // zero. The `vm` is zeroed before calling this method by `__GFP_ZERO` flag
                    // below.
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
            GFP_KERNEL | __GFP_ZERO,
        )?;
        // SAFETY: This transfers the initial refcount to the ARef.
        let aref = unsafe {
            ARef::from_raw(NonNull::new_unchecked(KBox::into_raw(
                Pin::into_inner_unchecked(obj),
            )))
        };
        // INVARIANT: This reference is unique.
        Ok(UniqueRefGpuVm(aref))
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
    ) -> Result<ARef<GpuVmBo<T>>, AllocError> {
        Ok(GpuVmBoAlloc::new(self, obj, data)?.obtain())
    }

    /// Prepare this GPUVM.
    ///
    /// `flags` controls how the locks are taken, and `num_fences` how many fences to preallocate
    /// space for.
    #[inline]
    pub fn prepare(
        &self,
        flags: ExecFlags,
        num_fences: u32,
    ) -> impl PinInit<GpuVmExec<'_, T>, Error> {
        try_pin_init!(GpuVmExec {
            exec <- Opaque::try_ffi_init(|exec: *mut bindings::drm_gpuvm_exec| {
                // SAFETY: exec is valid but unused memory, so we can write.
                unsafe {
                    ptr::write_bytes(exec, 0u8, 1usize);
                    ptr::write(&raw mut (*exec).vm, self.as_raw());
                    ptr::write(&raw mut (*exec).flags, flags.into());
                    ptr::write(&raw mut (*exec).num_fences, num_fences);
                }

                // SAFETY: If successful, this `struct drm_gpuvm_exec` remains valid until this is
                // unlocked because it's pinned and unlocks it in drop. The contained pointer to
                // `self` remains valid because `GpuVmExec` borrows from `self`.
                to_result(unsafe { bindings::drm_gpuvm_exec_lock(exec) })
            }),
            _gpuvm: PhantomData,
        })
    }

    /// Locks this GPUVM's own reservation in the [`ExecCtx`] round `ctx` and
    /// reserves `num_fences` slots on it, issuing the [`Prepared`] receipt for
    /// it.
    ///
    /// The reservation belongs to the GPUVM's root GEM object, which every
    /// object private to the GPUVM shares. A `num_fences` of zero only takes
    /// the lock, because `drm_gpuvm_prepare_vm()` routes it to
    /// `drm_exec_lock_obj()`.
    ///
    /// Wraps `drm_gpuvm_prepare_vm()`.
    #[inline]
    pub fn prepare_resv(&self, ctx: &mut ExecCtx<'_>, num_fences: u32) -> Result<Prepared> {
        // SAFETY: `drm_gpuvm_prepare_vm()` is a prepare call on the context it
        // is given, and locks the root object's reservation on success. The
        // round then holds a reference to the root object, so the reservation
        // outlives it.
        unsafe {
            ctx.prepare_with(
                |exec| {
                    to_result(bindings::drm_gpuvm_prepare_vm(
                        self.as_raw(),
                        exec,
                        num_fences,
                    ))
                },
                self.raw_resv(),
            )
        }
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

    /// Validates an evicted `vm_bo` with the closure of [`GpuVmExec::validate()`].
    ///
    /// # Safety
    ///
    /// `vm_bo` must be on the evicted list of a `GpuVm<T>`. The caller must hold the reservation
    /// locks of the GPUVM and of the object of `vm_bo` for the duration of the call, and must have
    /// taken them without guards.
    unsafe extern "C" fn vm_bo_validate(
        vm_bo: *mut bindings::drm_gpuvm_bo,
        _exec: *mut bindings::drm_exec,
    ) -> c_int {
        // SAFETY: Per the safety requirements, `vm_bo` is a valid `drm_gpuvm_bo` of a `GpuVm<T>`,
        // which it holds a reference to.
        let gpuvm = unsafe { Self::from_raw((*vm_bo).vm) };

        // SAFETY: The caller holds the reservation lock of the GPUVM, which protects `validate`.
        let validate = unsafe { *gpuvm.validate.get() }.cast::<&mut ValidateFn<'_, T>>();
        if validate.is_null() {
            return EOPNOTSUPP.to_errno();
        }

        // Clearing the evicted state of an external object leaves its `vm_bo` on the evicted list.
        // SAFETY: The caller holds the reservation lock of the object, which protects the evicted
        // state.
        if !unsafe { (*vm_bo).evicted } {
            return 0;
        }

        // SAFETY: The reservation lock of the GPUVM keeps an evicted `vm_bo` allocated, even when
        // its refcount drops to zero.
        if unsafe { bindings::kref_get_unless_zero(&raw mut (*vm_bo).kref) } == 0 {
            return 0;
        }

        // SAFETY: We took a reference to `vm_bo` above, which keeps it on the GEM list. It is a
        // `GpuVmBo<T>` of this GPUVM.
        let vm_bo = unsafe { ARef::from_raw(NonNull::new_unchecked(vm_bo.cast::<GpuVmBo<T>>())) };

        // SAFETY: Per the safety requirements, the caller holds the reservation lock of the object
        // without a guard for the duration of the call.
        let mut guard = unsafe { ResvGuard::assume_locked(vm_bo.obj()) };

        // SAFETY: `validate` is not null, as checked above, so by the type invariants it points at
        // the `&mut ValidateFn<'_, T>` of the running `GpuVmExec::validate()`, which nothing else
        // uses during this call.
        let validate = unsafe { &mut *validate };

        match validate(&vm_bo, &mut guard) {
            Ok(()) => 0,
            Err(e) => e.to_errno(),
        }
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
    fn raw_resv(&self) -> *mut bindings::dma_resv {
        // SAFETY: `r_obj` is immutable and valid for duration of GPUVM.
        unsafe { (*(*self.as_raw()).r_obj).resv }
    }

    /// Returns the GEM object whose reservation lock protects this GPUVM.
    #[inline]
    fn root_obj(&self) -> &T::Object {
        // SAFETY: `r_obj` is immutable, points to the `T::Object` passed to `new()`, and the GPUVM
        // holds a reference to it for its whole lifetime.
        unsafe { T::Object::from_raw((*self.as_raw()).r_obj) }
    }
}

/// The manager for a GPUVM.
pub trait DriverGpuVm: Sized + Send + Sync
where
    Self::Object: drm::driver::AllocImpl<Driver = Self::Driver>,
{
    /// Parent `Driver` for this object.
    type Driver: drm::Driver;

    /// The kind of GEM object stored in this GPUVM.
    type Object: IntoGEMObject + Send + Sync;

    /// Data stored with each [`struct drm_gpuva`](struct@GpuVa).
    ///
    /// Only `Send` is required: the data has a single owner at all times, moving
    /// between threads by value (handed back as a [`GpuVaRemoved`]) but never
    /// accessed by two threads concurrently.
    type VaData: Send;

    /// Data stored with each [`struct drm_gpuvm_bo`](struct@GpuVmBo).
    type VmBoData: Send + Sync;

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

/// A [`DriverGpuVm`] that is the only kind of GPUVM that maps its GEM objects.
///
/// This allows finding the [`GpuVmBo`]s of an object from the object, with [`GemGpuvaGuard`].
///
/// # Safety
///
/// Every `drm_gpuvm_bo` of an object of type [`DriverGpuVm::Object`] belongs to a
/// [`GpuVm<Self>`].
pub unsafe trait ExclusiveObjects: DriverGpuVm {}

/// The core of the DRM GPU VA manager.
///
/// This object is a unique reference to the VM that can access the interval tree and the Rust
/// `data` field.
///
/// # Invariants
///
/// Each `GpuVm` instance has at most one `UniqueRefGpuVm` reference.
// `Send`/`Sync` derive from `ARef<GpuVm<T>>`; the trait bounds make them correct for the unique
// handle's `&mut T` access.
pub struct UniqueRefGpuVm<T: DriverGpuVm>(ARef<GpuVm<T>>);

impl<T: DriverGpuVm> UniqueRefGpuVm<T> {
    /// Access the data owned by this `UniqueRefGpuVm` immutably.
    #[inline]
    pub fn data_ref(&self) -> &T {
        // SAFETY: By the type invariants we may access `data`.
        unsafe { &*self.0.data.get() }
    }

    /// Access the data owned by this `UniqueRefGpuVm` mutably.
    #[inline]
    pub fn data(&mut self) -> &mut T {
        // SAFETY: By the type invariants we may access `data`.
        unsafe { &mut *self.0.data.get() }
    }

    /// Returns the first [`GpuVa`] mapped within `[addr, addr + range)`,
    /// or `None` if no mapping intersects the range.
    ///
    /// Returns `None` for an empty range (`range == 0`), for ranges where
    /// `addr + range` overflows `u64`, and skips the GPUVM's internal
    /// reserved-range placeholder and sparse mappings, neither of which
    /// is associated with a [`GpuVmBo`].
    #[inline]
    pub fn find_first(&self, addr: u64, range: u64) -> Option<&GpuVa<T>> {
        if range == 0 {
            return None;
        }
        // The C helper computes `last = addr + range - 1`. Rejecting ranges
        // where `addr + range` overflows `u64` is conservatively one ULP
        // stricter, but keeps the FFI call free of wraparound.
        addr.checked_add(range)?;

        // SAFETY: `self.as_raw()` is a valid `drm_gpuvm`; the
        // `&UniqueRefGpuVm<T>` borrow keeps the interval tree stable
        // for the duration of the call.
        let ptr = unsafe { bindings::drm_gpuva_find_first(self.as_raw(), addr, range) };
        if ptr.is_null() {
            return None;
        }

        // SAFETY: `self.as_raw()` returns a valid `drm_gpuvm` pointer; taking
        // the address of its `kernel_alloc_node` field does not dereference
        // the field itself.
        let kernel_alloc_node = unsafe { &raw mut (*self.as_raw()).kernel_alloc_node };
        if ptr::eq(ptr, kernel_alloc_node) {
            return None;
        }

        // SAFETY: `ptr` is a non-null `drm_gpuva` returned by
        // `drm_gpuva_find_first` and resident in this GPUVM under the
        // `&UniqueRefGpuVm<T>` borrow, so the `flags` field is valid to
        // read.
        let flags = unsafe { (*ptr).flags };
        if flags & bindings::drm_gpuva_flags_DRM_GPUVA_SPARSE != 0 {
            return None;
        }

        // SAFETY: `ptr` is a non-null `drm_gpuva` resident in this `GpuVm<T>`,
        // and the `&UniqueRefGpuVm<T>` borrow keeps it resident for the
        // returned borrow. The filters above exclude both cases where the VA
        // would lack an associated `GpuVmBo<T>`: the GPUVM's
        // `kernel_alloc_node` and sparse mappings. Any remaining VA is
        // associated with a `GpuVmBo<T>` whose BO is on the GEM list,
        // satisfying `GpuVa::from_raw`'s contract.
        Some(unsafe { GpuVa::<T>::from_raw(ptr) })
    }

    /// Dumps this GPUVM's VA space to `m` in the standard DRM debugfs format.
    #[cfg(CONFIG_DEBUG_FS)]
    #[inline]
    pub fn debugfs_gpuva_info(&self, m: &SeqFile) -> Result {
        // SAFETY: `m.as_raw()` is a valid `seq_file` and `self.as_raw()` is a
        // valid `drm_gpuvm`. The `&UniqueRefGpuVm<T>` borrow holds the interval
        // tree stable for the call, satisfying the function's caller-side
        // locking requirement.
        to_result(unsafe { bindings::drm_debugfs_gpuva_info(m.as_raw(), self.as_raw()) })
    }
}

impl<T: DriverGpuVm> Deref for UniqueRefGpuVm<T> {
    type Target = GpuVm<T>;

    #[inline]
    fn deref(&self) -> &GpuVm<T> {
        &self.0
    }
}

/// A closure that validates an evicted [`GpuVmBo`] for [`GpuVmExec::validate()`].
type ValidateFn<'a, T> =
    dyn FnMut(&GpuVmBo<T>, &mut ResvGuard<'_, <T as DriverGpuVm>::Object>) -> Result + 'a;

/// The exec token for preparing the objects.
///
/// # Invariants
///
/// Owns a GPUVM exec context.
#[pin_data(PinnedDrop)]
pub struct GpuVmExec<'vm, T: DriverGpuVm> {
    #[pin]
    exec: Opaque<bindings::drm_gpuvm_exec>,
    _gpuvm: PhantomData<&'vm mut GpuVm<T>>,
}

impl<'vm, T: DriverGpuVm> GpuVmExec<'vm, T> {
    /// Add a fence.
    ///
    /// The caller must ensure that the preallocated space for fences is sufficient.
    #[inline]
    pub fn resv_add_fence(
        &self,
        fence: &PublicDmaFence,
        private_usage: DmaResvUsage,
        extobj_usage: DmaResvUsage,
    ) {
        // SAFETY: This method takes a refcount on the fence, so it's only required to be valid for
        // the duration of this method. If there is not enough space for the pre-allocated fence,
        // then this leads to a BUG_ON() but does not trigger UB.
        unsafe {
            bindings::drm_gpuvm_resv_add_fence(
                (*self.exec.get()).vm,
                &raw mut (*self.exec.get()).exec,
                fence.raw(),
                private_usage as u32,
                extobj_usage as u32,
            )
        }
    }

    /// Calls `f` for each evicted [`GpuVmBo`] of the GPUVM, with the reservation lock of its
    /// object held.
    ///
    /// `f` makes the object resident again and clears its evicted state with
    /// [`GpuVmBo::evict()`], after which the `vm_bo` leaves the evicted list. The walk stops at the
    /// first error that `f` returns. `f` must not take the reservation lock of the GPUVM, for
    /// example with [`GpuVm::deferred_cleanup()`].
    pub fn validate<F>(self: Pin<&mut Self>, mut f: F) -> Result
    where
        F: FnMut(&GpuVmBo<T>, &mut ResvGuard<'_, T::Object>) -> Result,
    {
        let mut f: &mut ValidateFn<'_, T> = &mut f;
        let exec = self.exec.get();

        // SAFETY: `exec` is valid, and its GPUVM is a `GpuVm<T>` that outlives `self`.
        let gpuvm = unsafe { GpuVm::<T>::from_raw((*exec).vm) };
        let slot = gpuvm.validate.get();

        // SAFETY: `self` holds the reservation lock of the GPUVM, which protects `validate`.
        unsafe { *slot = ptr::from_mut(&mut f).cast() };

        // SAFETY: `exec` holds the reservation locks of the GPUVM and of its external objects.
        // Locking it added the evicted external objects to the evicted list.
        let ret = to_result(unsafe {
            bindings::drm_gpuvm_validate(gpuvm.as_raw(), &raw mut (*exec).exec)
        });

        // SAFETY: `self` holds the reservation lock of the GPUVM, which protects `validate`.
        unsafe { *slot = ptr::null_mut() };

        ret
    }
}

#[pinned_drop]
impl<'vm, T: DriverGpuVm> PinnedDrop for GpuVmExec<'vm, T> {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: We hold the lock, so it's safe to unlock.
        unsafe { bindings::drm_gpuvm_exec_unlock(self.exec.get()) };
    }
}

#[cfg(CONFIG_RUST_DRM_GEM_SHMEM_HELPER)]
#[kunit_tests(rust_drm_gpuvm)]
mod tests {
    use super::*;
    use crate::{
        drm::{
            gem::shmem::{
                Object,
                ObjectConfig, //
            },
            DeviceContext, //
        },
        faux,
        page::PAGE_SIZE, //
    };

    #[pin_data]
    struct KunitData {}
    struct KunitDriver;
    struct KunitFile;
    #[pin_data]
    struct KunitObject {}

    type KunitGem = Object<KunitObject>;

    impl drm::file::DriverFile for KunitFile {
        type Driver = KunitDriver;

        fn open(_dev: &drm::Device<KunitDriver>) -> Result<Pin<KBox<Self>>> {
            Ok(KBox::new(Self, GFP_KERNEL)?.into())
        }
    }

    impl drm::gem::DriverObject for KunitObject {
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

    struct KunitVm;

    impl DriverGpuVm for KunitVm {
        type Driver = KunitDriver;
        type Object = KunitGem;
        type VaData = u64;
        type VmBoData = ();
        type SmContext<'ctx>
            = Option<GpuVaAlloc<Self>>
        where
            Self: 'ctx;

        fn sm_step_map<'op, 'ctx>(
            &mut self,
            op: OpMap<'op, Self>,
            context: &mut Self::SmContext<'ctx>,
        ) -> Result<OpMapped<'op, Self>, Error> {
            let addr = op.addr();
            Ok(op.insert(context.take().ok_or(EINVAL)?, addr))
        }

        fn sm_step_unmap<'op, 'ctx>(
            &mut self,
            op: OpUnmap<'op, Self>,
            _context: &mut Self::SmContext<'ctx>,
        ) -> Result<OpUnmapped<'op, Self>, Error> {
            Ok(op.remove().0)
        }

        fn sm_step_remap<'op, 'ctx>(
            &mut self,
            _op: OpRemap<'op, Self>,
            _context: &mut Self::SmContext<'ctx>,
        ) -> Result<OpRemapped<'op, Self>, Error> {
            Err(EINVAL)
        }
    }

    // SAFETY: The tests map `KunitGem` objects only in `GpuVm<KunitVm>`.
    unsafe impl ExclusiveObjects for KunitVm {}

    fn create_drm_dev(reg: &faux::Registration) -> Result<&drm::Device<KunitDriver>> {
        let drm = drm::device::UnregisteredDevice::<KunitDriver>::new(reg.as_ref())?;

        // SAFETY: The faux device is created and registered, so it is bound for the lifetime of
        // the test.
        let dev = unsafe { reg.as_ref().as_bound() };

        drm::driver::Registration::new_foreign_owned(drm, dev, try_pin_init!(KunitData {}), 0)
    }

    fn config(parent_resv_obj: Option<&KunitGem>) -> ObjectConfig<'_, KunitObject> {
        ObjectConfig {
            map_wc: false,
            parent_resv_obj,
        }
    }

    fn map(vm: &mut UniqueRefGpuVm<KunitVm>, vm_bo: &GpuVmBo<KunitVm>, addr: u64) -> Result {
        vm.sm_map(OpMapRequest {
            addr,
            range: PAGE_SIZE as u64,
            gem_offset: 0,
            vm_bo,
            context: &mut Some(GpuVaAlloc::new(GFP_KERNEL)?),
        })
    }

    #[test]
    fn evict_and_validate() -> Result {
        let reg = faux::Registration::new(c"Kunit", None)?;
        let drm = create_drm_dev(&reg)?;

        let root = KunitGem::new(drm, PAGE_SIZE, config(None), ())?;
        let private = KunitGem::new(drm, PAGE_SIZE, config(Some(&root)), ())?;
        let shared = KunitGem::new(drm, PAGE_SIZE, config(None), ())?;

        let mut vm = GpuVm::new::<Error, _>(c"kunit", drm, &*root, 0..1 << 32, 0..0, KunitVm)?;
        let objs = [&*private, &*shared];
        let vm_bos = [vm.obtain(&private, ())?, vm.obtain(&shared, ())?];
        for (addr, vm_bo) in [0x10000, 0x20000].into_iter().zip(&vm_bos) {
            map(&mut vm, vm_bo, addr)?;
        }

        for (addr, (obj, vm_bo)) in [0x10000, 0x20000].into_iter().zip(objs.iter().zip(&vm_bos)) {
            let gpuva = GemGpuvaGuard::<KunitVm>::lock(obj);
            let mut obj_vm_bos = gpuva.vm_bos();
            assert!(obj_vm_bos.next().is_some_and(|b| b == &**vm_bo));
            assert!(obj_vm_bos.next().is_none());

            let mut vas = vm_bo.vas(&gpuva)?;
            assert!(vas
                .next()
                .is_some_and(|va| va.addr() == addr && *va.data_ref() == addr));
            assert!(vas.next().is_none());
        }

        let gpuva = GemGpuvaGuard::<KunitVm>::lock(&root);
        assert!(gpuva.vm_bos().next().is_none());
        assert_eq!(vm_bos[0].vas(&gpuva).err(), Some(EINVAL));
        drop(gpuva);

        let resv = root.lock_resv();
        assert_eq!(vm_bos[1].evict(&resv, true).err(), Some(EINVAL));
        assert_eq!(vm_bos[1].is_evicted(&resv).err(), Some(EINVAL));
        drop(resv);

        for (obj, vm_bo) in objs.iter().zip(&vm_bos) {
            let resv = obj.lock_resv();
            vm_bo.evict(&resv, true)?;
            assert!(vm_bo.is_evicted(&resv)?);
        }

        let mut exec = KBox::pin_init(vm.prepare(ExecFlags::default(), 0), GFP_KERNEL)?;

        // An error stops the walk, and the `vm_bo`s stay evicted.
        let mut calls = 0;
        let ret = exec.as_mut().validate(|_, _| {
            calls += 1;
            Err(EIO)
        });
        assert_eq!(ret, Err(EIO));
        assert_eq!(calls, 1);

        let mut validated = 0;
        exec.as_mut().validate(|vm_bo, resv| {
            if vm_bos.iter().any(|b| &**b == vm_bo) {
                validated += 1;
            }
            vm_bo.evict(resv, false)
        })?;
        assert_eq!(validated, 2);

        // The validated `vm_bo`s left the evicted list.
        exec.as_mut().validate(|_, _| Err(EIO))?;
        drop(exec);

        for (obj, vm_bo) in objs.iter().zip(&vm_bos) {
            assert!(!vm_bo.is_evicted(&obj.lock_resv())?);
        }

        vm.sm_unmap(0, 1 << 32, &mut None)?;
        drop(vm_bos);
        vm.deferred_cleanup();

        Ok(())
    }

    #[test]
    fn validate_skips_restored_extobj() -> Result {
        let reg = faux::Registration::new(c"Kunit", None)?;
        let drm = create_drm_dev(&reg)?;

        let root = KunitGem::new(drm, PAGE_SIZE, config(None), ())?;
        let shared = KunitGem::new(drm, PAGE_SIZE, config(None), ())?;

        let vm = GpuVm::new::<Error, _>(c"kunit", drm, &*root, 0..1 << 32, 0..0, KunitVm)?;
        let vm_bo = vm.obtain(&shared, ())?;

        vm_bo.evict(&shared.lock_resv(), true)?;
        let exec = KBox::pin_init(vm.prepare(ExecFlags::default(), 0), GFP_KERNEL)?;
        drop(exec);
        vm_bo.evict(&shared.lock_resv(), false)?;

        let mut exec = KBox::pin_init(vm.prepare(ExecFlags::default(), 0), GFP_KERNEL)?;
        let mut calls = 0;
        exec.as_mut().validate(|_, _| {
            calls += 1;
            Ok(())
        })?;
        assert_eq!(calls, 0);
        drop(exec);

        drop(vm_bo);
        vm.deferred_cleanup();

        Ok(())
    }
}
