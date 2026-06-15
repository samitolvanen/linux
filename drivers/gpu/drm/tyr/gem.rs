// SPDX-License-Identifier: GPL-2.0 or MIT
//! GEM buffer object management for the Tyr driver.
//!
//! This module provides buffer object (BO) management functionality using
//! DRM's GEM subsystem with shmem backing.

use core::mem::{ManuallyDrop, MaybeUninit};
use core::ops::Range;

use kernel::{
    device::{
        self,
        Bound, //
    },
    dma::{
        sync_single_for_cpu,
        sync_single_for_device,
        DataDirection, //
    },
    drm::{
        gem,
        gem::shmem,
        gem::BaseObject,
        DeviceContext, //
    },
    new_mutex,
    pr_warn_once,
    prelude::*,
    str::CString,
    sync::{
        aref::ARef,
        Arc,
        ArcBorrow,
        Mutex, //
    },
    uapi, //
};

use crate::{
    driver::{
        CleanupQueue,
        TyrDrmDevice,
        TyrDrmDriver, //
    },
    file::TyrDrmFile,
    vm::{
        range,
        Vm,
        VmMapFlags, //
    },
};

/// Maximum length of a BO label, including the NUL terminator.
pub(crate) const BO_LABEL_MAXLEN: usize = 4096;

/// Driver-specific data for Tyr GEM buffer objects.
///
/// This structure contains Tyr-specific metadata associated with each GEM object.
/// It implements [`gem::DriverObject`] to provide driver-specific behavior for
/// buffer object creation and management.
#[pin_data]
pub(crate) struct BoData {
    /// Buffer object creation flags (currently unused).
    flags: u32,
    /// Root GEM object of the VM whose `dma_resv` this BO shares, if any.
    exclusive_vm_root_gem: Option<ARef<Bo>>,
    /// User-assigned label.
    #[pin]
    label: Mutex<Option<CString>>,
}

impl BoData {
    pub(crate) fn create_flags(&self) -> u32 {
        self.flags
    }

    pub(crate) fn exclusive_vm_root_gem(&self) -> Option<&Bo> {
        self.exclusive_vm_root_gem.as_deref()
    }

    pub(crate) fn set_label(&self, label: Option<CString>) {
        *self.label.lock() = label;
    }
}

/// Arguments for creating a [`BoData`] instance.
///
/// This structure is used to pass creation parameters when instantiating
/// a new buffer object, as required by the [`gem::DriverObject`] trait.
pub(crate) struct BoCreateArgs {
    /// Buffer object creation flags (currently unused).
    flags: u32,
    /// Root GEM object of the VM whose `dma_resv` this BO shares, if any.
    exclusive_vm_root_gem: Option<ARef<Bo>>,
}

impl gem::DriverObject for BoData {
    type Driver = TyrDrmDriver;
    type Args = BoCreateArgs;

    const EXPORT_CPU_ACCESS_SYNC: bool = true;

    const EXPOSE_DUMB_CREATE: bool = false;

    /// Constructs a new [`BoData`] instance for a GEM object.
    ///
    /// This function is called by the GEM subsystem when creating a new buffer
    /// object. It initializes the driver-specific data with the provided flags.
    /// The device and size parameters are currently unused but required by the
    /// [`gem::DriverObject`] trait.
    fn new<Ctx: DeviceContext>(
        _dev: &TyrDrmDevice<Ctx>,
        _size: usize,
        args: BoCreateArgs,
    ) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            flags: args.flags,
            exclusive_vm_root_gem: args.exclusive_vm_root_gem,
            label <- new_mutex!(None),
        })
    }

    fn create_imported(_dev: &TyrDrmDevice, _size: usize) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            flags: 0,
            exclusive_vm_root_gem: None,
            label <- new_mutex!(None),
        })
    }

    fn export(obj: &Bo, _flags: c_int) -> Result {
        if obj.exclusive_vm_root_gem.is_some() {
            return Err(EINVAL);
        }

        Ok(())
    }

    fn status(obj: &Bo) -> gem::ObjectStatus {
        if obj.pages_present() || obj.is_imported() {
            gem::ObjectStatus::RESIDENT
        } else {
            gem::ObjectStatus::empty()
        }
    }
}

/// Type alias for Tyr GEM buffer objects.
pub(crate) type Bo = gem::shmem::Object<BoData>;

/// A mapped kernel-owned buffer object with an always-valid kernel mapping.
pub(crate) struct MappedBo {
    kernel_bo: KernelBo,
    /// `Some` for the entire lifetime of the value; taken to `None`
    /// only by `Drop` when shipping the vmap to the cleanup
    /// workqueue.
    vmap: Option<shmem::VMapOwned<BoData>>,
}

impl MappedBo {
    pub(crate) fn new(kernel_bo: KernelBo) -> Result<Arc<Self>> {
        let vmap = kernel_bo.bo.owned_vmap::<0>()?;
        Ok(Arc::new(
            Self {
                kernel_bo,
                vmap: Some(vmap),
            },
            GFP_KERNEL,
        )?)
    }

    pub(crate) fn vmap(&self) -> &shmem::VMapOwned<BoData> {
        self.vmap
            .as_ref()
            .expect("MappedBo::vmap accessed after drop")
    }

    pub(crate) fn kernel_va(&self) -> Option<Range<u64>> {
        self.kernel_bo.kernel_va()
    }

    /// Verifies that `offset..offset + size_of::<T>()` is in bounds of the
    /// mapping and that `offset` is aligned for `T`.
    pub(crate) fn check_offset<T>(&self, offset: usize) -> Result {
        if offset % core::mem::align_of::<T>() != 0 {
            return Err(EINVAL);
        }

        let end = offset
            .checked_add(core::mem::size_of::<T>())
            .ok_or(EINVAL)?;
        if end > self.size() {
            return Err(EINVAL);
        }

        Ok(())
    }
}

impl core::ops::Deref for MappedBo {
    type Target = Bo;

    fn deref(&self) -> &Bo {
        self.vmap().owner()
    }
}

/// Send raw-pointer wrapper used to hand a heap-parked vmap to the
/// cleanup closure. Single-consumer: only the closure (success) or
/// this Drop body (failure) calls KBox::from_raw on the inner pointer.
#[repr(transparent)]
struct MappedBoCleanupPtr(*mut shmem::VMapOwned<BoData>);

// SAFETY: The pointer is produced by KBox::into_raw and reclaimed by
// KBox::from_raw exactly once, on whichever side observes it first
// (closure on success, this Drop body on failure).
unsafe impl Send for MappedBoCleanupPtr {}

impl Drop for MappedBo {
    fn drop(&mut self) {
        let Some(vmap) = self.vmap.take() else {
            return;
        };
        let cleanup_wq = self.kernel_bo.cleanup_wq.clone();

        let slot: KBox<MaybeUninit<shmem::VMapOwned<BoData>>> = match KBox::new_uninit(GFP_NOWAIT) {
            Ok(s) => s,
            Err(_) => {
                pr_warn_once!(
                    "tyr: MappedBo cleanup-state allocation failed; leaking vmap to avoid dma_resv_lock cycle in signalling section\n",
                );
                core::mem::forget(vmap);
                return;
            }
        };
        let boxed = KBox::write(slot, vmap);
        let ptr = KBox::into_raw(boxed);
        let send_ptr = MappedBoCleanupPtr(ptr);

        let res = cleanup_wq.try_spawn(GFP_NOWAIT, move || {
            // Force `Send` capture of the wrapper, see `KernelBo`.
            let send_ptr = send_ptr;
            // SAFETY: `send_ptr.0` was produced by `KBox::into_raw`
            // in the matching `MappedBo::drop` body and is only
            // reclaimed by `KBox::from_raw` once: by this closure on
            // the success path, or by the `Drop` body on the
            // enqueue-failure path. The cleanup workqueue runs
            // outside any dma-fence signalling section, so taking
            // `dma_resv_lock` from the vmap destructor is safe here.
            drop(unsafe { KBox::from_raw(send_ptr.0) });
        });

        if let Err(e) = res {
            pr_warn_once!(
                "tyr: MappedBo cleanup_wq enqueue failed under memory pressure; leaking vmap to avoid dma_resv_lock cycle in signalling section\n",
            );
            // SAFETY: `try_spawn` returned `Err`, so the closure was
            // dropped without observing `ptr`; ownership remains
            // here. Leak the box: dropping it would invoke the vmap
            // destructor and take `dma_resv_lock` from the
            // signalling section that prompted the deferral.
            let boxed = unsafe { KBox::from_raw(ptr) };
            core::mem::forget(KBox::into_inner(boxed));
            pr_err!("Failed to enqueue MappedBo vmap cleanup: {:?}\n", e);
        }
    }
}

/// A vmap of a user-mapped GPU buffer object.
///
/// Unlike `MappedBo` (which is kernel-only and carries the
/// kernel-side VA allocation), `MappedUserBo` is for BOs whose GPU
/// VA was allocated by userspace via the gpuvm ioctls. The wrapper
/// exists so the scheduler's foreign-BO sync-wait evaluator can read
/// sync values out of user BOs without those BOs being kernel-owned.
///
/// The BO must be pinned (i.e. it has at least one live GPU mapping)
/// for the vmap to be safe.
///
/// The vmap's `owner` is the only GEM reference this type holds.
/// `Drop` ships the vmap to the cleanup workqueue, so the final GEM put,
/// whose `free_callback` tears down the cached sg table under
/// `dma_resv_lock`, never runs on the dropping context, which may be
/// a dma-fence signalling section.
pub(crate) struct MappedUserBo {
    /// `Some` for the entire lifetime of the value; taken to `None`
    /// only by `Drop` when shipping the vmap to the cleanup
    /// workqueue.
    vmap: Option<shmem::VMapOwned<BoData>>,
    cleanup_wq: Arc<CleanupQueue>,
}

impl MappedUserBo {
    pub(crate) fn new(bo: &Bo, cleanup_wq: Arc<CleanupQueue>) -> Result<Arc<Self>> {
        let vmap = bo.owned_vmap::<0>()?;
        Ok(Arc::new(
            Self {
                vmap: Some(vmap),
                cleanup_wq,
            },
            GFP_KERNEL,
        )?)
    }

    pub(crate) fn vmap(&self) -> &shmem::VMapOwned<BoData> {
        self.vmap
            .as_ref()
            .expect("MappedUserBo::vmap accessed after drop")
    }

    /// Verifies that `offset..offset + size_of::<T>()` is in bounds of the
    /// mapping and that `offset` is aligned for `T`.
    pub(crate) fn check_offset<T>(&self, offset: usize) -> Result {
        if offset % core::mem::align_of::<T>() != 0 {
            return Err(EINVAL);
        }

        let end = offset
            .checked_add(core::mem::size_of::<T>())
            .ok_or(EINVAL)?;
        if end > self.size() {
            return Err(EINVAL);
        }

        Ok(())
    }

    pub(crate) fn size(&self) -> usize {
        self.vmap().owner().size()
    }
}

/// Send raw-pointer wrapper used to hand a heap-parked vmap to the
/// cleanup closure. Single-consumer: only the closure (success) or
/// this Drop body (failure) calls KBox::from_raw on the inner pointer.
#[repr(transparent)]
struct MappedUserBoCleanupPtr(*mut shmem::VMapOwned<BoData>);

// SAFETY: The pointer is produced by KBox::into_raw and reclaimed by
// KBox::from_raw exactly once, on whichever side observes it first
// (closure on success, this Drop body on failure).
unsafe impl Send for MappedUserBoCleanupPtr {}

impl Drop for MappedUserBo {
    fn drop(&mut self) {
        let Some(vmap) = self.vmap.take() else {
            return;
        };
        let cleanup_wq = self.cleanup_wq.clone();

        let slot: KBox<MaybeUninit<shmem::VMapOwned<BoData>>> = match KBox::new_uninit(GFP_NOWAIT) {
            Ok(s) => s,
            Err(_) => {
                pr_warn_once!(
                    "tyr: MappedUserBo cleanup-state allocation failed; leaking vmap to avoid dma_resv_lock cycle in signalling section\n",
                );
                core::mem::forget(vmap);
                return;
            }
        };
        let boxed = KBox::write(slot, vmap);
        let ptr = KBox::into_raw(boxed);
        let send_ptr = MappedUserBoCleanupPtr(ptr);

        let res = cleanup_wq.try_spawn(GFP_NOWAIT, move || {
            // Force `Send` capture of the wrapper, see `KernelBo`.
            let send_ptr = send_ptr;
            // SAFETY: `send_ptr.0` was produced by `KBox::into_raw`
            // in the matching `MappedUserBo::drop` body and is only
            // reclaimed by `KBox::from_raw` once: by this closure on
            // the success path, or by the `Drop` body on the
            // enqueue-failure path. The cleanup workqueue runs
            // outside any dma-fence signalling section, so taking
            // `dma_resv_lock` from the vmap destructor is safe here.
            drop(unsafe { KBox::from_raw(send_ptr.0) });
        });

        if let Err(e) = res {
            pr_warn_once!(
                "tyr: MappedUserBo cleanup_wq enqueue failed under memory pressure; leaking vmap to avoid dma_resv_lock cycle in signalling section\n",
            );
            // SAFETY: `try_spawn` returned `Err`, so the closure was
            // dropped without observing `ptr`; ownership remains
            // here. Leak the box: dropping it would invoke the vmap
            // destructor and take `dma_resv_lock` from the
            // signalling section that prompted the deferral.
            let boxed = unsafe { KBox::from_raw(ptr) };
            core::mem::forget(KBox::into_inner(boxed));
            pr_err!("Failed to enqueue MappedUserBo vmap cleanup: {:?}\n", e);
        }
    }
}

/// Returns whether a BO should be mapped write-combine.
pub(crate) fn should_map_wc(coherent: bool, flags: u32) -> bool {
    if coherent {
        return false;
    }

    if flags & uapi::drm_panthor_bo_flags_DRM_PANTHOR_BO_WB_MMAP != 0 {
        return false;
    }

    true
}

/// Creates a dummy GEM object to serve as the root of a GPUVM.
pub(crate) fn new_dummy_object<Ctx: DeviceContext>(
    ddev: &TyrDrmDevice<Ctx>,
    coherent: bool,
) -> Result<ARef<Bo>> {
    let bo = gem::shmem::Object::<BoData>::new(
        ddev,
        4096,
        shmem::ObjectConfig {
            map_wc: should_map_wc(coherent, 0),
            parent_resv_obj: None,
        },
        BoCreateArgs {
            flags: 0,
            exclusive_vm_root_gem: None,
        },
    )?;

    Ok(bo)
}

pub(crate) fn new_bo<Ctx: DeviceContext>(
    ddev: &TyrDrmDevice<Ctx>,
    size: usize,
    flags: u32,
    coherent: bool,
    exclusive_vm: Option<&Vm>,
) -> Result<ARef<Bo>> {
    if size == 0 {
        return Err(EINVAL);
    }
    let aligned_size = size.checked_next_multiple_of(1 << 12).ok_or(EINVAL)?;

    let map_wc = should_map_wc(coherent, flags);
    let bo = Bo::new(
        ddev,
        aligned_size,
        shmem::ObjectConfig {
            map_wc,
            parent_resv_obj: exclusive_vm.map(|vm| vm.root_gem()),
        },
        BoCreateArgs {
            flags,
            exclusive_vm_root_gem: exclusive_vm.map(|vm| vm.root_gem().into()),
        },
    )?;

    if map_wc {
        // SAFETY: `ddev` is bound for the duration of the ioctl path that
        // reaches this function.
        let dev = unsafe { ddev.as_ref().as_bound() };
        bo.sg_table(dev)?;
    }

    Ok(bo)
}

pub(crate) fn lookup_handle(file: &TyrDrmFile, handle: u32) -> Result<ARef<Bo>> {
    shmem::Object::lookup_handle(file, handle)
}

/// Performs explicit CPU cache maintenance on a sub-range of `bo`.
pub(crate) fn sync(
    bo: &Bo,
    dev: &device::Device<Bound>,
    type_: u32,
    offset: u64,
    size: u64,
) -> Result {
    let bo_size = bo.size() as u64;
    let end = offset.checked_add(size).ok_or(EINVAL)?;
    if end > bo_size {
        return Err(EINVAL);
    }

    if bo.is_imported() {
        return Err(EINVAL);
    }

    match type_ {
        uapi::drm_panthor_bo_sync_op_type_DRM_PANTHOR_BO_SYNC_CPU_CACHE_FLUSH
        | uapi::drm_panthor_bo_sync_op_type_DRM_PANTHOR_BO_SYNC_CPU_CACHE_FLUSH_AND_INVALIDATE => {}
        _ => return Err(EINVAL),
    }

    if bo.map_wc() {
        return Ok(());
    }

    if size == 0 {
        return Ok(());
    }

    let sgt = bo.sg_table(dev)?;

    let mut offset = offset;
    let mut size = size;

    for entry in sgt.iter() {
        if size == 0 {
            break;
        }

        let paddr = entry.dma_address();
        let len: u64 = entry.dma_len();

        if len <= offset {
            offset -= len;
            continue;
        }

        let paddr = paddr + offset;
        let mut len = len - offset;
        if len > size {
            len = size;
        }
        size -= len;
        offset = 0;

        // A single bidirectional sync does not both flush and invalidate on arm64,
        // so the invalidate case needs a second sync in the other direction.
        // SAFETY: `paddr` and `len` describe a sub-range of `sgt`, DMA-mapped for `dev` as
        // DMA_BIDIRECTIONAL by `bo.sg_table(dev)` and live for this call. DMA_TO_DEVICE and
        // DMA_FROM_DEVICE are valid subsets of that direction.
        unsafe { sync_single_for_device(dev, paddr, len as usize, DataDirection::ToDevice) };
        if type_
            == uapi::drm_panthor_bo_sync_op_type_DRM_PANTHOR_BO_SYNC_CPU_CACHE_FLUSH_AND_INVALIDATE
        {
            // SAFETY: As above.
            unsafe { sync_single_for_cpu(dev, paddr, len as usize, DataDirection::FromDevice) };
        }
    }

    Ok(())
}

/// Creates a kernel-owned GEM object mapped into the VM and vmapped for CPU access.
///
/// The BO's `dma_resv` is aliased to the VM root GEM, so a fence on one
/// VM BO blocks operations on the others.
pub(crate) fn new_kernel_object<Ctx: DeviceContext>(
    dev: &TyrDrmDevice<Ctx>,
    vm: &Arc<Vm>,
    size: usize,
    flags: VmMapFlags,
    coherent: bool,
    cleanup_wq: Arc<CleanupQueue>,
) -> Result<Arc<MappedBo>> {
    MappedBo::new(new_kernel_object_no_vmap(
        dev, vm, size, flags, coherent, cleanup_wq,
    )?)
}

/// Creates a kernel-owned GEM object mapped into the VM, without a vmap
/// for CPU access.
///
/// Prefer this over `new_kernel_object` for buffers touched only by the GPU or
/// firmware touch. On a non-coherent device, the CPU vmap would be
/// write-combined while the GPU mapping is cacheable. Accessing memory
/// through mismatched attributes is architecturally unpredictable on
/// arm64.
///
/// The BO's `dma_resv` is aliased to the VM root GEM, so a fence on one
/// VM BO blocks operations on the others.
pub(crate) fn new_kernel_object_no_vmap<Ctx: DeviceContext>(
    dev: &TyrDrmDevice<Ctx>,
    vm: &Arc<Vm>,
    size: usize,
    flags: VmMapFlags,
    coherent: bool,
    cleanup_wq: Arc<CleanupQueue>,
) -> Result<KernelBo> {
    let aligned_size = size.next_multiple_of(1 << 12);
    let node = vm.alloc_kernel_range(aligned_size)?;
    let va = node.start();

    Ok(KernelBo::new(
        dev,
        vm.as_arc_borrow(),
        aligned_size as u64,
        KernelBoVaAlloc::Explicit(va),
        flags,
        coherent,
        cleanup_wq,
    )?
    .with_va_reservation(node))
}

/// VA allocation strategy for kernel buffer objects.
///
/// Specifies how the GPU virtual address should be determined when creating
/// a [`KernelBo`]. An automatic VA allocation strategy will be added in the future.
pub(crate) enum KernelBoVaAlloc {
    /// Explicit VA address specified by the caller.
    Explicit(u64),
}

/// A kernel-owned buffer object with automatic GPU virtual address mapping.
///
/// This structure represents a buffer object that is created and managed entirely
/// by the kernel driver, as opposed to userspace-created GEM objects. It combines
/// a GEM object with automatic GPU virtual address (VA) space mapping and cleanup.
///
/// When dropped, the buffer is automatically unmapped from the GPU VA space.
pub(crate) struct KernelBo {
    /// The underlying GEM buffer object.
    ///
    /// Wrapped in `ManuallyDrop` so that `Drop` can move the single
    /// owning reference into the deferred cleanup, leaving nothing for
    /// `drop_in_place` to release inline. The GEM object's final drop
    /// runs `Object::free_callback`, whose cached sg-table teardown
    /// takes `dma_resv_lock`; on the success path that must happen on
    /// the cleanup workqueue, never on the dma-fence signalling path
    /// that may be dropping this `KernelBo`.
    pub(crate) bo: ManuallyDrop<ARef<Bo>>,
    /// The GPU VM this buffer is mapped into.
    ///
    /// `ManuallyDrop` so the final `Arc<Vm>` release runs from the
    /// deferred cleanup rather than inline on the dma-fence signalling
    /// path.
    vm: ManuallyDrop<Arc<Vm>>,
    /// The GPU VA range occupied by this buffer.
    va_range: Range<u64>,
    /// Kernel-VA pool reservation backing `va_range`, for BOs whose
    /// VA was handed out by `Vm::alloc_kernel_range`. Dropped from
    /// the deferred cleanup closure once `Vm::unmap_range` has torn
    /// the mapping down. Leaked instead if the unmap fails, since a
    /// live mapping still covers the address. `None` for BOs with
    /// externally managed reservations (the firmware load path,
    /// which uses `Vm::reserve_kernel_range`).
    kernel_node: Option<range::LiveRange>,
    /// Cleanup workqueue used by `Drop` to defer the GPU unmap out
    /// of any dma-fence signalling section the drop may run under.
    cleanup_wq: Arc<CleanupQueue>,
}

impl KernelBo {
    /// Creates a new kernel-owned buffer object and maps it into GPU VA space.
    ///
    /// This function allocates a new shmem-backed GEM object and immediately maps
    /// it into the specified GPU virtual memory space. The mapping is automatically
    /// cleaned up when the [`KernelBo`] is dropped.
    pub(crate) fn new<Ctx: DeviceContext>(
        ddev: &TyrDrmDevice<Ctx>,
        vm: ArcBorrow<'_, Vm>,
        size: u64,
        va_alloc: KernelBoVaAlloc,
        flags: VmMapFlags,
        coherent: bool,
        cleanup_wq: Arc<CleanupQueue>,
    ) -> Result<Self> {
        if size == 0 {
            pr_err!("Cannot create KernelBo with size 0\n");
            return Err(EINVAL);
        }

        let KernelBoVaAlloc::Explicit(va) = va_alloc;

        let bo = gem::shmem::Object::<BoData>::new(
            ddev,
            size as usize,
            shmem::ObjectConfig {
                map_wc: should_map_wc(coherent, 0),
                parent_resv_obj: Some(vm.root_gem()),
            },
            BoCreateArgs {
                flags: 0,
                exclusive_vm_root_gem: Some(vm.root_gem().into()),
            },
        )?;

        vm.map_bo_range(&bo, 0, size, va, flags)?;

        Ok(KernelBo {
            bo: ManuallyDrop::new(bo),
            vm: ManuallyDrop::new(vm.into()),
            va_range: va..(va + size),
            kernel_node: None,
            cleanup_wq,
        })
    }

    /// Returns the GPU virtual address range occupied by this buffer.
    pub(crate) fn va_range(&self) -> Range<u64> {
        self.va_range.clone()
    }

    /// Returns the kernel-VA pool reservation range, if this buffer
    /// was created against `Vm::alloc_kernel_range`. `None` for
    /// firmware-load BOs whose VA is owned by
    /// `Vm::reserve_kernel_range`.
    pub(crate) fn kernel_va(&self) -> Option<Range<u64>> {
        self.kernel_node.as_ref().map(|node| node.range())
    }

    /// Attaches a kernel-VA pool reservation to this buffer so that the
    /// VA cannot be reused until the deferred unmap in `Drop` has
    /// actually run. Only used by `new_kernel_object_no_vmap`; the
    /// firmware load path leaves the reservation `None` and manages its
    /// VA via `Vm::reserve_kernel_range` instead.
    fn with_va_reservation(mut self, node: range::LiveRange) -> Self {
        self.kernel_node = Some(node);
        self
    }
}

/// Heap-parked captures for the `KernelBo::drop` hand-off to the
/// cleanup workqueue.
///
/// Living on the heap rather than inside the `Queue::try_spawn`
/// closure lets the `Drop` body recover the captures and run the
/// cleanup inline if enqueue fails on the dma-fence signalling path.
/// Letting the closure drop in place on enqueue failure would skip
/// the GPU unmap entirely, leaving stale PTEs that could be observed
/// by the next allocation handed the same VA.
struct KernelBoCleanup {
    vm: Arc<Vm>,
    bo: ARef<Bo>,
    va: u64,
    size: u64,
    /// Kernel-VA pool reservation, held until the deferred unmap has
    /// actually torn down the GPU PTEs. `None` for BOs whose VA is
    /// managed externally (the firmware load path, which uses
    /// `Vm::reserve_kernel_range`).
    kernel_node: Option<range::LiveRange>,
}

/// `Send` raw-pointer wrapper used to hand a `KernelBoCleanup` box
/// to the cleanup closure. Ownership transfers to whichever side
/// observes `KBox::from_raw` first; that is the closure on the
/// success path and the `Drop` body on the enqueue-failure path.
#[repr(transparent)]
struct KernelBoCleanupPtr(*mut KernelBoCleanup);

// SAFETY: The pointer is produced by `KBox::into_raw` and is never
// duplicated: the closure captures one copy by value, and the
// `Drop` body retains a sibling copy that it only converts back to
// a `KBox` on the enqueue-failure branch, where `try_spawn` has
// already dropped the closure without observing the pointer.
unsafe impl Send for KernelBoCleanupPtr {}

impl Drop for KernelBo {
    fn drop(&mut self) {
        let va = self.va_range.start;
        let size = self.va_range.end - self.va_range.start;
        // SAFETY: `drop` runs once, this is the only take of `self.vm`,
        // and the field is not read afterwards. Moving the reference out
        // keeps the final `Arc<Vm>` release off the inline drop path.
        let vm = unsafe { ManuallyDrop::take(&mut self.vm) };
        // SAFETY: `Drop::drop` runs at most once, and this is the only
        // `ManuallyDrop::take` of `self.bo`; the field is never read
        // again afterwards. Moving out the single owning reference here
        // (rather than cloning) means `drop_in_place` has nothing left
        // to release inline, so the GEM object's final drop, with its
        // `dma_resv_lock`-taking sg-table teardown, can only run from
        // the cleanup closure or the inline fallback below.
        let bo = unsafe { ManuallyDrop::take(&mut self.bo) };
        let kernel_node = self.kernel_node.take();

        let slot: KBox<MaybeUninit<KernelBoCleanup>> = match KBox::new_uninit(GFP_NOWAIT) {
            Ok(s) => s,
            Err(_) => {
                pr_warn_once!(
                    "tyr: KernelBo cleanup-state allocation failed; performing inline unmap (lockdep cycle may fire)\n",
                );
                inline_kernel_bo_unmap(KernelBoCleanup {
                    vm,
                    bo,
                    va,
                    size,
                    kernel_node,
                });
                return;
            }
        };
        let boxed = KBox::write(
            slot,
            KernelBoCleanup {
                vm,
                bo,
                va,
                size,
                kernel_node,
            },
        );
        let ptr = KBox::into_raw(boxed);
        let send_ptr = KernelBoCleanupPtr(ptr);

        let res = self.cleanup_wq.try_spawn(GFP_NOWAIT, move || {
            // Force the closure to capture the whole `Send` wrapper
            // by value rather than disjointly capturing the `*mut`
            // field; capturing just the field would make the closure
            // non-`Send`.
            let send_ptr = send_ptr;
            // SAFETY: `send_ptr.0` was produced by `KBox::into_raw`
            // in the matching `KernelBo::drop` body and is only
            // reclaimed by `KBox::from_raw` once: by this closure on
            // the success path, or by the `Drop` body on the
            // enqueue-failure path. `try_spawn` runs the closure at
            // most once and only when enqueue succeeded.
            let boxed = unsafe { KBox::from_raw(send_ptr.0) };
            let KernelBoCleanup {
                vm,
                bo,
                va,
                size,
                kernel_node,
            } = KBox::into_inner(boxed);
            let unmapped = vm
                .unmap_range(va, size)
                .inspect_err(|e| {
                    pr_err!(
                        "Failed to unmap KernelBo range {:#x}..{:#x}: {:?}\n",
                        va,
                        va + size,
                        e
                    );
                })
                .is_ok();
            // Force the closure to capture `bo` so its drop runs on the
            // cleanup workqueue, not back here on the dma-fence
            // signalling path.
            drop(bo);
            release_kernel_va(kernel_node, unmapped);
        });

        if let Err(e) = res {
            pr_warn_once!(
                "tyr: KernelBo cleanup_wq enqueue failed under memory pressure; performing inline unmap (lockdep cycle may fire)\n",
            );
            // SAFETY: `try_spawn` returned `Err`, so the closure was
            // dropped without observing `ptr`; ownership of the
            // boxed captures therefore remains with this thread.
            let boxed = unsafe { KBox::from_raw(ptr) };
            let captures = KBox::into_inner(boxed);
            pr_err!(
                "Failed to enqueue KernelBo cleanup for {:#x}..{:#x}: {:?}\n",
                captures.va,
                captures.va + captures.size,
                e,
            );
            inline_kernel_bo_unmap(captures);
        }
    }
}

/// Inline fallback for `KernelBo::drop` when the cleanup workqueue
/// hand-off cannot be set up. Runs the unmap and then releases the VA
/// reservation. Taking `gpuvm_unique` here may trigger a lockdep
/// splat if Drop fired from a dma-fence signalling path.
fn inline_kernel_bo_unmap(captures: KernelBoCleanup) {
    let KernelBoCleanup {
        vm,
        bo,
        va,
        size,
        kernel_node,
    } = captures;
    let unmapped = vm
        .unmap_range(va, size)
        .inspect_err(|e| {
            pr_err!(
                "Failed to inline-unmap KernelBo range {:#x}..{:#x}: {:?}\n",
                va,
                va + size,
                e
            );
        })
        .is_ok();
    drop(bo);
    release_kernel_va(kernel_node, unmapped);
}

/// Frees the kernel-VA reservation, or keeps it out of the pool when the
/// unmap failed and a live mapping still covers the address.
fn release_kernel_va(node: Option<range::LiveRange>, unmapped: bool) {
    match node {
        Some(node) if !unmapped => node.leak(),
        node => drop(node),
    }
}
