// SPDX-License-Identifier: GPL-2.0 or MIT
//! GEM buffer object management for the Tyr driver.
//!
//! This module provides buffer object (BO) management functionality using
//! DRM's GEM subsystem with shmem backing.

use core::mem::ManuallyDrop;
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
        gem::IntoGEMObject,
        DeviceContext, //
    },
    new_mutex,
    page::PAGE_SIZE,
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
    cleanup,
    driver::{
        TyrDrmDevice,
        TyrDrmDriver, //
    },
    file::TyrDrmFile,
    trace,
    vm::{
        range,
        Vm,
        VmMapFlags, //
    },
};

#[cfg(CONFIG_DEBUG_FS)]
use crate::debugfs::{
    GEM_USAGE_FW_MAPPED,
    GEM_USAGE_KERNEL,
    NOT_REGISTERED, //
};
#[cfg(CONFIG_DEBUG_FS)]
use kernel::str::CStr;
#[cfg(CONFIG_DEBUG_FS)]
use kernel::sync::atomic::Atomic;

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
    /// Index of this BO in the device-wide debugfs registry, or
    /// `NOT_REGISTERED`. Only ever touched under the registry lock.
    #[cfg(CONFIG_DEBUG_FS)]
    registry_slot: Atomic<usize>,
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

    /// Returns this BO's slot in the device-wide debugfs registry.
    #[cfg(CONFIG_DEBUG_FS)]
    pub(crate) fn registry_slot(&self) -> &Atomic<usize> {
        &self.registry_slot
    }

    /// Runs `f` with the BO label held under its lock.
    #[cfg(CONFIG_DEBUG_FS)]
    pub(crate) fn with_label<R>(&self, f: impl FnOnce(Option<&CStr>) -> R) -> R {
        f(self.label.lock().as_deref())
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
            #[cfg(CONFIG_DEBUG_FS)]
            registry_slot: Atomic::new(NOT_REGISTERED),
        })
    }

    fn create_imported(_dev: &TyrDrmDevice, _size: usize) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            flags: 0,
            exclusive_vm_root_gem: None,
            label <- new_mutex!(None),
            #[cfg(CONFIG_DEBUG_FS)]
            registry_slot: Atomic::new(NOT_REGISTERED),
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

    #[cfg(CONFIG_DEBUG_FS)]
    fn free(obj: &Bo) {
        // A firmware-section BO can be created on the unregistered device and
        // freed on a probe-error path, where the driver data is absent.
        if let Some(data) = obj.dev().data() {
            data.gem_registry().unregister(obj.registry_slot());
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
    /// Ships the vmap to the cleanup workqueue and keeps the device alive
    /// for its final GEM put. `Some` for the entire lifetime of the value,
    /// taken by `Drop` with `vmap`.
    handoff: Option<cleanup::Handoff<MappedBoRelease, ARef<TyrDrmDevice>>>,
}

impl MappedBo {
    pub(crate) fn new(kernel_bo: KernelBo) -> Result<Arc<Self>> {
        let handoff = cleanup::Handoff::new(kernel_bo.bo.dev().into())?;
        let vmap = kernel_bo.bo.owned_vmap::<0>()?;
        Ok(Arc::new(
            Self {
                kernel_bo,
                vmap: Some(vmap),
                handoff: Some(handoff),
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

impl Drop for MappedBo {
    fn drop(&mut self) {
        let (Some(vmap), Some(handoff)) = (self.vmap.take(), self.handoff.take()) else {
            return;
        };
        let range = self.kernel_bo.va_range();
        let va = range.start;
        let size = range.end - range.start;

        trace::cleanup_wq_enqueue(trace::CleanupWqKind::MappedBoVmap, va, size);
        handoff.spawn((vmap, va, size), mapped_bo_vmap_drop);
    }
}

/// The vmap and GPU VA range that `MappedBo::drop` hands to
/// `mapped_bo_vmap_drop`.
type MappedBoRelease = (shmem::VMapOwned<BoData>, u64, u64);

/// Drops a `MappedBo` vmap on the cleanup workqueue.
fn mapped_bo_vmap_drop((vmap, va, size): MappedBoRelease) {
    trace::cleanup_wq_exec(trace::CleanupWqKind::MappedBoVmap, va, size);
    drop(vmap);
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
    /// Ships the vmap to the cleanup workqueue and keeps the device alive
    /// for its final GEM put. `Some` for the entire lifetime of the value,
    /// taken by `Drop` with `vmap`.
    handoff: Option<cleanup::Handoff<shmem::VMapOwned<BoData>, ARef<TyrDrmDevice>>>,
}

impl MappedUserBo {
    pub(crate) fn new(bo: &Bo) -> Result<Arc<Self>> {
        let handoff = cleanup::Handoff::new(bo.dev().into())?;
        let vmap = bo.owned_vmap::<0>()?;
        Ok(Arc::new(
            Self {
                vmap: Some(vmap),
                handoff: Some(handoff),
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

impl Drop for MappedUserBo {
    fn drop(&mut self) {
        let (Some(vmap), Some(handoff)) = (self.vmap.take(), self.handoff.take()) else {
            return;
        };

        handoff.spawn(vmap, drop);
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
        PAGE_SIZE,
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

pub(crate) fn new_bo(
    ddev: &TyrDrmDevice,
    size: usize,
    flags: u32,
    coherent: bool,
    exclusive_vm: Option<&Vm>,
) -> Result<ARef<Bo>> {
    if size == 0 {
        return Err(EINVAL);
    }
    let aligned_size = size.checked_next_multiple_of(PAGE_SIZE).ok_or(EINVAL)?;

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

    #[cfg(CONFIG_DEBUG_FS)]
    ddev.gem_registry().register(&bo, 0);

    if map_wc {
        // SAFETY: `ddev` is bound for the duration of the ioctl path that
        // reaches this function.
        let dev = unsafe { ddev.as_ref().as_bound() };
        if let Err(e) = bo.sg_table(dev) {
            dev_err!(
                ddev.as_ref(),
                "tyr: eager sg_table fetch failed for WC BO (size={aligned_size}): {e:?}\n"
            );
            return Err(e);
        }
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

/// Returns the address of the underlying `struct drm_gem_object` as a
/// file-independent debug identity for the BO. Used only to correlate a
/// BO's mapping lifecycle in tracepoints; never dereferenced.
pub(crate) fn debug_id(bo: &Bo) -> u64 {
    bo.as_raw() as u64
}

/// Creates a kernel-owned GEM object mapped into the VM and vmapped for CPU access.
///
/// The BO's `dma_resv` is aliased to the VM root GEM, so a fence on one
/// VM BO blocks operations on the others.
pub(crate) fn new_kernel_object(
    dev: &TyrDrmDevice,
    vm: &Arc<Vm>,
    size: usize,
    flags: VmMapFlags,
    coherent: bool,
) -> Result<Arc<MappedBo>> {
    MappedBo::new(new_kernel_object_no_vmap(dev, vm, size, flags, coherent)?)
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
///
/// The object and the mapping are both rounded to the host page size,
/// so `Bo::size()` matches the mapping.
pub(crate) fn new_kernel_object_no_vmap(
    dev: &TyrDrmDevice,
    vm: &Arc<Vm>,
    size: usize,
    flags: VmMapFlags,
    coherent: bool,
) -> Result<KernelBo> {
    let aligned_size = size.checked_next_multiple_of(PAGE_SIZE).ok_or(EINVAL)?;
    let node = vm.alloc_kernel_range(aligned_size)?;
    let va = node.start();

    let kernel_bo = KernelBo::new(
        dev,
        vm.as_arc_borrow(),
        aligned_size as u64,
        KernelBoVaAlloc::Explicit(va),
        flags,
        coherent,
        KernelBoOwner::User(dev.into()),
    )?
    .with_va_reservation(node);

    #[cfg(CONFIG_DEBUG_FS)]
    {
        let usage = GEM_USAGE_KERNEL | if vm.is_fw() { GEM_USAGE_FW_MAPPED } else { 0 };
        dev.gem_registry().register(&kernel_bo.bo, usage);
    }

    Ok(kernel_bo)
}

/// VA allocation strategy for kernel buffer objects.
///
/// Specifies how the GPU virtual address should be determined when creating
/// a [`KernelBo`]. An automatic VA allocation strategy will be added in the future.
pub(crate) enum KernelBoVaAlloc {
    /// Explicit VA address specified by the caller.
    Explicit(u64),
}

/// Owner of a `KernelBo`.
pub(crate) enum KernelBoOwner {
    /// The device, for a firmware section.
    Firmware,
    /// A group, queue or heap object. The BO holds this device reference
    /// until its deferred unmap has run.
    User(ARef<TyrDrmDevice>),
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
    /// the deferred cleanup once `Vm::unmap_exact` has torn
    /// the mapping down. Leaked instead if the unmap fails, since a
    /// live mapping still covers the address. `None` for BOs with
    /// externally managed reservations (the firmware load path,
    /// which uses `Vm::reserve_kernel_range`).
    kernel_node: Option<range::LiveRange>,
    /// Ships the unmap to the cleanup workqueue and keeps the device alive
    /// until it has run. `None` for firmware sections, which the device owns.
    handoff: Option<cleanup::Handoff<KernelBoCleanup, ARef<TyrDrmDevice>>>,
}

impl KernelBo {
    /// Creates a new kernel-owned buffer object and maps it into GPU VA space.
    ///
    /// This function allocates a new shmem-backed GEM object and immediately maps
    /// it into the specified GPU virtual memory space. The mapping is automatically
    /// cleaned up when the [`KernelBo`] is dropped.
    ///
    /// The object is rounded up to the host page size while the mapping
    /// keeps `size`.
    pub(crate) fn new<Ctx: DeviceContext>(
        ddev: &TyrDrmDevice<Ctx>,
        vm: ArcBorrow<'_, Vm>,
        size: u64,
        va_alloc: KernelBoVaAlloc,
        flags: VmMapFlags,
        coherent: bool,
        owner: KernelBoOwner,
    ) -> Result<Self> {
        if size == 0 {
            pr_err!("Cannot create KernelBo with size 0\n");
            return Err(EINVAL);
        }

        let KernelBoVaAlloc::Explicit(va) = va_alloc;

        let bo_size = usize::try_from(size)
            .ok()
            .and_then(|bytes| bytes.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(EOVERFLOW)?;
        let handoff = match owner {
            KernelBoOwner::Firmware => None,
            KernelBoOwner::User(dev) => Some(cleanup::Handoff::new(dev)?),
        };

        let bo = gem::shmem::Object::<BoData>::new(
            ddev,
            bo_size,
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
            handoff,
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

/// Captures for the `KernelBo::drop` hand-off to the cleanup workqueue.
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
        // the cleanup workqueue or the inline path below.
        let bo = unsafe { ManuallyDrop::take(&mut self.bo) };
        let kernel_node = self.kernel_node.take();

        let captures = KernelBoCleanup {
            vm,
            bo,
            va,
            size,
            kernel_node,
        };

        // Firmware sections have no hand-off. They are dropped only by probe
        // and the device release, outside any signalling section.
        match self.handoff.take() {
            Some(handoff) => {
                trace::cleanup_wq_enqueue(trace::CleanupWqKind::KernelBo, va, size);
                handoff.spawn(captures, kernel_bo_unmap_deferred);
            }
            None => kernel_bo_unmap(captures),
        }
    }
}

/// Adds the exec trace to the hand-off path. A firmware section calls
/// `kernel_bo_unmap` without it.
fn kernel_bo_unmap_deferred(captures: KernelBoCleanup) {
    trace::cleanup_wq_exec(trace::CleanupWqKind::KernelBo, captures.va, captures.size);
    kernel_bo_unmap(captures);
}

/// Tears down a `KernelBo` mapping and then releases the VA
/// reservation. Runs on the cleanup workqueue, or inline from
/// `KernelBo::drop` for a firmware section.
fn kernel_bo_unmap(captures: KernelBoCleanup) {
    let KernelBoCleanup {
        vm,
        bo,
        va,
        size,
        kernel_node,
    } = captures;
    let unmapped = vm
        .unmap_exact(va, size)
        .inspect_err(|e| {
            pr_err!(
                "Failed to unmap KernelBo range {:#x}..{:#x}: {:?}\n",
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
