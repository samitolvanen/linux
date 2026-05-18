// SPDX-License-Identifier: GPL-2.0 or MIT
//! GEM buffer object management for the Tyr driver.
//!
//! This module provides buffer object (BO) management functionality using
//! DRM's GEM subsystem with shmem backing.

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
    prelude::*,
    sync::{
        aref::ARef,
        Arc,
        ArcBorrow, //
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

/// Driver-specific data for Tyr GEM buffer objects.
///
/// This structure contains Tyr-specific metadata associated with each GEM object.
/// It implements [`gem::DriverObject`] to provide driver-specific behavior for
/// buffer object creation and management.
#[pin_data]
pub(crate) struct BoData {
    /// Buffer object creation flags (currently unused).
    flags: u32,
}

impl BoData {
    pub(crate) fn create_flags(&self) -> u32 {
        self.flags
    }
}

/// Arguments for creating a [`BoData`] instance.
///
/// This structure is used to pass creation parameters when instantiating
/// a new buffer object, as required by the [`gem::DriverObject`] trait.
pub(crate) struct BoCreateArgs {
    /// Buffer object creation flags (currently unused).
    flags: u32,
}

impl gem::DriverObject for BoData {
    type Driver = TyrDrmDriver;
    type Args = BoCreateArgs;

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
        try_pin_init!(Self { flags: args.flags })
    }

    fn create_imported(_dev: &TyrDrmDevice, _size: usize) -> impl PinInit<Self, Error> {
        try_pin_init!(Self { flags: 0 })
    }
}

/// Type alias for Tyr GEM buffer objects.
pub(crate) type Bo = gem::shmem::Object<BoData>;

/// A mapped kernel-owned buffer object with an always-valid kernel mapping.
pub(crate) struct MappedBo {
    kernel_bo: KernelBo,
    kernel_node: range::LiveRange,
    /// `Some` for the entire lifetime of the value; taken to `None`
    /// only by [`Drop`] when shipping the vmap to the cleanup
    /// workqueue.
    vmap: Option<shmem::VMapOwned<BoData>>,
}

impl MappedBo {
    pub(crate) fn new(kernel_bo: KernelBo, kernel_node: range::LiveRange) -> Result<Arc<Self>> {
        let vmap = kernel_bo.bo.owned_vmap::<0>()?;
        Ok(Arc::new(
            Self {
                kernel_bo,
                kernel_node,
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
        Some(self.kernel_node.range())
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
        let Some(vmap) = self.vmap.take() else {
            return;
        };
        let cleanup_wq = self.kernel_bo.cleanup_wq.clone();

        let res = cleanup_wq.try_spawn(GFP_NOWAIT, move || {
            drop(vmap);
        });

        if let Err(e) = res {
            pr_err!(
                "Failed to enqueue MappedBo vmap cleanup: {:?}; dropping inline\n",
                e,
            );
        }
    }
}

/// A vmap of a user-mapped GPU buffer object.
///
/// Unlike [`MappedBo`] (which is kernel-only and carries the
/// kernel-side VA allocation), `MappedUserBo` is for BOs whose GPU
/// VA was allocated by userspace via the gpuvm ioctls. The wrapper
/// exists so the scheduler's foreign-BO sync-wait evaluator can read
/// sync values out of user BOs without those BOs being kernel-owned.
///
/// The BO must be pinned (i.e. it has at least one live GPU mapping)
/// for the vmap to be safe. All current callers materialise the BO
/// via [`Vm::get_bo_for_va`], which only returns BOs reachable
/// through a live `drm_gpuva`, satisfying that precondition.
pub(crate) struct MappedUserBo {
    #[expect(dead_code)]
    bo: ARef<Bo>,
    /// `Some` for the entire lifetime of the value; taken to `None`
    /// only by [`Drop`] when shipping the vmap to the cleanup
    /// workqueue.
    vmap: Option<shmem::VMapOwned<BoData>>,
    cleanup_wq: Arc<CleanupQueue>,
}

impl MappedUserBo {
    pub(crate) fn new(bo: &Bo, cleanup_wq: Arc<CleanupQueue>) -> Result<Arc<Self>> {
        let vmap = bo.owned_vmap::<0>()?;
        Ok(Arc::new(
            Self {
                bo: bo.into(),
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

impl Drop for MappedUserBo {
    fn drop(&mut self) {
        let Some(vmap) = self.vmap.take() else {
            return;
        };
        let cleanup_wq = self.cleanup_wq.clone();

        let res = cleanup_wq.try_spawn(GFP_NOWAIT, move || {
            drop(vmap);
        });

        if let Err(e) = res {
            pr_err!(
                "Failed to enqueue MappedUserBo vmap cleanup: {:?}; dropping inline\n",
                e,
            );
        }
    }
}

/// Returns whether a BO should be mapped write-combine given the device's
/// DMA coherence and the user-supplied BO creation flags.
///
/// FIXME: Note that this problem is going to pop up again when we decide to
/// support mapping buffers with the NO_MMAP flag as non-shareable (AKA
/// buffers accessed only by the GPU), because we need the same CPU flush to
/// happen after page allocation, otherwise there's a risk of data leak or
/// late corruption caused by a dirty cacheline being evicted. At this point
/// we'll need a way to force CPU cache maintenance regardless of whether the
/// device is coherent or not.
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
        BoCreateArgs { flags: 0 },
    )?;

    Ok(bo)
}

pub(crate) fn new_bo<Ctx: DeviceContext>(
    ddev: &TyrDrmDevice<Ctx>,
    size: usize,
    flags: u32,
    coherent: bool,
) -> Result<ARef<Bo>> {
    let aligned_size = size.next_multiple_of(1 << 12);

    if size == 0 || size > aligned_size {
        return Err(EINVAL);
    }

    let map_wc = should_map_wc(coherent, flags);
    let bo = Bo::new(
        ddev,
        aligned_size,
        shmem::ObjectConfig {
            map_wc,
            parent_resv_obj: None,
        },
        BoCreateArgs { flags },
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
///
/// Mirrors `panthor_gem_sync()`: a no-op for WC-mapped or imported buffers,
/// otherwise walks the BO's scatter-gather table and synchronises the
/// intersecting segments using `dma_sync_single_for_{device,cpu}` for the
/// FLUSH and FLUSH_AND_INVALIDATE op types respectively.
pub(crate) fn sync(
    bo: &Bo,
    dev: &device::Device<Bound>,
    type_: u32,
    offset: u64,
    size: u64,
    coherent: bool,
) -> Result {
    let bo_size = bo.size() as u64;
    let end = offset.checked_add(size).ok_or(EINVAL)?;
    if end > bo_size {
        return Err(EINVAL);
    }

    // SAFETY: `bo.as_raw()` is a valid pointer to a `drm_gem_object` for the
    // lifetime of `bo`. `import_attach` is set at most once at gem creation
    // and never cleared, so a plain read is sound.
    let imported = unsafe { !(*bo.as_raw()).import_attach.is_null() };
    if imported {
        return Err(EINVAL);
    }

    match type_ {
        uapi::drm_panthor_bo_sync_op_type_DRM_PANTHOR_BO_SYNC_CPU_CACHE_FLUSH
        | uapi::drm_panthor_bo_sync_op_type_DRM_PANTHOR_BO_SYNC_CPU_CACHE_FLUSH_AND_INVALIDATE => {}
        _ => return Err(EINVAL),
    }

    if should_map_wc(coherent, bo.create_flags()) {
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

        sync_single_for_device(dev, paddr, len as usize, DataDirection::ToDevice);
        if type_
            == uapi::drm_panthor_bo_sync_op_type_DRM_PANTHOR_BO_SYNC_CPU_CACHE_FLUSH_AND_INVALIDATE
        {
            sync_single_for_cpu(dev, paddr, len as usize, DataDirection::FromDevice);
        }
    }

    Ok(())
}

/// Creates a kernel-owned GEM object mapped into the VM and vmapped for CPU access.
pub(crate) fn new_kernel_object<Ctx: DeviceContext>(
    dev: &TyrDrmDevice<Ctx>,
    vm: &Arc<Vm>,
    size: usize,
    flags: VmMapFlags,
    coherent: bool,
    cleanup_wq: Arc<CleanupQueue>,
) -> Result<Arc<MappedBo>> {
    let aligned_size = size.next_multiple_of(1 << 12);
    let node = vm.alloc_kernel_range(aligned_size)?;
    let va = node.start();

    let kernel_bo = KernelBo::new(
        dev,
        vm.as_arc_borrow(),
        aligned_size as u64,
        KernelBoVaAlloc::Explicit(va),
        flags,
        coherent,
        cleanup_wq,
    )?;

    MappedBo::new(kernel_bo, node)
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
    pub(crate) bo: ARef<Bo>,
    /// The GPU VM this buffer is mapped into.
    vm: Arc<Vm>,
    /// The GPU VA range occupied by this buffer.
    va_range: Range<u64>,
    /// Cleanup workqueue used by [`Drop`] to defer the GPU unmap out
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
                parent_resv_obj: None,
            },
            BoCreateArgs { flags: 0 },
        )?;

        vm.map_bo_range(&bo, 0, size, va, flags)?;

        Ok(KernelBo {
            bo,
            vm: vm.into(),
            va_range: va..(va + size),
            cleanup_wq,
        })
    }

    /// Returns the GPU virtual address range occupied by this buffer.
    pub(crate) fn va_range(&self) -> Range<u64> {
        self.va_range.clone()
    }
}

impl Drop for KernelBo {
    fn drop(&mut self) {
        let va = self.va_range.start;
        let size = self.va_range.end - self.va_range.start;
        let vm = self.vm.clone();
        let bo = self.bo.clone();

        let res = self.cleanup_wq.try_spawn(GFP_NOWAIT, move || {
            if let Err(e) = vm.unmap_range(va, size) {
                pr_err!(
                    "Failed to unmap KernelBo range {:#x}..{:#x}: {:?}\n",
                    va,
                    va + size,
                    e
                );
            }
            // Force the closure to capture `bo` so its drop runs on
            // the cleanup workqueue, not back here on the dma-fence
            // signalling path.
            drop(bo);
        });

        if let Err(e) = res {
            pr_err!(
                "Failed to enqueue KernelBo cleanup for {:#x}..{:#x}: {:?}; leaking range\n",
                va,
                va + size,
                e,
            );
        }
    }
}
