// SPDX-License-Identifier: GPL-2.0 or MIT
//! GEM buffer object management for the Tyr driver.
//!
//! This module provides buffer object (BO) management functionality using
//! DRM's GEM subsystem with shmem backing.

use core::mem::ManuallyDrop;
use core::ops::Range;

use kernel::{
    device::{
        Bound,
        Device, //
    },
    drm::gem::{
        self,
        shmem,
        BaseObject, //
    },
    pr_warn_once,
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    }, //
};

use crate::{
    cleanup,
    driver::{
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

/// Tyr's DriverObject type for GEM objects.
#[pin_data]
pub(crate) struct BoData {
    flags: u32,
    /// Root GEM object of the VM whose `dma_resv` this BO shares, if any.
    exclusive_vm_root_gem: Option<ARef<Bo>>,
}

impl BoData {
    pub(crate) fn create_flags(&self) -> u32 {
        self.flags
    }

    pub(crate) fn exclusive_vm_root_gem(&self) -> Option<&Bo> {
        self.exclusive_vm_root_gem.as_deref()
    }
}

/// Provides a way to pass arguments when creating BoData
/// as required by the gem::DriverObject trait.
pub(crate) struct BoCreateArgs {
    flags: u32,
    /// Root GEM object of the VM whose `dma_resv` this BO shares, if any.
    exclusive_vm_root_gem: Option<ARef<Bo>>,
}

impl gem::DriverObject for BoData {
    type Driver = TyrDrmDriver;
    type Args = BoCreateArgs;

    fn new(_dev: &TyrDrmDevice, _size: usize, args: BoCreateArgs) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            flags: args.flags,
            exclusive_vm_root_gem: args.exclusive_vm_root_gem,
        })
    }

    fn create_imported(_dev: &TyrDrmDevice, _size: usize) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            flags: 0,
            exclusive_vm_root_gem: None,
        })
    }

    fn export(obj: &Bo, _flags: c_int) -> Result {
        if obj.exclusive_vm_root_gem.is_some() {
            return Err(EINVAL);
        }

        Ok(())
    }
}

/// Type alias for Tyr GEM buffer objects.
pub(crate) type Bo = gem::shmem::Object<BoData>;

/// A mapped kernel-owned buffer object with an always-valid kernel mapping.
///
/// `vmap` owns its mapping and GEM reference, so it stays valid after
/// `kernel_bo` drops.
pub(crate) struct MappedBo {
    kernel_bo: KernelBo,
    vmap: BoVmap,
}

impl MappedBo {
    pub(crate) fn new(kernel_bo: KernelBo) -> Result<Arc<Self>> {
        let vmap = BoVmap::new(kernel_bo.bo())?;
        Ok(Arc::new(Self { kernel_bo, vmap }, GFP_KERNEL)?)
    }

    pub(crate) fn kernel_va(&self) -> Option<Range<u64>> {
        self.kernel_bo.kernel_va()
    }
}

impl core::ops::Deref for MappedBo {
    type Target = BoVmap;

    fn deref(&self) -> &BoVmap {
        &self.vmap
    }
}

/// An owned CPU mapping of a GPU buffer object.
///
/// The BO must be pinned (i.e. it has at least one live GPU mapping)
/// for the vmap to be safe.
///
/// The vmap's `owner` is the only GEM reference this type holds.
/// `Drop` ships the vmap to the cleanup workqueue, so the final GEM put,
/// whose `free_callback` tears down the cached sg table under
/// `dma_resv_lock`, never runs on the dropping context, which may be
/// a dma-fence signalling section.
pub(crate) struct BoVmap {
    /// `Some` for the entire lifetime of the value; taken to `None`
    /// only by `Drop` when shipping the vmap to the cleanup
    /// workqueue.
    vmap: Option<shmem::VMapOwned<BoData>>,
}

impl BoVmap {
    pub(crate) fn new(bo: &Bo) -> Result<Self> {
        let vmap = bo.owned_vmap::<0>()?;
        Ok(Self { vmap: Some(vmap) })
    }

    pub(crate) fn vmap(&self) -> &shmem::VMapOwned<BoData> {
        self.vmap
            .as_ref()
            .expect("BoVmap::vmap accessed after drop")
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

impl core::ops::Deref for BoVmap {
    type Target = Bo;

    fn deref(&self) -> &Bo {
        self.vmap().owner()
    }
}

impl Drop for BoVmap {
    fn drop(&mut self) {
        let Some(vmap) = self.vmap.take() else {
            return;
        };

        let Err(e) = cleanup::try_spawn_owned(vmap, drop) else {
            return;
        };

        match e {
            cleanup::SpawnError::QueueGone(vmap) => drop(vmap),
            cleanup::SpawnError::NoMemory(vmap) => {
                pr_warn_once!(
                    "BoVmap cleanup hand-off failed under memory pressure; leaking vmap to avoid dma_resv_lock cycle in signalling section\n",
                );
                // Dropping the vmap would take `dma_resv_lock` from the
                // signalling section that prompted the deferral.
                core::mem::forget(vmap);
            }
        }
    }
}

/// Returns whether a BO should be mapped write-combine given the device's
/// DMA coherence.
pub(crate) fn should_map_wc(coherent: bool) -> bool {
    if coherent {
        return false;
    }

    true
}

/// Creates a dummy GEM object to serve as the root of a GPUVM.
pub(crate) fn new_dummy_object(ddev: &TyrDrmDevice, coherent: bool) -> Result<ARef<Bo>> {
    let bo = Bo::new(
        ddev,
        4096,
        shmem::ObjectConfig {
            map_wc: should_map_wc(coherent),
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
    dev: &Device<Bound>,
    ddev: &TyrDrmDevice,
    size: usize,
    flags: u32,
    coherent: bool,
    exclusive_vm: Option<&Vm>,
) -> Result<ARef<Bo>> {
    if size == 0 {
        return Err(EINVAL);
    }
    let aligned_size = size.checked_next_multiple_of(1 << 12).ok_or(EINVAL)?;

    let map_wc = should_map_wc(coherent);
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
        bo.sg_table(dev)?;
    }

    Ok(bo)
}

pub(crate) fn lookup_handle(file: &TyrDrmFile, handle: u32) -> Result<ARef<Bo>> {
    shmem::Object::lookup_handle(file, handle)
}

/// Creates a kernel-owned GEM object mapped into the VM and vmapped for CPU access.
///
/// The BO's `dma_resv` is aliased to the VM root GEM, so a fence on one
/// VM BO blocks operations on the others.
pub(crate) fn new_kernel_object(
    dev: &Device<Bound>,
    ddev: &TyrDrmDevice,
    vm: &Arc<Vm>,
    size: usize,
    flags: VmMapFlags,
    coherent: bool,
) -> Result<Arc<MappedBo>> {
    MappedBo::new(new_kernel_object_no_vmap(
        dev, ddev, vm, size, flags, coherent,
    )?)
}

/// Creates a kernel-owned GEM object mapped into the VM, without a vmap
/// for CPU access.
///
/// Prefer this over `new_kernel_object` for buffers only the GPU or the
/// firmware touches. On a non-coherent device the CPU vmap is
/// write-combined while the GPU mapping is cacheable, and accessing memory
/// through mismatched attributes is architecturally unpredictable on arm64.
///
/// The BO's `dma_resv` is aliased to the VM root GEM, so a fence on one
/// VM BO blocks operations on the others.
pub(crate) fn new_kernel_object_no_vmap(
    dev: &Device<Bound>,
    ddev: &TyrDrmDevice,
    vm: &Arc<Vm>,
    size: usize,
    flags: VmMapFlags,
    coherent: bool,
) -> Result<KernelBo> {
    let aligned_size = size.next_multiple_of(1 << 12);
    let node = vm.alloc_kernel_range(aligned_size)?;
    let va = node.start();

    Ok(KernelBo::new(
        dev,
        ddev,
        vm.clone(),
        aligned_size as u64,
        KernelBoVaAlloc::Explicit(va),
        flags,
        coherent,
    )?
    .with_va_reservation(node))
}

/// Specifies how to choose a GPU virtual address for a [`KernelBo`].
/// An automatic VA allocation strategy will be added in the future.
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
    /// Wrapped in `ManuallyDrop` so `Drop` can move the single owning
    /// reference into the deferred cleanup. The GEM object's final drop
    /// runs `Object::free_callback`, whose cached sg-table teardown
    /// takes `dma_resv_lock`, so it must not run on the dma-fence
    /// signalling path that may be dropping this `KernelBo`.
    bo: ManuallyDrop<ARef<Bo>>,
    /// The GPU VM this buffer is mapped into.
    ///
    /// `ManuallyDrop` so the final `Arc<Vm>` release runs from the
    /// deferred cleanup rather than inline on the dma-fence signalling
    /// path.
    vm: ManuallyDrop<Arc<Vm>>,
    /// The GPU VA range occupied by this buffer.
    va_range: Range<u64>,
    /// Kernel-VA pool reservation backing `va_range`. Dropped from the
    /// deferred cleanup once `Vm::unmap_range` has torn the mapping
    /// down, or leaked if the unmap fails and a live mapping still
    /// covers the address. `None` when the VA is managed externally,
    /// as on the firmware load path.
    kernel_node: Option<range::LiveRange>,
}

impl KernelBo {
    /// Creates a new kernel-owned buffer object and maps it into GPU VA space.
    ///
    /// This function allocates a new shmem-backed GEM object and immediately maps
    /// it into the specified GPU virtual memory space. The mapping is automatically
    /// cleaned up when the [`KernelBo`] is dropped.
    pub(crate) fn new(
        dev: &Device<Bound>,
        ddev: &TyrDrmDevice,
        vm: Arc<Vm>,
        size: u64,
        va_alloc: KernelBoVaAlloc,
        flags: VmMapFlags,
        coherent: bool,
    ) -> Result<Self> {
        if size == 0 {
            dev_err!(dev, "Cannot create KernelBo with size 0");
            return Err(EINVAL);
        }

        let KernelBoVaAlloc::Explicit(va) = va_alloc;

        let bo_size = usize::try_from(size).map_err(|_| EOVERFLOW)?;
        let va_end = va.checked_add(size).ok_or(EINVAL)?;

        let bo = Bo::new(
            ddev,
            bo_size,
            shmem::ObjectConfig {
                map_wc: should_map_wc(coherent),
                parent_resv_obj: Some(vm.root_gem()),
            },
            BoCreateArgs {
                flags: 0,
                exclusive_vm_root_gem: Some(vm.root_gem().into()),
            },
        )?;

        vm.map_bo_range(dev, &bo, 0, size, va, flags)?;

        Ok(KernelBo {
            bo: ManuallyDrop::new(bo),
            vm: ManuallyDrop::new(vm),
            va_range: va..va_end,
            kernel_node: None,
        })
    }

    pub(crate) fn bo(&self) -> &Bo {
        &self.bo
    }

    /// Returns the GPU virtual address range occupied by this buffer.
    pub(crate) fn va_range(&self) -> &Range<u64> {
        &self.va_range
    }

    /// Returns the kernel-VA pool reservation range, or `None` when the
    /// VA is managed externally.
    pub(crate) fn kernel_va(&self) -> Option<Range<u64>> {
        self.kernel_node.as_ref().map(|node| node.range())
    }

    /// Attaches a kernel-VA pool reservation to this buffer so that the
    /// VA cannot be reused until the deferred unmap in `Drop` has
    /// actually run. Only used by `new_kernel_object_no_vmap`. The
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
/// Keeping them off the closure lets `Drop` recover them and unmap
/// inline when enqueue fails. Dropping the closure in place would skip
/// the unmap and leave stale PTEs for the next user of the VA.
struct KernelBoCleanup {
    vm: Arc<Vm>,
    bo: ARef<Bo>,
    va: u64,
    size: u64,
    /// Kernel-VA pool reservation, held until the deferred unmap has
    /// torn down the GPU PTEs.
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
        // SAFETY: `Drop::drop` runs at most once, this is the only
        // `ManuallyDrop::take` of `self.bo`, and the field is never
        // read again afterwards.
        let bo = unsafe { ManuallyDrop::take(&mut self.bo) };
        let kernel_node = self.kernel_node.take();

        let captures = KernelBoCleanup {
            vm,
            bo,
            va,
            size,
            kernel_node,
        };

        let Err(e) = cleanup::try_spawn_owned(captures, kernel_bo_unmap) else {
            return;
        };

        let captures = match e {
            cleanup::SpawnError::QueueGone(captures) => captures,
            cleanup::SpawnError::NoMemory(captures) => {
                pr_warn_once!(
                    "KernelBo cleanup hand-off failed under memory pressure; performing inline unmap (lockdep cycle may fire)\n",
                );
                captures
            }
        };
        kernel_bo_unmap(captures);
    }
}

/// Tears down a `KernelBo` mapping and then releases the VA
/// reservation. Runs on the cleanup workqueue, or inline from
/// `KernelBo::drop` when the hand-off cannot be set up, where taking
/// `gpuvm_unique` may trigger a lockdep splat.
fn kernel_bo_unmap(captures: KernelBoCleanup) {
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
            dev_err!(
                vm.dev(),
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
