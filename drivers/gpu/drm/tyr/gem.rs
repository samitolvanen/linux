// SPDX-License-Identifier: GPL-2.0 or MIT
//! GEM buffer object management for the Tyr driver.
//!
//! This module provides buffer object (BO) management functionality using
//! DRM's GEM subsystem with shmem backing.

use core::mem::{
    ManuallyDrop,
    MaybeUninit, //
};
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

/// Tyr's DriverObject type for GEM objects.
#[pin_data]
pub(crate) struct BoData {
    flags: u32,
}

impl BoData {
    pub(crate) fn create_flags(&self) -> u32 {
        self.flags
    }
}

/// Provides a way to pass arguments when creating BoData
/// as required by the gem::DriverObject trait.
pub(crate) struct BoCreateArgs {
    flags: u32,
}

impl gem::DriverObject for BoData {
    type Driver = TyrDrmDriver;
    type Args = BoCreateArgs;

    fn new(_dev: &TyrDrmDevice, _size: usize, args: BoCreateArgs) -> impl PinInit<Self, Error> {
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
        self.kernel_bo.kernel_node_range()
    }
}

impl core::ops::Deref for MappedBo {
    type Target = Bo;

    fn deref(&self) -> &Bo {
        self.vmap().owner()
    }
}

/// Send raw-pointer wrapper used to hand a heap-parked vmap to the
/// cleanup closure. Only the closure (success) or this Drop body
/// (failure) calls KBox::from_raw on the inner pointer.
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
                    "MappedBo cleanup-state allocation failed; leaking vmap to avoid dma_resv_lock cycle in signalling section\n",
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
                "MappedBo cleanup_wq enqueue failed under memory pressure; leaking vmap to avoid dma_resv_lock cycle in signalling section\n",
            );
            // SAFETY: `try_spawn` returned `Err`, so the closure was
            // dropped without observing `ptr`. Ownership remains
            // here. Leak the box, because dropping it would invoke the vmap
            // destructor and take `dma_resv_lock` from the
            // signalling section that prompted the deferral.
            let boxed = unsafe { KBox::from_raw(ptr) };
            core::mem::forget(KBox::into_inner(boxed));
            pr_err!("Failed to enqueue MappedBo vmap cleanup: {:?}\n", e);
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
        BoCreateArgs { flags: 0 },
    )?;

    Ok(bo)
}

pub(crate) fn new_bo(
    dev: &Device<Bound>,
    ddev: &TyrDrmDevice,
    size: usize,
    flags: u32,
    coherent: bool,
) -> Result<ARef<Bo>> {
    let aligned_size = size.next_multiple_of(1 << 12);

    if size == 0 || size > aligned_size {
        return Err(EINVAL);
    }

    let map_wc = should_map_wc(coherent);
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
        bo.sg_table(dev)?;
    }

    Ok(bo)
}

pub(crate) fn lookup_handle(file: &TyrDrmFile, handle: u32) -> Result<ARef<Bo>> {
    shmem::Object::lookup_handle(file, handle)
}

/// Creates a kernel-owned GEM object mapped into the VM and vmapped for CPU access.
pub(crate) fn new_kernel_object(
    dev: &Device<Bound>,
    ddev: &TyrDrmDevice,
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
        ddev,
        vm.clone(),
        aligned_size as u64,
        KernelBoVaAlloc::Explicit(va),
        flags,
        coherent,
        cleanup_wq,
    )?
    .with_va_reservation(node);

    MappedBo::new(kernel_bo)
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
    vm: Arc<Vm>,
    /// The GPU VA range occupied by this buffer.
    va_range: Range<u64>,
    /// Kernel-VA pool reservation backing `va_range`. Dropped from the
    /// deferred cleanup once `Vm::unmap_range` has torn the mapping
    /// down. `None` when the VA is managed externally, as on the
    /// firmware load path.
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
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        dev: &Device<Bound>,
        ddev: &TyrDrmDevice,
        vm: Arc<Vm>,
        size: u64,
        va_alloc: KernelBoVaAlloc,
        flags: VmMapFlags,
        coherent: bool,
        cleanup_wq: Arc<CleanupQueue>,
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
                parent_resv_obj: None,
            },
            BoCreateArgs { flags: 0 },
        )?;

        vm.map_bo_range(dev, &bo, 0, size, va, flags)?;

        Ok(KernelBo {
            bo: ManuallyDrop::new(bo),
            vm,
            va_range: va..va_end,
            kernel_node: None,
            cleanup_wq,
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
    fn kernel_node_range(&self) -> Option<Range<u64>> {
        self.kernel_node.as_ref().map(|node| node.range())
    }

    /// Attaches a kernel-VA pool reservation to this buffer so that the
    /// VA cannot be reused until the deferred unmap in `Drop` has
    /// actually run. Only used by `new_kernel_object`. The firmware
    /// load path leaves the reservation `None` and manages its VA via
    /// `Vm::reserve_kernel_range` instead.
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

/// `Send` raw-pointer wrapper used to hand a `KernelBoCleanup` box
/// to the cleanup closure. Ownership transfers to whichever side
/// observes `KBox::from_raw` first. That is the closure on the
/// success path and the `Drop` body on the enqueue-failure path.
#[repr(transparent)]
struct KernelBoCleanupPtr(*mut KernelBoCleanup);

// SAFETY: The pointer is produced by `KBox::into_raw` and is never
// duplicated. The closure captures one copy by value, and the
// `Drop` body retains a sibling copy that it only converts back to
// a `KBox` on the enqueue-failure branch, where `try_spawn` has
// already dropped the closure without observing the pointer.
unsafe impl Send for KernelBoCleanupPtr {}

impl Drop for KernelBo {
    fn drop(&mut self) {
        let va = self.va_range.start;
        let size = self.va_range.end - self.va_range.start;
        let vm = self.vm.clone();
        // SAFETY: `Drop::drop` runs at most once, this is the only
        // `ManuallyDrop::take` of `self.bo`, and the field is never
        // read again afterwards.
        let bo = unsafe { ManuallyDrop::take(&mut self.bo) };
        let kernel_node = self.kernel_node.take();

        let slot: KBox<MaybeUninit<KernelBoCleanup>> = match KBox::new_uninit(GFP_NOWAIT) {
            Ok(s) => s,
            Err(_) => {
                pr_warn_once!(
                    "KernelBo cleanup-state allocation failed; performing inline unmap (lockdep cycle may fire)\n",
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
            // field. Capturing just the field would make the closure
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
            // signalling path. Likewise hold the kernel-VA reservation
            // until the unmap above has actually torn down the mapping.
            drop(bo);
            drop(kernel_node);
        });

        if let Err(e) = res {
            pr_warn_once!(
                "KernelBo cleanup_wq enqueue failed under memory pressure; performing inline unmap (lockdep cycle may fire)\n",
            );
            // SAFETY: `try_spawn` returned `Err`, so the closure was
            // dropped without observing `ptr`. Ownership of the
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
    if let Err(e) = vm.unmap_range(va, size) {
        pr_err!(
            "Failed to inline-unmap KernelBo range {:#x}..{:#x}: {:?}\n",
            va,
            va + size,
            e
        );
    }
    // Order: drop `bo` first (just a refcount), then `kernel_node`
    // which releases the VA back to the pool. The unmap above must
    // complete first so the next allocation handed this VA does not
    // observe stale PTEs.
    drop(bo);
    drop(kernel_node);
}
