// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU virtual memory management using the DRM GPUVM framework.
//!
//! This module manages GPU virtual address spaces, providing memory isolation and
//! the illusion of owning the entire virtual address (VA) range, similar to CPU virtual memory.
//! Each virtual memory (VM) area is backed by ARM64 LPAE Stage 1 page tables and can be
//! mapped into hardware address space (AS) slots for GPU execution.

mod exec;
pub(crate) mod pt_alloc;
pub(crate) mod range;

use core::mem::ManuallyDrop;
use core::ops::{
    Deref,
    Range, //
};

use kernel::{
    device::{
        Bound,
        Device, //
    },
    dma::DmaAddress,
    dma_buf::dma_fence::{
        DmaFenceWorkqueue,
        DriverDmaFence,
        DriverDmaFenceOps,
        PublicDmaFence,
        Published, //
    },
    drm::{
        exec::{
            ExecCtx,
            Prepared, //
        },
        gem::BaseObject,
        gpuvm::{
            DriverGpuVm,
            GpuVaAlloc,
            GpuVm,
            GpuVmBo,
            OpMap,
            OpMapRequest,
            OpMapped,
            OpRemap,
            OpRemapped,
            OpUnmap,
            OpUnmapped,
            UniqueRefGpuVm, //
        },
        job_queue::{
            JobQueue,
            JobQueueLockClasses,
            JobRef,
            PipelineBuilder,
            PreparedJob,
            QueueOps,
            SubmitResult, //
        }, //
    },
    fmt,
    impl_flags,
    io::PhysAddr,
    iommu::pgtable::prot,
    new_mutex,
    platform,
    pr_warn_once,
    prelude::*,
    ptr::{
        Alignable,
        Alignment, //
    },
    sizes::{
        SZ_1G,
        SZ_2M,
        SZ_4K, //
    },
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc,
        ArcBorrow,
        LockClassKey,
        Mutex,
        MutexGuard, //
    },
    uapi, //
};

use crate::{
    cleanup,
    driver::{
        TyrDrmDevice,
        TyrDrmDriver,
        TyrDrmRegistrationData, //
    },
    gem,
    gem::Bo,
    gpu::GpuInfo,
    mmu::{
        address_space::VmAsData,
        Mmu, //
    },
    pool::Pool as ObjectPool,
    regs::gpu_control::MMU_FEATURES,
    sched::deps,
};

// SAFETY: The key is in static memory, is pinned with `Pin::static_ref()` before use, and a
// static is never dropped.
static VM_BIND_QUEUE_INBOX_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static VM_BIND_QUEUE_STATE_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static VM_BIND_QUEUE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static VM_BIND_QUEUE_CLEANUP_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static VM_BIND_QUEUE_STAGE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static VM_BIND_QUEUE_STAGE_TIMER_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static VM_BIND_QUEUE_DRIVER_FENCE_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };

pub(crate) struct Pool {
    entries: ObjectPool<Vm>,
}

impl Pool {
    pub(crate) fn create() -> Result<Self> {
        Ok(Self {
            entries: ObjectPool::create()?,
        })
    }

    fn create_vm_range(
        &self,
        ddev: &TyrDrmDevice,
        reg_data: &TyrDrmRegistrationData<'_>,
        requested_user_va_range: u64,
    ) -> Result<(usize, u64)> {
        let user_va_range = normalize_user_va_range(&reg_data.gpu_info, requested_user_va_range);
        let kernel_range = kernel_va_window(&reg_data.gpu_info, user_va_range)?;
        let user_va_limit = kernel_range.start;

        let vm = Vm::new_for_user(
            reg_data.pdev,
            ddev,
            reg_data.mmu.as_arc_borrow(),
            &reg_data.gpu_info,
            kernel_range,
            reg_data.wq.clone(),
        )?;

        let index = self.entries.insert(vm)?;

        Ok((index, user_va_limit))
    }

    pub(crate) fn create_vm(
        &self,
        ddev: &TyrDrmDevice,
        reg_data: &TyrDrmRegistrationData<'_>,
        vmcreate: &mut uapi::drm_panthor_vm_create,
    ) -> Result {
        let (id, user_va_range) = self.create_vm_range(ddev, reg_data, vmcreate.user_va_range)?;

        vmcreate.id = id as u32;
        vmcreate.user_va_range = user_va_range;
        Ok(())
    }

    pub(crate) fn get_vm(&self, index: usize) -> Option<Arc<Vm>> {
        self.entries.get(index)
    }

    pub(crate) fn get_vm_state(&self, vmgetstate: &mut uapi::drm_panthor_vm_get_state) -> Result {
        let vm = self.get_vm(vmgetstate.vm_id as usize).ok_or(EINVAL)?;

        vmgetstate.state = if vm.is_unusable() {
            uapi::drm_panthor_vm_state_DRM_PANTHOR_VM_STATE_UNUSABLE
        } else {
            uapi::drm_panthor_vm_state_DRM_PANTHOR_VM_STATE_USABLE
        };

        Ok(())
    }

    fn destroy_vm_index(&self, tdev: &TyrDrmDevice, index: usize) -> Result {
        let vm = self.entries.remove(index)?;

        vm.mark_unusable();
        if vm.as_slot().is_some() {
            tdev.flush_tick();
        }

        vm.kill();
        Ok(())
    }

    pub(crate) fn destroy_vm(
        &self,
        tdev: &TyrDrmDevice,
        vmdestroy: &uapi::drm_panthor_vm_destroy,
    ) -> Result {
        if vmdestroy.pad != 0 {
            return Err(EINVAL);
        }

        self.destroy_vm_index(tdev, vmdestroy.id as usize)
    }

    pub(crate) fn destroy_all(&self, tdev: &TyrDrmDevice) -> Result {
        let max_index = self.entries.index_upper_bound();

        for index in 1..max_index {
            let _ = self.destroy_vm_index(tdev, index);
        }

        Ok(())
    }
}

/// Minimum VA space every VM leaves for kernel objects.
const MIN_KERNEL_VA_SIZE: u64 = 0x10000000;

impl_flags!(
    /// Flags controlling virtual memory mapping behavior.
    ///
    /// These flags control access permissions and caching behavior for GPU virtual
    /// memory mappings.
    #[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
    pub(crate) struct VmMapFlags(u32);

    /// Individual flags that can be combined in [`VmMapFlags`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum VmFlag {
        /// Map as read-only.
        Readonly = uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_READONLY as u32,
        /// Map as non-executable.
        Noexec = uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_NOEXEC as u32,
        /// Map as uncached.
        Uncached = uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_UNCACHED as u32,
    }
);

impl VmMapFlags {
    /// Convert the flags to `pgtable::prot`.
    fn to_prot(self) -> u32 {
        let mut prot = 0;

        if self.contains(VmFlag::Readonly) {
            prot |= prot::READ;
        } else {
            prot |= prot::READ | prot::WRITE;
        }

        if self.contains(VmFlag::Noexec) {
            prot |= prot::NOEXEC;
        }

        if !self.contains(VmFlag::Uncached) {
            prot |= prot::CACHE;
        }

        prot
    }
}

impl fmt::Display for VmMapFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;

        if self.contains(VmFlag::Readonly) {
            write!(f, "READONLY")?;
            first = false;
        }
        if self.contains(VmFlag::Noexec) {
            if !first {
                write!(f, " | ")?;
            }
            write!(f, "NOEXEC")?;
            first = false;
        }

        if self.contains(VmFlag::Uncached) {
            if !first {
                write!(f, " | ")?;
            }
            write!(f, "UNCACHED")?;
        }

        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct VmBindFenceData;

#[vtable]
impl DriverDmaFenceOps for VmBindFenceData {
    fn driver_name(&self) -> &'static CStr {
        c"tyr"
    }

    fn timeline_name(&self) -> &'static CStr {
        c"tyr_vm_bind"
    }
}

pub(crate) enum VmBindJobOp {
    Map {
        bo_offset: u64,
        size: u64,
        va: u64,
        flags: VmMapFlags,
        resources: Pin<KBox<Mutex<Option<VmOpResources>>>>,
    },
    Unmap {
        va: u64,
        size: u64,
        resources: Pin<KBox<Mutex<Option<VmOpResources>>>>,
    },
}

pub(crate) struct VmBindJob {
    ops: KVec<VmBindJobOp>,
}

impl VmBindJob {
    pub(crate) fn new() -> Self {
        Self { ops: KVec::new() }
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn push_map(
        &mut self,
        dev: &Device<Bound>,
        vm: &Vm,
        bo: ARef<Bo>,
        bo_offset: u64,
        size: u64,
        va: u64,
        flags: VmMapFlags,
    ) -> Result {
        let resources = VmOpResources {
            preallocated_gpuvas: [
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
            ],
            vm_bo: Some(vm.exec.gpuvm.obtain(&bo, ())?),
            map_sgt: Some(prefetch_map_sgt(&bo, dev)?),
            pt_reserve: pt_alloc::PtReserve::for_map(va, size)?,
        };
        let resources = KBox::pin_init(new_mutex!(Some(resources)), GFP_KERNEL)?;
        self.ops
            .push(
                VmBindJobOp::Map {
                    bo_offset,
                    size,
                    va,
                    flags,
                    resources,
                },
                GFP_KERNEL,
            )
            .map_err(Error::from)
    }

    pub(crate) fn push_unmap(&mut self, va: u64, size: u64) -> Result {
        let resources = VmOpResources {
            preallocated_gpuvas: [
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
            ],
            vm_bo: None,
            map_sgt: None,
            pt_reserve: pt_alloc::PtReserve::for_unmap(va, size)?,
        };
        let resources = KBox::pin_init(new_mutex!(Some(resources)), GFP_KERNEL)?;
        self.ops
            .push(
                VmBindJobOp::Unmap {
                    va,
                    size,
                    resources,
                },
                GFP_KERNEL,
            )
            .map_err(Error::from)
    }
}

pub(crate) struct VmBindQueueOps {
    ddev: ARef<TyrDrmDevice>,
    exec: Arc<VmExec>,
}

impl QueueOps for VmBindQueueOps {
    type Job = VmBindJob;
    type FenceData = VmBindFenceData;

    fn lock_classes() -> JobQueueLockClasses {
        JobQueueLockClasses {
            inbox: &VM_BIND_QUEUE_INBOX_LOCK_CLASS,
            state: &VM_BIND_QUEUE_STATE_LOCK_CLASS,
            work: &VM_BIND_QUEUE_WORK_LOCK_CLASS,
            cleanup_work: &VM_BIND_QUEUE_CLEANUP_WORK_LOCK_CLASS,
            stage_work: &VM_BIND_QUEUE_STAGE_WORK_LOCK_CLASS,
            stage_timer: &VM_BIND_QUEUE_STAGE_TIMER_LOCK_CLASS,
            driver_fence: &VM_BIND_QUEUE_DRIVER_FENCE_LOCK_CLASS,
        }
    }

    fn submit(
        &self,
        job: &JobRef<'_, Self::Job>,
        fence: DriverDmaFence<Self::FenceData, Published>,
        _wq: &DmaFenceWorkqueue,
    ) -> Result<SubmitResult<Self::FenceData>> {
        let Some(guard) = self.ddev.registration_guard() else {
            fence.signal(Err(ENODEV));
            return Err(ENODEV);
        };

        let result = guard.registration_data_with(|reg_data| {
            for op in job.job.ops.iter() {
                match op {
                    VmBindJobOp::Map {
                        bo_offset,
                        size,
                        va,
                        flags,
                        resources,
                    } => {
                        let mut resources = resources.lock().take().ok_or(EINVAL)?;
                        self.exec.map_bo_range_inner(
                            reg_data.pdev.as_ref(),
                            *bo_offset,
                            *size,
                            *va,
                            *flags,
                            &mut resources,
                        )?
                    }
                    VmBindJobOp::Unmap {
                        va,
                        size,
                        resources,
                    } => {
                        let mut resources = resources.lock().take().ok_or(EINVAL)?;
                        self.exec.unmap_range_inner(*va, *size, &mut resources)?
                    }
                }
            }

            Ok(())
        });

        let submitted = match result {
            Ok(()) => {
                fence.signal(Ok(()));
                Ok(SubmitResult::Submitted)
            }
            Err(err) => {
                self.exec.mark_unusable();
                fence.signal(Err(err));
                Err(err)
            }
        };

        let exec = self.exec.clone();
        let queued = cleanup::try_spawn_owned(exec, |exec| exec.flush_deferred_cleanup());

        if queued.is_err() {
            pr_warn_once!(
                "VM_BIND cleanup workqueue enqueue failed, so deferred vm_bos wait for the next flush\n",
            );
        }

        submitted
    }
}

pub(crate) type PreparedVmBindJob = PreparedJob<VmBindQueueOps>;

/// Runs the ops of an async VM bind through `deps::Context`.
pub(crate) struct BindOps {
    vm: Arc<Vm>,
}

impl BindOps {
    pub(crate) fn new(vm: Arc<Vm>) -> Self {
        Self { vm }
    }
}

impl deps::BatchOps for BindOps {
    type Job = VmBindJob;
    type Prepared = PreparedVmBindJob;

    fn prepare(
        &self,
        job: VmBindJob,
        deps: &[ARef<PublicDmaFence>],
        extra_dep_capacity: usize,
    ) -> Result<PreparedVmBindJob> {
        self.vm.prepare_bind_job(job, deps, extra_dep_capacity)
    }

    fn add_dep(&self, prepared: &mut PreparedVmBindJob, fence: ARef<PublicDmaFence>) -> Result {
        prepared.add_dep(fence)
    }

    fn commit(&self, prepared: PreparedVmBindJob) -> Result<ARef<PublicDmaFence>> {
        self.vm.commit_bind_job(prepared)
    }
}

impl TryFrom<u32> for VmMapFlags {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let valid = VmFlag::Readonly as u32 | VmFlag::Noexec as u32 | VmFlag::Uncached as u32;

        if value & !valid != 0 {
            return Err(EINVAL);
        }
        Ok(Self(value))
    }
}

/// Arguments for a virtual memory map operation.
struct VmMapArgs<'a> {
    /// Access permissions and caching behavior for the mapping.
    flags: VmMapFlags,
    /// GEM buffer object registered with the GPUVM framework.
    vm_bo: ARef<GpuVmBo<GpuVmData>>,
    /// Offset in bytes from the start of the buffer object.
    bo_offset: u64,
    /// Device the buffer object is mapped for.
    dev: &'a Device<Bound>,
}

/// Type of virtual memory operation.
enum VmOpType<'a> {
    /// Map a GEM buffer object into the virtual address space.
    Map(VmMapArgs<'a>),
    /// Unmap a region from the virtual address space.
    Unmap,
}

/// Preallocated resources needed to execute a VM operation.
///
/// VM operations may require allocating new GPUVA objects to track mappings.
/// To avoid allocation failures during the operation, preallocate the
/// maximum number of GPUVAs that might be needed.
pub(crate) struct VmOpResources {
    /// Preallocated GPUVA objects for remap operations.
    ///
    /// Partial unmap requests or map requests overlapping existing mappings
    /// will trigger a remap call, which needs to register up to three VA
    /// objects (one for the new mapping, and two for the previous and next
    /// mappings).
    preallocated_gpuvas: [Option<GpuVaAlloc<GpuVmData>>; 3],
    /// The `drm_gpuvm_bo` for the Map path, obtained outside the VM_BIND
    /// signalling section so its external-object `dma_resv_lock`
    /// registration does not run on the path to `dma_fence_signal()`.
    /// `None` for Unmap.
    vm_bo: Option<ARef<GpuVmBo<GpuVmData>>>,
    /// SG-table segments of the BO being mapped, prefetched outside the
    /// VM_BIND dma-fence signalling section. Each entry is a
    /// `(dma_address, dma_len)` pair, in the order yielded by the BO's
    /// scatter-gather table. `None` for Unmap.
    map_sgt: Option<KVVec<(DmaAddress, u64)>>,
    /// Page tables the operation can need, reserved outside the VM_BIND
    /// dma-fence signalling section because that section must not make
    /// allocations that can wait for reclaim.
    pt_reserve: pt_alloc::PtReserve,
}

/// Request to execute a virtual memory operation.
struct VmOpRequest<'a> {
    /// Request type.
    op_type: VmOpType<'a>,

    /// Region of the virtual address space covered by this request.
    region: Range<u64>,
}

/// Arguments for a page table map operation.
struct PtMapArgs<'a> {
    /// Memory protection flags describing allowed accesses for this mapping.
    ///
    /// This is directly derived from [`VmMapFlags`] via [`VmMapFlags::to_prot`].
    prot: u32,

    /// Device used to DMA-map the buffer object and to reach the page table.
    dev: &'a Device<Bound>,
}

/// Type of page table operation.
enum PtOpType<'a> {
    /// Map pages into the page table.
    Map(PtMapArgs<'a>),
    /// Unmap pages from the page table.
    Unmap,
}

/// Context for updating the GPU page table.
///
/// This context is created when beginning a page table update operation and
/// automatically flushes changes when dropped. It ensures that the
/// Memory Management Unit (MMU) state is properly managed and Translation
/// Lookaside Buffer (TLB) entries are flushed.
pub(crate) struct PtUpdateContext<'ctx> {
    /// Device used for logging.
    dev: &'ctx Device,

    /// Page table.
    pt: &'ctx pt_alloc::DevresPageTable,

    /// MMU manager.
    mmu: &'ctx Mmu,

    /// Reference to the address space data to pass to the MMU functions.
    as_data: &'ctx VmAsData,

    /// Region of the virtual address space covered by this request.
    region: Range<u64>,

    /// Operation type.
    op_type: PtOpType<'ctx>,

    /// Preallocated resources that can be used when executing the request.
    resources: &'ctx mut VmOpResources,

    /// Serializes this span against hardware residency changes on the VM
    /// for its whole life.
    _op_lock: MutexGuard<'ctx, ()>,
}

impl<'ctx> PtUpdateContext<'ctx> {
    /// Creates a new page table update context.
    ///
    /// This prepares the MMU for a page table update.
    /// The context will automatically flush the TLB and
    /// complete the update when dropped.
    fn new(
        dev: &'ctx Device,
        pt: &'ctx pt_alloc::DevresPageTable,
        mmu: &'ctx Mmu,
        as_data: &'ctx VmAsData,
        region: Range<u64>,
        op_type: PtOpType<'ctx>,
        resources: &'ctx mut VmOpResources,
    ) -> Result<PtUpdateContext<'ctx>> {
        let _op_lock = as_data.lock_ops();
        mmu.start_vm_update(as_data, &region)?;
        as_data
            .pt_allocator
            .set_reserve(core::mem::take(&mut resources.pt_reserve));

        Ok(Self {
            dev,
            pt,
            mmu,
            as_data,
            region,
            op_type,
            resources,
            _op_lock,
        })
    }

    /// Finds one of our pre-allocated VAs.
    fn preallocated_gpuva(&mut self) -> Result<GpuVaAlloc<GpuVmData>> {
        self.resources
            .preallocated_gpuvas
            .iter_mut()
            .find_map(|f| f.take())
            .ok_or(EINVAL)
    }

    /// Returns an unused GPUVA object to the preallocated pool.
    /// If the pool is already full, the unused allocation is simply dropped.
    fn return_preallocated_gpuva(&mut self, gpuva: GpuVaAlloc<GpuVmData>) {
        if let Some(slot) = self
            .resources
            .preallocated_gpuvas
            .iter_mut()
            .find(|slot| slot.is_none())
        {
            *slot = Some(gpuva);
        }
    }

    /// Widens the AS lock to also cover `region`.
    ///
    /// A remap can rebuild fragments beyond the originally locked request,
    /// so the lock is grown to the union of the two before those fragments
    /// are torn down. The locked region only ever grows, so several remaps
    /// in one unmap union onto a single widening lock.
    fn extend_lock(&mut self, region: Range<u64>) -> Result {
        let union = self.region.start.min(region.start)..self.region.end.max(region.end);
        if union.start < self.region.start || union.end > self.region.end {
            self.mmu.extend_vm_update(self.as_data, &union)?;
            self.region = union;
        }
        Ok(())
    }
}

impl Drop for PtUpdateContext<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.mmu.end_vm_update(self.as_data, &self.region) {
            dev_err!(self.dev, "Failed to end VM update {:?}", e);
        }

        // The leftovers go back to the resources. They are freed with
        // everything else the operation reserved, once this context has
        // released the op lock.
        self.resources.pt_reserve = self.as_data.pt_allocator.take_reserve();
    }
}

/// Driver implementation for the GPUVM framework.
///
/// Implements [`DriverGpuVm`] to provide VM operation callbacks (map, unmap, remap)
/// and associated types for buffer objects, virtual addresses, and contexts.
pub(crate) struct GpuVmData;

/// Per-mapping private data stored on each `GpuVa`.
///
/// A remap splits an existing mapping and may have to rebuild page-table
/// entries for the surviving fragments. Those fragments keep the protection
/// of the original mapping, so the protection flags are recorded here.
pub(crate) struct GpuVaData {
    /// Memory protection flags of this mapping, as passed to `pt_map`.
    prot: u32,
}

fn max_va_range(gpu_info: &GpuInfo) -> u64 {
    1u64 << MMU_FEATURES::from_raw(gpu_info.mmu_features)
        .va_bits()
        .get()
}

pub(crate) fn normalize_user_va_range(gpu_info: &GpuInfo, requested: u64) -> u64 {
    let max_va_range = max_va_range(gpu_info) - MIN_KERNEL_VA_SIZE;

    if requested == 0 {
        max_va_range
    } else {
        core::cmp::min(requested, max_va_range)
    }
}

/// The kernel window at the top of the VA space, given the user range.
///
/// The window is the largest power of two that fits in the space remaining after
/// the user range. The address space is itself a power of two, so the window
/// base is aligned to the window size.
fn kernel_va_window(gpu_info: &GpuInfo, user_va_range: u64) -> Result<Range<u64>> {
    let full_va_range = max_va_range(gpu_info);
    let leftover = full_va_range - user_va_range;
    let kernel_va_range = 1u64 << leftover.checked_ilog2().ok_or(EINVAL)?;

    Ok((full_va_range - kernel_va_range)..full_va_range)
}

/// GPU virtual address space.
///
/// Each VM can be mapped into a hardware address space slot.
#[pin_data(PinnedDrop)]
pub(crate) struct VmExec {
    /// Data referenced by an AS when the VM is active.
    pub(crate) as_data: Arc<VmAsData>,
    /// MMU manager.
    mmu: Arc<Mmu>,
    /// Parent device used for logging.
    pdev: ARef<platform::Device>,
    /// DRM GPUVM core for managing virtual address space.
    ///
    /// `Some` for the entire lifetime of the value; taken to `None`
    /// only by `Drop` when handing the gpuvm reference to the cleanup
    /// workqueue.
    #[pin]
    gpuvm_unique: Mutex<Option<UniqueRefGpuVm<GpuVmData>>>,
    /// Non-core part of the GPUVM. Can be used for stuff that doesn't modify the
    /// internal mapping tree, like GpuVm::obtain()
    ///
    /// Wrapped in `ManuallyDrop` so `Drop` can move this reference into
    /// the cleanup workqueue closure rather than dropping it inline.
    gpuvm: ManuallyDrop<ARef<GpuVm<GpuVmData>>>,
    /// Whether the VM can no longer service user requests.
    unusable: Atomic<bool>,
    /// VA range for this VM.
    va_range: Range<u64>,
}

#[pinned_drop]
impl PinnedDrop for VmExec {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: We do not move out of any structurally pinned field.
        // The `Mutex` is only accessed through `try_lock` in place, and
        // the only field moved out is `gpuvm`, which is not `#[pin]`.
        let this = unsafe { self.get_unchecked_mut() };

        // SAFETY: `Drop` runs at most once, and this is the only
        // `ManuallyDrop::take` of `gpuvm`. The field is never read again
        // afterwards. Moving out the reference here (rather than dropping
        // it inline) keeps the final `drm_gpuvm_put`, which frees the
        // GPUVM's r_obj GEM under `dma_resv_lock`, off the dma-fence
        // signalling section this drop may run under.
        let gpuvm = unsafe { ManuallyDrop::take(&mut this.gpuvm) };
        // The last `VmExec` reference is dropping, so nothing else can
        // hold the lock and `try_lock` cannot block here on the
        // signalling path. `None` only on the impossible contended case,
        // in which the inner reference drops inline with the mutex.
        let gpuvm_unique = this.gpuvm_unique.try_lock().and_then(|mut g| g.take());
        let Err(e) = cleanup::try_spawn_owned((gpuvm, gpuvm_unique), drop) else {
            return;
        };

        let captures = match e {
            cleanup::SpawnError::QueueGone(captures) => captures,
            cleanup::SpawnError::NoMemory(captures) => {
                pr_warn_once!(
                    "VmExec cleanup hand-off failed under memory pressure; performing inline gpuvm teardown (lockdep cycle may fire)\n",
                );
                captures
            }
        };
        drop(captures);
    }
}

/// GPU virtual address space.
///
/// Owns the user-visible VM lifetime and the kernel-only VA allocators, while
/// [`VmExec`] carries the execution-facing state that async VM_BIND will need
/// to reference independently.
#[pin_data]
pub(crate) struct Vm {
    exec: Arc<VmExec>,
    bind_queue: Option<JobQueue<VmBindQueueOps>>,
    /// Serializes the window from prepare to commit of an async bind,
    /// so the bind queue claims its pipeline slots and its fence
    /// sequence numbers in the same order.
    #[pin]
    bind_lock: Mutex<()>,
    /// Exclusive upper bound on what user space may bind.
    user_va_limit: u64,
    /// Kernel VA allocator for auto-placement of kernel buffer objects.
    kernel_va: range::RangeAlloc,
    /// Kernel VA reservations that must live as long as the VM.
    #[pin]
    kernel_reservations: Mutex<KVec<range::LiveRange>>,
    /// Dummy GEM object that anchors the VM's `dma_resv`.
    ///
    /// Every kernel-owned BO in this VM aliases this `dma_resv`, so a
    /// fence on one blocks operations on the others.
    root_gem: ARef<Bo>,
}

impl Vm {
    #[expect(clippy::too_many_arguments)]
    fn new_with_ranges(
        pdev: &platform::Device<Bound>,
        ddev: &TyrDrmDevice,
        mmu: ArcBorrow<'_, Mmu>,
        gpu_info: &GpuInfo,
        total_range: Range<u64>,
        kernel_range: Range<u64>,
        bind_wq: Option<Arc<DmaFenceWorkqueue>>,
        coherent: bool,
    ) -> Result<Arc<Vm>> {
        let mmu_features = MMU_FEATURES::from_raw(gpu_info.mmu_features);
        let va_bits = mmu_features.va_bits().get();
        let pa_bits = mmu_features.pa_bits().get();

        let reserve_range = 0..0u64;

        // Initializes the GPUVM tree and is kept as the VM's root_gem.
        let dummy_obj = gem::new_dummy_object(ddev, coherent).inspect_err(|e| {
            dev_err!(pdev, "Failed to create dummy GEM object: {:?}", e);
        })?;

        let gpuvm_unique = GpuVm::new::<Error, _>(
            c"Tyr::GpuVm",
            ddev,
            &*dummy_obj,
            total_range.clone(),
            reserve_range,
            GpuVmData,
        )
        .inspect_err(|e| {
            dev_err!(pdev, "Failed to create GpuVm: {:?}", e);
        })?;
        let gpuvm = ARef::from(&*gpuvm_unique);

        let as_data = Arc::pin_init(
            VmAsData::new(&mmu, pdev.as_ref(), va_bits, pa_bits)?,
            GFP_KERNEL,
        )?;
        let kernel_va = range::RangeAlloc::new(kernel_range.start, kernel_range.end, GFP_KERNEL)?;

        let exec = Arc::pin_init(
            pin_init!(VmExec {
                as_data,
                pdev: pdev.into(),
                mmu: mmu.into(),
                gpuvm: ManuallyDrop::new(gpuvm),
                gpuvm_unique <- new_mutex!(Some(gpuvm_unique)),
                unusable: Atomic::new(false),
                va_range: total_range,
            }),
            GFP_KERNEL,
        )?;

        let bind_queue = match bind_wq {
            Some(wq) => Some(JobQueue::new(
                VmBindQueueOps {
                    ddev: ddev.into(),
                    exec: exec.clone(),
                },
                wq.clone(),
                wq,
                PipelineBuilder::new(),
            )?),
            None => None,
        };

        let vm = Arc::pin_init(
            pin_init!(Self {
                exec,
                bind_queue,
                bind_lock <- new_mutex!(()),
                user_va_limit: kernel_range.start,
                kernel_va,
                kernel_reservations <- new_mutex!(KVec::new()),
                root_gem: dummy_obj,
            }),
            GFP_KERNEL,
        )?;

        Ok(vm)
    }

    /// Creates the firmware MCU VM with an explicit kernel auto-VA window.
    ///
    /// Callers must reserve any explicit-VA sections inside the window with
    /// `reserve_kernel_range` before
    /// `alloc_kernel_range` is called.
    pub(crate) fn new_fw(
        pdev: &platform::Device<Bound>,
        ddev: &TyrDrmDevice,
        mmu: ArcBorrow<'_, Mmu>,
        gpu_info: &GpuInfo,
        auto_kernel_va_start: u64,
        auto_kernel_va_size: u64,
        coherent: bool,
    ) -> Result<Arc<Vm>> {
        let total_range = 0..max_va_range(gpu_info);
        let kernel_range = auto_kernel_va_start..(auto_kernel_va_start + auto_kernel_va_size);

        Self::new_with_ranges(
            pdev,
            ddev,
            mmu,
            gpu_info,
            total_range,
            kernel_range,
            None,
            coherent,
        )
    }

    pub(crate) fn new_for_user(
        pdev: &platform::Device<Bound>,
        ddev: &TyrDrmDevice,
        mmu: ArcBorrow<'_, Mmu>,
        gpu_info: &GpuInfo,
        kernel_range: Range<u64>,
        bind_wq: Arc<DmaFenceWorkqueue>,
    ) -> Result<Arc<Vm>> {
        let total_range = 0..max_va_range(gpu_info);

        Self::new_with_ranges(
            pdev,
            ddev,
            mmu,
            gpu_info,
            total_range,
            kernel_range,
            Some(bind_wq),
            ddev.coherent,
        )
    }

    /// Kills the VM by deactivating it and unmapping all regions.
    pub(crate) fn kill(&self) {
        self.exec.mark_unusable();
        let _ = self
            .exec
            .unmap_range(self.va_range.start, self.va_range.end - self.va_range.start)
            .inspect_err(|e| {
                dev_err!(self.dev(), "Failed to unmap range in kill(): {:?}", e);
            });
        let _ = self.exec.deactivate();
    }

    pub(crate) fn alloc_kernel_range(&self, size: usize) -> Result<range::LiveRange> {
        let align = if size >= SZ_2M {
            Alignment::new::<SZ_2M>()
        } else {
            Alignment::new::<SZ_4K>()
        };

        self.kernel_va.allocate(size, align, GFP_KERNEL)
    }

    /// Returns whether `[va, va + size)` lies wholly below the exclusive
    /// user VA limit.
    pub(crate) fn in_user_va_range(&self, va: u64, size: u64) -> bool {
        va < self.user_va_limit && size <= self.user_va_limit - va
    }

    /// Returns the dummy GEM object whose `dma_resv` anchors this VM.
    pub(crate) fn root_gem(&self) -> &Bo {
        &self.root_gem
    }

    pub(crate) fn with_prepared_vm<R>(
        &self,
        num_slots: u32,
        f: impl FnOnce(PreparedVm<'_>) -> Result<R>,
    ) -> Result<R> {
        let exec_token = exec::ExecToken::prepare(&self.exec.gpuvm, num_slots)?;
        let prepared_vm = PreparedVm {
            exec_token,
            num_slots,
        };

        f(prepared_vm)
    }

    /// Locks this VM's reservation in `ctx` and reserves one fence slot on it.
    pub(crate) fn prepare_resv(&self, ctx: &mut ExecCtx<'_>) -> Result<Prepared> {
        self.exec.gpuvm.prepare_resv(ctx, 1)
    }

    /// Reserves `[start, end)` in the kernel auto-VA window so future
    /// `alloc_kernel_range` calls cannot hand
    /// out an overlapping range. Used for explicit-VA mappings created
    /// before the auto-allocator opens.
    pub(crate) fn reserve_kernel_range(&self, start: u64, end: u64) -> Result {
        let node = self.kernel_va.insert(start, end, GFP_KERNEL)?;
        self.kernel_reservations.lock().push(node, GFP_KERNEL)?;
        Ok(())
    }

    /// Returns the bind queue, which only a user VM has.
    fn bind_queue(&self) -> Result<&JobQueue<VmBindQueueOps>> {
        self.bind_queue.as_ref().ok_or(EINVAL)
    }

    /// Acquires the lock that serializes the window from prepare to
    /// commit of an async bind on this VM.
    ///
    /// Lock order `bind_lock > {drm_exec, job queue}`, with nothing else
    /// held when it is taken. The window allocates and holds the VM
    /// reservation lock, so the lock is off limits to dma-fence
    /// signalling sections and must not cover a userspace copy.
    pub(crate) fn lock_binds(&self) -> MutexGuard<'_, ()> {
        self.bind_lock.lock()
    }

    pub(crate) fn prepare_bind_job(
        &self,
        job: VmBindJob,
        deps: &[ARef<PublicDmaFence>],
        extra_dep_capacity: usize,
    ) -> Result<PreparedVmBindJob> {
        self.flush_deferred_cleanup();

        self.bind_queue()?
            .prepare(job, deps, extra_dep_capacity, VmBindFenceData)
    }

    pub(crate) fn commit_bind_job(
        &self,
        prepared: PreparedVmBindJob,
    ) -> Result<ARef<PublicDmaFence>> {
        Ok(self.bind_queue()?.commit(prepared))
    }
}

impl Deref for Vm {
    type Target = VmExec;

    fn deref(&self) -> &Self::Target {
        &self.exec
    }
}

pub(crate) struct PreparedVm<'a> {
    exec_token: exec::ExecToken<'a, GpuVmData>,
    #[expect(dead_code)]
    num_slots: u32,
}

impl PreparedVm<'_> {
    pub(crate) fn resv_add_fence(
        &mut self,
        fence: &PublicDmaFence,
        private_usage: u32,
        extobj_usage: u32,
    ) {
        self.exec_token
            .resv_add_fence(fence, private_usage, extobj_usage);
    }
}

impl VmExec {
    /// Returns the parent device of this VM.
    pub(crate) fn dev(&self) -> &Device {
        self.pdev.as_ref()
    }

    /// Activate the VM in a hardware address space slot.
    pub(crate) fn activate(&self) -> Result {
        self.mmu
            .activate_vm(self.as_data.as_arc_borrow())
            .inspect_err(|e| {
                dev_err!(self.dev(), "Failed to activate VM: {:?}", e);
            })
    }

    /// Returns the AS slot index this VM is currently bound to.
    ///
    /// Returns `None` while the VM has no resident AS slot. See
    /// `Mmu::vm_as_slot` for the
    /// stability rules around the returned value.
    pub(crate) fn as_slot(&self) -> Option<u8> {
        self.mmu.vm_as_slot(&self.as_data)
    }

    /// Returns the buffer object mapped at `va` and its offset within
    /// that buffer object, or `None` if no mapping covers `va`.
    ///
    /// The lookup is a snapshot taken under `gpuvm_unique`. The
    /// returned `ARef<Bo>` keeps the BO alive, but a subsequent
    /// unmap+remap at `va` will not invalidate it. Callers that need
    /// the mapping to remain stable past the call must hold a lock
    /// that serializes against `unmap_range`.
    pub(crate) fn get_bo_for_va(&self, va: u64) -> Option<(ARef<Bo>, u64)> {
        let guard = self.gpuvm_unique.lock();
        let gpuva = guard.as_ref()?.find_first(va, 1)?;
        let bo = gpuva.obj();
        let bo_offset = gpuva.gem_offset() + (va - gpuva.addr());
        Some((ARef::from(bo), bo_offset))
    }

    pub(crate) fn is_unusable(&self) -> bool {
        self.unusable.load(Relaxed)
    }

    pub(crate) fn mark_unusable(&self) {
        self.unusable.store(true, Relaxed);
    }

    /// Flag the VM idle, keeping its address space slot resident.
    ///
    /// The slot is reclaimed lazily under pressure. Use `deactivate`
    /// instead when the address space must be torn down (teardown or an
    /// unhandled fault).
    pub(crate) fn idle(&self) -> Result {
        self.mmu.idle_vm(&self.as_data).inspect_err(|e| {
            dev_err!(self.dev(), "Failed to idle VM: {:?}", e);
        })
    }

    /// Deactivate the VM by evicting it from its address space slot.
    pub(crate) fn deactivate(&self) -> Result {
        self.mmu.deactivate_vm(&self.as_data).inspect_err(|e| {
            dev_err!(self.dev(), "Failed to deactivate VM: {:?}", e);
        })
    }

    /// Executes a virtual memory operation.
    ///
    /// This handles both map and unmap operations by coordinating between the
    /// GPUVM framework and the hardware page table.
    fn exec_op(
        &self,
        gpuvm_unique: &mut UniqueRefGpuVm<GpuVmData>,
        req: VmOpRequest<'_>,
        resources: &mut VmOpResources,
    ) -> Result {
        let pt = &self.as_data.page_table;

        match req.op_type {
            VmOpType::Map(args) => {
                let mut pt_upd = PtUpdateContext::new(
                    self.dev(),
                    pt,
                    &self.mmu,
                    &self.as_data,
                    req.region,
                    PtOpType::Map(PtMapArgs {
                        prot: args.flags.to_prot(),
                        dev: args.dev,
                    }),
                    resources,
                )?;

                gpuvm_unique.sm_map(OpMapRequest {
                    addr: pt_upd.region.start,
                    range: pt_upd.region.end - pt_upd.region.start,
                    gem_offset: args.bo_offset,
                    vm_bo: &args.vm_bo,
                    context: &mut pt_upd,
                })
                //PtUpdateContext drops here flushing the page table
            }
            VmOpType::Unmap => {
                let mut pt_upd = PtUpdateContext::new(
                    self.dev(),
                    pt,
                    &self.mmu,
                    &self.as_data,
                    req.region,
                    PtOpType::Unmap,
                    resources,
                )?;

                gpuvm_unique.sm_unmap(
                    pt_upd.region.start,
                    pt_upd.region.end - pt_upd.region.start,
                    &mut pt_upd,
                )
                //PtUpdateContext drops here flushing the page table
            }
        }
    }

    /// Maps a GEM buffer object range into the VM at the specified virtual address.
    ///
    /// This creates a mapping from GPU virtual address `va` to the physical pages
    /// backing the GEM object, starting at `bo_offset` bytes into the object and
    /// spanning `map_size` bytes. The mapping respects the access permissions and
    /// caching behavior specified in `flags`.
    fn map_bo_range_inner(
        &self,
        dev: &Device<Bound>,
        bo_offset: u64,
        map_size: u64,
        va: u64,
        flags: VmMapFlags,
        resources: &mut VmOpResources,
    ) -> Result {
        let vm_bo = resources.vm_bo.take().ok_or(EINVAL)?;

        if map_size == 0
            || va % SZ_4K as u64 != 0
            || bo_offset % SZ_4K as u64 != 0
            || map_size % SZ_4K as u64 != 0
        {
            return Err(EINVAL);
        }

        let bo_size = u64::try_from(vm_bo.obj().size()).map_err(|_| EOVERFLOW)?;
        let bo_end = bo_offset.checked_add(map_size).ok_or(EINVAL)?;

        if bo_end > bo_size {
            dev_err!(
                self.dev(),
                "BO mapping range {:#x}..{:#x} exceeds BO size {:#x}",
                bo_offset,
                bo_end,
                bo_size
            );
            return Err(EINVAL);
        }

        let va_end: u64 = va.checked_add(map_size).ok_or(EINVAL)?;

        let req = VmOpRequest {
            op_type: VmOpType::Map(VmMapArgs {
                vm_bo,
                flags,
                bo_offset,
                dev,
            }),
            region: va..va_end,
        };
        let mut gpuvm_unique = self.gpuvm_unique.lock();

        // kill() marks the VM unusable under gpuvm_unique before unmapping,
        // so this check under the same lock cannot race with teardown.
        if self.is_unusable() {
            return Err(EINVAL);
        }

        self.exec_op((*gpuvm_unique).as_mut().ok_or(EINVAL)?, req, resources)
    }

    pub(crate) fn flush_deferred_cleanup(&self) {
        self.gpuvm.deferred_cleanup();
    }

    pub(crate) fn map_bo_range(
        &self,
        dev: &Device<Bound>,
        bo: &Bo,
        bo_offset: u64,
        map_size: u64,
        va: u64,
        flags: VmMapFlags,
    ) -> Result {
        let mut resources = VmOpResources {
            preallocated_gpuvas: [
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
            ],
            vm_bo: Some(self.gpuvm.obtain(bo, ())?),
            map_sgt: Some(prefetch_map_sgt(bo, dev)?),
            pt_reserve: pt_alloc::PtReserve::for_map(va, map_size)?,
        };
        let result = self.map_bo_range_inner(dev, bo_offset, map_size, va, flags, &mut resources);

        // Flush inline here. The asynchronous VM_BIND path defers this to
        // the cleanup workqueue instead.
        self.flush_deferred_cleanup();
        result
    }

    /// Unmaps a virtual address range from the VM.
    ///
    /// This removes any existing mappings in the specified range, freeing the
    /// virtual address space for reuse.
    fn unmap_range_inner(&self, va: u64, size: u64, resources: &mut VmOpResources) -> Result {
        if size == 0 || va % SZ_4K as u64 != 0 || size % SZ_4K as u64 != 0 {
            return Err(EINVAL);
        }

        let end = va.checked_add(size).ok_or(EINVAL)?;

        if va < self.va_range.start || end > self.va_range.end {
            dev_err!(
                self.dev(),
                "Unmap range {:#x}..{:#x} exceeds VM range {:#x}..{:#x}",
                va,
                end,
                self.va_range.start,
                self.va_range.end
            );
            return Err(EINVAL);
        }

        let req = VmOpRequest {
            op_type: VmOpType::Unmap,
            region: va..end,
        };

        let mut gpuvm_unique = self.gpuvm_unique.lock();
        self.exec_op((*gpuvm_unique).as_mut().ok_or(EINVAL)?, req, resources)
    }

    pub(crate) fn unmap_range(&self, va: u64, size: u64) -> Result {
        let end = va.checked_add(size).ok_or(EINVAL)?;
        let full_vm = va == self.va_range.start && end == self.va_range.end;

        let mut resources = VmOpResources {
            preallocated_gpuvas: if full_vm {
                // Unmapping the entire VM cannot split an existing mapping,
                // so no GPUVA objects are needed for remap operations.
                [None, None, None]
            } else {
                [
                    Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                    Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                    Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                ]
            },
            vm_bo: None,
            map_sgt: None,
            pt_reserve: pt_alloc::PtReserve::for_unmap(va, size)?,
        };
        let result = self.unmap_range_inner(va, size, &mut resources);

        // Flush inline here. The asynchronous VM_BIND path defers this to
        // the cleanup workqueue instead.
        self.flush_deferred_cleanup();
        result
    }
}

impl DriverGpuVm for GpuVmData {
    type Driver = TyrDrmDriver;
    type Object = Bo;
    type VmBoData = ();
    type VaData = GpuVaData;
    type SmContext<'ctx>
        = PtUpdateContext<'ctx>
    where
        Self: 'ctx;

    /// Create a new mapping.
    fn sm_step_map<'op>(
        &mut self,
        op: OpMap<'op, Self>,
        context: &mut Self::SmContext<'_>,
    ) -> Result<OpMapped<'op, Self>, Error> {
        let start_iova = op.addr();
        let mut iova = start_iova;
        let mut bytes_left_to_map = op.length();
        let mut gem_offset = op.gem_offset();

        // Make sure that the end of the requested GEM range doesn't run past the
        // end of the GEM buffer itself.
        let gem_range_end = op.gem_offset().checked_add(op.length()).ok_or(EINVAL)?;

        if gem_range_end > op.obj().size() as u64 {
            dev_err!(
                context.dev,
                "Requested GEM range ends at {} which is beyond the GEM buffer size {}",
                gem_range_end,
                op.obj().size()
            );
            return Err(EINVAL);
        }

        let (prot, dev) = match &context.op_type {
            PtOpType::Map(args) => (args.prot, args.dev),
            _ => {
                return Err(EINVAL);
            }
        };

        let map_sgt = context.resources.map_sgt.as_ref().ok_or(EINVAL)?;

        for &(paddr, mut sgt_entry_length) in map_sgt.iter() {
            // Expressly convert to u64 to work with arm 32-bit builds.
            #[allow(clippy::useless_conversion)]
            let mut paddr = u64::from(paddr);

            if bytes_left_to_map == 0 {
                break;
            }

            if gem_offset > 0 {
                // Skip the entire SGT entry if the gem_offset exceeds its length.
                let skip = u64::min(sgt_entry_length, gem_offset);
                paddr += skip;
                sgt_entry_length -= skip;
                gem_offset -= skip;
            }

            if sgt_entry_length == 0 {
                continue;
            }

            let len = u64::min(sgt_entry_length, bytes_left_to_map);

            let segment_mapped = match pt_map(dev, context.pt, iova, paddr, len, prot) {
                Ok(segment_mapped) => segment_mapped,
                Err(e) => {
                    // clean up any successful mappings from previous SGT entries.
                    let total_mapped = iova - start_iova;
                    if total_mapped > 0 {
                        let _ = pt_unmap(
                            context.dev,
                            context.pt,
                            start_iova..(start_iova + total_mapped),
                        );
                    }
                    return Err(e);
                }
            };

            bytes_left_to_map -= segment_mapped;
            iova += segment_mapped;
        }

        if bytes_left_to_map != 0 {
            let total_mapped = iova - start_iova;

            if total_mapped > 0 {
                let _ = pt_unmap(context.dev, context.pt, start_iova..iova);
            }

            dev_err!(
                context.dev,
                "SG table is too small for requested mapping: {} bytes remain",
                bytes_left_to_map
            );

            return Err(EINVAL);
        }

        let gpuva = context.preallocated_gpuva()?;
        let op = op.insert(gpuva, GpuVaData { prot });

        Ok(op)
    }

    /// Indicates that an existing mapping should be removed.
    fn sm_step_unmap<'op>(
        &mut self,
        op: OpUnmap<'op, Self>,
        context: &mut Self::SmContext<'_>,
    ) -> Result<OpUnmapped<'op, Self>, Error> {
        let start_iova = op.va().addr();
        let length = op.va().length();

        let region = start_iova..(start_iova + length);
        pt_unmap(context.dev, context.pt, region.clone()).inspect_err(|e| {
            dev_err!(
                context.dev,
                "Failed to unmap region {:#x}..{:#x}: {:?}",
                region.start,
                region.end,
                e
            );
        })?;

        let (op_unmapped, _va_removed) = op.remove();

        Ok(op_unmapped)
    }

    /// Split up an existing mapping.
    fn sm_step_remap<'op>(
        &mut self,
        op: OpRemap<'op, Self>,
        context: &mut Self::SmContext<'_>,
    ) -> Result<OpRemapped<'op, Self>, Error> {
        let unmap_start = if let Some(prev) = op.prev() {
            prev.addr() + prev.length()
        } else {
            op.va_to_unmap().addr()
        };

        let unmap_end = if let Some(next) = op.next() {
            next.addr()
        } else {
            op.va_to_unmap().addr() + op.va_to_unmap().length()
        };

        // The surviving fragments inherit the protection of the mapping being
        // split.
        let prot = op.va_to_unmap().data_ref().prot;

        let block = Alignment::new::<{ pt_alloc::PT_MIN_BLOCK_SIZE }>();
        let aligned_start = unmap_start.align_down(block);
        let aligned_end = unmap_end.align_up(block).ok_or(EINVAL)?;

        // An end may only be expanded if the fragment the expansion sweeps and
        // rebuilds is fully mapped and physically contiguous, because the
        // rebuild maps it linearly from a single recovered address. A genuine
        // 2MB block is always contiguous, so this never misses one and the
        // partial-block unmap can never reach arm-lpae. A fragmented region is
        // never expanded, so its sub-range unmap stays correct.
        let head_paddr = match op.prev() {
            Some(prev) if aligned_start < unmap_start && prev.addr() <= aligned_start => {
                contiguous_phys(context.pt, aligned_start..unmap_start)
            }
            _ => None,
        };
        let tail_paddr = match op.next() {
            Some(next) if aligned_end > unmap_end && next.addr() + next.length() >= aligned_end => {
                contiguous_phys(context.pt, unmap_end..aligned_end)
            }
            _ => None,
        };

        let region_start = if head_paddr.is_some() {
            aligned_start
        } else {
            unmap_start
        };
        let region_end = if tail_paddr.is_some() {
            aligned_end
        } else {
            unmap_end
        };

        if region_end > region_start {
            let region = region_start..region_end;
            context.extend_lock(region.clone())?;
            pt_unmap(context.dev, context.pt, region.clone()).inspect_err(|e| {
                dev_err!(
                    context.dev,
                    "Failed to unmap remap region {:#x}..{:#x}: {:?}",
                    region.start,
                    region.end,
                    e
                );
            })?;
        }

        if let Some(head_paddr) = head_paddr {
            pt_map_fragment(
                context.dev,
                context.pt,
                aligned_start,
                head_paddr,
                unmap_start - aligned_start,
                prot,
            )?;
        }
        if let Some(tail_paddr) = tail_paddr {
            pt_map_fragment(
                context.dev,
                context.pt,
                unmap_end,
                tail_paddr,
                aligned_end - unmap_end,
                prot,
            )?;
        }

        let prev_va = context.preallocated_gpuva()?;
        let next_va = context.preallocated_gpuva()?;

        let (op_remapped, remap_ret) =
            op.remap([prev_va, next_va], GpuVaData { prot }, GpuVaData { prot });

        if let Some(unused_va) = remap_ret.unused_va {
            context.return_preallocated_gpuva(unused_va);
        }

        Ok(op_remapped)
    }
}

/// Returns the base physical address of `range` if every 4KB page in it is
/// mapped and the whole range is physically contiguous, otherwise `None`.
///
/// `range` is a sub-block fragment, so its length is below 2MB and the walk
/// visits at most 511 pages. The walk is read-only, lock-free and does not
/// allocate, so it is safe on the dma-fence signalling path. A revoked page
/// table also reports `None`, leaving the unmap unexpanded.
fn contiguous_phys(page_table: &pt_alloc::DevresPageTable, range: Range<u64>) -> Option<PhysAddr> {
    let pt = page_table.try_access()?;

    // SAFETY: The page table is exclusively accessed through the
    // &mut UniqueRefGpuVm held under the gpuvm_unique mutex for the duration of
    // the VM update, so no other io-pgtable operation runs concurrently.
    let base = unsafe { pt.iova_to_phys(range.start as usize) }?;

    let mut iova = range.start + SZ_4K as u64;
    while iova < range.end {
        let offset = (iova - range.start) as PhysAddr;
        // SAFETY: The page table is accessed exclusively through the
        // &mut UniqueRefGpuVm held under the gpuvm_unique mutex, so no
        // concurrent io-pgtable operation runs.
        let paddr = unsafe { pt.iova_to_phys(iova as usize) }?;
        if paddr != base + offset {
            return None;
        }
        iova += SZ_4K as u64;
    }

    Some(base)
}

/// This function selects the largest supported block size (currently 4KB or 2MB)
/// that can be used for a mapping at the given address and size, respecting alignment constraints.
///
/// We can map multiple pages at once but we can't exceed the size of the
/// table entry itself. So, if mapping 4KB pages, figure out how many pages
/// can be mapped before we hit the 2MB boundary. Or, if mapping 2MB pages,
/// figure out how many pages can be mapped before hitting the 1GB boundary
/// Returns the page size (4KB or 2MB) and the number of pages that can be mapped at that size.
fn get_pgsize(addr: u64, size: u64) -> (u64, u64) {
    // Get the distance to the next boundary of 2MB block
    let blk_offset_2m = addr.wrapping_neg() % (SZ_2M as u64);

    // Use 4K blocks if the address is not 2MB aligned, or we have less than 2MB to map
    if blk_offset_2m != 0 || size < SZ_2M as u64 {
        let pgcount = if blk_offset_2m == 0 {
            size / SZ_4K as u64
        } else {
            u64::min(blk_offset_2m, size) / SZ_4K as u64
        };
        return (SZ_4K as u64, pgcount);
    }

    let blk_offset_1g = addr.wrapping_neg() % (SZ_1G as u64);
    let blk_offset = if blk_offset_1g == 0 {
        SZ_1G as u64
    } else {
        blk_offset_1g
    };
    let pgcount = u64::min(blk_offset, size) / SZ_2M as u64;

    (SZ_2M as u64, pgcount)
}

/// Collects the BO's scatter-gather segments outside the VM_BIND
/// signalling section.
///
/// The first call for a buffer populates the cached SG table under
/// `dma_resv_lock`, which must not be taken on the path to
/// `dma_fence_signal()`. Later calls are lock-free. The segments are
/// consumed lock-free inside the signalling section.
fn prefetch_map_sgt(bo: &Bo, dev: &Device<Bound>) -> Result<KVVec<(DmaAddress, u64)>> {
    let sgt = bo.sg_table(dev).inspect_err(|e| {
        dev_err!(dev, "Failed to get sg_table: {:?}", e);
    })?;

    let mut segments = KVVec::new();
    for sgt_entry in sgt.iter() {
        // Expressly convert to u64 to work with arm 32-bit builds.
        #[allow(clippy::useless_conversion)]
        let len = u64::from(sgt_entry.dma_len());

        segments.push((sgt_entry.dma_address(), len), GFP_KERNEL)?;
    }

    Ok(segments)
}

/// Maps a physical address range into the page table at the specified virtual address.
///
/// This function maps `len` bytes of physical memory starting at `paddr` to the
/// virtual address `iova`, using the protection flags specified in `prot`. It
/// automatically selects optimal page sizes to minimize page table overhead.
///
/// If the mapping fails partway through, all successfully mapped pages are
/// unmapped before returning an error.
///
/// Returns the number of bytes successfully mapped.
fn pt_map(
    dev: &Device<Bound>,
    page_table: &pt_alloc::DevresPageTable,
    iova: u64,
    paddr: u64,
    len: u64,
    prot: u32,
) -> Result<u64> {
    let pt = page_table.access(dev)?;

    let (mapped, result) = pt_map_pages(dev, pt, iova, paddr, len, prot);
    if let Err(e) = result {
        if mapped > 0 {
            let _ = pt_unmap(dev, page_table, iova..(iova + mapped));
        }
        return Err(e);
    }

    Ok(mapped)
}

/// Maps the fragment a remap expansion swept away.
///
/// Same as `pt_map`, but the page table is resolved through the revocable
/// guard because the remap path has no `&Device<Bound>` to resolve it with.
///
/// A revoked page table is an error here. `pt_unmap` instead succeeds
/// because a freed table has nothing left to unmap.
fn pt_map_fragment(
    dev: &Device,
    page_table: &pt_alloc::DevresPageTable,
    iova: u64,
    paddr: PhysAddr,
    len: u64,
    prot: u32,
) -> Result {
    // Expressly convert to u64 to work with arm 32-bit builds.
    #[allow(clippy::useless_conversion)]
    let paddr = u64::from(paddr);

    let (mapped, result) = {
        let pt = page_table.try_access().ok_or(ENODEV)?;
        pt_map_pages(dev, &pt, iova, paddr, len, prot)
    };

    if result.is_err() && mapped > 0 {
        let _ = pt_unmap(dev, page_table, iova..(iova + mapped));
    }

    result
}

/// Maps `len` bytes at `paddr` to `iova` in an already-resolved page table.
///
/// Returns how many bytes were mapped along with the outcome, so the caller
/// can decide whether to unmap a partial mapping.
fn pt_map_pages(
    dev: &Device,
    pt: &pt_alloc::PageTable<'_>,
    iova: u64,
    paddr: u64,
    len: u64,
    prot: u32,
) -> (u64, Result) {
    let mut segment_mapped = 0u64;
    while segment_mapped < len {
        let remaining = len - segment_mapped;
        let curr_iova = iova + segment_mapped;
        let curr_paddr = paddr + segment_mapped;

        let (pgsize, pgcount) = get_pgsize(curr_iova | curr_paddr, remaining);

        // On 32-bit systems, usize is only 32 bits, so check that
        // the iova can be converted without truncation.
        let curr_iova = match usize::try_from(curr_iova) {
            Ok(curr_iova) => curr_iova,
            Err(_) => {
                dev_err!(
                    dev,
                    "curr_iova {:#x} cannot be represented as usize (max {:#x})",
                    curr_iova,
                    usize::MAX
                );

                return (segment_mapped, Err(EOVERFLOW));
            }
        };

        // The page tables for this map come from the reserve. The flags only
        // reach the fallback path, which runs in the VM_BIND dma-fence
        // signalling section and so must not wait for reclaim.
        //
        // SAFETY:
        // No other io-pgtable operation can currently access this range because Tyr holds
        // the gpuvm_unique mutex for the entire sm_map() operation.
        // The addresses being mapped won't overlap any existing mappings in this
        // page table because drm_gpuvm_sm_map() checks each requested mapping and either unmaps
        // or remaps any overlap before creating the new mapping.
        let (mapped, result) = unsafe {
            pt.map_pages(
                curr_iova,
                curr_paddr as PhysAddr,
                pgsize as usize,
                pgcount as usize,
                prot,
                GFP_NOWAIT,
            )
        };

        if let Err(e) = result {
            // If map_pages fails, mapped will be zero because the ARM LPAE backend
            // only updates the mapped value after the entire request succeeds.
            dev_err!(dev, "pt.map_pages failed at iova {:#x}: {:?}", curr_iova, e);
            return (segment_mapped, Err(e));
        }

        if mapped == 0 {
            dev_err!(dev, "Failed to map any pages at iova {:#x}", curr_iova);
            return (segment_mapped, Err(ENOMEM));
        }

        segment_mapped += mapped as u64;
    }

    (segment_mapped, Ok(()))
}

/// Unmaps a virtual address range from the page table.
///
/// This function removes all page table entries in the specified range,
/// automatically handling different page sizes that may be present.
fn pt_unmap(dev: &Device, page_table: &pt_alloc::DevresPageTable, range: Range<u64>) -> Result {
    let mut iova = range.start;
    let mut bytes_left_to_unmap = range.end - range.start;

    while bytes_left_to_unmap > 0 {
        // It is fine to use just the iova to determine the page size
        // because if the actual mapping was represented with smaller page sizes,
        // (e.g. because the physical address was not 2MiB aligned)
        // the ARM LPAE backend will notice and handle the lower-level table correctly.
        let (pgsize, pgcount) = get_pgsize(iova, bytes_left_to_unmap);

        // On 32-bit systems, usize is only 32 bits, so check that
        // the iova can be converted without truncation.
        let iova_usize = usize::try_from(iova).map_err(|_| {
            dev_err!(
                dev,
                "IOVA {:#x} cannot be represented as usize (max {:#x})",
                iova,
                usize::MAX
            );
            EOVERFLOW
        })?;

        // The guard is taken per chunk so the RCU read-side section covers a single
        // `unmap_pages()` call. The page table is freed when the device is unbound, leaving
        // nothing to unmap. Rollback calls from `pt_map()` never observe that, since
        // `pt_map()` holds a `&Device<Bound>`. A fragment rollback can.
        let Some(pt) = page_table.try_access() else {
            return Ok(());
        };

        // SAFETY:
        // No other io-pgtable operation can currently access this range because Tyr holds
        // the gpuvm_unique mutex for the entire sm_unmap() operation.
        // We know that this page table has one or more consecutive mappings
        // starting at `iova` with the total size of `pgcount * pgsize` because
        // gpuvm callbacks provide exactly the range that was previously mapped.
        let unmapped = unsafe { pt.unmap_pages(iova_usize, pgsize as usize, pgcount as usize) };

        if unmapped == 0 {
            dev_err!(dev, "Failed to unmap any bytes at iova {:#x}", iova_usize);
            return Err(EINVAL);
        }

        bytes_left_to_unmap -= unmapped as u64;
        iova += unmapped as u64;
    }

    Ok(())
}
