// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU virtual memory management using the DRM GPUVM framework.
//!
//! This module manages GPU virtual address spaces, providing memory isolation and
//! the illusion of owning the entire virtual address (VA) range, similar to CPU virtual memory.
//! Each virtual memory (VM) area is backed by ARM64 LPAE Stage 1 page tables and can be
//! mapped into hardware address space (AS) slots for GPU execution.

mod exec;
pub(crate) mod range;

use core::{
    mem::ManuallyDrop,
    ops::{Deref, Range},
    sync::atomic::{AtomicBool, Ordering},
};

use kernel::{
    c_str,
    device::{
        Bound,
        Device, //
    },
    dma_buf::dma_fence::{
        DmaFenceWorkqueue, DriverDmaFence, DriverDmaFenceOps, PublicDmaFence, Published,
    },
    drm::{
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
            JobQueue, JobQueueLockClasses, JobRef, PipelineBuilder, PreparedJob, QueueOps,
            SubmitResult,
        },
        DeviceContext, //
    },
    impl_flags,
    io::PhysAddr,
    iommu::pgtable::{
        prot,
        IoPageTable,
        ARM64LPAES1, //
    },
    new_mutex,
    platform,
    pr_warn_once,
    prelude::*,
    sizes::{
        SZ_1G,
        SZ_2M,
        SZ_4K, //
    },
    sync::{
        aref::ARef,
        Arc,
        ArcBorrow,
        LockClassKey,
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
    gem,
    gem::Bo,
    gpu::GpuInfo,
    mmu::{
        address_space::VmAsData,
        Mmu, //
    },
    pool::Pool as ObjectPool,
    regs::gpu_control::MMU_FEATURES,
};

// SAFETY: todo
static VM_BIND_QUEUE_INBOX_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
static VM_BIND_QUEUE_STATE_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
static VM_BIND_QUEUE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
static VM_BIND_QUEUE_CLEANUP_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
static VM_BIND_QUEUE_STAGE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
static VM_BIND_QUEUE_STAGE_TIMER_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
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
        tdev: &ARef<TyrDrmDevice>,
        requested_user_va_range: u64,
    ) -> Result<(usize, u64)> {
        let user_va_range = normalize_user_va_range(&tdev.gpu_info, requested_user_va_range);
        let vm = Vm::new_for_user(
            &tdev.pdev,
            tdev,
            tdev.mmu.as_arc_borrow(),
            &tdev.gpu_info,
            user_va_range,
        )?;

        let index = self.entries.insert(vm)?;

        Ok((index, user_va_range))
    }

    pub(crate) fn create_vm(
        &self,
        tdev: &ARef<TyrDrmDevice>,
        vmcreate: &mut uapi::drm_panthor_vm_create,
    ) -> Result {
        let (id, user_va_range) = self.create_vm_range(tdev, vmcreate.user_va_range)?;

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

    fn destroy_vm_index(&self, index: usize) -> Result {
        let vm = self.entries.remove(index)?;

        vm.kill();
        Ok(())
    }

    pub(crate) fn destroy_vm(&self, vmdestroy: &uapi::drm_panthor_vm_destroy) -> Result {
        if vmdestroy.pad != 0 {
            return Err(EINVAL);
        }

        self.destroy_vm_index(vmdestroy.id as usize)
    }

    pub(crate) fn destroy_all(&self) -> Result {
        let max_index = self.entries.index_upper_bound();

        for index in 1..max_index {
            let _ = self.destroy_vm_index(index);
        }

        Ok(())
    }
}

/// 256M of every VM is reserved for kernel objects by default.
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

impl core::fmt::Display for VmMapFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
        c_str!("tyr")
    }

    fn timeline_name(&self) -> &'static CStr {
        c_str!("tyr_vm_bind")
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

    pub(crate) fn push_map(
        &mut self,
        vm: &Vm,
        bo: ARef<Bo>,
        bo_offset: u64,
        size: u64,
        va: u64,
        flags: VmMapFlags,
    ) -> Result {
        // SAFETY: pdev is a bound device.
        let dev = unsafe { vm.exec.pdev.as_ref().as_bound() };
        let resources = VmOpResources {
            preallocated_gpuvas: [
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
            ],
            vm_bo: Some(vm.exec.gpuvm.obtain(&bo, ())?),
            map_sgt: Some(prefetch_map_sgt(&bo, dev)?),
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
                None,
            ],
            vm_bo: None,
            map_sgt: None,
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
        let result = (|| {
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
        })();

        match result {
            Ok(()) => {
                fence.signal(Ok(()));
                Ok(SubmitResult::Submitted)
            }
            Err(err) => {
                fence.signal(Err(err));
                Err(err)
            }
        }
    }
}

pub(crate) type PreparedVmBindJob = PreparedJob<VmBindQueueOps>;

impl TryFrom<u32> for VmMapFlags {
    type Error = Error;

    fn try_from(value: u32) -> core::result::Result<Self, Self::Error> {
        let valid = (kernel::uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_READONLY
            | kernel::uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_NOEXEC
            | kernel::uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_UNCACHED)
            as u32;

        if value & !valid != 0 {
            pr_err!("Invalid VM map flags: {:#x}\n", value);
            return Err(EINVAL);
        }
        Ok(Self(value))
    }
}

/// Arguments for a virtual memory map operation.
struct VmMapArgs {
    /// Access permissions and caching behavior for the mapping.
    flags: VmMapFlags,
    /// GEM buffer object registered with the GPUVM framework.
    vm_bo: ARef<GpuVmBo<GpuVmData>>,
    /// Offset in bytes from the start of the buffer object.
    bo_offset: u64,
}

/// Type of virtual memory operation.
enum VmOpType {
    /// Map a GEM buffer object into the virtual address space.
    Map(VmMapArgs),
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
    map_sgt: Option<KVec<(PhysAddr, u64)>>,
}

// SAFETY: `VmOpResources` holds `GpuVaAlloc` instances and an obtained
// `ARef<GpuVmBo<GpuVmData>>`. `GpuVaAlloc` wraps a
// `KBox<MaybeUninit<GpuVa<GpuVmData>>>` of uninitialised slab memory and is
// `!Send` only because its `Opaque<drm_gpuva>` field transitively inherits
// `!Send` from the C bindings; the allocation carries no thread-bound state.
// `GpuVmBo<GpuVmData>` is `!Send` for the same reason, but its `drm_gpuvm_bo`
// refcount is not thread-bound and the only thread-bound state it could carry
// is its `VmBoData = ()` payload, which is `Send`. Handing the resources off to
// the VM_BIND worker thread that consumes them is therefore sound.
unsafe impl Send for VmOpResources {}

/// Request to execute a virtual memory operation.
struct VmOpRequest {
    /// Request type.
    op_type: VmOpType,

    /// Region of the virtual address space covered by this request.
    region: Range<u64>,
}

/// Arguments for a page table map operation.
struct PtMapArgs {
    /// Memory protection flags describing allowed accesses for this mapping.
    ///
    /// This is directly derived from [`VmMapFlags`] via [`VmMapFlags::to_prot`].
    prot: u32,
}

/// Type of page table operation.
enum PtOpType {
    /// Map pages into the page table.
    Map(PtMapArgs),
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
    /// Page table.
    pt: &'ctx IoPageTable<ARM64LPAES1>,

    /// MMU manager.
    mmu: &'ctx Mmu,

    /// Reference to the address space data to pass to the MMU functions.
    as_data: &'ctx VmAsData,

    /// Region of the virtual address space covered by this request.
    region: Range<u64>,

    /// Operation type.
    op_type: PtOpType,

    /// Preallocated resources that can be used when executing the request.
    resources: &'ctx mut VmOpResources,
}

impl<'ctx> PtUpdateContext<'ctx> {
    /// Creates a new page table update context.
    ///
    /// This prepares the MMU for a page table update.
    /// The context will automatically flush the TLB and
    /// complete the update when dropped.
    fn new(
        pt: &'ctx IoPageTable<ARM64LPAES1>,
        mmu: &'ctx Mmu,
        as_data: &'ctx VmAsData,
        region: Range<u64>,
        op_type: PtOpType,
        resources: &'ctx mut VmOpResources,
    ) -> Result<PtUpdateContext<'ctx>> {
        mmu.start_vm_update(as_data, &region)?;

        Ok(Self {
            pt,
            mmu,
            as_data,
            region,
            op_type,
            resources,
        })
    }

    /// Finds one of our pre-allocated VAs.
    ///
    /// It is a logic error to call this more than three times for a given
    /// PtUpdateContext.
    fn preallocated_gpuva(&mut self) -> Result<GpuVaAlloc<GpuVmData>> {
        self.resources
            .preallocated_gpuvas
            .iter_mut()
            .find_map(|f| f.take())
            .ok_or(EINVAL)
    }
}

impl Drop for PtUpdateContext<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.mmu.end_vm_update(self.as_data) {
            pr_err!("Failed to end VM update {:?}\n", e);
        }

        if let Err(e) = self.mmu.flush_vm(self.as_data) {
            pr_err!("Failed to flush VM {:?}\n", e);
        }
    }
}

/// Driver implementation for the GPUVM framework.
///
/// Implements [`DriverGpuVm`] to provide VM operation callbacks (map, unmap, remap)
/// and associated types for buffer objects, virtual addresses, and contexts.
pub(crate) struct GpuVmData {}

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

/// GPU virtual address space.
///
/// Each VM can be mapped into a hardware address space slot.
#[pin_data(PinnedDrop)]
pub(crate) struct VmExec {
    /// Data referenced by an AS when the VM is active.
    pub(crate) as_data: Arc<VmAsData>,
    /// MMU manager.
    mmu: Arc<Mmu>,
    /// Platform device reference (needed to access the page table via devres).
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
    unusable: AtomicBool,
    /// Cleanup workqueue used by `Drop` to defer the final
    /// `drm_gpuvm_put` out of any dma-fence signalling section the drop
    /// may run under.
    cleanup_wq: Arc<CleanupQueue>,
}

#[pinned_drop]
impl PinnedDrop for VmExec {
    fn drop(self: Pin<&mut Self>) {
        // SAFETY: We do not move out of any structurally pinned field.
        // The `Mutex` is only accessed through `try_lock` in place, and
        // the only field moved out is `gpuvm`, which is not `#[pin]`.
        let this = unsafe { self.get_unchecked_mut() };

        // SAFETY: `Drop` runs at most once, and this is the only
        // `ManuallyDrop::take` of `gpuvm`; the field is never read again
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

        let res = this.cleanup_wq.try_spawn(GFP_NOWAIT, move || {
            drop(gpuvm);
            drop(gpuvm_unique);
        });

        if res.is_err() {
            pr_warn_once!(
                "tyr: VmExec cleanup_wq enqueue failed under memory pressure; performing inline gpuvm teardown (lockdep cycle may fire)\n",
            );
        }
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
    /// VA range for this VM.
    va_range: Range<u64>,
    /// Kernel VA allocator for auto-placement of kernel buffer objects.
    kernel_va: range::RangeAlloc,
    /// Kernel VA reservations that must live as long as the VM.
    #[pin]
    kernel_reservations: Mutex<KVec<range::LiveRange>>,
}

impl Vm {
    #[allow(clippy::too_many_arguments)]
    fn new_with_ranges<Ctx: DeviceContext>(
        pdev: &platform::Device,
        ddev: &TyrDrmDevice<Ctx>,
        mmu: ArcBorrow<'_, Mmu>,
        gpu_info: &GpuInfo,
        total_range: Range<u64>,
        kernel_range: Range<u64>,
        bind_wq: Option<Arc<DmaFenceWorkqueue>>,
        coherent: bool,
        cleanup_wq: Arc<CleanupQueue>,
    ) -> Result<Arc<Vm>> {
        let mmu_features = MMU_FEATURES::from_raw(gpu_info.mmu_features);
        let va_bits = mmu_features.va_bits().get();
        let pa_bits = mmu_features.pa_bits().get();

        let reserve_range = 0..0u64;

        // dummy_obj is used to initialize the GPUVM tree.
        let dummy_obj = gem::new_dummy_object(ddev, coherent).inspect_err(|e| {
            pr_err!("Failed to create dummy GEM object: {:?}\n", e);
        })?;

        let gpuvm_unique = kernel::drm::gpuvm::GpuVm::new::<Error, _>(
            c_str!("Tyr::GpuVm"),
            ddev,
            &*dummy_obj,
            total_range.clone(),
            reserve_range,
            GpuVmData {},
        )
        .inspect_err(|e| {
            pr_err!("Failed to create GpuVm: {:?}\n", e);
        })?;
        let gpuvm = ARef::from(&*gpuvm_unique);

        let as_data = Arc::pin_init(VmAsData::new(&mmu, pdev, va_bits, pa_bits), GFP_KERNEL)?;
        let kernel_va = range::RangeAlloc::new(kernel_range.start, kernel_range.end, GFP_KERNEL)?;

        let exec = Arc::pin_init(
            pin_init!(VmExec {
                as_data,
                pdev: pdev.into(),
                mmu: mmu.into(),
                gpuvm: ManuallyDrop::new(gpuvm),
                gpuvm_unique <- new_mutex!(Some(gpuvm_unique)),
                unusable: AtomicBool::new(false),
                cleanup_wq,
            }),
            GFP_KERNEL,
        )?;
        let bind_queue = match bind_wq {
            Some(wq) => Some(JobQueue::new(
                VmBindQueueOps { exec: exec.clone() },
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
                va_range: total_range,
                kernel_va,
                kernel_reservations <- new_mutex!(KVec::new()),
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_fw<Ctx: DeviceContext>(
        pdev: &platform::Device,
        ddev: &TyrDrmDevice<Ctx>,
        mmu: ArcBorrow<'_, Mmu>,
        gpu_info: &GpuInfo,
        auto_kernel_va_start: u64,
        auto_kernel_va_size: u64,
        coherent: bool,
        cleanup_wq: Arc<CleanupQueue>,
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
            cleanup_wq,
        )
    }

    pub(crate) fn new_for_user(
        pdev: &platform::Device,
        ddev: &TyrDrmDevice,
        mmu: ArcBorrow<'_, Mmu>,
        gpu_info: &GpuInfo,
        user_va_range: u64,
    ) -> Result<Arc<Vm>> {
        let user_va_range = normalize_user_va_range(gpu_info, user_va_range);

        let total_va_end = if user_va_range >= max_va_range(gpu_info) {
            max_va_range(gpu_info)
        } else {
            user_va_range + MIN_KERNEL_VA_SIZE
        };
        let total_range = 0..total_va_end;
        let kernel_range = (total_va_end - MIN_KERNEL_VA_SIZE)..total_va_end;

        Self::new_with_ranges(
            pdev,
            ddev,
            mmu,
            gpu_info,
            total_range,
            kernel_range,
            Some(ddev.wq.clone()),
            ddev.coherent,
            ddev.cleanup_wq.clone(),
        )
    }

    /// Activate the VM in a hardware address space slot.
    pub(crate) fn kill(&self) {
        self.exec.mark_unusable();
        let _ = self.exec.deactivate().inspect_err(|e| {
            pr_err!("Failed to deactivate VM: {:?}\n", e);
        });
        let _ = self
            .exec
            .unmap_range(self.va_range.start, self.va_range.end - self.va_range.start)
            .inspect_err(|e| {
                pr_err!("Failed to unmap range during deactivate: {:?}\n", e);
            });
    }

    pub(crate) fn alloc_kernel_range(&self, size: usize) -> Result<range::LiveRange> {
        self.kernel_va.allocate(size, GFP_KERNEL)
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

    /// Reserves `[start, end)` in the kernel auto-VA window so future
    /// `alloc_kernel_range` calls cannot hand
    /// out an overlapping range. Used for explicit-VA mappings created
    /// before the auto-allocator opens.
    pub(crate) fn reserve_kernel_range(&self, start: u64, end: u64) -> Result {
        let node = self.kernel_va.insert(start, end, GFP_KERNEL)?;
        self.kernel_reservations.lock().push(node, GFP_KERNEL)?;
        Ok(())
    }

    pub(crate) fn prepare_bind_job(
        &self,
        job: VmBindJob,
        deps: &[ARef<PublicDmaFence>],
    ) -> Result<PreparedVmBindJob> {
        self.flush_deferred_cleanup();

        self.bind_queue
            .as_ref()
            .ok_or(EINVAL)?
            .prepare(job, deps, 0, VmBindFenceData)
    }

    pub(crate) fn commit_bind_job(&self, prepared: PreparedVmBindJob) -> ARef<PublicDmaFence> {
        self.bind_queue
            .as_ref()
            .expect("Vm::commit_bind_job called without a bind queue")
            .commit(prepared)
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
    /// Activate the VM in a hardware address space slot.
    pub(crate) fn activate(&self) -> Result {
        self.mmu
            .activate_vm(self.as_data.as_arc_borrow())
            .inspect_err(|e| {
                pr_err!("Failed to activate VM: {:?}\n", e);
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

    pub(crate) fn is_unusable(&self) -> bool {
        self.unusable.load(Ordering::Relaxed)
    }

    fn mark_unusable(&self) {
        self.unusable.store(true, Ordering::Relaxed);
    }

    /// Returns the buffer object mapped at `va` and its offset within
    /// that buffer object, or `None` if no mapping covers `va`.
    ///
    /// The lookup is a snapshot taken under `gpuvm_unique`: the
    /// returned `ARef<Bo>` keeps the BO alive, but a subsequent
    /// unmap+remap at `va` will not invalidate it. Callers that need
    /// the mapping to remain stable past the call must hold a lock
    /// that serialises against `unmap_range`.
    pub(crate) fn get_bo_for_va(&self, va: u64) -> Option<(ARef<Bo>, u64)> {
        let guard = self.gpuvm_unique.lock();
        let gpuva = guard.as_ref()?.find_first(va, 1)?;
        let bo = gpuva.obj();
        let bo_offset = gpuva.gem_offset() + (va - gpuva.addr());
        Some((ARef::from(bo), bo_offset))
    }

    /// Deactivate the VM by evicting it from its address space slot.
    pub(crate) fn deactivate(&self) -> Result {
        self.mmu.deactivate_vm(&self.as_data).inspect_err(|e| {
            pr_err!("Failed to deactivate VM: {:?}\n", e);
        })
    }

    /// Executes a virtual memory operation.
    ///
    /// This handles both map and unmap operations by coordinating between the
    /// GPUVM framework and the hardware page table.
    fn exec_op(
        &self,
        gpuvm_unique: &mut UniqueRefGpuVm<GpuVmData>,
        req: VmOpRequest,
        resources: &mut VmOpResources,
    ) -> Result {
        // SAFETY: pdev is a bound device.
        let dev = unsafe { self.pdev.as_ref().as_bound() };

        let pt = self.as_data.page_table.access(dev).inspect_err(|e| {
            pr_err!("Failed to access page table while mapping pages: {:?}\n", e);
        })?;

        match req.op_type {
            VmOpType::Map(args) => {
                let mut pt_upd = PtUpdateContext::new(
                    pt,
                    &self.mmu,
                    &self.as_data,
                    req.region,
                    PtOpType::Map(PtMapArgs {
                        prot: args.flags.to_prot(),
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
    /// spanning `size` bytes. The mapping respects the access permissions and
    /// caching behavior specified in `flags`.
    fn map_bo_range_inner(
        &self,
        bo_offset: u64,
        size: u64,
        va: u64,
        flags: VmMapFlags,
        resources: &mut VmOpResources,
    ) -> Result {
        let vm_bo = resources.vm_bo.take().ok_or(EINVAL)?;
        let req = VmOpRequest {
            op_type: VmOpType::Map(VmMapArgs {
                vm_bo,
                flags,
                bo_offset,
            }),
            region: va..(va + size),
        };
        let mut gpuvm_unique = self.gpuvm_unique.lock();

        self.exec_op((*gpuvm_unique).as_mut().ok_or(EINVAL)?, req, resources)?;

        Ok(())
    }

    pub(crate) fn flush_deferred_cleanup(&self) {
        self.gpuvm.deferred_cleanup();
    }

    pub(crate) fn map_bo_range(
        &self,
        bo: &Bo,
        bo_offset: u64,
        size: u64,
        va: u64,
        flags: VmMapFlags,
    ) -> Result {
        // SAFETY: pdev is a bound device.
        let dev = unsafe { self.pdev.as_ref().as_bound() };
        let mut resources = VmOpResources {
            preallocated_gpuvas: [
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
            ],
            vm_bo: Some(self.gpuvm.obtain(bo, ())?),
            map_sgt: Some(prefetch_map_sgt(bo, dev)?),
        };
        self.map_bo_range_inner(bo_offset, size, va, flags, &mut resources)?;

        // We flush the defer cleanup list now. Things will be different in
        // the asynchronous VM_BIND path, where we want the cleanup to
        // happen outside the DMA signalling path.
        self.flush_deferred_cleanup();
        Ok(())
    }

    /// Unmaps a virtual address range from the VM.
    ///
    /// This removes any existing mappings in the specified range, freeing the
    /// virtual address space for reuse.
    fn unmap_range_inner(&self, va: u64, size: u64, resources: &mut VmOpResources) -> Result {
        let req = VmOpRequest {
            op_type: VmOpType::Unmap,
            region: va..(va + size),
        };
        let mut gpuvm_unique = self.gpuvm_unique.lock();

        self.exec_op((*gpuvm_unique).as_mut().ok_or(EINVAL)?, req, resources)?;

        Ok(())
    }

    pub(crate) fn unmap_range(&self, va: u64, size: u64) -> Result {
        let mut resources = VmOpResources {
            preallocated_gpuvas: [
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                Some(GpuVaAlloc::<GpuVmData>::new(GFP_KERNEL)?),
                None,
            ],
            vm_bo: None,
            map_sgt: None,
        };
        self.unmap_range_inner(va, size, &mut resources)?;

        // We flush the defer cleanup list now. Things will be different in
        // the asynchronous VM_BIND path, where we want the cleanup to
        // happen outside the DMA signalling path.
        self.flush_deferred_cleanup();
        Ok(())
    }
}

impl DriverGpuVm for GpuVmData {
    type Driver = TyrDrmDriver;
    type Object = Bo;
    type VmBoData = ();
    type VaData = ();
    type SmContext<'ctx> = PtUpdateContext<'ctx>;

    /// Indicates that a new mapping should be created.
    fn sm_step_map<'op>(
        &mut self,
        op: OpMap<'op, Self>,
        context: &mut Self::SmContext<'_>,
    ) -> Result<OpMapped<'op, Self>, Error> {
        let start_iova = op.addr();
        let mut iova = start_iova;
        let mut bytes_left_to_map = op.length();
        let mut gem_offset = op.gem_offset();
        let map_sgt = context.resources.map_sgt.as_ref().ok_or(EINVAL)?;
        let prot = match &context.op_type {
            PtOpType::Map(args) => args.prot,
            _ => {
                return Err(EINVAL);
            }
        };

        for &(mut paddr, mut sgt_entry_length) in map_sgt.iter() {
            if bytes_left_to_map == 0 {
                break;
            }

            if gem_offset > 0 {
                // Skip the entire SGT entry if the gem_offset exceeds its length
                let skip = sgt_entry_length.min(gem_offset);
                paddr += skip;
                sgt_entry_length -= skip;
                gem_offset -= skip;
            }

            if sgt_entry_length == 0 {
                continue;
            }

            if gem_offset != 0 {
                pr_err!("Invalid gem_offset {} in page table mapping.\n", gem_offset);
                return Err(EINVAL);
            }
            let len = sgt_entry_length.min(bytes_left_to_map);

            let segment_mapped = match pt_map(context.pt, iova, paddr, len, prot) {
                Ok(segment_mapped) => segment_mapped,
                Err(e) => {
                    // clean up any successful mappings from previous SGT entries.
                    let total_mapped = iova - start_iova;
                    if total_mapped > 0 {
                        pt_unmap(context.pt, start_iova..(start_iova + total_mapped)).ok();
                    }
                    return Err(e);
                }
            };

            // Since there could be a partial mapping, only advance by the actual amount mapped
            bytes_left_to_map -= segment_mapped;
            iova += segment_mapped;
        }

        let gpuva = context.preallocated_gpuva()?;
        let op = op.insert(gpuva, pin_init::init_zeroed());

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
        pt_unmap(context.pt, region.clone()).inspect_err(|e| {
            pr_err!(
                "Failed to unmap region {:#x}..{:#x}: {:?}\n",
                region.start,
                region.end,
                e
            );
        })?;

        let (op_unmapped, _va_removed) = op.remove();

        Ok(op_unmapped)
    }

    /// Indicates that an existing mapping should be split up.
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

        let unmap_length = unmap_end - unmap_start;

        if unmap_length > 0 {
            let region = unmap_start..(unmap_start + unmap_length);
            pt_unmap(context.pt, region.clone()).inspect_err(|e| {
                pr_err!(
                    "Failed to unmap remap region {:#x}..{:#x}: {:?}\n",
                    region.start,
                    region.end,
                    e
                );
            })?;
        }

        let prev_va = context.preallocated_gpuva()?;
        let next_va = context.preallocated_gpuva()?;

        let (op_remapped, _remap_ret) = op.remap(
            [prev_va, next_va],
            pin_init::init_zeroed(),
            pin_init::init_zeroed(),
        );

        Ok(op_remapped)
    }
}

/// This function selects the largest supported block size (currently 4KB or 2MB)
/// that can be used for a mapping at the given address and size, respecting alignment constraints.
///
/// We can map multiple pages at once but we can't exceed the size of the
// table entry itself. So, if mapping 4KB pages, figure out how many pages
// can be mapped before we hit the 2MB boundary. Or, if mapping 2MB pages,
// figure out how many pages can be mapped before hitting the 1GB boundary
// Returns the page size (4KB or 2MB) and the number of pages that can be mapped at that size.
fn get_pgsize(addr: u64, size: u64) -> (u64, u64) {
    // Get the distance to the next boundary of 2MB block
    let blk_offset_2m = addr.wrapping_neg() % (SZ_2M as u64);

    // Use 4K blocks if the address is not 2MB aligned, or we have less than 2MB to map
    if blk_offset_2m != 0 || size < SZ_2M as u64 {
        let pgcount = if blk_offset_2m == 0 {
            size / SZ_4K as u64
        } else {
            blk_offset_2m.min(size) / SZ_4K as u64
        };
        return (SZ_4K as u64, pgcount);
    }

    let blk_offset_1g = addr.wrapping_neg() % (SZ_1G as u64);
    let blk_offset = if blk_offset_1g == 0 {
        SZ_1G as u64
    } else {
        blk_offset_1g
    };
    let pgcount = blk_offset.min(size) / SZ_2M as u64;

    (SZ_2M as u64, pgcount)
}

/// Collects the BO's scatter-gather segments outside the VM_BIND
/// signalling section.
///
/// `Object::sg_table` takes `dma_resv_lock`, which must not be taken on
/// the path to `dma_fence_signal()`. The segments are consumed lock-free
/// inside the signalling section.
fn prefetch_map_sgt(bo: &Bo, dev: &Device<Bound>) -> Result<KVec<(PhysAddr, u64)>> {
    let sgt = bo.sg_table(dev).inspect_err(|e| {
        pr_err!("Failed to get sg_table: {:?}\n", e);
    })?;

    let mut segments = KVec::new();
    for sgt_entry in sgt.iter() {
        segments.push((sgt_entry.dma_address(), sgt_entry.dma_len()), GFP_KERNEL)?;
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
    pt: &IoPageTable<ARM64LPAES1>,
    iova: u64,
    paddr: u64,
    len: u64,
    prot: u32,
) -> Result<u64> {
    let mut segment_mapped = 0u64;
    while segment_mapped < len {
        let remaining = len - segment_mapped;
        let curr_iova = iova + segment_mapped;
        let curr_paddr = paddr + segment_mapped;

        let (pgsize, pgcount) = get_pgsize(curr_iova | curr_paddr, remaining);

        // TODO: GFP_NOWAIT because this runs in the VM_BIND dma-fence
        // signalling section. The proper fix is to preallocate page-table
        // pages in the prepare phase (like Panthor's rsvd_page_tables +
        // custom io-pgtable allocator) so this path does not allocate.
        //
        // SAFETY: Exclusive access to the page table is ensured because
        // the pt reference comes from PtUpdateContext, which is created
        // during a VM update operation, ensuring the driver does not concurrently
        // modify the page table.
        let (mapped, result) = unsafe {
            pt.map_pages(
                curr_iova as usize,
                (curr_paddr as usize).try_into().unwrap(),
                pgsize as usize,
                pgcount as usize,
                prot,
                GFP_NOWAIT,
            )
        };

        if let Err(e) = result {
            pr_err!("pt.map_pages failed at iova {:#x}: {:?}\n", curr_iova, e);
            if segment_mapped > 0 {
                pt_unmap(pt, iova..(iova + segment_mapped)).ok();
            }
            return Err(e);
        }

        if mapped == 0 {
            pr_err!("Failed to map any pages at iova {:#x}\n", curr_iova);
            if segment_mapped > 0 {
                pt_unmap(pt, iova..(iova + segment_mapped)).ok();
            }
            return Err(ENOMEM);
        }

        segment_mapped += mapped as u64;
    }

    Ok(segment_mapped)
}

/// Unmaps a virtual address range from the page table.
///
/// This function removes all page table entries in the specified range,
/// automatically handling different page sizes that may be present.
fn pt_unmap(pt: &IoPageTable<ARM64LPAES1>, range: Range<u64>) -> Result {
    let mut iova = range.start;
    let mut bytes_left_to_unmap = range.end - range.start;

    while bytes_left_to_unmap > 0 {
        let (pgsize, pgcount) = get_pgsize(iova, bytes_left_to_unmap);

        // SAFETY: Exclusive access to the page table is ensured because
        // the pt reference comes from PtUpdateContext, which was
        // created while holding &mut Vm, preventing any other access to the
        // page table for the duration of this operation.
        let unmapped = unsafe { pt.unmap_pages(iova as usize, pgsize as usize, pgcount as usize) };

        if unmapped == 0 {
            pr_err!("Failed to unmap any bytes at iova {:#x}\n", iova);
            return Err(EINVAL);
        }

        bytes_left_to_unmap -= unmapped as u64;
        iova += unmapped as u64;
    }

    Ok(())
}
