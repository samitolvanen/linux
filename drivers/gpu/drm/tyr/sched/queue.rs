// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::{
    Deref,
    Range, //
};

use kernel::{
    alloc::KVec,
    bindings,
    dma_buf::dma_fence::{
        DmaFenceSignallingAnnotation,
        DmaFenceWorkqueue,
        DriverDmaFence,
        DriverDmaFenceOps,
        PublicDmaFence,
        Published, //
    },
    drm::{
        job_queue::{
            JobQueue,
            JobQueueLockClasses,
            JobRef,
            PipelineBuilder,
            PreparedJob,
            QueueOps,
            StageAdvance,
            StageContext,
            StageOps,
            SubmitResult, //
        }, //
    },
    io::{
        mem::DevresIoMem,
        register::Array,
        Io,
        IoBase, //
    },
    new_mutex,
    prelude::*,
    sizes::{
        SZ_2M,
        SZ_4K,
        SZ_64K, //
    },
    sync::{
        aref::ARef,
        atomic::{
            Acquire,
            Atomic,
            Relaxed,
            Release, //
        },
        barrier::{
            smp_mb,
            Write, //
        },
        Arc,
        LockClassKey,
        Mutex, //
    },
    time::{
        msecs_to_jiffies,
        Jiffies, //
    },
    transmute::FromBytes,
    uapi, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData,
        TyrDrmRegistrationData, //
    },
    gem,
    regs::doorbell_block,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    }, //
};

use super::group::Group;

const UNASSIGNED_DOORBELL_ID: usize = usize::MAX;
const JOB_POLL_INTERVAL_MS: u32 = 1;
const JOB_TIMEOUT_MS: u32 = 5000;

// SAFETY: The key is in static memory, is pinned with `Pin::static_ref()` before use, and a
// static is never dropped.
static TYR_QUEUE_INBOX_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static TYR_QUEUE_STATE_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static TYR_QUEUE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static TYR_QUEUE_CLEANUP_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static TYR_QUEUE_STAGE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static TYR_QUEUE_STAGE_TIMER_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: See above.
static TYR_QUEUE_DRIVER_FENCE_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };

#[repr(transparent)]
pub(crate) struct QueueCreate(uapi::drm_panthor_queue_create);

// SAFETY: This wrapper is layout-identical to the UAPI queue-create record
// read from userspace.
unsafe impl FromBytes for QueueCreate {}

impl QueueCreate {
    pub(crate) fn validate(&self) -> Result {
        if self.0.pad != [0; 3] {
            return Err(EINVAL);
        }

        if self.0.priority > 15 {
            return Err(EINVAL);
        }

        if self.0.ringbuf_size < SZ_4K as u32
            || self.0.ringbuf_size > SZ_64K as u32
            || !self.0.ringbuf_size.is_power_of_two()
        {
            return Err(EINVAL);
        }

        Ok(())
    }

    pub(crate) fn priority(&self) -> u8 {
        self.0.priority
    }

    pub(crate) fn ringbuf_size(&self) -> u32 {
        self.0.ringbuf_size
    }
}

#[pin_data]
pub(crate) struct QueueData {
    priority: u8,
    ringbuf: Arc<gem::MappedBo>,
    interfaces: Interfaces,
    doorbell_id: Atomic<usize>,
    next_seqno: Atomic<u64>,
    iomem: Arc<DevresIoMem<SZ_2M>>,
    #[pin]
    pending_submit_fences: Mutex<KVec<PendingSubmitFence>>,
    #[pin]
    last_submit_fence: Mutex<Option<ARef<PublicDmaFence>>>,
    /// Active GPU sync-wait captured for this queue. The `Default`
    /// value (`gpu_va == 0`) means no wait is currently active.
    #[pin]
    syncwait: Mutex<SyncWait>,
}

impl QueueData {
    fn ringbuf_space_for(&self, instr_count: usize) -> Result<RingBufferInput> {
        let ringbuf_input = self.interfaces.read_input()?;
        let size = self.ringbuf.vmap().size();
        let ringbuf_output = self.interfaces.read_output()?;
        let used = ringbuf_input
            .insert
            .checked_sub(ringbuf_output.extract)
            .ok_or(EIO)?;

        if instr_count > size {
            return Err(ENOSPC);
        }

        if used > size as u64 || instr_count as u64 > size as u64 - used {
            return Err(ENOSPC);
        }

        Ok(ringbuf_input)
    }

    fn doorbell_id(&self) -> Option<usize> {
        let doorbell_id = self.doorbell_id.load(Relaxed);

        if doorbell_id == UNASSIGNED_DOORBELL_ID {
            None
        } else {
            Some(doorbell_id)
        }
    }

    pub(super) fn set_doorbell_id(&self, doorbell_id: Option<usize>) {
        self.doorbell_id
            .store(doorbell_id.unwrap_or(UNASSIGNED_DOORBELL_ID), Relaxed);
    }

    pub(super) fn can_append(&self, instr_count: usize) -> Result {
        self.ringbuf_space_for(instr_count)?;
        Ok(())
    }

    pub(super) fn claim_seqno(&self) -> u64 {
        self.next_seqno.fetch_add(1, Relaxed) + 1
    }

    pub(super) fn append_instrs(&self, instrs: &[u8]) -> Result<u64> {
        let mut ringbuf_input = self.ringbuf_space_for(instrs.len())?;

        let ringbuf = self.ringbuf.vmap();
        let size = ringbuf.size();
        let ringbuf_output = self.interfaces.read_output()?;

        let cs_insert = (ringbuf_input.insert & (size as u64 - 1)) as usize;

        let first_chunk = core::cmp::min(size - cs_insert, instrs.len());
        let dst = ringbuf.as_view().as_ptr().cast::<u8>();
        // SAFETY: `dst` is the writable CPU mapping of the ring buffer, valid
        // for `size` bytes, and `instrs` is a separate allocation. The mask
        // puts `cs_insert` below `size`, and `first_chunk` is at most
        // `size - cs_insert`, so the first copy stays inside the mapping. An
        // append larger than the ring is rejected, so the wrapped remainder
        // `instrs.len() - first_chunk` is at most `size`.
        unsafe {
            core::ptr::copy_nonoverlapping(instrs.as_ptr(), dst.add(cs_insert), first_chunk);
            core::ptr::copy_nonoverlapping(
                instrs.as_ptr().add(first_chunk),
                dst,
                instrs.len() - first_chunk,
            );
        }

        smp_mb(Write);

        ringbuf_input.extract_init = ringbuf_output.extract;
        ringbuf_input.insert += instrs.len() as u64;
        let completion_point = ringbuf_input.insert;

        self.interfaces.write_input(ringbuf_input)?;
        smp_mb(Write);
        Ok(completion_point)
    }

    pub(super) fn kick(&self) -> Result {
        let io = self.iomem.try_access().ok_or(ENODEV)?;
        let doorbell_reg =
            doorbell_block::DOORBELL::try_at(self.doorbell_id().ok_or(EINVAL)?).ok_or(EINVAL)?;

        io.try_write(
            doorbell_reg,
            doorbell_block::DOORBELL::zeroed().with_ring(true),
        )
    }

    fn reserve_pending_submit_fence(&self) -> Result {
        self.pending_submit_fences
            .lock()
            .reserve(1, GFP_KERNEL)
            .map_err(Error::from)
    }

    fn add_pending_submit_fence(
        &self,
        completion_point: u64,
        fence: DriverDmaFence<QueueFenceData, Published>,
    ) -> core::result::Result<(), (Error, DriverDmaFence<QueueFenceData, Published>)> {
        let pending_fence = PendingSubmitFence {
            completion_point,
            fence,
        };

        match self
            .pending_submit_fences
            .lock()
            .push_within_capacity(pending_fence)
        {
            Ok(()) => Ok(()),
            Err(err) => Err((EINVAL, err.0.fence)),
        }
    }

    fn signal_submit_fences_up_to(&self, completion_point: u64, result: Result) {
        loop {
            let pending_fence = {
                let mut pending = self.pending_submit_fences.lock();

                match pending.first() {
                    Some(pending_fence) if pending_fence.completion_point <= completion_point => {
                        pending.remove(0).ok()
                    }
                    _ => None,
                }
            };

            let Some(pending_fence) = pending_fence else {
                break;
            };

            let _annotation = DmaFenceSignallingAnnotation::new();
            pending_fence.fence.signal(result);
        }
    }

    fn signal_submit_fence(&self, completion_point: u64, result: Result) -> bool {
        let pending_fence = {
            let mut pending = self.pending_submit_fences.lock();
            let mut position = None;

            for (index, pending_fence) in pending.iter().enumerate() {
                if pending_fence.completion_point == completion_point {
                    position = Some(index);
                    break;
                }
            }

            position.and_then(|index| pending.remove(index).ok())
        };

        let Some(pending_fence) = pending_fence else {
            return false;
        };

        let _annotation = DmaFenceSignallingAnnotation::new();
        pending_fence.fence.signal(result);
        true
    }

    fn complete_submit_fences(&self) -> Result {
        let ringbuf_output = self.interfaces.read_output()?;
        self.signal_submit_fences_up_to(ringbuf_output.extract, Ok(()));
        Ok(())
    }

    /// Reads the firmware-visible `EXTRACT` for this queue and stages
    /// `err` on every pending submit fence whose `completion_point` is
    /// strictly past it, i.e. submissions whose ringbuf range the firmware
    /// has not yet reached.
    ///
    /// The fences are left in the pending list. The regular seqno-ordered
    /// drain in `Self::complete_pending_fences_up_to` will signal them
    /// at their natural completion points so waiters still observe a
    /// monotonic submit-order signal sequence.
    ///
    /// Safe to call from inside a `DmaFenceSignallingAnnotation` section.
    pub(in crate::sched) fn fail_inflight_submit_fences(&self, err: Error) -> Result {
        let extract = self.interfaces.read_output()?.extract;
        let mut pending = self.pending_submit_fences.lock();
        for entry in pending.iter_mut() {
            if entry.completion_point > extract {
                entry.fence.set_error(err);
            }
        }
        Ok(())
    }

    /// Returns a clone of the active sync-wait snapshot.
    pub(crate) fn syncwait_snapshot(&self) -> SyncWait {
        self.syncwait.lock().clone()
    }

    /// Updates the firmware-reported fields of the active sync-wait
    /// snapshot. The cached BO resolution is keyed independently by
    /// its own `(gpu_va, sync64)`. `Group::eval_syncwait` detects
    /// when the live wait has moved to a different key and rebuilds.
    pub(crate) fn set_syncwait(&self, gpu_va: u64, ref_val: u64, sync64: bool, gt: bool) {
        let mut wait = self.syncwait.lock();
        wait.gpu_va = gpu_va;
        wait.ref_val = ref_val;
        wait.sync64 = sync64;
        wait.gt = gt;
    }

    /// Stores a resolved BO cache on the active sync-wait snapshot if
    /// `gpu_va` and `sync64` still match.
    ///
    /// Both `gpu_va` and `sync64` are re-checked under the lock so a
    /// concurrent `set_syncwait` that reuses the same address with a
    /// different sync-object width does not install a stale resolution
    /// that would later be read with the wrong type. Returns `true` if
    /// the cache was applied.
    pub(crate) fn cache_syncwait_bo(
        &self,
        gpu_va: u64,
        sync64: bool,
        bo: Arc<gem::BoVmap>,
        offset: usize,
    ) -> bool {
        let mut wait = self.syncwait.lock();
        if wait.gpu_va != gpu_va || wait.sync64 != sync64 {
            return false;
        }
        wait.cached = Some(CachedBo {
            gpu_va,
            sync64,
            bo,
            offset,
        });
        true
    }

    /// Removes and returns the cached BO resolution from the active
    /// sync-wait snapshot.
    pub(crate) fn take_syncwait_bo(&self) -> Option<Arc<gem::BoVmap>> {
        let mut wait = self.syncwait.lock();
        wait.cached.take().map(|c| c.bo)
    }

    /// Returns `true` if the firmware-visible ring buffer is currently
    /// empty (`INSERT == EXTRACT`).
    pub(crate) fn is_ringbuf_empty(&self) -> Result<bool> {
        let input = self.interfaces.read_input()?;
        let output = self.interfaces.read_output()?;
        Ok(input.insert == output.extract)
    }

    pub(super) fn last_submit_fence(&self) -> Option<ARef<PublicDmaFence>> {
        self.last_submit_fence.lock().clone()
    }
}

pub(super) struct TyrQueueOps {
    data: Arc<QueueData>,
}

impl QueueOps for TyrQueueOps {
    type Job = QueueJob;
    type FenceData = QueueFenceData;

    fn lock_classes() -> JobQueueLockClasses {
        JobQueueLockClasses {
            inbox: &TYR_QUEUE_INBOX_LOCK_CLASS,
            state: &TYR_QUEUE_STATE_LOCK_CLASS,
            work: &TYR_QUEUE_WORK_LOCK_CLASS,
            cleanup_work: &TYR_QUEUE_CLEANUP_WORK_LOCK_CLASS,
            stage_work: &TYR_QUEUE_STAGE_WORK_LOCK_CLASS,
            stage_timer: &TYR_QUEUE_STAGE_TIMER_LOCK_CLASS,
            driver_fence: &TYR_QUEUE_DRIVER_FENCE_LOCK_CLASS,
        }
    }

    fn submit(
        &self,
        job: &JobRef<'_, Self::Job>,
        fence: DriverDmaFence<Self::FenceData, Published>,
        _wq: &DmaFenceWorkqueue,
    ) -> Result<SubmitResult<Self::FenceData>> {
        if job.job.stream.is_empty() {
            fence.signal(Ok(()));
            return Ok(SubmitResult::Submitted);
        }

        if job.job.stream.len() > self.data.ringbuf.vmap().size() {
            fence.signal(Err(ENOSPC));
            return Err(ENOSPC);
        }

        if let Err(err) = self.data.can_append(job.job.stream.len()) {
            if err == ENOSPC {
                return Ok(SubmitResult::NoResources(fence));
            }

            fence.signal(Err(err));
            return Err(err);
        }

        if let Err(err) = self.data.reserve_pending_submit_fence() {
            fence.signal(Err(err));
            return Err(err);
        }

        let completion_point = match self.data.append_instrs(&job.job.stream) {
            Ok(completion_point) => completion_point,
            Err(err) => {
                fence.signal(Err(err));
                return Err(err);
            }
        };

        job.job.set_completion_point(completion_point);

        if let Err((err, fence)) = self.data.add_pending_submit_fence(completion_point, fence) {
            fence.signal(Err(err));
            return Err(err);
        }

        // Decide bound-vs-unbound under the group's inner mutex and
        // ring the doorbell while still holding it. The publish side
        // (`Scheduler::program_csg_activate`) and the clear side
        // (`CsgSlotOps::evict`) both update `csg_id` and the per-queue
        // `doorbell_id` together under the same lock, so observing
        // `csg_id == Some(_)` here guarantees `doorbell_id` is still
        // assigned for the entire kick. Without the lock-spanning
        // kick, a concurrent eviction could clear `doorbell_id`
        // between the bound test and the MMIO write, surfacing
        // `EINVAL` on already-committed ringbuf bytes that will
        // execute as soon as the queue rebinds. The locked window is
        // one MMIO doorbell write: no `GFP_KERNEL` allocation, no
        // `dma_resv_lock`, no `mmu_notifier` path.
        let group = &job.job.group;
        let (bound, kick_err) = group.with_locked_inner(|inner| {
            if inner.csg_id.is_none() {
                return (false, Ok(()));
            }
            let kick_res = self.data.kick();
            (true, kick_res)
        });

        if bound {
            if let Err(err) = kick_err {
                self.data.signal_submit_fence(completion_point, Err(err));
                return Err(err);
            }
        } else {
            // Group is unbound. Mark it runnable so the rule engine sees
            // it on the tick scheduled below.
            if let Err(err) = group.tdev.with_locked_scheduler(|sched| {
                sched.mark_group_runnable(group);
                Ok(())
            }) {
                self.data.signal_submit_fence(completion_point, Err(err));
                return Err(err);
            }
            TyrDrmDeviceData::schedule_tick(&group.tdev);
        }

        Ok(SubmitResult::Submitted)
    }
}

struct QueueCompletionStage {
    data: Arc<QueueData>,
    poll_interval: Jiffies,
    timeout: Jiffies,
}

impl StageOps<TyrQueueOps> for QueueCompletionStage {
    fn process(&self, ctx: &StageContext<'_, TyrQueueOps>) -> StageAdvance {
        if ctx.submit_fence.is_signaled() {
            return StageAdvance::Advance;
        }

        if let Err(err) = self.data.complete_submit_fences() {
            if let Some(completion_point) = ctx.job.completion_point() {
                self.data.signal_submit_fence(completion_point, Err(err));
            }
            return StageAdvance::TimedOut(err);
        }

        if ctx.submit_fence.is_signaled() {
            return StageAdvance::Advance;
        }

        let elapsed = msecs_to_jiffies(ctx.stage_elapsed().as_millis().max(0) as u32);
        if elapsed >= self.timeout {
            pr_err!("Tyr queue job {} timed out\n", ctx.counter);
            if let Some(completion_point) = ctx.job.completion_point() {
                self.data
                    .signal_submit_fence(completion_point, Err(ETIMEDOUT));
            }
            return StageAdvance::TimedOut(ETIMEDOUT);
        }

        StageAdvance::WaitFor(self.poll_interval)
    }

    fn teardown(&self, job: &QueueJob, _counter: u64) {
        if let Some(completion_point) = job.completion_point() {
            self.data.signal_submit_fence(
                completion_point,
                Err(Error::from_errno(-(bindings::ECANCELED as i32))),
            );
        }
    }
}

pub(super) type PreparedQueueJob = PreparedJob<TyrQueueOps>;

#[derive(Default)]
pub(super) struct QueueFenceData;

#[vtable]
impl DriverDmaFenceOps for QueueFenceData {
    fn driver_name(&self) -> &'static CStr {
        c"tyr"
    }

    fn timeline_name(&self) -> &'static CStr {
        c"tyr_queue"
    }
}

pub(super) struct QueueJob {
    stream: KVec<u8>,
    completion_point: Atomic<u64>,
    /// Back-reference to the owning group; used by
    /// `TyrQueueOps::submit` to reach the scheduler workqueue when
    /// no CSG doorbell has been assigned to the queue yet.
    pub(super) group: Arc<Group>,
}

impl QueueJob {
    pub(super) fn new(stream: KVec<u8>, group: Arc<Group>) -> Self {
        Self {
            stream,
            completion_point: Atomic::new(0),
            group,
        }
    }

    fn completion_point(&self) -> Option<u64> {
        match self.completion_point.load(Acquire) {
            0 => None,
            completion_point => Some(completion_point),
        }
    }

    fn set_completion_point(&self, completion_point: u64) {
        self.completion_point.store(completion_point, Release);
    }
}

/// Per-queue snapshot of the active GPU sync-wait. Populated when the
/// firmware reports `BlockedReason::SyncWait` for the queue's CS.
///
/// A `gpu_va` of `0` is the sentinel for "no active wait captured"
/// and is the value the field holds at queue creation and after a
/// successful unblock.
///
/// `cached` carries a BO resolution from a prior evaluation. It
/// stores its own `(gpu_va, sync64)` so the next evaluation can
/// detect when the live wait has moved on and rebuild rather than
/// read from a stale BO.
#[derive(Default, Clone)]
pub(crate) struct SyncWait {
    /// GPU virtual address of the awaited sync object. `0` means no
    /// active wait is currently captured.
    pub(crate) gpu_va: u64,
    /// Reference value the wait compares against.
    pub(crate) ref_val: u64,
    /// Whether the awaited sync object is 64-bit (`true`) or 32-bit.
    pub(crate) sync64: bool,
    /// Wait condition: `true` for `>` (Gt), `false` for `<=` (Le).
    pub(crate) gt: bool,
    /// Memoized BO resolution from a prior evaluation, keyed by its
    /// own `(gpu_va, sync64)`.
    ///
    /// Only populated when the awaited sync object lives in a
    /// userspace-mapped BO reached via `Vm::get_bo_for_va`. Sync
    /// waits targeting the group's own per-queue syncobjs pool do
    /// not allocate this cache.
    pub(crate) cached: Option<CachedBo>,
}

/// Memoized BO resolution for a foreign-BO sync-wait. Keyed by its
/// own `(gpu_va, sync64)` so an evaluation against a wait whose live
/// `(gpu_va, sync64)` no longer matches falls through to a fresh
/// gpuvm walk instead of reading from a stale BO.
#[derive(Clone)]
pub(crate) struct CachedBo {
    pub(crate) gpu_va: u64,
    pub(crate) sync64: bool,
    pub(crate) bo: Arc<gem::BoVmap>,
    pub(crate) offset: usize,
}

struct PendingSubmitFence {
    completion_point: u64,
    fence: DriverDmaFence<QueueFenceData, Published>,
}

/// A minimal hardware queue object owned by a scheduling group.
pub(crate) struct Queue {
    data: Arc<QueueData>,
    job_queue: JobQueue<TyrQueueOps>,
}

impl Queue {
    pub(crate) fn new(
        tdev: &TyrDrmDevice,
        reg_data: &TyrDrmRegistrationData<'_>,
        queue_args: &QueueCreate,
        vm: Arc<Vm>,
    ) -> Result<Self> {
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let ringbuf = gem::new_kernel_object(
            reg_data.pdev.as_ref(),
            tdev,
            &vm,
            queue_args.ringbuf_size() as usize,
            flags,
            tdev.coherent,
            tdev.cleanup_wq.clone(),
        )?;
        let iface_mem = reg_data.fw.alloc_queue_mem(tdev)?;
        let interfaces = Interfaces::new(iface_mem)?;

        let data = Arc::pin_init(
            pin_init!(QueueData {
                priority: queue_args.priority(),
                ringbuf,
                interfaces,
                doorbell_id: Atomic::new(UNASSIGNED_DOORBELL_ID),
                next_seqno: Atomic::new(0),
                iomem: reg_data.iomem.clone(),
                pending_submit_fences <- new_mutex!(KVec::new()),
                last_submit_fence <- new_mutex!(None),
                syncwait <- new_mutex!(SyncWait::default()),
            }),
            GFP_KERNEL,
        )?;

        let pipeline = PipelineBuilder::new()
            .set_cancel_timeout(msecs_to_jiffies(JOB_TIMEOUT_MS))
            .add_stage(QueueCompletionStage {
                data: data.clone(),
                poll_interval: msecs_to_jiffies(JOB_POLL_INTERVAL_MS),
                timeout: msecs_to_jiffies(JOB_TIMEOUT_MS),
            })?;
        let job_queue = JobQueue::new(
            TyrQueueOps { data: data.clone() },
            reg_data.wq.clone(),
            reg_data.wq.clone(),
            pipeline,
        )?;

        Ok(Self { data, job_queue })
    }

    pub(super) fn prepare_job(
        &self,
        job: QueueJob,
        deps: &[ARef<PublicDmaFence>],
        extra_dep_capacity: usize,
    ) -> Result<PreparedQueueJob> {
        self.job_queue
            .prepare(job, deps, extra_dep_capacity, QueueFenceData)
    }

    pub(super) fn commit_job(&self, prepared: PreparedQueueJob) -> ARef<PublicDmaFence> {
        let submit_fence = self.job_queue.commit(prepared);
        *self.data.last_submit_fence.lock() = Some(submit_fence.clone());
        submit_fence
    }
}

impl Deref for Queue {
    type Target = QueueData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

/// Firmware layout of the queue input block.
#[repr(C)]
pub(super) struct RingBufferInput {
    insert: u64,
    extract_init: u64,
}

impl RingBufferInput {
    const INSERT: usize = core::mem::offset_of!(Self, insert);
    const EXTRACT_INIT: usize = core::mem::offset_of!(Self, extract_init);
}

/// Firmware layout of the queue output block. It stops at `extract`,
/// since the driver never reads the word that follows.
#[repr(C)]
pub(super) struct RingBufferOutput {
    extract: u64,
}

impl RingBufferOutput {
    const EXTRACT: usize = core::mem::offset_of!(Self, extract);
}

/// The firmware-owned input and output blocks of a single queue.
pub(crate) struct Interfaces {
    mem: Arc<gem::MappedBo>,
    #[expect(dead_code)]
    pub(super) input_va: Range<u64>,
    #[expect(dead_code)]
    pub(super) output_va: Range<u64>,
    input_offset: usize,
    output_offset: usize,
}

impl Interfaces {
    fn new(mem: Arc<gem::MappedBo>) -> Result<Self> {
        let input_va = mem.kernel_va().ok_or(EINVAL)?;
        let output_start = input_va.start + SZ_4K as u64;
        let output_va = output_start..(output_start + SZ_4K as u64);

        Ok(Self {
            mem,
            input_va,
            output_va,
            input_offset: 0,
            output_offset: SZ_4K,
        })
    }

    pub(super) fn read_input(&self) -> Result<RingBufferInput> {
        let vmap = self.mem.vmap();

        Ok(RingBufferInput {
            insert: vmap.try_read64(self.input_offset + RingBufferInput::INSERT)?,
            extract_init: vmap.try_read64(self.input_offset + RingBufferInput::EXTRACT_INIT)?,
        })
    }

    pub(super) fn write_input(&self, value: RingBufferInput) -> Result {
        let vmap = self.mem.vmap();

        vmap.try_write64(
            value.extract_init,
            self.input_offset + RingBufferInput::EXTRACT_INIT,
        )?;
        vmap.try_write64(value.insert, self.input_offset + RingBufferInput::INSERT)
    }

    pub(super) fn read_output(&self) -> Result<RingBufferOutput> {
        Ok(RingBufferOutput {
            extract: self
                .mem
                .vmap()
                .try_read64(self.output_offset + RingBufferOutput::EXTRACT)?,
        })
    }
}
