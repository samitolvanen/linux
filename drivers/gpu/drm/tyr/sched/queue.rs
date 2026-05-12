// SPDX-License-Identifier: GPL-2.0 or MIT

use core::{
    ops::{Deref, Range},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use kernel::{
    alloc::KVec,
    c_str,
    dma_buf::dma_fence::{
        DmaFenceSignallingAnnotation, DmaFenceWorkqueue, DriverDmaFence, DriverDmaFenceOps,
        PublicDmaFence, Published,
    },
    drm::{
        gem::BaseObject,
        job_queue::{
            JobQueue, JobQueueLockClasses, JobRef, PipelineBuilder, PreparedJob, QueueOps,
            StageAdvance, StageContext, StageOps, SubmitResult,
        },
    },
    io::register::Array,
    io::Io,
    new_mutex,
    prelude::*,
    sizes::SZ_4K,
    sizes::SZ_64K,
    sync::{aref::ARef, Arc, LockClassKey, Mutex},
    time::{msecs_to_jiffies, Jiffies},
    transmute::FromBytes,
    uapi,
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    fw::global::CsActivateInputs,
    gem,
    regs::doorbell_block,
    vm::{Vm, VmFlag, VmMapFlags},
};

use super::group::Group;

const UNASSIGNED_DOORBELL_ID: usize = usize::MAX;
const JOB_POLL_INTERVAL_MS: u32 = 1;
const JOB_TIMEOUT_MS: u32 = 5000;

static TYR_QUEUE_INBOX_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_STATE_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_CLEANUP_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_STAGE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_STAGE_TIMER_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
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

#[derive(Default)]
pub(super) struct QueueFenceData;

#[vtable]
impl DriverDmaFenceOps for QueueFenceData {
    fn driver_name(&self) -> &'static CStr {
        c_str!("tyr")
    }

    fn timeline_name(&self) -> &'static CStr {
        c_str!("tyr_queue")
    }
}

struct PendingSubmitFence {
    completion_point: u64,
    fence: DriverDmaFence<QueueFenceData, Published>,
}

/// Per-queue snapshot of the active GPU sync-wait. Populated when the
/// firmware reports `BlockedReason::SyncWait` for the queue's CS.
///
/// A `gpu_va` of `0` is the sentinel for "no active wait captured"
/// and is the value the field holds at queue creation and after a
/// successful unblock.
///
/// `cached` carries a BO resolution from a prior evaluation; it
/// stores its own `(gpu_va, sync64)` so the next evaluation can
/// detect when the live wait has moved on and rebuild rather than
/// read from a stale BO. Leaving the cache untouched in the
/// firmware-update path keeps the eventual `Arc<gem::MappedUserBo>` drop
/// out of the dma-fence signalling section that wraps that path; the
/// drop happens via the sync-update worker instead.
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
    /// Memoised BO resolution from a prior evaluation, keyed by its
    /// own `(gpu_va, sync64)`.
    ///
    /// Only populated when the awaited sync object lives in a
    /// userspace-mapped BO reached via [`Vm::get_bo_for_va`]; sync
    /// waits targeting the group's own per-queue syncobjs pool do
    /// not allocate this cache.
    ///
    /// [`Vm::get_bo_for_va`]: crate::vm::Vm::get_bo_for_va
    pub(crate) cached: Option<CachedBo>,
}

/// Memoised BO resolution for a foreign-BO sync-wait. Keyed by its
/// own `(gpu_va, sync64)` so an evaluation against a wait whose live
/// `(gpu_va, sync64)` no longer matches falls through to a fresh
/// gpuvm walk instead of reading from a stale BO.
#[derive(Clone)]
pub(crate) struct CachedBo {
    pub(crate) gpu_va: u64,
    pub(crate) sync64: bool,
    pub(crate) bo: Arc<gem::MappedUserBo>,
    pub(crate) offset: usize,
}

pub(super) struct QueueJob {
    stream: KVec<u8>,
    completion_point: AtomicU64,
    /// Back-reference to the owning group; used by
    /// [`TyrQueueOps::submit`] to reach the scheduler workqueue when
    /// no CSG doorbell has been assigned to the queue yet.
    pub(super) group: Arc<Group>,
}

impl QueueJob {
    pub(super) fn new(stream: KVec<u8>, group: Arc<Group>) -> Self {
        Self {
            stream,
            completion_point: AtomicU64::new(0),
            group,
        }
    }

    fn completion_point(&self) -> Option<u64> {
        match self.completion_point.load(Ordering::Acquire) {
            0 => None,
            completion_point => Some(completion_point),
        }
    }

    fn set_completion_point(&self, completion_point: u64) {
        self.completion_point
            .store(completion_point, Ordering::Release);
    }
}

#[pin_data]
pub(crate) struct QueueData {
    priority: u8,
    ringbuf: Arc<gem::MappedBo>,
    interfaces: Interfaces,
    doorbell_id: AtomicUsize,
    next_seqno: AtomicU64,
    iomem: Arc<kernel::devres::Devres<IoMem>>,
    #[pin]
    pending_submit_fences: Mutex<KVec<PendingSubmitFence>>,
    /// Active GPU sync-wait captured for this queue. The `Default`
    /// value (`gpu_va == 0`) means no wait is currently active.
    #[pin]
    syncwait: Mutex<SyncWait>,
}

impl QueueData {
    fn ringbuf_space_for(&self, instr_count: usize) -> Result<RingBufferInput> {
        let ringbuf_input = self.interfaces.read_input()?;
        let ringbuf_sz = self.ringbuf.size() as u64;
        let ringbuf_output = self.interfaces.read_output()?;
        let used = ringbuf_input
            .insert
            .checked_sub(ringbuf_output.extract)
            .ok_or(EIO)?;

        if instr_count as u64 > ringbuf_sz {
            return Err(ENOSPC);
        }

        if used > ringbuf_sz || instr_count as u64 > ringbuf_sz - used {
            return Err(ENOSPC);
        }

        Ok(ringbuf_input)
    }

    fn doorbell_id(&self) -> Option<usize> {
        let doorbell_id = self.doorbell_id.load(Ordering::Relaxed);

        if doorbell_id == UNASSIGNED_DOORBELL_ID {
            None
        } else {
            Some(doorbell_id)
        }
    }

    pub(super) fn set_doorbell_id(&self, doorbell_id: Option<usize>) {
        self.doorbell_id.store(
            doorbell_id.unwrap_or(UNASSIGNED_DOORBELL_ID),
            Ordering::Relaxed,
        );
    }

    pub(super) fn can_append(&self, instr_count: usize) -> Result {
        self.ringbuf_space_for(instr_count)?;
        Ok(())
    }

    /// Claims `n` consecutive seqnos in a single atomic step and returns
    /// the highest one claimed.
    pub(super) fn claim_seqnos(&self, n: usize) -> u64 {
        self.next_seqno.fetch_add(n as u64, Ordering::Relaxed) + n as u64
    }

    /// Returns the highest seqno claimed so far on this queue.
    pub(crate) fn next_seqno(&self) -> u64 {
        self.next_seqno.load(Ordering::Relaxed)
    }

    /// Copies `instrs` into the ringbuffer at the current `INSERT`. The
    /// returned completion point is the `INSERT` value
    /// [`Self::commit_ringbuf_range`] will publish once the caller has
    /// registered the matching pending submit fence.
    pub(super) fn claim_ringbuf_range(&self, instrs: &[u8]) -> Result<u64> {
        let ringbuf_input = self.ringbuf_space_for(instrs.len())?;
        let ringbuf_sz = self.ringbuf.size() as u64;

        let ringbuf_start = ringbuf_input.insert;
        let cs_insert = (ringbuf_start & (ringbuf_sz - 1)) as usize;

        let ringbuf = self.ringbuf.vmap();
        let size = ringbuf.owner().size();
        // SAFETY: `ringbuf` owns a writable CPU mapping for the queue ring buffer
        // and `size` matches the mapped object size.
        let bytes = unsafe { core::slice::from_raw_parts_mut(ringbuf.addr() as *mut u8, size) };

        let first_chunk = core::cmp::min(size - cs_insert, instrs.len());
        bytes[cs_insert..cs_insert + first_chunk].copy_from_slice(&instrs[..first_chunk]);
        if first_chunk < instrs.len() {
            bytes[..instrs.len() - first_chunk].copy_from_slice(&instrs[first_chunk..]);
        }

        let completion_point = ringbuf_start + instrs.len() as u64;
        Ok(completion_point)
    }

    /// Publishes a previously claimed ringbuffer range to the firmware.
    ///
    /// `completion_point` must equal the value returned from the matching
    /// [`Self::claim_ringbuf_range`]. The leading `wmb()` orders the prior
    /// byte-copy into the firmware-shared ringbuffer before the `INSERT`
    /// write; the trailing `wmb()` orders the `INSERT` write before the
    /// doorbell ring that follows. Both barriers use the full `wmb()`
    /// rather than `smp_wmb()` because the ringbuffer and input pages are
    /// observed by the GPU firmware: `smp_wmb()` only orders CPU-visible
    /// stores on coherent memory, whereas `wmb()` additionally drains
    /// write-combining buffers so the writes become visible to the
    /// external agent.
    pub(super) fn commit_ringbuf_range(&self, completion_point: u64) -> Result {
        kernel::sync::barrier::wmb();

        let mut ringbuf_input = self.interfaces.read_input()?;
        let ringbuf_output = self.interfaces.read_output()?;
        ringbuf_input.extract_init = ringbuf_output.extract;
        ringbuf_input.insert = completion_point;

        self.interfaces.write_input(ringbuf_input)?;
        kernel::sync::barrier::wmb();
        Ok(())
    }

    pub(super) fn kick(&self) -> Result {
        let io = self.iomem.try_access().ok_or(EINVAL)?;
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
    /// The fences are left in the pending list; the regular seqno-ordered
    /// drain in [`Self::complete_pending_fences_up_to`] will signal them
    /// at their natural completion points so waiters still observe a
    /// monotonic submit-order signal sequence.
    ///
    /// Safe to call from inside a [`DmaFenceSignallingAnnotation`] section.
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
    /// its own `(gpu_va, sync64)`; `Group::eval_syncwait` detects
    /// when the live wait has moved to a different key and rebuilds.
    /// Leaving the cache untouched here keeps the eventual
    /// `Arc<gem::MappedUserBo>` drop out of the dma-fence signalling
    /// annotation that wraps this caller; the drop happens in
    /// `eval_syncwait`'s rebuild or `take_syncwait_bo` path, both of
    /// which run from the sync-update worker on `system_unbound()`.
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
    /// that would later be read with the wrong type. Any previously
    /// stored `CachedBo` is dropped here, which is safe because the
    /// caller runs from the sync-update worker, outside any dma-fence
    /// signalling annotation. Returns `true` if the cache was applied.
    pub(crate) fn cache_syncwait_bo(
        &self,
        gpu_va: u64,
        sync64: bool,
        bo: Arc<gem::MappedUserBo>,
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
    ///
    /// Must not be called from a dma-fence signalling section: the
    /// returned value's drop acquires `dma_resv_lock`.
    pub(crate) fn take_syncwait_bo(&self) -> Option<Arc<gem::MappedUserBo>> {
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

    /// Synchronises the queue's `input.extract_init` from the firmware's
    /// current `output.extract` value.
    ///
    /// Mirrors Panthor's `cs_slot_prog_locked` invariant: must be
    /// called before staging `CS_REQ.state = Start` at CSG-bind time
    /// so the firmware sees a consistent `(insert, extract_init)`
    /// snapshot when it starts reading the per-queue ringbuf mailbox.
    ///
    /// The read-modify-write preserves `insert`: only `extract_init`
    /// is updated. This matches Panthor, which writes
    /// `queue->iface.input->extract = queue->iface.output->extract`
    /// and leaves `insert` untouched.
    pub(crate) fn sync_extract_init(&self) -> Result {
        let ringbuf_output = self.interfaces.read_output()?;
        let mut ringbuf_input = self.interfaces.read_input()?;
        ringbuf_input.extract_init = ringbuf_output.extract;
        self.interfaces.write_input(ringbuf_input)?;
        Ok(())
    }

    /// Builds the [`CsActivateInputs`] needed to program this queue's
    /// CS slot at CSG-bind time.
    ///
    /// `doorbell_id` is the per-CS doorbell index assigned by the
    /// caller (in practice `slot_idx + 1`).
    pub(crate) fn cs_activate_inputs(&self, doorbell_id: u32) -> Result<CsActivateInputs> {
        Ok(CsActivateInputs {
            ringbuf_base: self.ringbuf.kernel_va().ok_or(EINVAL)?.start,
            ringbuf_size: self.ringbuf.size() as u32,
            ringbuf_input_va: self.interfaces.input_va.start,
            ringbuf_output_va: self.interfaces.output_va.start,
            priority: self.priority,
            doorbell_id,
        })
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

        if job.job.stream.len() as u64 > self.data.ringbuf.size() as u64 {
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

        let completion_point = match self.data.claim_ringbuf_range(&job.job.stream) {
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

        if let Err(err) = self.data.commit_ringbuf_range(completion_point) {
            self.data.signal_submit_fence(completion_point, Err(err));
            return Err(err);
        }

        // Decide bound-vs-unbound under the group's inner mutex and
        // ring the doorbell while still holding it. The publish side
        // (`CsgSlotOps::activate`) and the clear side
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
            // Group is unbound; mark it runnable so the rule engine sees
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
            self.data
                .signal_submit_fence(completion_point, Err(ECANCELED));
        }
    }
}

pub(super) type PreparedQueueJob = PreparedJob<TyrQueueOps>;

/// A minimal hardware queue object owned by a scheduling group.
pub(crate) struct Queue {
    data: Arc<QueueData>,
    job_queue: JobQueue<TyrQueueOps>,
}

impl Queue {
    pub(crate) fn new(tdev: &TyrDrmDevice, queue_args: &QueueCreate, vm: Arc<Vm>) -> Result<Self> {
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let ringbuf = gem::new_kernel_object(tdev, &vm, queue_args.ringbuf_size() as usize, flags)?;
        let iface_mem = tdev.fw.alloc_queue_mem(tdev)?;
        let interfaces = Interfaces::new(iface_mem)?;

        let data = Arc::pin_init(
            pin_init!(QueueData {
                priority: queue_args.priority(),
                ringbuf,
                interfaces,
                doorbell_id: AtomicUsize::new(UNASSIGNED_DOORBELL_ID),
                next_seqno: AtomicU64::new(0),
                iomem: tdev.iomem.clone(),
                pending_submit_fences <- new_mutex!(KVec::new()),
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
            tdev.wq.clone(),
            tdev.wq.clone(),
            pipeline,
        )?;

        Ok(Self { data, job_queue })
    }

    pub(super) fn prepare_job(
        &self,
        job: QueueJob,
        deps: &[ARef<PublicDmaFence>],
    ) -> Result<PreparedQueueJob> {
        self.job_queue.prepare(job, deps, QueueFenceData)
    }

    pub(super) fn commit_job(&self, prepared: PreparedQueueJob) -> ARef<PublicDmaFence> {
        self.job_queue.commit(prepared)
    }

    /// Cancels every job tracked by this queue and signals all
    /// remaining pending submit fences with `err`.
    ///
    /// Must be called from process context: `cancel_all` may sleep
    /// waiting for in-flight HW fences.
    pub(crate) fn cancel(&self, err: Error) {
        self.job_queue.cancel_all();
        self.data.signal_submit_fences_up_to(u64::MAX, Err(err));
    }
}

impl Deref for Queue {
    type Target = QueueData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

#[allow(dead_code)]
#[repr(C)]
pub(super) struct RingBufferInput {
    insert: u64,
    extract_init: u64,
}

#[allow(dead_code)]
#[repr(C)]
pub(super) struct RingBufferOutput {
    extract: u64,
    active: u32,
}

pub(crate) struct Interfaces {
    mem: Arc<gem::MappedBo>,
    #[allow(dead_code)]
    pub(super) input_va: Range<u64>,
    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub(super) fn read_input(&self) -> Result<RingBufferInput> {
        let vmap = self.mem.vmap();
        // SAFETY: `input_offset` selects the queue input structure inside the
        // writable CPU mapping owned by `mem`.
        let input = unsafe {
            (vmap.addr() as *mut u8)
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .read_volatile()
        };

        Ok(input)
    }

    #[allow(dead_code)]
    pub(super) fn write_input(&self, value: RingBufferInput) -> Result {
        let vmap = self.mem.vmap();

        // SAFETY: `input_offset` selects the queue input structure inside the
        // writable CPU mapping owned by `mem`.
        unsafe {
            (vmap.addr() as *mut u8)
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .write_volatile(value)
        };

        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn read_output(&self) -> Result<RingBufferOutput> {
        let vmap = self.mem.vmap();
        // SAFETY: `output_offset` selects the queue output structure inside the
        // writable CPU mapping owned by `mem`.
        let output = unsafe {
            (vmap.addr() as *mut u8)
                .add(self.output_offset)
                .cast::<RingBufferOutput>()
                .read_volatile()
        };

        Ok(output)
    }
}
