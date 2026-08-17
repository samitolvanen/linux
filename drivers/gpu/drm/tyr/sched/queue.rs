// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::{
    Deref,
    Range, //
};

use kernel::{
    alloc::KVec,
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
            Atomic,
            Relaxed, //
        },
        barrier::{
            mb,
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
    fw::global::CsActivateInputs,
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

    /// Claims `n` consecutive seqnos in a single atomic step and returns
    /// the highest one claimed.
    pub(super) fn claim_seqnos(&self, n: usize) -> u64 {
        self.next_seqno.fetch_add(n as u64, Relaxed) + n as u64
    }

    /// Returns the highest seqno claimed so far on this queue.
    pub(crate) fn next_seqno(&self) -> u64 {
        self.next_seqno.load(Relaxed)
    }

    /// Copies `instrs` into the ringbuffer at the current `INSERT`. The
    /// returned completion point is the `INSERT` value
    /// `Self::commit_ringbuf_range` will publish once the caller has
    /// registered the matching pending submit fence.
    pub(super) fn claim_ringbuf_range(&self, instrs: &[u8]) -> Result<u64> {
        let ringbuf_input = self.ringbuf_space_for(instrs.len())?;

        let ringbuf = self.ringbuf.vmap();
        let size = ringbuf.size();

        let ringbuf_start = ringbuf_input.insert;
        let cs_insert = (ringbuf_start & (size as u64 - 1)) as usize;

        let first_chunk = core::cmp::min(size - cs_insert, instrs.len());
        let dst = ringbuf.as_view().as_ptr().cast::<u8>();
        // SAFETY: `dst` is the writable CPU mapping of the ring buffer, valid
        // for `size` bytes, and `instrs` is a separate allocation. The mask
        // puts `cs_insert` below `size`, and `first_chunk` is at most
        // `size - cs_insert`, putting the first copy inside the mapping.
        // `ringbuf_space_for` rejects an append larger than the ring, so the
        // wrapped remainder `instrs.len() - first_chunk` is at most `size`.
        unsafe {
            core::ptr::copy_nonoverlapping(instrs.as_ptr(), dst.add(cs_insert), first_chunk);
            core::ptr::copy_nonoverlapping(
                instrs.as_ptr().add(first_chunk),
                dst,
                instrs.len() - first_chunk,
            );
        }

        let completion_point = ringbuf_start + instrs.len() as u64;
        Ok(completion_point)
    }

    /// Publishes a previously claimed ringbuffer range to the firmware.
    ///
    /// `completion_point` must equal the value returned from the matching
    /// `claim_ringbuf_range`. The leading `mb(Write)` orders the ringbuffer
    /// writes before the `INSERT` write. The trailing `mb(Write)` orders `INSERT`
    /// before the doorbell ring.
    pub(super) fn commit_ringbuf_range(&self, completion_point: u64) -> Result {
        mb(Write);

        let mut ringbuf_input = self.interfaces.read_input()?;
        let ringbuf_output = self.interfaces.read_output()?;
        ringbuf_input.extract_init = ringbuf_output.extract;
        ringbuf_input.insert = completion_point;

        self.interfaces.write_input(ringbuf_input)?;
        mb(Write);
        Ok(())
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
        done_seqno: u64,
        fence: DriverDmaFence<QueueFenceData, Published>,
    ) -> core::result::Result<(), (Error, DriverDmaFence<QueueFenceData, Published>)> {
        let pending_fence = PendingSubmitFence { done_seqno, fence };

        match self
            .pending_submit_fences
            .lock()
            .push_within_capacity(pending_fence)
        {
            Ok(()) => Ok(()),
            Err(err) => Err((EINVAL, err.0.fence)),
        }
    }

    fn signal_submit_fences_up_to(&self, up_to_seqno: u64, result: Result) {
        loop {
            let pending_fence = {
                let mut pending = self.pending_submit_fences.lock();

                match pending.first() {
                    Some(pending_fence) if pending_fence.done_seqno <= up_to_seqno => {
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

    /// Drains every leading entry of `pending_submit_fences` whose
    /// `done_seqno` is `<= up_to_seqno` into a local vec, then
    /// signals each drained fence with `Ok(())` with no driver lock
    /// held.
    fn complete_pending_fences_up_to(&self, up_to_seqno: u64) {
        let drained = {
            let mut pending = self.pending_submit_fences.lock();

            let mut k = 0usize;
            for entry in pending.iter() {
                if entry.done_seqno > up_to_seqno {
                    break;
                }
                k += 1;
            }

            let mut drained = match KVec::with_capacity(k, GFP_KERNEL) {
                Ok(v) => v,
                Err(_) => {
                    pr_err!("Tyr queue: drain allocation failed; deferring drain\n");
                    return;
                }
            };

            // Reverse once so the leading prefix is at the tail. Pop
            // returns the original head-first sequence in O(1) each.
            // Reverse the surviving suffix back after the pop loop.
            pending.reverse();
            for _ in 0..k {
                let Some(entry) = pending.pop() else {
                    break;
                };
                let _ = drained.push_within_capacity(entry);
            }
            pending.reverse();

            drained
        };

        for pending_fence in drained.into_iter() {
            let _annotation = DmaFenceSignallingAnnotation::new();
            pending_fence.fence.signal(Ok(()));
        }
    }

    fn signal_submit_fence(&self, done_seqno: u64, result: Result) -> bool {
        let pending_fence = {
            let mut pending = self.pending_submit_fences.lock();
            let mut position = None;

            for (index, pending_fence) in pending.iter().enumerate() {
                if pending_fence.done_seqno == done_seqno {
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

    /// Signals every leading pending submit fence whose stored
    /// `done_seqno` is at or below `syncobj_seqno`, which the caller
    /// reads with `Group::read_syncobj`.
    ///
    /// The syncobj is the completion gate rather than the firmware's
    /// `EXTRACT` pointer. Each wrapper bumps it only after
    /// `WAIT(all scoreboards)`, so every async sub-job the piece
    /// dispatched has landed. `EXTRACT` would race them.
    ///
    /// Used by both `QueueCompletionStage::process` (its progress-poll
    /// path) and the IRQ-driven completion path on the scheduler
    /// side.
    pub(in crate::sched) fn complete_submit_fences(&self, syncobj_seqno: u64) {
        self.complete_pending_fences_up_to(syncobj_seqno);
    }

    /// Stages `err` on every pending submit fence whose `done_seqno`
    /// is strictly past `syncobj_seqno`, i.e. submissions whose
    /// `SYNC_ADD64` the firmware has not yet retired.
    ///
    /// The caller is expected to pass the value of the per-queue
    /// syncobj, read with `Group::read_syncobj`. The fences are left
    /// in the pending list. The regular seqno-ordered drain in
    /// `Self::complete_pending_fences_up_to` will signal them at
    /// their natural completion points so waiters still observe a
    /// monotonic submit-order signal sequence.
    ///
    /// Safe to call from inside a `DmaFenceSignallingAnnotation` section.
    pub(in crate::sched) fn fail_inflight_submit_fences(&self, syncobj_seqno: u64, err: Error) {
        let mut pending = self.pending_submit_fences.lock();
        for entry in pending.iter_mut() {
            if entry.done_seqno > syncobj_seqno {
                entry.fence.set_error(err);
            }
        }
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

    /// Synchronizes the queue's `input.extract_init` from the firmware's
    /// current `output.extract` value.
    ///
    /// Must be called before staging `CS_REQ.state = Start` at CSG-bind
    /// time so the firmware sees a consistent `(insert, extract_init)`
    /// snapshot when it starts reading the per-queue ringbuf mailbox.
    ///
    /// The read-modify-write preserves `insert` and updates only
    /// `extract_init`.
    pub(crate) fn sync_extract_init(&self) -> Result {
        let ringbuf_output = self.interfaces.read_output()?;
        let mut ringbuf_input = self.interfaces.read_input()?;
        ringbuf_input.extract_init = ringbuf_output.extract;
        self.interfaces.write_input(ringbuf_input)?;
        Ok(())
    }

    /// Builds the `CsActivateInputs` needed to program this queue's
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

        let ringbuf_completion_point = match self.data.claim_ringbuf_range(&job.job.stream) {
            Ok(completion_point) => completion_point,
            Err(err) => {
                fence.signal(Err(err));
                return Err(err);
            }
        };

        let Some(done_seqno) = job.job.done_seqno() else {
            fence.signal(Err(EINVAL));
            return Err(EINVAL);
        };

        if let Err((err, fence)) = self.data.add_pending_submit_fence(done_seqno, fence) {
            fence.signal(Err(err));
            return Err(err);
        }

        if let Err(err) = self.data.commit_ringbuf_range(ringbuf_completion_point) {
            self.data.signal_submit_fence(done_seqno, Err(err));
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
                self.data.signal_submit_fence(done_seqno, Err(err));
                return Err(err);
            }
        } else {
            // Group is unbound. Mark it runnable so the rule engine sees
            // it on the tick scheduled below.
            if let Err(err) = group.tdev.with_locked_scheduler(|sched| {
                sched.mark_group_runnable(group);
                Ok(())
            }) {
                self.data.signal_submit_fence(done_seqno, Err(err));
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

        match ctx.job.group.read_syncobj(ctx.job.queue_index) {
            Ok(syncobj_seqno) => self.data.complete_submit_fences(syncobj_seqno),
            Err(err) => {
                if let Some(done_seqno) = ctx.job.done_seqno() {
                    self.data.signal_submit_fence(done_seqno, Err(err));
                }
                return StageAdvance::TimedOut(err);
            }
        }

        if ctx.submit_fence.is_signaled() {
            return StageAdvance::Advance;
        }

        let elapsed = msecs_to_jiffies(ctx.stage_elapsed().as_millis().max(0) as u32);
        if elapsed >= self.timeout {
            pr_err!("Tyr queue job {} timed out\n", ctx.counter);
            if let Some(done_seqno) = ctx.job.done_seqno() {
                self.data.signal_submit_fence(done_seqno, Err(ETIMEDOUT));
            }
            return StageAdvance::TimedOut(ETIMEDOUT);
        }

        StageAdvance::WaitFor(self.poll_interval)
    }

    fn teardown(&self, job: &QueueJob, _counter: u64) {
        if let Some(done_seqno) = job.done_seqno() {
            self.data.signal_submit_fence(done_seqno, Err(ECANCELED));
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
    /// Per-queue syncobj seqno value at which this job is complete.
    /// `Some(v)` for stream-bearing jobs; `None` for sync-only jobs
    /// that emit no `SYNC_ADD64` and thus do not advance the syncobj.
    /// Set at prepare time from `QueueData::claim_seqnos` so the
    /// submit and timeout paths can look up the matching pending
    /// fence by the same key the firmware's `SYNC_ADD64` will produce.
    done_seqno: Option<u64>,
    /// Back-reference to the owning group; used by
    /// `TyrQueueOps::submit` to reach the scheduler workqueue when
    /// no CSG doorbell has been assigned to the queue yet.
    pub(super) group: Arc<Group>,
    /// Index of the owning queue inside `Group::queues`. Captured
    /// at prepare time so the timeout stage can read the per-queue
    /// syncobj without an extra lookup.
    queue_index: usize,
}

impl QueueJob {
    pub(super) fn new(
        stream: KVec<u8>,
        done_seqno: Option<u64>,
        group: Arc<Group>,
        queue_index: usize,
    ) -> Self {
        Self {
            stream,
            done_seqno,
            group,
            queue_index,
        }
    }

    fn done_seqno(&self) -> Option<u64> {
        self.done_seqno
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
    /// Per-queue syncobj seqno value at or above which this fence is
    /// considered complete. Matches the highest seqno claimed by
    /// `QueueData::claim_seqnos` for the wrapped job. The firmware's
    /// `SYNC_ADD64` retires after the per-piece `WAIT(all scoreboards)`
    /// so the syncobj only reaches this value once every dispatched
    /// async sub-job has landed in memory.
    done_seqno: u64,
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

    /// Cancels every job tracked by this queue and signals all
    /// remaining pending submit fences with `err`.
    ///
    /// `cancel_all` may sleep waiting for in-flight hardware fences, so
    /// this must be called from process context.
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
    pub(super) input_va: Range<u64>,
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
