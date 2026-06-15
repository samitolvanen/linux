// SPDX-License-Identifier: GPL-2.0 or MIT

use core::{
    ops::{Deref, Range},
    sync::atomic::{
        AtomicBool,
        AtomicI64,
        AtomicU64,
        AtomicUsize,
        Ordering, //
    },
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
    time::{
        msecs_to_jiffies,
        Delta,
        Instant,
        Jiffies,
        Monotonic, //
    },
    transmute::FromBytes,
    uapi,
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice,
        TyrDrmDeviceData,
        DEVICE_PROFILING_CYCLES,
        DEVICE_PROFILING_TIMESTAMP, //
    },
    fw::global::CsActivateInputs,
    gem,
    regs::doorbell_block,
    vm::{Vm, VmFlag, VmMapFlags},
};

use super::group::{
    Group,
    State, //
};

const UNASSIGNED_DOORBELL_ID: usize = usize::MAX;
const JOB_TIMEOUT_MS: u32 = 5000;

/// Smallest ringbuffer byte count one wrapped job stream consumes.
///
/// `sched::job::build_wrapped_stream` emits 11 8-byte instructions per
/// piece and pads the concatenation up to a 64-byte boundary, so the
/// minimum is `next_multiple_of(88, 64) == 128`. Profiled wrappers are
/// larger, so this stays a lower bound. Used to size the pre-allocated
/// pending-fence vec so `Queue::reserve_pending_submit_fence` never
/// needs to allocate under the lock, and to bound the per-queue
/// profiling slot count.
const WRAPPER_RINGBUF_BYTES: usize = 128;

// SAFETY: todo
static TYR_QUEUE_INBOX_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
static TYR_QUEUE_STATE_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
static TYR_QUEUE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
static TYR_QUEUE_CLEANUP_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
static TYR_QUEUE_STAGE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
static TYR_QUEUE_STAGE_TIMER_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
// SAFETY: todo
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
    /// Per-queue syncobj seqno value at or above which this fence is
    /// considered complete. Matches the highest seqno claimed by
    /// `QueueData::claim_seqnos` for the wrapped job; the firmware's
    /// `SYNC_ADD64` retires after the per-piece `WAIT(all scoreboards)`
    /// so the syncobj only reaches this value once every dispatched
    /// async sub-job has landed in memory.
    done_seqno: u64,
    /// Profiling slot the wrapped stream sampled into, read back at
    /// completion to accumulate the group's GPU usage.
    profiling_slot: u32,
    /// Profiling flags the wrapped stream emitted samples for. `0` when
    /// profiling was disabled for this job.
    profiling_mask: u32,
    fence: Option<DriverDmaFence<QueueFenceData, Published>>,
}

/// State protected by the pending-submit-fences mutex.
///
/// `vec` carries the live ordered list of in-flight per-job fences.
/// `outstanding` counts reservations made by
/// `Queue::reserve_pending_submit_fence` whose `PendingFenceReservation`
/// guard has not yet been consumed or dropped.
///
/// Tracking `outstanding` separately is what makes multiple consecutive
/// reserves accumulate space. `KVec::reserve(additional)` only ensures
/// `capacity - len >= additional` at the moment of the call, so without
/// `outstanding` the second of two back-to-back reserves on an empty
/// vec would observe `capacity - len == 1` already, do nothing, and
/// the matching second push would fail `push_within_capacity` from
/// inside the dma-fence signalling section that wraps the submit path.
///
/// `head` is the cursor into `vec` past which entries are live: the
/// prefix `vec[..head]` is drained but not yet truncated and every
/// such entry has `fence == None`. The suffix `vec[head..]` is the
/// live ordered list; an entry inside it may still have `fence ==
/// None` if an error path already took the fence out, which is
/// treated as a hole and skipped on drain.
/// `Queue::maybe_truncate_pending` compacts the prefix away once
/// `head` exceeds `max(len / 2, 16)`.
///
/// `profiling_free` is a stack of profiling sample slots not currently
/// assigned to any job. A slot is popped when a profiled job reserves,
/// pushed back when its reservation drops unconsumed or when its
/// completed entry drains. Pre-sized to the slot count so the pop and
/// push never allocate.
struct PendingFences {
    vec: KVec<PendingSubmitFence>,
    head: usize,
    outstanding: usize,
    profiling_free: KVec<u32>,
}

/// RAII guard for a pending-submit-fence reservation.
///
/// `profiling_slot` is the sample slot popped from `profiling_free` for a
/// profiled job. The guard returns it on drop unless the reservation is
/// consumed, in which case the slot passes to the pending entry.
pub(in crate::sched) struct PendingFenceReservation {
    queue: Arc<QueueData>,
    consumed: AtomicBool,
    profiling_slot: Option<u32>,
}

impl PendingFenceReservation {
    fn new(queue: Arc<QueueData>, profiling_slot: Option<u32>) -> Self {
        Self {
            queue,
            consumed: AtomicBool::new(false),
            profiling_slot,
        }
    }

    /// The profiling sample slot held for this reservation, if any.
    pub(in crate::sched) fn profiling_slot(&self) -> Option<u32> {
        self.profiling_slot
    }

    /// Pushes `fence` into the queue's pending list, consuming this reservation.
    fn consume(
        &self,
        done_seqno: u64,
        profiling_mask: u32,
        fence: DriverDmaFence<QueueFenceData, Published>,
    ) -> Result<(), (Error, DriverDmaFence<QueueFenceData, Published>)> {
        let pending_fence = PendingSubmitFence {
            done_seqno,
            profiling_slot: self.profiling_slot.unwrap_or(0),
            profiling_mask,
            fence: Some(fence),
        };

        let mut pending = self.queue.pending_submit_fences.lock();
        match pending.vec.push_within_capacity(pending_fence) {
            Ok(()) => {
                pending.outstanding = pending.outstanding.saturating_sub(1);
                self.consumed.store(true, Ordering::Relaxed);
                Ok(())
            }
            Err(err) => match err.0.fence {
                Some(fence) => Err((EINVAL, fence)),
                None => {
                    pending.outstanding = pending.outstanding.saturating_sub(1);
                    self.consumed.store(true, Ordering::Relaxed);
                    Ok(())
                }
            },
        }
    }
}

impl Drop for PendingFenceReservation {
    fn drop(&mut self) {
        if *self.consumed.get_mut() {
            return;
        }
        let mut pending = self.queue.pending_submit_fences.lock();
        pending.outstanding = pending.outstanding.saturating_sub(1);
        if let Some(slot) = self.profiling_slot {
            let _ = pending.profiling_free.push_within_capacity(slot);
        }
    }
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
    /// Memoised BO resolution from a prior evaluation, keyed by its
    /// own `(gpu_va, sync64)`.
    ///
    /// Only populated when the awaited sync object lives in a
    /// userspace-mapped BO reached via `Vm::get_bo_for_va`; sync
    /// waits targeting the group's own per-queue syncobjs pool do
    /// not allocate this cache.
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
    /// Per-queue syncobj seqno at which this job is complete. Zero for a
    /// sync-only job that advances no syncobj. Claimed at commit time, the
    /// same key the firmware's `SYNC_ADD64` produces for the job.
    done_seqno: AtomicU64,
    /// Snapshot of `QueueData::suspend_snapshot` taken at submit
    /// time, folded with any in-flight suspend interval; subtracted
    /// from the queue's current accumulator by the timeout stage so a
    /// job is not faulted for time the queue spent suspended off its
    /// CSG slot before this job was submitted.
    baseline_suspend_nanos: AtomicI64,
    /// Back-reference to the owning group; used by
    /// `TyrQueueOps::submit` to reach the scheduler workqueue when
    /// no CSG doorbell has been assigned to the queue yet.
    pub(super) group: Arc<Group>,
    /// Index of the owning queue inside `Group::queues`. Captured
    /// at prepare time so the timeout stage can read the per-queue
    /// syncobj without an extra lookup.
    queue_index: usize,
    /// Snapshot of the device profile mask taken at submit time. Selects
    /// which sample deltas the completion path accumulates. `0` when the
    /// job carries no profiling slot.
    profiling_mask: u32,
    /// Reserved at prepare time, consumed in submit, rolled back on drop.
    /// Also holds the profiling sample slot baked into `stream`.
    reservation: Option<PendingFenceReservation>,
}

impl QueueJob {
    pub(super) fn new(
        stream: KVec<u8>,
        group: Arc<Group>,
        queue_index: usize,
        profiling_mask: u32,
        reservation: Option<PendingFenceReservation>,
    ) -> Self {
        Self {
            stream,
            done_seqno: AtomicU64::new(0),
            baseline_suspend_nanos: AtomicI64::new(0),
            group,
            queue_index,
            profiling_mask,
            reservation,
        }
    }

    fn done_seqno(&self) -> Option<u64> {
        match self.done_seqno.load(Ordering::Relaxed) {
            0 => None,
            v => Some(v),
        }
    }

    pub(super) fn set_done_seqno(&self, done_seqno: u64) {
        self.done_seqno.store(done_seqno, Ordering::Relaxed);
    }

    pub(super) fn baseline_suspend(&self) -> Delta {
        Delta::from_nanos(self.baseline_suspend_nanos.load(Ordering::Relaxed))
    }

    fn set_baseline_suspend(&self, baseline: Delta) {
        self.baseline_suspend_nanos
            .store(baseline.as_nanos(), Ordering::Relaxed);
    }
}

/// Per-queue accounting of time spent off the CSG slot.
struct SuspendState {
    /// `Some(t)` when the queue is currently suspended off its CSG
    /// slot; `t` is the monotonic instant at which the suspend began.
    since: Option<Instant<Monotonic>>,
    /// Total time the queue has spent suspended off its CSG slot
    /// since creation.
    accumulated: Delta,
}

impl Default for SuspendState {
    fn default() -> Self {
        Self {
            since: None,
            accumulated: Delta::ZERO,
        }
    }
}

#[pin_data]
pub(crate) struct QueueData {
    priority: u8,
    ringbuf: Arc<gem::MappedBo>,
    interfaces: Interfaces,
    doorbell_id: AtomicUsize,
    next_seqno: AtomicU64,
    /// Per-job profiling sample slots, mapped into the VM and the
    /// kernel. Holds `profiling_slot_count` `JobProfilingData` records.
    profiling_slots: Arc<gem::MappedBo>,
    /// Number of `JobProfilingData` records in `profiling_slots`. Sized
    /// to the maximum number of wrappers the ring buffer can hold.
    profiling_slot_count: u32,
    iomem: Arc<kernel::devres::Devres<IoMem>>,
    #[pin]
    pending_submit_fences: Mutex<PendingFences>,
    /// Submit fence of the most-recently committed command-stream job
    /// on this queue, in FIFO submit order. A stream-less job emits no
    /// GPU work of its own, so it adopts this fence as the producer for
    /// its signal syncobjs: the syncobj only advances once the prior
    /// command stream's GPU work retires. `None` until the first
    /// command-stream job is committed.
    #[pin]
    last_submit_fence: Mutex<Option<ARef<PublicDmaFence>>>,
    /// Active GPU sync-wait captured for this queue. The `Default`
    /// value (`gpu_va == 0`) means no wait is currently active.
    #[pin]
    syncwait: Mutex<SyncWait>,
    /// Per-queue accounting of off-slot suspend time, credited against
    /// the job deadline.
    #[pin]
    suspend_state: Mutex<SuspendState>,
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

    /// Returns a drained job's profiling sample slot to the free list.
    fn release_profiling_slot(&self, slot: u32) {
        let mut pending = self.pending_submit_fences.lock();
        let _ = pending.profiling_free.push_within_capacity(slot);
    }

    /// GPU virtual address of the profiling sample slot `slot`.
    pub(super) fn profiling_slot_va(&self, slot: u32) -> Result<u64> {
        let base = self.profiling_slots.kernel_va().ok_or(EINVAL)?.start;
        Ok(base + u64::from(slot) * size_of::<super::job::JobProfilingData>() as u64)
    }

    /// Records `fence` as the queue's last command-stream submit fence,
    /// dropping the previously stored one. Called in FIFO submit order
    /// from `Context::commit` so a later stream-less job adopts the
    /// fence of the immediately-FIFO-earlier command stream.
    pub(in crate::sched) fn set_last_submit_fence(&self, fence: ARef<PublicDmaFence>) {
        *self.last_submit_fence.lock() = Some(fence);
    }

    /// Returns a clone of the queue's last command-stream submit fence,
    /// or `None` if no command-stream job has been committed yet.
    pub(in crate::sched) fn last_submit_fence(&self) -> Option<ARef<PublicDmaFence>> {
        self.last_submit_fence.lock().clone()
    }

    /// Copies `instrs` into the ringbuffer at the current `INSERT`. The
    /// returned completion point is the `INSERT` value
    /// `Self::commit_ringbuf_range` will publish once the caller has
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
    /// `claim_ringbuf_range`. `extract_init` and the ringbuffer bytes are
    /// written before the leading `wmb()`, so they land before `insert`. The
    /// trailing `wmb()` orders `insert` before the doorbell ring.
    pub(super) fn commit_ringbuf_range(&self, completion_point: u64) -> Result {
        let ringbuf_output = self.interfaces.read_output()?;
        self.interfaces.write_extract_init(ringbuf_output.extract)?;

        kernel::sync::barrier::wmb();
        self.interfaces.write_insert(completion_point)?;
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

    fn signal_submit_fences_up_to(&self, up_to_seqno: u64, result: Result) {
        loop {
            let (profiling_slot, profiling_mask, fence) = {
                let mut pending = self.pending_submit_fences.lock();
                let head = pending.head;
                let Some(entry) = pending.vec.get_mut(head) else {
                    Self::maybe_truncate_pending(&mut pending);
                    break;
                };
                if entry.done_seqno > up_to_seqno {
                    Self::maybe_truncate_pending(&mut pending);
                    break;
                }
                let profiling_slot = entry.profiling_slot;
                let profiling_mask = entry.profiling_mask;
                let fence = entry.fence.take();
                pending.head = head + 1;
                (profiling_slot, profiling_mask, fence)
            };

            if profiling_mask != 0 {
                self.release_profiling_slot(profiling_slot);
            }

            if let Some(fence) = fence {
                let _annotation = DmaFenceSignallingAnnotation::new();
                fence.signal(result);
            }
        }
    }

    /// Signals each leading pending submit fence whose `done_seqno` is
    /// `<= up_to_seqno`, dropping the queue lock before each
    /// `dma_fence_signal()` so no driver lock is held across the signal.
    ///
    /// For each completed job, the per-job profiling samples are read
    /// back from the slot BO and accumulated into `group`'s fdinfo.
    ///
    /// Obeys the dma-fence signalling-section constraints, because the
    /// readback only reads a kernel-mapped BO (normal memory) and takes the
    /// fdinfo spinlock. It allocates nothing, takes no `dma_resv` lock, and
    /// waits on no fence.
    fn complete_pending_fences_up_to(&self, group: &Group, up_to_seqno: u64) {
        loop {
            let (profiling_slot, profiling_mask, fence) = {
                let mut pending = self.pending_submit_fences.lock();
                let head = pending.head;
                let Some(entry) = pending.vec.get_mut(head) else {
                    Self::maybe_truncate_pending(&mut pending);
                    break;
                };
                if entry.done_seqno > up_to_seqno {
                    Self::maybe_truncate_pending(&mut pending);
                    break;
                }
                let profiling_slot = entry.profiling_slot;
                let profiling_mask = entry.profiling_mask;
                let fence = entry.fence.take();
                pending.head = head + 1;
                (profiling_slot, profiling_mask, fence)
            };

            if profiling_mask != 0 {
                self.accumulate_profiling_sample(group, profiling_slot, profiling_mask);
                self.release_profiling_slot(profiling_slot);
            }

            if let Some(fence) = fence {
                let _annotation = DmaFenceSignallingAnnotation::new();
                fence.signal(Ok(()));
            }
        }
    }

    /// Reads the profiling slot `slot` and accumulates the enabled
    /// before/after deltas into `group`'s fdinfo.
    ///
    /// A read error is logged and skipped, because a missed sample must not
    /// abort fence completion.
    fn accumulate_profiling_sample(&self, group: &Group, slot: u32, mask: u32) {
        let offset = slot as usize * size_of::<super::job::JobProfilingData>();
        let data = match super::job::JobProfilingData::read(&*self.profiling_slots, offset) {
            Ok(data) => data,
            Err(err) => {
                pr_err!("profiling slot read failed: {}\n", err.to_errno());
                return;
            }
        };

        let cycles = if mask & DEVICE_PROFILING_CYCLES != 0 {
            data.cycles_after.wrapping_sub(data.cycles_before)
        } else {
            0
        };
        let time = if mask & DEVICE_PROFILING_TIMESTAMP != 0 {
            data.time_after.wrapping_sub(data.time_before)
        } else {
            0
        };
        group.accumulate_fdinfo(cycles, time);
    }

    /// Compacts the drained prefix away once `head` has grown past
    /// `max(len / 2, 16)`.
    ///
    /// Must preserve `vec.capacity()` so `Queue::reserve_pending_submit_fence`
    /// never needs to grow the vec. `KVec::retain` shifts surviving
    /// entries in place and only adjusts `len`, leaving the underlying
    /// allocation intact.
    fn maybe_truncate_pending(pending: &mut PendingFences) {
        let len = pending.vec.len();
        let threshold = core::cmp::max(len / 2, 16);
        if pending.head < threshold {
            return;
        }
        let drop_count = pending.head;
        let mut i = 0usize;
        pending.vec.retain(|_| {
            let keep = i >= drop_count;
            i += 1;
            keep
        });
        pending.head = 0;
    }

    fn signal_submit_fence(&self, done_seqno: u64, result: Result) -> bool {
        let fence = {
            let mut pending = self.pending_submit_fences.lock();
            let head = pending.head;
            let mut position = None;
            for (idx, entry) in pending.vec.iter().enumerate().skip(head) {
                if entry.done_seqno == done_seqno {
                    position = Some(idx);
                    break;
                }
            }
            position.and_then(|idx| pending.vec.get_mut(idx).and_then(|e| e.fence.take()))
        };

        let Some(fence) = fence else {
            return false;
        };

        let _annotation = DmaFenceSignallingAnnotation::new();
        fence.signal(result);
        true
    }

    /// Signals every leading pending submit fence whose stored
    /// `done_seqno` is at or below `syncobj_seqno`.
    ///
    /// The caller is expected to pass the value of the per-queue
    /// syncobj, read with `Group::read_syncobj`. The wrapped command
    /// stream emitted by
    /// `Job::build_wrapped_stream`
    /// ends each piece with `WAIT(all scoreboards) ; SYNC_ADD64(+1)`, so
    /// the firmware advances the syncobj by one only after every async
    /// sub-job the piece dispatched has retired through the scoreboards.
    /// Gating signalling on the syncobj therefore guarantees waiters see
    /// the fence only once the GPU work is actually complete, where
    /// gating on the firmware's `EXTRACT` decode pointer would race the
    /// dispatched work.
    ///
    /// Called from both the IRQ-driven completion path on the scheduler
    /// side and from `QueueCompletionStage::process` as a defensive
    /// backstop in case a sync-update IRQ was missed.
    ///
    /// `group` owns the fdinfo accumulator the per-job profiling samples
    /// are folded into as each fence completes.
    pub(in crate::sched) fn complete_submit_fences(&self, group: &Group, syncobj_seqno: u64) {
        self.complete_pending_fences_up_to(group, syncobj_seqno);
    }

    /// Stages `err` on every pending submit fence whose `done_seqno`
    /// is strictly past `syncobj_seqno`, i.e. submissions whose
    /// `SYNC_ADD64` the firmware has not yet retired.
    ///
    /// The caller is expected to pass the value of the per-queue
    /// syncobj, read with `Group::read_syncobj`. The fences are left
    /// in the pending list; the regular seqno-ordered drain in
    /// `Self::complete_pending_fences_up_to` will signal them at
    /// their natural completion points so waiters still observe a
    /// monotonic submit-order signal sequence.
    ///
    /// Safe to call from inside a `DmaFenceSignallingAnnotation` section.
    pub(in crate::sched) fn fail_inflight_submit_fences(&self, syncobj_seqno: u64, err: Error) {
        let mut pending = self.pending_submit_fences.lock();
        let head = pending.head;
        for entry in pending.vec.iter_mut().skip(head) {
            if entry.done_seqno > syncobj_seqno {
                if let Some(fence) = entry.fence.as_mut() {
                    fence.set_error(err);
                }
            }
        }
    }

    /// Returns a clone of the active sync-wait snapshot.
    pub(crate) fn syncwait_snapshot(&self) -> SyncWait {
        self.syncwait.lock().clone()
    }

    /// Updates the firmware-reported fields of the active sync-wait
    /// snapshot. The cached BO resolution is keyed independently by
    /// its own `(gpu_va, sync64)`; `Group::eval_syncwait` detects
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
    /// Must be called before staging `CS_REQ.state = Start` at CSG-bind
    /// time so the firmware sees a consistent `(insert, extract_init)`
    /// snapshot when it starts reading the per-queue ringbuf mailbox.
    pub(crate) fn sync_extract_init(&self) -> Result {
        let ringbuf_output = self.interfaces.read_output()?;
        self.interfaces.write_extract_init(ringbuf_output.extract)
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

    /// Atomic snapshot of `(accumulated, in_flight_since)` for the
    /// timeout stage. The returned `since` is `Some(t)` when the queue
    /// is currently suspended off its CSG slot; `t` is the monotonic
    /// instant at which that suspend interval began.
    fn suspend_snapshot(&self) -> (Delta, Option<Instant<Monotonic>>) {
        let state = self.suspend_state.lock();
        (state.accumulated, state.since)
    }

    /// Marks the queue as suspended off its CSG slot.
    ///
    /// Records the current monotonic instant so a later
    /// `Self::resume_timeout` can fold the interval into
    /// `SuspendState::accumulated`. No-op when the queue is already
    /// suspended; this preserves the existing start time rather than
    /// restarting the interval.
    pub(super) fn suspend_timeout(&self) {
        let mut state = self.suspend_state.lock();
        if state.since.is_none() {
            state.since = Some(Instant::<Monotonic>::now());
        }
    }

    /// Marks the queue as resumed onto its CSG slot.
    ///
    /// Adds the time since the matching `Self::suspend_timeout` to
    /// `SuspendState::accumulated`. No-op if the queue is not
    /// currently suspended.
    pub(super) fn resume_timeout(&self) {
        let mut state = self.suspend_state.lock();
        if let Some(start) = state.since.take() {
            let elapsed = Instant::<Monotonic>::now() - start;
            state.accumulated += elapsed;
        }
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

        if !job.job.group.can_run() {
            fence.signal(Err(ECANCELED));
            TyrDrmDeviceData::schedule_tick(&job.job.group.tdev);
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

        // Fold any in-flight suspend interval into the baseline so it
        // matches the shape the timeout stage uses on the consumer
        // side; subtraction is exact only when both sides fold.
        let (accumulated, in_flight_since) = self.data.suspend_snapshot();
        let baseline = match in_flight_since {
            Some(start) => accumulated + (Instant::<Monotonic>::now() - start),
            None => accumulated,
        };
        job.job.set_baseline_suspend(baseline);

        let ringbuf_completion_point = match self.data.claim_ringbuf_range(&job.job.stream) {
            Ok(completion_point) => completion_point,
            Err(err) => {
                fence.signal(Err(err));
                return Err(err);
            }
        };

        let (Some(reservation), Some(done_seqno)) =
            (job.job.reservation.as_ref(), job.job.done_seqno())
        else {
            fence.signal(Err(EINVAL));
            return Err(EINVAL);
        };

        if let Err((err, fence)) = reservation.consume(done_seqno, job.job.profiling_mask, fence) {
            fence.signal(Err(err));
            return Err(err);
        }

        if let Err(err) = self.data.commit_ringbuf_range(ringbuf_completion_point) {
            self.data.signal_submit_fence(done_seqno, Err(err));
            return Err(err);
        }

        // `CsgSlotOps::activate` and `CsgSlotOps::evict` update `csg_id` and
        // the per-queue `doorbell_id` together under this lock, so a bound
        // group observed here keeps its doorbell for the whole kick. Ringing
        // outside the lock would race an eviction and fail the kick for
        // committed ringbuf bytes.
        //
        // Ring only while the device is runtime-active. When it is not, a
        // suspend is evicting the group and the rebind re-rings the
        // committed bytes.
        let group = &job.job.group;
        let awake = group.tdev.pm_get_if_active();
        let device_active = awake.is_some();
        let queue_index = job.job.queue_index;
        let (active, kick_err, resume_tick) = group.with_locked_inner(|inner| {
            if inner.csg_id.is_none() || inner.state != State::Active {
                return (false, Ok(()), false);
            }
            let group_idle = inner.is_idle();
            let blocked = inner.blocked_queues() & (1u32 << queue_index) != 0;
            let queue_idle = inner.set_queue_idle(queue_index, false);
            if awake.is_none() {
                return (true, Ok(()), group_idle && queue_idle && !blocked);
            }
            let kick_res = self.data.kick();
            (true, kick_res, group_idle && queue_idle && !blocked)
        });
        drop(awake);

        if active {
            if let Err(err) = kick_err {
                self.data.signal_submit_fence(done_seqno, Err(err));
                return Err(err);
            }
            // This path does not always schedule a tick, so record the busy
            // edge here.
            group.tdev.devfreq_data.devfreq_state.lock().mark_busy();
            let _ = group.tdev.with_locked_scheduler(|sched| {
                // Close the interval only if the group is still bound. A
                // rotation tick may have evicted it since the kick saw it
                // resident.
                if device_active && group.with_locked_inner(|inner| inner.csg_id.is_some()) {
                    self.data.resume_timeout();
                }
                if sched.pm_ref.is_none() {
                    sched.pm_ref = group.tdev.sched_pm_get();
                }
                Ok(())
            });

            if resume_tick {
                if let Ok(tick) = group
                    .tdev
                    .with_locked_scheduler(|sched| Ok(sched.resident_submit_tick()))
                {
                    tick.dispatch(&group.tdev);
                }
            }
        } else {
            // A concurrent eviction requeues by live ring state, so the
            // bytes committed above are still kicked.
            let tick = match group.tdev.with_locked_scheduler(|sched| {
                sched.mark_group_runnable(group);
                Ok(sched.submit_tick(group.priority))
            }) {
                Ok(tick) => tick,
                Err(err) => {
                    self.data.signal_submit_fence(done_seqno, Err(err));
                    return Err(err);
                }
            };
            tick.dispatch(&group.tdev);
        }

        Ok(SubmitResult::Submitted)
    }
}

/// Bounds an in-flight job by `JOB_TIMEOUT_MS` of on-slot time.
///
/// "Suspend-adjusted" means the time the queue spent evicted off
/// its CSG slot for higher-priority work is credited back against
/// the per-job deadline.
struct QueueCompletionStage {
    data: Arc<QueueData>,
    timeout: Jiffies,
}

impl StageOps<TyrQueueOps> for QueueCompletionStage {
    fn process(&self, ctx: &StageContext<'_, TyrQueueOps>) -> StageAdvance {
        if ctx.submit_fence.is_signaled() {
            return StageAdvance::Advance;
        }

        match ctx.job.group.read_syncobj(ctx.job.queue_index) {
            Ok(syncobj) => self
                .data
                .complete_submit_fences(&ctx.job.group, syncobj.seqno),
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

        // Compute the suspend allowance under one lock acquire so the
        // in-flight interval and the accumulator are read atomically.
        let (accumulated, in_flight_since) = self.data.suspend_snapshot();
        let mut suspended = accumulated;
        if let Some(start) = in_flight_since {
            suspended += Instant::<Monotonic>::now() - start;
        }
        let allowance = suspended - ctx.job.baseline_suspend();
        let allowance_jiffies = msecs_to_jiffies(allowance.as_millis().max(0) as u32);

        let elapsed = msecs_to_jiffies(ctx.stage_elapsed().as_millis().max(0) as u32);
        let adjusted_elapsed = elapsed.saturating_sub(allowance_jiffies);

        if adjusted_elapsed >= self.timeout {
            pr_err!("Tyr queue job {} timed out\n", ctx.counter);
            ctx.job
                .group
                .with_locked_inner(|inner| inner.mark_timedout());
            TyrDrmDeviceData::schedule_tick(&ctx.job.group.tdev);
            if let Some(done_seqno) = ctx.job.done_seqno() {
                self.data.signal_submit_fence(done_seqno, Err(ETIMEDOUT));
            }
            return StageAdvance::TimedOut(ETIMEDOUT);
        }

        // Wake at the remaining deadline. The submit fence's
        // progress callback (registered by the framework's
        // `process_exec`) will wake the pipeline earlier when
        // `Scheduler::sync_upd_step` signals the fence in response
        // to a sync-update IRQ; this `WaitFor` is just the
        // worst-case bound for actually faulting the job.
        StageAdvance::WaitFor(self.timeout - adjusted_elapsed)
    }

    fn teardown(&self, job: &QueueJob, _counter: u64) {
        if let Some(done_seqno) = job.done_seqno() {
            self.data.signal_submit_fence(done_seqno, Err(ECANCELED));
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
        let ringbuf = gem::new_kernel_object(
            tdev,
            &vm,
            queue_args.ringbuf_size() as usize,
            flags,
            tdev.coherent,
            tdev.cleanup_wq.clone(),
        )?;
        let iface_mem = tdev.fw.alloc_queue_mem(tdev)?;
        let interfaces = Interfaces::new(iface_mem)?;

        let max_jobs = queue_args.ringbuf_size() as usize / WRAPPER_RINGBUF_BYTES;
        let pending_fence_vec = KVec::with_capacity(max_jobs, GFP_KERNEL)?;

        // One profiling slot per wrapper the ring can hold simultaneously.
        let profiling_slot_count = max_jobs as u32;
        let mut profiling_free = KVec::with_capacity(max_jobs, GFP_KERNEL)?;
        for slot in 0..profiling_slot_count {
            profiling_free.push(slot, GFP_KERNEL)?;
        }
        let profiling_slots = gem::new_kernel_object(
            tdev,
            &vm,
            profiling_slot_count as usize * size_of::<super::job::JobProfilingData>(),
            flags,
            tdev.coherent,
            tdev.cleanup_wq.clone(),
        )?;

        let data = Arc::pin_init(
            pin_init!(QueueData {
                priority: queue_args.priority(),
                ringbuf,
                interfaces,
                doorbell_id: AtomicUsize::new(UNASSIGNED_DOORBELL_ID),
                next_seqno: AtomicU64::new(0),
                profiling_slots,
                profiling_slot_count,
                iomem: tdev.iomem.clone(),
                pending_submit_fences <- new_mutex!(PendingFences {
                    vec: pending_fence_vec,
                    head: 0,
                    outstanding: 0,
                    profiling_free,
                }),
                last_submit_fence <- new_mutex!(None),
                syncwait <- new_mutex!(SyncWait::default()),
                suspend_state <- new_mutex!(SuspendState {
                    since: Some(Instant::<Monotonic>::now()),
                    accumulated: Delta::ZERO,
                }),
            }),
            GFP_KERNEL,
        )?;

        let pipeline = PipelineBuilder::new()
            .set_cancel_timeout(msecs_to_jiffies(JOB_TIMEOUT_MS))
            .add_stage(QueueCompletionStage {
                data: data.clone(),
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
        extra_dep_capacity: usize,
    ) -> Result<PreparedQueueJob> {
        self.job_queue
            .prepare(job, deps, extra_dep_capacity, QueueFenceData)
    }

    /// Reserves capacity for one pending submit fence and returns an
    /// RAII guard for the reservation.
    ///
    /// The pending-fence vec is pre-sized at queue creation to the
    /// maximum number of wrappers the ringbuf can hold, so this
    /// performs no allocation: it only checks that the new reservation
    /// still fits within `capacity`. Keeping the lock allocation-free
    /// breaks the lockdep cycle through `fs_reclaim` that would
    /// otherwise close via `JobQueue::state` -> `dma_fence_map` ->
    /// `mmu_notifier` -> `fs_reclaim` -> `pending_submit_fences`.
    ///
    /// When `profiling` is set, a sample slot is popped from
    /// `profiling_free` and carried by the reservation. The free list holds
    /// one slot per capacity unit, so a granted reservation always finds
    /// one.
    pub(in crate::sched) fn reserve_pending_submit_fence(
        &self,
        profiling: bool,
    ) -> Result<PendingFenceReservation> {
        let mut pending = self.data.pending_submit_fences.lock();
        let additional = pending.outstanding.checked_add(1).ok_or(EOVERFLOW)?;
        if pending.vec.len() + additional > pending.vec.capacity() {
            return Err(ENOSPC);
        }
        pending.outstanding = additional;
        let profiling_slot = if profiling {
            pending.profiling_free.pop()
        } else {
            None
        };
        Ok(PendingFenceReservation::new(
            self.data.clone(),
            profiling_slot,
        ))
    }

    pub(super) fn commit_job(&self, prepared: PreparedQueueJob) -> ARef<PublicDmaFence> {
        self.job_queue.commit(prepared)
    }

    /// Stops the pipeline from handing any further job to the
    /// firmware and from failing one. Jobs keep resolving their
    /// dependencies and pile up in front of the exec stage, and the
    /// per-job deadline stops being evaluated until the unpark.
    pub(crate) fn park(&self) {
        self.job_queue.park();
    }

    /// Releases a park and rechecks the pipeline, so jobs that piled
    /// up behind it are submitted without waiting for another event.
    pub(crate) fn unpark(&self) {
        self.job_queue.unpark();
    }

    /// Cancels every job tracked by this queue and signals all
    /// remaining pending submit fences with `err`.
    ///
    /// Must be called from process context: `cancel_all` may sleep
    /// waiting for in-flight HW fences.
    pub(crate) fn cancel(&self, err: Error) {
        self.job_queue.park();
        self.data.signal_submit_fences_up_to(u64::MAX, Err(err));
        self.job_queue.cancel_all();
        self.data.signal_submit_fences_up_to(u64::MAX, Err(err));
        self.job_queue.unpark();
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

    pub(super) fn write_insert(&self, insert: u64) -> Result {
        let vmap = self.mem.vmap();
        let input = (vmap.addr() + self.input_offset) as *mut RingBufferInput;

        // SAFETY: `input` points at the queue input structure inside the
        // writable CPU mapping owned by `mem`. `addr_of_mut!` projects to the
        // `insert` field without forming a reference to the mapped page.
        unsafe { core::ptr::addr_of_mut!((*input).insert).write_volatile(insert) };

        Ok(())
    }

    pub(super) fn write_extract_init(&self, extract_init: u64) -> Result {
        let vmap = self.mem.vmap();
        let input = (vmap.addr() + self.input_offset) as *mut RingBufferInput;

        // SAFETY: `input` points at the queue input structure inside the
        // writable CPU mapping owned by `mem`. `addr_of_mut!` projects to the
        // `extract_init` field without forming a reference to the mapped page.
        unsafe { core::ptr::addr_of_mut!((*input).extract_init).write_volatile(extract_init) };

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
