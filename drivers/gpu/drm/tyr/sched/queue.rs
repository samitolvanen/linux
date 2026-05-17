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
        TyrDrmDeviceData, //
    },
    fw::global::CsActivateInputs,
    gem,
    regs::doorbell_block,
    trace,
    vm::{Vm, VmFlag, VmMapFlags},
};

use super::group::Group;

const UNASSIGNED_DOORBELL_ID: usize = usize::MAX;
const JOB_TIMEOUT_MS: u32 = 5000;

/// Smallest ringbuffer byte count one wrapped job stream consumes.
///
/// `sched::job::build_wrapped_stream` emits 11 8-byte instructions per
/// piece and pads the concatenation up to a 64-byte boundary, so the
/// minimum is `next_multiple_of(88, 64) == 128`. Used to size the
/// pre-allocated pending-fence vec so [`Queue::reserve_pending_submit_fence`]
/// never needs to allocate under the lock.
const WRAPPER_RINGBUF_BYTES: usize = 128;

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
    fence: Option<DriverDmaFence<QueueFenceData, Published>>,
}

/// State protected by the pending-submit-fences mutex.
///
/// `vec` carries the live ordered list of in-flight per-job fences.
/// `outstanding` counts reservations made by
/// [`Queue::reserve_pending_submit_fence`] whose [`PendingFenceReservation`]
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
/// [`Queue::maybe_truncate_pending`] compacts the prefix away once
/// `head` exceeds `max(len / 2, 16)`.
struct PendingFences {
    vec: KVec<PendingSubmitFence>,
    head: usize,
    outstanding: usize,
}

/// RAII guard for a pending-submit-fence reservation.
pub(in crate::sched) struct PendingFenceReservation {
    queue: Arc<QueueData>,
    consumed: AtomicBool,
}

impl PendingFenceReservation {
    fn new(queue: Arc<QueueData>) -> Self {
        Self {
            queue,
            consumed: AtomicBool::new(false),
        }
    }

    /// Pushes `fence` into the queue's pending list, consuming this reservation.
    fn consume(
        &self,
        completion_point: u64,
        fence: DriverDmaFence<QueueFenceData, Published>,
    ) -> Result<(), (Error, DriverDmaFence<QueueFenceData, Published>)> {
        let pending_fence = PendingSubmitFence {
            completion_point,
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
    /// Snapshot of `QueueData::suspend_snapshot` taken at submit
    /// time, folded with any in-flight suspend interval; subtracted
    /// from the queue's current accumulator by the timeout stage so a
    /// job is not faulted for time the queue spent suspended off its
    /// CSG slot before this job was submitted.
    baseline_suspend_nanos: AtomicI64,
    /// Back-reference to the owning group; used by
    /// [`TyrQueueOps::submit`] to reach the scheduler workqueue when
    /// no CSG doorbell has been assigned to the queue yet.
    pub(super) group: Arc<Group>,
    /// Reserved at prepare time, consumed in submit, rolled back on drop.
    reservation: Option<PendingFenceReservation>,
}

impl QueueJob {
    pub(super) fn new(
        stream: KVec<u8>,
        group: Arc<Group>,
        reservation: Option<PendingFenceReservation>,
    ) -> Self {
        Self {
            stream,
            completion_point: AtomicU64::new(0),
            baseline_suspend_nanos: AtomicI64::new(0),
            group,
            reservation,
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
    /// Index of this queue within its owning group's `queues` vec.
    cs_id: u32,
    /// Owning group's pool handle, captured at queue-create time so
    /// tracepoints emitted without a `&Group` can carry a stable
    /// identifier.
    ///
    /// Set once by `set_group_id` before the queue is published to any
    /// path that can emit a tracepoint; reads after publish are stable.
    group_id: AtomicU64,
    ringbuf: Arc<gem::MappedBo>,
    interfaces: Interfaces,
    doorbell_id: AtomicUsize,
    next_seqno: AtomicU64,
    iomem: Arc<kernel::devres::Devres<IoMem>>,
    #[pin]
    pending_submit_fences: Mutex<PendingFences>,
    /// Active GPU sync-wait captured for this queue. The `Default`
    /// value (`gpu_va == 0`) means no wait is currently active.
    #[pin]
    syncwait: Mutex<SyncWait>,
    /// Per-queue accounting of off-slot suspend time; advanced by
    /// [`Self::suspend_timeout`] / [`Self::resume_timeout`] from
    /// [`CsgSlotOps::evict`] / [`CsgSlotOps::activate`] and snapshotted
    /// by [`TyrQueueOps::submit`] for the per-job baseline.
    ///
    /// [`CsgSlotOps::activate`]: crate::sched::CsgSlotOps::activate
    /// [`CsgSlotOps::evict`]: crate::sched::CsgSlotOps::evict
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

    /// Sets the owning group's pool handle. Must be called once after
    /// the group is inserted into the pool, before any path that can
    /// emit a tracepoint runs.
    pub(crate) fn set_group_id(&self, group_id: u64) {
        self.group_id.store(group_id, Ordering::Relaxed);
    }

    fn group_id(&self) -> u64 {
        self.group_id.load(Ordering::Relaxed)
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
        let prev_insert = ringbuf_input.insert;
        ringbuf_input.extract_init = ringbuf_output.extract;
        ringbuf_input.insert = completion_point;

        self.interfaces.write_input(ringbuf_input)?;
        trace::fw_cs_ringbuf_publish(
            self.group_id(),
            self.cs_id,
            completion_point,
            ringbuf_output.extract,
        );

        // Dump the first 32 bytes of the just-committed range so the
        // Mali prologue can be inspected from trace alone. Wraparound
        // is handled by masking each 8-byte offset into the ringbuf.
        let ringbuf_sz = self.ringbuf.size() as u64;
        if ringbuf_sz != 0 && completion_point > prev_insert {
            let ringbuf = self.ringbuf.vmap();
            let size = ringbuf.owner().size();
            // SAFETY: `ringbuf` owns a readable CPU mapping for the
            // queue ring buffer and `size` matches the mapped object
            // size; the previously-written bytes at `prev_insert` are
            // already ordered-before by the leading `wmb()`.
            let bytes = unsafe { core::slice::from_raw_parts(ringbuf.addr() as *const u8, size) };
            let mut words = [0u64; 4];
            let payload = completion_point - prev_insert;
            for (i, word) in words.iter_mut().enumerate() {
                let off = prev_insert + (i as u64) * 8;
                if off + 8 > prev_insert + payload {
                    break;
                }
                let cs_off = (off & (ringbuf_sz - 1)) as usize;
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[cs_off..cs_off + 8]);
                *word = u64::from_le_bytes(buf);
            }
            trace::cs_ringbuf_dump(
                self.group_id(),
                self.cs_id,
                prev_insert,
                words[0],
                words[1],
                words[2],
                words[3],
            );
        }

        kernel::sync::barrier::wmb();
        trace::cs_ring_ptrs(
            self.group_id(),
            self.cs_id,
            completion_point,
            ringbuf_output.extract,
        );
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

    fn signal_submit_fences_up_to(&self, completion_point: u64, result: Result) {
        loop {
            let fence = {
                let mut pending = self.pending_submit_fences.lock();
                let head = pending.head;
                let Some(entry) = pending.vec.get_mut(head) else {
                    Self::maybe_truncate_pending(&mut pending);
                    break;
                };
                if entry.completion_point > completion_point {
                    Self::maybe_truncate_pending(&mut pending);
                    break;
                }
                let fence = entry.fence.take();
                pending.head = head + 1;
                fence
            };

            if let Some(fence) = fence {
                let _annotation = DmaFenceSignallingAnnotation::new();
                fence.signal(result);
            }
        }
    }

    /// Per Documentation/driver-api/dma-buf.rst, no driver lock may
    /// be held across `dma_fence_signal()`.
    fn complete_pending_fences_up_to(&self, up_to: u64) {
        let mut drained_count: u32 = 0;
        let mut last_completion_point: u64 = 0;

        loop {
            let (completion_point, fence) = {
                let mut pending = self.pending_submit_fences.lock();
                let head = pending.head;
                let Some(entry) = pending.vec.get_mut(head) else {
                    Self::maybe_truncate_pending(&mut pending);
                    break;
                };
                if entry.completion_point > up_to {
                    Self::maybe_truncate_pending(&mut pending);
                    break;
                }
                let completion_point = entry.completion_point;
                let fence = entry.fence.take();
                pending.head = head + 1;
                (completion_point, fence)
            };

            if let Some(fence) = fence {
                let _annotation = DmaFenceSignallingAnnotation::new();
                trace::submit_fence_signal(self.group_id(), self.cs_id, completion_point, 0);
                fence.signal(Ok(()));
                drained_count += 1;
                last_completion_point = completion_point;
            }
        }

        if drained_count > 0 {
            trace::sync_upd_drain(
                self.group_id(),
                self.cs_id,
                last_completion_point,
                drained_count,
            );
        }
    }

    /// Compacts the drained prefix away once `head` has grown past
    /// `max(len / 2, 16)`. Matches the 6.18 heuristic.
    ///
    /// Must preserve `vec.capacity()` so [`Queue::reserve_pending_submit_fence`]
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

    fn signal_submit_fence(&self, completion_point: u64, result: Result) -> bool {
        let fence = {
            let mut pending = self.pending_submit_fences.lock();
            let head = pending.head;
            let mut position = None;
            for (idx, entry) in pending.vec.iter().enumerate().skip(head) {
                if entry.completion_point == completion_point {
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
        let result_errno = match result {
            Ok(()) => 0,
            Err(e) => e.to_errno(),
        };
        trace::submit_fence_signal(self.group_id(), self.cs_id, completion_point, result_errno);
        fence.signal(result);
        true
    }

    /// Reads the firmware-visible `EXTRACT` for this queue and signals
    /// every leading pending submit fence whose `completion_point` is
    /// at or below it.
    ///
    /// Called from both the IRQ-driven completion path on the
    /// scheduler side and from [`QueueCompletionStage::process`] as a
    /// defensive backstop in case a sync-update IRQ was missed.
    pub(in crate::sched) fn complete_submit_fences(&self) -> Result {
        let ringbuf_output = self.interfaces.read_output()?;
        self.complete_pending_fences_up_to(ringbuf_output.extract);
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
        let head = pending.head;
        for entry in pending.vec.iter_mut().skip(head) {
            if entry.completion_point > extract {
                if let Some(fence) = entry.fence.as_mut() {
                    fence.set_error(err);
                }
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
        drop(wait);
        trace::queue_state(self.group_id(), self.cs_id, gpu_va != 0);
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

    /// Returns the current `(insert, extract)` ringbuffer cursor pair
    /// read from the kernel-visible mailbox pages. Used by the MMU
    /// fault path to capture the GPU's view of the queue without
    /// going through the firmware interface.
    pub(crate) fn ringbuf_ptrs(&self) -> Result<(u64, u64)> {
        let input = self.interfaces.read_input()?;
        let output = self.interfaces.read_output()?;
        Ok((input.insert, output.extract))
    }

    /// Reads up to 256 bytes from the BO that contains the GPU VA
    /// derived from `cs_extract`, centred on that VA. Used by the
    /// CS_FAULT / CS_FATAL trace path to capture the bytes the
    /// firmware was actually decoding at the moment of the fault.
    ///
    /// Per the CSF architecture spec, `cs_extract` is a monotonic byte
    /// counter relative to the per-queue ring buffer base, so the GPU
    /// VA used for the lookup is `ringbuf_base + (cs_extract %
    /// ringbuf_size)`.
    ///
    /// This is best-effort tracing. The GPU VA lookup uses
    /// [`Vm::try_get_bo_for_va`], which takes `gpuvm_unique` via
    /// `try_lock()` to keep the helper safe from the dma-fence
    /// signalling section that wraps `fw_events_work`: that mutex
    /// composes with `GFP_KERNEL` allocation on the `vm_bind_ioctl`
    /// paths, so a blocking acquisition would create a
    /// `dma_fence_map → fs_reclaim` edge. If the lock is held
    /// elsewhere the helper returns a `LockContended` sentinel
    /// rather than waiting. The read goes through the queue's
    /// existing kernel vmap; no allocation, no `dma_resv_lock`, no
    /// `mmu_notifier` callback.
    ///
    /// [`Vm::try_get_bo_for_va`]: crate::vm::Vm::try_get_bo_for_va
    pub(crate) fn user_stream_window_around(
        &self,
        cs_extract: u64,
        vm: &Vm,
    ) -> trace::CsUserStreamDump {
        let ringbuf_size = self.ringbuf.size() as u64;
        if ringbuf_size == 0 || !ringbuf_size.is_power_of_two() {
            return trace::CsUserStreamDump::default();
        }
        let Some(ringbuf_base) = self.ringbuf.kernel_va().map(|r| r.start) else {
            return trace::CsUserStreamDump::default();
        };
        let gpu_va = ringbuf_base.wrapping_add(cs_extract & (ringbuf_size - 1));

        let (bo, bo_offset) = match vm.try_get_bo_for_va(gpu_va) {
            Ok(Some(hit)) => hit,
            Ok(None) => return trace::CsUserStreamDump::default(),
            Err(()) => {
                return trace::CsUserStreamDump {
                    status: trace::CsUserStreamDumpStatus::LockContended,
                    ..Default::default()
                };
            }
        };

        let bo_raw = kernel::drm::gem::IntoGEMObject::as_raw(&*bo);
        // SAFETY: `bo_raw` is a valid pointer to a `drm_gem_object`
        // for the lifetime of the `ARef<Bo>` held in `bo`.
        // `import_attach` is set at most once at gem creation and
        // never cleared, so a plain read is sound. The same idiom is
        // used in `gem::sync`.
        let imported = unsafe { !(*bo_raw).import_attach.is_null() };
        let bo_va_base = gpu_va.saturating_sub(bo_offset);
        if imported {
            return trace::CsUserStreamDump {
                bo_va_base,
                bo_offset,
                status: trace::CsUserStreamDumpStatus::BoImported,
                ..Default::default()
            };
        }

        // The only BO we know is guaranteed to have a stable kernel
        // vmap in this dma-fence signalling section is the queue's
        // own ring buffer, which is held vmapped by `MappedBo` for
        // the queue's lifetime. For any other BO (e.g. a Mesa-owned
        // user CS BO) `MappedUserBo::new` would have to take
        // `dma_resv_lock` and a `GFP_KERNEL` vmap, both forbidden
        // here. Report those cases via `BoNotVmapped` so the trace
        // consumer can see that we located the BO but could not read.
        let ringbuf_obj = core::ptr::eq(
            kernel::drm::gem::IntoGEMObject::as_raw(&**self.ringbuf),
            bo_raw,
        );
        if !ringbuf_obj {
            return trace::CsUserStreamDump {
                bo_va_base,
                bo_offset,
                status: trace::CsUserStreamDumpStatus::BoNotVmapped,
                ..Default::default()
            };
        }

        let vmap = self.ringbuf.vmap();
        let bo_size = vmap.owner().size();
        let offset = bo_offset as usize;
        if offset > bo_size {
            return trace::CsUserStreamDump {
                bo_va_base,
                bo_offset,
                status: trace::CsUserStreamDumpStatus::WindowClamped,
                ..Default::default()
            };
        }

        let start = offset.saturating_sub(128);
        let end = offset.saturating_add(128).min(bo_size);
        let len = end - start;
        let mut bytes = [0u8; 256];
        // SAFETY: `vmap` owns a CPU mapping of the queue ringbuffer
        // and `bo_size` matches the mapped object size; `start..end`
        // is in bounds of that mapping by construction above.
        let src =
            unsafe { core::slice::from_raw_parts((vmap.addr() as *const u8).add(start), len) };
        bytes[..len].copy_from_slice(src);

        let status = if len < 256 {
            trace::CsUserStreamDumpStatus::WindowClamped
        } else {
            trace::CsUserStreamDumpStatus::Ok
        };
        trace::CsUserStreamDump {
            bo_va_base,
            bo_offset,
            payload_offset: start as u64,
            status,
            bytes,
            len: len as u32,
        }
    }

    /// Reads eight u64 ringbuffer words around `extract`: the four
    /// words immediately before the firmware's decode pointer (at
    /// offsets -32, -24, -16, -8 from `extract`) followed by the
    /// four words at and ahead of `extract` (offsets 0, +8, +16,
    /// +24). All offsets are taken modulo the ringbuffer size so
    /// the window wraps correctly. Used by the MMU fault path to
    /// attach a ringbuf snapshot covering the actively-decoded
    /// instruction to the fault trace.
    pub(crate) fn ringbuf_window_around_extract(&self, extract: u64) -> [u64; 8] {
        let vmap = self.ringbuf.vmap();
        let size = vmap.owner().size();
        if size == 0 || !size.is_power_of_two() {
            return [0u64; 8];
        }
        // SAFETY: `vmap` owns a CPU mapping of the queue ringbuffer
        // and `size` matches the mapped object size.
        let bytes = unsafe { core::slice::from_raw_parts(vmap.addr() as *const u8, size) };

        let mask = (size as u64).wrapping_sub(1);
        let offsets: [i64; 8] = [-32, -24, -16, -8, 0, 8, 16, 24];
        let mut words = [0u64; 8];
        for (i, off) in offsets.iter().enumerate() {
            let start = ((extract as i64).wrapping_add(*off) as u64) & mask;
            let mut buf = [0u8; 8];
            for j in 0..8 {
                let pos = ((start + j) & mask) as usize;
                buf[j as usize] = bytes[pos];
            }
            words[i] = u64::from_le_bytes(buf);
        }
        words
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
    /// [`Self::resume_timeout`] can fold the interval into
    /// [`SuspendState::accumulated`]. No-op when the queue is already
    /// suspended; this preserves the existing start time rather than
    /// restarting the interval.
    pub(super) fn suspend_timeout(&self) {
        let mut state = self.suspend_state.lock();
        if state.since.is_none() {
            state.since = Some(Instant::<Monotonic>::now());
        }
        drop(state);
        trace::queue_timeout_state(self.group_id(), self.cs_id, true);
    }

    /// Marks the queue as resumed onto its CSG slot.
    ///
    /// Adds the time since the matching [`Self::suspend_timeout`] to
    /// [`SuspendState::accumulated`]. No-op if the queue is not
    /// currently suspended.
    pub(super) fn resume_timeout(&self) {
        let mut state = self.suspend_state.lock();
        if let Some(start) = state.since.take() {
            let elapsed = Instant::<Monotonic>::now() - start;
            state.accumulated += elapsed;
        }
        drop(state);
        trace::queue_timeout_state(self.group_id(), self.cs_id, false);
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

        // Fold any in-flight suspend interval into the baseline so it
        // matches the shape the timeout stage uses on the consumer
        // side; subtraction is exact only when both sides fold.
        let (accumulated, in_flight_since) = self.data.suspend_snapshot();
        let baseline = match in_flight_since {
            Some(start) => accumulated + (Instant::<Monotonic>::now() - start),
            None => accumulated,
        };
        job.job.set_baseline_suspend(baseline);

        let completion_point = match self.data.claim_ringbuf_range(&job.job.stream) {
            Ok(completion_point) => completion_point,
            Err(err) => {
                fence.signal(Err(err));
                return Err(err);
            }
        };

        job.job.set_completion_point(completion_point);

        let Some(reservation) = job.job.reservation.as_ref() else {
            fence.signal(Err(EINVAL));
            return Err(EINVAL);
        };

        if let Err((err, fence)) = reservation.consume(completion_point, fence) {
            fence.signal(Err(err));
            return Err(err);
        }

        if let Err(err) = self.data.commit_ringbuf_range(completion_point) {
            self.data.signal_submit_fence(completion_point, Err(err));
            return Err(err);
        }

        trace::job_submit(
            completion_point,
            self.data.group_id(),
            self.data.cs_id,
            job.job.stream.len() as u32,
        );

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
            if let Some(doorbell) = self.data.doorbell_id() {
                trace::queue_doorbell(self.data.group_id(), self.data.cs_id, doorbell as u32);
            }
            // The doorbell ring above puts the queue back in firmware
            // hands without going through a tick first. Record the
            // transition for devfreq accounting now so the governor
            // observes the busy delta between ticks. The locked
            // critical section does only `Instant::now()` and field
            // updates, with no `GFP_KERNEL` allocation, no
            // `dma_resv_lock`, and no `mmu_notifier` path.
            group.tdev.devfreq_state.lock().mark_busy();
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

        if let Err(err) = self.data.complete_submit_fences() {
            if let Some(completion_point) = ctx.job.completion_point() {
                self.data.signal_submit_fence(completion_point, Err(err));
            }
            return StageAdvance::TimedOut(err);
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
        let elapsed_ms = ctx.stage_elapsed().as_millis().max(0) as u32;
        let allowance_ms = allowance.as_millis().max(0) as u32;
        let faulted = adjusted_elapsed >= self.timeout;
        trace::deadline_check(
            self.data.group_id(),
            self.data.cs_id,
            elapsed_ms,
            allowance_ms,
            faulted,
        );

        if adjusted_elapsed >= self.timeout {
            let completion_point = ctx.job.completion_point().unwrap_or(0);
            pr_warn!(
                "queue job timed out: group={} cs={} completion_point={} elapsed_ms={}\n",
                self.data.group_id(),
                self.data.cs_id,
                completion_point,
                elapsed_ms,
            );
            trace::group_timedout(self.data.group_id());
            ctx.job.group.with_locked_inner(|inner| {
                if inner.fatal_error.is_none() {
                    inner.fatal_error = Some(ETIMEDOUT);
                }
            });
            TyrDrmDeviceData::schedule_tick(&ctx.job.group.tdev);
            if let Some(completion_point) = ctx.job.completion_point() {
                self.data
                    .signal_submit_fence(completion_point, Err(ETIMEDOUT));
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
    pub(crate) fn new(
        tdev: &TyrDrmDevice,
        queue_args: &QueueCreate,
        vm: Arc<Vm>,
        cs_id: u32,
    ) -> Result<Self> {
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

        let data = Arc::pin_init(
            pin_init!(QueueData {
                priority: queue_args.priority(),
                cs_id,
                group_id: AtomicU64::new(0),
                ringbuf,
                interfaces,
                doorbell_id: AtomicUsize::new(UNASSIGNED_DOORBELL_ID),
                next_seqno: AtomicU64::new(0),
                iomem: tdev.iomem.clone(),
                pending_submit_fences <- new_mutex!(PendingFences {
                    vec: pending_fence_vec,
                    head: 0,
                    outstanding: 0,
                }),
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
    /// otherwise close via `JobQueue::state` → `dma_fence_map` →
    /// `mmu_notifier` → `fs_reclaim` → `pending_submit_fences`.
    pub(in crate::sched) fn reserve_pending_submit_fence(&self) -> Result<PendingFenceReservation> {
        let mut pending = self.data.pending_submit_fences.lock();
        let additional = pending.outstanding.checked_add(1).ok_or(EOVERFLOW)?;
        if pending.vec.len() + additional > pending.vec.capacity() {
            return Err(ENOSPC);
        }
        pending.outstanding = additional;
        Ok(PendingFenceReservation::new(self.data.clone()))
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
