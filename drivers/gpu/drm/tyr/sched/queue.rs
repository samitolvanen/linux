// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::{
    Deref,
    Range, //
};

use kernel::{
    alloc::KVec,
    dma_buf::{
        dma_fence::FenceWaitResult,
        fence_work::DmaFenceWorkqueue,
        Fence,
        SignallingSection, //
    },
    drm::{
        gem::{
            BaseObject,
            IntoGEMObject,
            //
        },
        job_queue::{
            JobQueue,
            JobQueueOps,
            JobRunnable,
            RunResult, //
        }, //
    },
    io::{
        mem::DevresIoMem,
        register::Array,
        Io,
        IoBase, //
    },
    new_mutex,
    new_spinlock,
    pr_err_once,
    pr_warn_once,
    prelude::*,
    sizes::{
        SZ_2M,
        SZ_4K,
        SZ_64K, //
    },
    str::CString,
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        },
        barrier::{
            dma_mb,
            mb,
            Read,
            Write, //
        },
        Arc,
        Mutex,
        SpinLock, //
    },
    time::{
        msecs_to_jiffies,
        Delta,
        Instant,
        Monotonic, //
    },
    transmute::FromBytes,
    uapi,
    workqueue, //
};

use crate::{
    cleanup,
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData,
        TyrDrmRegistrationData,
        DEVICE_PROFILING_CYCLES,
        DEVICE_PROFILING_TIMESTAMP, //
    },
    fw::{
        global::CsActivateInputs,
        CsDbMask,
        CsWaitCondition,
        Firmware, //
    },
    gem,
    regs::doorbell_block,
    trace,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    }, //
};

use super::{
    deps::PreparedJob,
    group::{
        Group,
        QueueIdx,
        State, //
    },
    job::JobProfilingData,
    SubmitTick, //
};

const UNASSIGNED_DOORBELL_ID: usize = usize::MAX;
pub(super) const JOB_TIMEOUT_MS: u32 = 5000;

/// Smallest ringbuffer byte count one wrapped job stream consumes.
///
/// `sched::job::build_wrapped_stream` emits 11 8-byte instructions and
/// pads them up to a 64-byte boundary, so the minimum is
/// `next_multiple_of(88, 64) == 128`. Profiled wrappers are larger. A job
/// takes one credit per `WRAPPER_RINGBUF_BYTES` of its wrapper. Used to size
/// the queue's credits, the pre-allocated pending-fence vec and the profiling
/// slot count. Sync-only jobs take no ring space but still take a credit and a
/// vec entry.
const WRAPPER_RINGBUF_BYTES: usize = 128;

/// Wrappers the queue's credits keep free for the lag of `EXTRACT`.
///
/// The `EXTRACT` the firmware publishes trails the jobs that have completed:
/// on a G610 it was seen up to three wrappers behind the queue's syncobj
/// with back-to-back small jobs. The firmware checks `INSERT` against that
/// value, so a job that finds the ring full waits for it to advance. The
/// credits leave twice the lag free to keep that wait rare.
const EXTRACT_LAG_WRAPPERS: usize = 6;
static_assert!(
    (MIN_RINGBUF_SIZE - RINGBUF_RESERVED_BYTES) / WRAPPER_RINGBUF_BYTES > 1 + EXTRACT_LAG_WRAPPERS
);

/// The hardware considers a CSF ring buffer full one 64-byte cache
/// line short of its allocated size.
pub(super) const RINGBUF_RESERVED_BYTES: usize = 64;

/// Smallest ring buffer size a queue can be created with.
pub(super) const MIN_RINGBUF_SIZE: usize = SZ_4K;

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

        if self.0.ringbuf_size < MIN_RINGBUF_SIZE as u32
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
    /// Runs the queue's jobs. Declared first, so no job runs while the
    /// other fields drop.
    #[pin]
    job_queue: JobQueue<TyrQueueOps>,
    priority: u8,
    /// Index of this queue within its owning group's `queues` vec.
    cs_id: u32,
    /// Owning group's pool handle, captured at queue-create time so
    /// tracepoints emitted without a `&Group` can carry a stable
    /// identifier.
    ///
    /// Set once by `set_group_id` before the queue is published to any
    /// path that can emit a tracepoint; reads after publish are stable.
    group_id: Atomic<u64>,
    /// Owning group's reuse-proof uid, captured alongside `group_id` so
    /// tracepoints emitted without a `&Group` can carry a handle-reuse
    /// proof identity. Published once by `set_group_id`.
    group_uid: Atomic<u64>,
    ringbuf: Arc<gem::MappedBo>,
    interfaces: Interfaces,
    doorbell_id: Atomic<usize>,
    /// Set while a submit waits for ring space. Changed under the
    /// slot-manager mutex.
    ring_full: Atomic<bool>,
    next_seqno: Atomic<u64>,
    /// Per-job profiling sample slots, mapped into the VM and the
    /// kernel. Holds `PendingFences::profiling_slot_count`
    /// `JobProfilingData` records.
    profiling_slots: Arc<gem::MappedBo>,
    iomem: Arc<DevresIoMem<SZ_2M>>,
    #[pin]
    pending_submit_fences: SpinLock<PendingFences>,
    /// Submit fence of the most recently committed job of any kind.
    #[pin]
    last_job_fence: Mutex<Option<ARef<Fence>>>,
    /// Active GPU sync-wait captured for this queue.
    #[pin]
    syncwait: Mutex<SyncWait>,
    /// Per-queue accounting of off-slot suspend time, credited against
    /// the job deadline. Nests inside `pending_submit_fences`.
    #[pin]
    suspend_state: SpinLock<SuspendState>,
    /// Set while `Queue::park` holds the queue, so that no deadline of its
    /// jobs is evaluated until the unpark.
    parked: Atomic<bool>,
}

impl QueueData {
    /// Total size of the queue's kernel BOs, summed into a group's
    /// fdinfo memory footprint.
    pub(super) fn mem_size(&self) -> usize {
        self.ringbuf.size() + self.interfaces.mem_size() + self.profiling_slots.size()
    }

    fn ringbuf_capacity(&self) -> usize {
        self.ringbuf.size() - RINGBUF_RESERVED_BYTES
    }

    /// The distance from `EXTRACT` to `INSERT` uses only the low 32 bits, so a
    /// torn read of `EXTRACT` still gives an exact distance.
    fn ringbuf_space_for(&self, instr_count: usize) -> Result<u64, RingBufferError> {
        let insert = self.interfaces.read_insert()?;
        let capacity = self.ringbuf_capacity() as u64;
        let extract = self.interfaces.read_extract()?;
        let used = u64::from((insert as u32).wrapping_sub(extract as u32));

        if used > capacity {
            return Err(RingBufferError::Inconsistent { insert, extract });
        }

        if instr_count as u64 > capacity - used {
            return Err(RingBufferError::Full);
        }

        Ok(insert)
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

    /// Sets the owning group's pool handle and reuse-proof uid. Must be
    /// called once after the group's pool index is reserved, before any
    /// path that can emit a tracepoint runs.
    pub(crate) fn set_group_id(&self, group_id: u64, group_uid: u64) {
        self.group_id.store(group_id, Relaxed);
        self.group_uid.store(group_uid, Relaxed);
    }

    fn group_id(&self) -> u64 {
        self.group_id.load(Relaxed)
    }

    fn group_uid(&self) -> u64 {
        self.group_uid.load(Relaxed)
    }

    pub(super) fn can_append(&self, instr_count: usize) -> Result<(), RingBufferError> {
        self.ringbuf_space_for(instr_count)?;
        Ok(())
    }

    /// Claims the next seqno and returns it.
    pub(super) fn claim_seqno(&self) -> u64 {
        self.next_seqno.fetch_add(1, Relaxed) + 1
    }

    /// Returns the highest seqno claimed so far on this queue.
    pub(crate) fn next_seqno(&self) -> u64 {
        self.next_seqno.load(Relaxed)
    }

    /// GPU virtual address of the profiling sample slot `slot`.
    pub(super) fn profiling_slot_va(&self, slot: u32) -> Result<u64> {
        let base = self.profiling_slots.kernel_va().ok_or(EINVAL)?.start;
        Ok(base + u64::from(slot) * size_of::<JobProfilingData>() as u64)
    }

    /// Copies `instrs` into the ringbuffer at the current `INSERT` and returns
    /// the ring offsets they occupy. The range end is the `INSERT` value
    /// `Self::commit_ringbuf_range` will publish once the caller has
    /// registered the matching pending submit fence.
    pub(super) fn claim_ringbuf_range(&self, instrs: &[u8]) -> Result<Range<u64>, RingBufferError> {
        let ringbuf_start = self.ringbuf_space_for(instrs.len())?;
        let completion_point = ringbuf_start.checked_add(instrs.len() as u64).ok_or(EIO)?;

        let ringbuf = self.ringbuf.vmap();
        let size = ringbuf.size();

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

        Ok(ringbuf_start..completion_point)
    }

    /// Points the ring copy of `job` at sample slot `slot`, before
    /// `Self::commit_ringbuf_range` publishes it. The copy ends at
    /// `completion_point`.
    ///
    /// The addresses stay inside `profiling_slots`, so the add never carries
    /// out of the 48-bit `MOV48` operand.
    fn relocate_profiling(&self, job: &QueueJob, completion_point: u64, slot: u32) {
        let delta = u64::from(slot) * size_of::<JobProfilingData>() as u64;
        let ringbuf_start = completion_point - job.stream.len() as u64;
        let ringbuf = self.ringbuf.vmap();
        let ring_mask = ringbuf.size() as u64 - 1;

        for &offset in job.profiling_relocs.iter() {
            let pos = ((ringbuf_start + offset as u64) & ring_mask) as usize;
            let written = match job.stream.get(offset..).and_then(|s| s.first_chunk()) {
                Some(instr) => {
                    let word = u64::from_le_bytes(*instr) + delta;
                    ringbuf.try_write64(word.to_le(), pos)
                }
                None => Err(EINVAL),
            };
            if written.is_err() {
                pr_err_once!("profiling relocation out of range\n");
            }
        }
    }

    /// Publishes a previously claimed ringbuffer range to the firmware.
    ///
    /// `completion_point` must equal the range end returned by the matching
    /// `claim_ringbuf_range`. `extract_init` and the ringbuffer bytes are
    /// written before the leading `mb(Write)`, so they land before `insert`.
    /// The trailing `mb(Write)` orders `insert` before the doorbell ring.
    ///
    /// The `extract` read here can race the firmware, but it need not be
    /// exact. `program_csg_activate` re-latches `extract_init` for every
    /// queue while the CSG is unbound, and the firmware starts a CS from
    /// that value.
    pub(super) fn commit_ringbuf_range(&self, completion_point: u64) -> Result {
        let prev_insert = if trace::cs_ringbuf_dump_enabled() {
            Some(self.interfaces.read_insert()?)
        } else {
            None
        };
        let extract = self.interfaces.read_extract()?;
        self.interfaces.write_extract_init(extract)?;

        mb(Write);
        self.interfaces.write_insert(completion_point)?;
        trace::fw_cs_ringbuf_publish(self.group_id(), self.cs_id, completion_point, extract);

        // Dump the first 32 bytes of the just-committed range so the
        // Mali prologue can be inspected from trace alone. Wraparound
        // is handled by masking each 8-byte offset into the ringbuf.
        let ringbuf_sz = self.ringbuf.size() as u64;
        if let Some(prev_insert) =
            prev_insert.filter(|&prev| ringbuf_sz != 0 && completion_point > prev)
        {
            let ringbuf = self.ringbuf.vmap();
            let mut words = [0u64; 4];
            let payload = completion_point - prev_insert;
            for (i, word) in words.iter_mut().enumerate() {
                let off = prev_insert + (i as u64) * 8;
                if off + 8 > prev_insert + payload {
                    break;
                }
                let cs_off = (off & (ringbuf_sz - 1)) as usize;
                *word = ringbuf.try_read64(cs_off).unwrap_or(0);
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

        mb(Write);
        trace::cs_ring_ptrs(
            self.group_id(),
            self.group_uid(),
            self.cs_id,
            completion_point,
            extract,
        );
        Ok(())
    }

    pub(super) fn kick(&self) -> Result {
        let io = self.iomem.try_access().ok_or(ENODEV)?;
        let doorbell_id = self.doorbell_id().ok_or(EINVAL)?;
        let doorbell_reg = doorbell_block::DOORBELL::try_at(doorbell_id).ok_or(EINVAL)?;

        trace::fw_doorbell_ring(doorbell_id as u32);
        io.try_write(
            doorbell_reg,
            doorbell_block::DOORBELL::zeroed().with_ring(true),
        )
    }

    /// Signals each leading pending submit fence whose `done_seqno` is
    /// `<= up_to_seqno`. Each fence signals under `pending_submit_fences`,
    /// so concurrent drains signal in seqno order.
    ///
    /// `on_drain` sees each entry between its fence signal and the head
    /// advance, under the pending-submit-fences spinlock, so it must not sleep.
    ///
    /// Returns the number of fences signaled and the `done_seqno` of the
    /// last one.
    fn signal_submit_fences_up_to(
        &self,
        up_to_seqno: u64,
        result: Result,
        mut on_drain: impl FnMut(&PendingSubmitFence),
    ) -> (u32, u64) {
        let mut drained_count: u32 = 0;
        let mut last_done_seqno: u64 = 0;

        loop {
            let _section = SignallingSection::begin();
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
            let timed = entry.is_timed();
            let done_seqno = entry.done_seqno;
            let taken = entry.take_fence(result);
            if let Some((fence_seqno, result)) = taken {
                self.job_queue
                    .complete_jobs_up_to_seqno(fence_seqno, result);
                trace::submit_fence_signal(
                    self.group_id(),
                    self.group_uid(),
                    self.cs_id,
                    done_seqno,
                    match result {
                        Ok(()) => 0,
                        Err(e) => e.to_errno(),
                    },
                );
                drained_count += 1;
                last_done_seqno = done_seqno;
            }
            on_drain(entry);
            pending.head = head + 1;
            if timed {
                self.start_head_timeout(&mut pending);
            }
        }

        (drained_count, last_done_seqno)
    }

    /// Reads the profiling sample in slot `slot`.
    fn read_profiling_sample(&self, slot: u32) -> Result<JobProfilingData> {
        let offset = slot as usize * size_of::<JobProfilingData>();
        JobProfilingData::read(&self.profiling_slots, offset)
    }

    /// Accumulates the enabled before/after deltas of `sample` into
    /// `group`'s fdinfo.
    ///
    /// A read error is logged and skipped, because a missed sample must not
    /// abort fence completion.
    fn accumulate_profiling_sample(group: &Group, sample: Result<JobProfilingData>, mask: u32) {
        let data = match sample {
            Ok(data) => data,
            Err(err) => {
                dev_err!(
                    group.tdev.as_ref(),
                    "profiling slot read failed: {}\n",
                    err.to_errno()
                );
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

    /// Compacts the drained prefix away once `head` reaches
    /// `max(len / 2, 16)`, or once `head` is non-zero in a full vec so that
    /// `push_submit_fence` finds a free slot.
    ///
    /// Must preserve `vec.capacity()`, which bounds the submitted jobs whose
    /// fences have not drained yet. `KVec::retain` shifts surviving entries
    /// in place and only adjusts `len`, leaving the underlying allocation
    /// intact.
    fn maybe_truncate_pending(pending: &mut PendingFences) {
        let len = pending.vec.len();
        let threshold = if len == pending.vec.capacity() {
            1
        } else {
            core::cmp::max(len / 2, 16)
        };
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

    /// Pushes the job with fence sequence number `fence_seqno` into the
    /// pending list.
    ///
    /// Every entry is a job that holds at least one of the queue's credits,
    /// and the vec has room for as many entries as the queue has credits, so
    /// the push does not fail. It must not sleep or allocate under the
    /// pending-submit-fences spinlock.
    ///
    /// Returns the profiling sample slot assigned to the job, if
    /// `profiling_mask` enables sampling.
    fn push_submit_fence(
        &self,
        done_seqno: u64,
        ringbuf_range: Range<u64>,
        fence_seqno: u64,
        error: Option<Error>,
        baseline_suspend: Delta,
        profiling_mask: u32,
    ) -> Option<u32> {
        let mut pending = self.pending_submit_fences.lock();
        Self::push_locked(
            &mut pending,
            done_seqno,
            ringbuf_range,
            fence_seqno,
            error,
            baseline_suspend,
            profiling_mask,
        )
    }

    fn push_locked(
        pending: &mut PendingFences,
        done_seqno: u64,
        ringbuf_range: Range<u64>,
        fence_seqno: u64,
        error: Option<Error>,
        baseline_suspend: Delta,
        profiling_mask: u32,
    ) -> Option<u32> {
        Self::maybe_truncate_pending(pending);
        let profiling_slot = (profiling_mask != 0).then_some(pending.next_profiling_slot);
        // A sync-only job pushed after a CS fault failed the job it completes
        // with takes the same error.
        let fault = pending
            .fault
            .filter(|(seqno, _)| *seqno == done_seqno)
            .map(|(_, err)| err);
        let pending_fence = PendingSubmitFence {
            done_seqno,
            ringbuf_range,
            profiling_slot: profiling_slot.unwrap_or(0),
            profiling_mask,
            fence: Some(fence_seqno),
            error: error.or(fault),
            unpushed: error.is_some(),
            started: Instant::<Monotonic>::now(),
            baseline_suspend,
        };

        if pending.vec.push_within_capacity(pending_fence).is_err() {
            pr_warn_once!("queue pending-fence vec is full\n");
            return None;
        }
        if let Some(slot) = profiling_slot {
            let next = slot + 1;
            pending.next_profiling_slot = if next < pending.profiling_slot_count {
                next
            } else {
                0
            };
        }
        profiling_slot
    }

    /// Signals the job with fence sequence number `fence_seqno`, which was
    /// never pushed, with `err`. While an older pending fence is live, it
    /// is queued behind that one with `err` instead, so the queue signals
    /// its fences in order.
    fn signal_unpushed_fence(&self, fence_seqno: u64, err: Error) {
        let _section = SignallingSection::begin();
        let mut pending = self.pending_submit_fences.lock();
        let head = pending.head;
        if pending.vec.iter().skip(head).any(|e| e.fence.is_some()) {
            Self::push_locked(
                &mut pending,
                self.next_seqno(),
                0..0,
                fence_seqno,
                Some(err),
                Delta::ZERO,
                0,
            );
            return;
        }
        self.job_queue
            .complete_jobs_up_to_seqno(fence_seqno, Err(err));
        trace::submit_fence_signal(
            self.group_id(),
            self.group_uid(),
            self.cs_id,
            self.next_seqno(),
            err.to_errno(),
        );
    }

    /// Fails the pending fence for `done_seqno` with `err`. While an older
    /// pending fence is live, the error is staged for the in-order drain.
    pub(super) fn fail_submit_fence(&self, done_seqno: u64, err: Error) {
        let _section = SignallingSection::begin();
        let mut pending = self.pending_submit_fences.lock();
        let head = pending.head;
        let mut older_live = false;
        let mut signaled = None;
        for (idx, entry) in pending.vec.iter_mut().enumerate().skip(head) {
            if entry.done_seqno == done_seqno && entry.fence.is_some() {
                entry.profiling_mask = 0;
                if older_live {
                    entry.error = Some(err);
                } else if let Some(fence_seqno) = entry.fence.take() {
                    self.job_queue
                        .complete_jobs_up_to_seqno(fence_seqno, Err(err));
                    trace::submit_fence_signal(
                        self.group_id(),
                        self.group_uid(),
                        self.cs_id,
                        done_seqno,
                        err.to_errno(),
                    );
                    signaled = Some((idx, !entry.unpushed));
                }
                break;
            }
            older_live |= entry.fence.is_some();
        }
        // No entry before a signaled one is live, so drain them all. An
        // entry left behind would hold a slot after the job's credit has
        // come back.
        if let Some((idx, timed)) = signaled {
            pending.head = idx + 1;
            if timed {
                self.start_head_timeout(&mut pending);
            }
        }
    }

    /// Starts the job timeout of the oldest timed entry of `pending`, after
    /// the caller drained the one ahead of it.
    fn start_head_timeout(&self, pending: &mut PendingFences) {
        let head = pending.head;
        let Some(entry) = pending.vec.iter_mut().skip(head).find(|e| e.is_timed()) else {
            return;
        };
        let (accumulated, in_flight_since) = self.suspend_snapshot();
        let now = Instant::<Monotonic>::now();
        entry.started = now;
        entry.baseline_suspend = match in_flight_since {
            Some(start) => accumulated + (now - start),
            None => accumulated,
        };
    }

    /// Signals every leading pending submit fence whose stored
    /// `done_seqno` is at or below `syncobj_seqno`, which the caller
    /// reads with `Group::read_syncobj_raw`. `syncobj_status` is
    /// carried only into the `sync_upd_drain` trace.
    ///
    /// The syncobj is the completion gate rather than the firmware's
    /// `EXTRACT` pointer. Each wrapper bumps it only after
    /// `WAIT(all scoreboards)`, so every async sub-job the job
    /// dispatched has landed. `EXTRACT` would race them.
    ///
    /// `TyrQueueOps::run_job` and the group's timeout work also call this
    /// as a backstop for a missed sync-update IRQ.
    ///
    /// For each completed job, the per-job profiling samples are read
    /// back from the slot BO and accumulated into `group`'s fdinfo.
    ///
    /// Obeys the dma-fence signalling-section constraints, because the
    /// readback only reads a kernel-mapped BO (normal memory) and takes the
    /// fdinfo spinlock. It allocates nothing, takes no `dma_resv` lock, and
    /// waits on no fence.
    pub(in crate::sched) fn complete_submit_fences(
        &self,
        group: &Group,
        syncobj_seqno: u64,
        syncobj_status: u32,
    ) {
        // No sample may be read before the sync object that marks it complete.
        dma_mb(Read);
        let (drained_count, last_done_seqno) =
            self.signal_submit_fences_up_to(syncobj_seqno, Ok(()), |entry| {
                if entry.profiling_mask != 0 {
                    // Read the sample before the head advance lets its slot be
                    // reassigned.
                    let sample = self.read_profiling_sample(entry.profiling_slot);
                    Self::accumulate_profiling_sample(group, sample, entry.profiling_mask);
                }
            });

        if drained_count > 0 {
            trace::sync_upd_drain(
                self.group_id(),
                self.cs_id,
                last_done_seqno,
                drained_count,
                syncobj_seqno,
                syncobj_status,
            );
        }
    }

    /// Returns the firmware's current `EXTRACT` offset.
    pub(super) fn read_extract(&self) -> Result<u64> {
        self.interfaces.read_extract()
    }

    /// Stages `err` on the pending submit fence of the job whose ring range
    /// holds `extract`, and on the sync-only jobs that complete with it. The
    /// in-order drain signals the fences once the job retires.
    pub(in crate::sched) fn fail_job_at_extract(&self, extract: u64, err: Error) {
        let mut pending = self.pending_submit_fences.lock();
        let head = pending.head;
        let Some(done_seqno) = pending
            .vec
            .iter()
            .skip(head)
            .find(|entry| entry.ringbuf_range.contains(&extract))
            .map(|entry| entry.done_seqno)
        else {
            return;
        };
        pending.fault = Some((done_seqno, err));
        for entry in pending.vec.iter_mut().skip(head) {
            if entry.done_seqno == done_seqno && entry.fence.is_some() && !entry.unpushed {
                entry.error = Some(err);
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
    pub(crate) fn set_syncwait(
        &self,
        gpu_va: u64,
        ref_val: u64,
        sync64: bool,
        condition: Option<CsWaitCondition>,
    ) {
        let mut wait = self.syncwait.lock();
        wait.gpu_va = gpu_va;
        wait.ref_val = ref_val;
        wait.sync64 = sync64;
        wait.condition = condition;
        drop(wait);
        trace::queue_state(self.group_id(), self.cs_id, gpu_va != 0);
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
        Ok(self.interfaces.read_insert()? == self.interfaces.read_extract()?)
    }

    /// Returns the current `(insert, extract)` ringbuffer cursor pair
    /// read from the kernel-visible mailbox pages. Used by the MMU
    /// fault path to capture the GPU's view of the queue without
    /// going through the firmware interface.
    pub(crate) fn ringbuf_ptrs(&self) -> Result<(u64, u64)> {
        Ok((
            self.interfaces.read_insert()?,
            self.interfaces.read_extract()?,
        ))
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
    /// `Vm::try_with_bo_for_va`, which takes `gpuvm_unique` via
    /// `try_lock()` to keep the helper safe from the dma-fence
    /// signalling section in `Scheduler::process_fw_events`, because
    /// that mutex composes with `GFP_KERNEL` allocation on the
    /// `vm_bind_ioctl` paths, so a blocking acquisition would create a
    /// `dma_fence_map -> fs_reclaim` edge. If the lock is held
    /// elsewhere the helper returns a `LockContended` sentinel
    /// rather than waiting. The read goes through the queue's
    /// existing kernel vmap; no allocation, no `dma_resv_lock`, no
    /// `mmu_notifier` callback.
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

        let lookup = vm.try_with_bo_for_va(gpu_va, |bo, bo_offset| {
            let ringbuf_obj = core::ptr::eq(
                IntoGEMObject::as_raw(&***self.ringbuf),
                IntoGEMObject::as_raw(bo),
            );
            (bo_offset, bo.is_imported(), ringbuf_obj)
        });
        let (bo_offset, imported, ringbuf_obj) = match lookup {
            Ok(Some(hit)) => hit,
            Ok(None) => return trace::CsUserStreamDump::default(),
            Err(()) => {
                return trace::CsUserStreamDump {
                    status: trace::CsUserStreamDumpStatus::LockContended,
                    ..Default::default()
                };
            }
        };

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
        // user CS BO) `BoVmap::new` would have to take
        // `dma_resv_lock` and a `GFP_KERNEL` vmap, both forbidden
        // here. Report those cases via `BoNotVmapped` so the trace
        // consumer can see that we located the BO but could not read.
        if !ringbuf_obj {
            return trace::CsUserStreamDump {
                bo_va_base,
                bo_offset,
                status: trace::CsUserStreamDumpStatus::BoNotVmapped,
                ..Default::default()
            };
        }

        let vmap = self.ringbuf.vmap();
        let bo_size = vmap.size();
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
        for (i, slot) in bytes[..len].iter_mut().enumerate() {
            *slot = vmap.try_read8(start + i).unwrap_or(0);
        }

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

    /// Reads the 64 bytes (eight Mali CSF instructions) starting at
    /// the firmware's execution pointer `cs_extract`, taken from the
    /// queue's ringbuffer vmap with the standard `extract % size`
    /// wrap. Returns `(ringbuf_va, bytes, len)` where `ringbuf_va`
    /// is the GPU VA the first byte was read from. `len` is the
    /// number of valid bytes in `bytes` (always 64 on a clean read;
    /// 0 if the ringbuf has no vmap or no GPU VA). Used by the
    /// CS_FAULT / CS_FATAL trace path to feed
    /// [`crate::trace::cs_fault_instruction_decode`].
    pub(crate) fn ringbuf_instructions_at_extract(&self, cs_extract: u64) -> (u64, [u8; 64], u32) {
        let vmap = self.ringbuf.vmap();
        let size = vmap.size();
        if size == 0 || !size.is_power_of_two() {
            return (0, [0u8; 64], 0);
        }
        let Some(ringbuf_base) = self.ringbuf.kernel_va().map(|r| r.start) else {
            return (0, [0u8; 64], 0);
        };

        let mask = (size as u64).wrapping_sub(1);
        let start = (cs_extract & mask) as usize;
        let ringbuf_va = ringbuf_base.wrapping_add(cs_extract & mask);

        let mut bytes = [0u8; 64];
        for (i, slot) in bytes.iter_mut().enumerate() {
            let pos = ((start + i) as u64 & mask) as usize;
            *slot = vmap.try_read8(pos).unwrap_or(0);
        }
        (ringbuf_va, bytes, 64)
    }

    /// Reads eight u64 ringbuffer words around `extract`, the four words
    /// immediately before the firmware's decode pointer (at offsets -32, -24,
    /// -16, -8 from `extract`) followed by the four words at and ahead of
    /// `extract` (offsets 0, +8, +16, +24). All offsets are taken modulo the
    /// ringbuffer size so the window wraps correctly. Used by the MMU fault
    /// path to attach a ringbuf snapshot covering the actively-decoded
    /// instruction to the fault trace.
    pub(crate) fn ringbuf_window_around_extract(&self, extract: u64) -> [u64; 8] {
        let vmap = self.ringbuf.vmap();
        let size = vmap.size();
        if size == 0 || !size.is_power_of_two() {
            return [0u64; 8];
        }

        let mask = (size as u64).wrapping_sub(1);
        let offsets: [i64; 8] = [-32, -24, -16, -8, 0, 8, 16, 24];
        let mut words = [0u64; 8];
        for (i, off) in offsets.iter().enumerate() {
            let start = ((extract as i64).wrapping_add(*off) as u64) & mask;
            let mut buf = [0u8; 8];
            for j in 0..8 {
                let pos = ((start + j) & mask) as usize;
                buf[j as usize] = vmap.try_read8(pos).unwrap_or(0);
            }
            words[i] = u64::from_le_bytes(buf);
        }
        words
    }

    /// Synchronizes the queue's `input.extract_init` from the firmware's
    /// current `output.extract` value.
    ///
    /// Must be called before staging `CS_REQ.state = Start` at CSG-bind
    /// time so the firmware sees a consistent `(insert, extract_init)`
    /// snapshot when it starts reading the per-queue ringbuf mailbox.
    pub(crate) fn sync_extract_init(&self) -> Result {
        let extract = self.interfaces.read_extract()?;
        self.interfaces.write_extract_init(extract)
    }

    /// Reads back the firmware-visible ringbuf mailbox pointers for tracing.
    /// Returns `(insert, extract, extract_init)` sampled from the queue
    /// interface BO. Intended to be called at CSG-bind time,
    /// after `sync_extract_init`, so `extract_init` reflects the value
    /// the firmware will sample when it starts reading the ringbuf.
    pub(crate) fn ringbuf_state_for_trace(&self) -> Result<(u64, u64, u64)> {
        let insert = self.interfaces.read_insert()?;
        let extract = self.interfaces.read_extract()?;
        let extract_init = self.interfaces.read_extract_init()?;
        Ok((insert, extract, extract_init))
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
    /// is currently suspended off its CSG slot. `t` is the monotonic
    /// instant at which that suspend interval began.
    fn suspend_snapshot(&self) -> (Delta, Option<Instant<Monotonic>>) {
        let state = self.suspend_state.lock();
        (state.accumulated, state.since)
    }

    /// Returns the `done_seqno` of the oldest live job and how long it has
    /// left before `JOB_TIMEOUT_MS`, not counting the time the queue spent
    /// suspended off its CSG slot since the job reached the queue head. A
    /// queue blocked on a sync wait gets no such credit when no queue in its
    /// group is active. Also returns the elapsed time and the suspend credit
    /// in milliseconds, for the `deadline_check` tracepoint.
    pub(super) fn oldest_job_deadline(&self) -> Option<(u64, Delta, u32, u32)> {
        if self.parked.load(Relaxed) {
            return None;
        }

        let (done_seqno, started, baseline_suspend) = {
            let pending = self.pending_submit_fences.lock();
            let head = pending.head;
            let entry = pending.vec.iter().skip(head).find(|e| e.is_timed())?;
            (entry.done_seqno, entry.started, entry.baseline_suspend)
        };

        let (accumulated, in_flight_since) = self.suspend_snapshot();
        let mut suspended = accumulated;
        if let Some(start) = in_flight_since {
            suspended += Instant::<Monotonic>::now() - start;
        }
        let allowance = (suspended - baseline_suspend).as_millis().max(0);
        let elapsed = (Instant::<Monotonic>::now() - started).as_millis().max(0);
        let adjusted_elapsed = (elapsed - allowance).max(0);

        Some((
            done_seqno,
            Delta::from_millis(i64::from(JOB_TIMEOUT_MS) - adjusted_elapsed),
            elapsed as u32,
            allowance as u32,
        ))
    }

    /// Marks the queue as suspended off its CSG slot.
    ///
    /// Records the current monotonic instant so a later
    /// `Self::resume_timeout` can fold the interval into
    /// `SuspendState::accumulated`. No-op when the queue is already
    /// suspended. This preserves the existing start time rather than
    /// restarting the interval.
    pub(super) fn suspend_timeout(&self) {
        let mut state = self.suspend_state.lock();
        let opened = state.since.is_none();
        if opened {
            state.since = Some(Instant::<Monotonic>::now());
        }
        drop(state);
        if opened {
            trace::queue_timeout_state(self.group_id(), self.cs_id, true);
        }
    }

    /// Marks the queue as resumed onto its CSG slot.
    ///
    /// Adds the time since the matching `Self::suspend_timeout` to
    /// `SuspendState::accumulated`. No-op if the queue is not
    /// currently suspended.
    pub(super) fn resume_timeout(&self) {
        let mut state = self.suspend_state.lock();
        let closed = if let Some(start) = state.since.take() {
            let elapsed = Instant::<Monotonic>::now() - start;
            state.accumulated += elapsed;
            true
        } else {
            false
        };
        drop(state);
        if closed {
            trace::queue_timeout_state(self.group_id(), self.cs_id, false);
        }
    }
}

pub(super) struct TyrQueueOps {
    wq: Arc<DmaFenceWorkqueue>,
    _hold: cleanup::JobQueueHold,
}

impl QueueData {
    /// Cancels a job of a group that can no longer run.
    fn cancel_job(&self, job: &QueueJob, fence_seqno: u64) {
        TyrDrmDeviceData::schedule_tick(&job.group.tdev);
        self.signal_unpushed_fence(fence_seqno, ECANCELED);
    }

    /// Fails the queue of `job` after a ring claim error.
    fn fail_queue(&self, job: &QueueJob, fence_seqno: u64, err: RingBufferError) {
        let group = &job.group;
        group.with_locked_inner(|inner| inner.set_queue_fatal(job.queue_index));
        trace::queue_fatal_state(self.group_id(), self.cs_id, true);
        group.detach_and_terminate();
        match err {
            RingBufferError::Inconsistent { insert, extract } => pr_warn!(
                "queue {} has inconsistent ring pointers: insert={:#x}, extract={:#x}, pid={}, comm={}\n",
                job.queue_index.get(),
                insert,
                extract,
                group.task_pid(),
                group.task_comm()
            ),
            RingBufferError::Full | RingBufferError::Other => pr_warn!(
                "queue {} ring claim failed: pid={}, comm={}\n",
                job.queue_index.get(),
                group.task_pid(),
                group.task_comm()
            ),
        }
        self.cancel_job(job, fence_seqno)
    }

    /// Rechecks the ring space for `job` under the slot-manager mutex, so no
    /// `Queue::wake_ring_full` call is missed. On a full ring, requests an
    /// `EXTRACT_EVENT` while the group is active.
    fn request_ring_space(&self, job: &QueueJob) -> Result<(), RingBufferError> {
        let tdev = &job.group.tdev;
        let awake = tdev.pm_get_if_active();
        let guard = tdev.registration_guard();
        let _slots = tdev.csg_slot_manager.lock();

        let space = self.can_append(job.stream.len());
        let full = matches!(space, Err(RingBufferError::Full));
        self.ring_full.store(full, Relaxed);
        if !full {
            return space;
        }

        let csg_id = job
            .group
            .with_locked_inner(|inner| inner.csg_id.filter(|_| inner.state == State::Active));
        let (Some(_), Some(guard), Some(csg_id)) = (&awake, &guard, csg_id) else {
            return space;
        };
        guard.registration_data_with(|reg_data| {
            arm_extract_event(&reg_data.fw, csg_id, job.queue_index)
        })?;
        space
    }

    /// Copies the wrapper of `job`, whose fence has sequence number
    /// `fence_seqno`, into the ring and rings the doorbell. Returns the
    /// `done_seqno` the job completes at when it is pushed, or `RingFull`,
    /// leaving the job unclaimed, while the ring has no room for the wrapper.
    fn submit_job(&self, job: &QueueJob, fence_seqno: u64) -> Result<Option<u64>, RingFull> {
        if !job.group.can_run() {
            self.cancel_job(job, fence_seqno);
            return Ok(None);
        }

        // Fold any in-flight suspend interval into the baseline so it
        // matches the shape the timeout stage uses on the consumer
        // side. Subtraction is exact only when both sides fold.
        let (accumulated, in_flight_since) = self.suspend_snapshot();
        let baseline = match in_flight_since {
            Some(start) => accumulated + (Instant::<Monotonic>::now() - start),
            None => accumulated,
        };

        if job.stream.is_empty() {
            // A sync-only job completes with the command-stream job before
            // it, or at once when there is none.
            let done_seqno = self.next_seqno();
            if done_seqno == 0 {
                self.job_queue
                    .complete_jobs_up_to_seqno(fence_seqno, Ok(()));
                trace::submit_fence_signal(self.group_id(), self.group_uid(), self.cs_id, 0, 0);
                return Ok(None);
            }
            self.push_submit_fence(
                done_seqno,
                0..0,
                fence_seqno,
                None,
                baseline,
                job.profiling_mask,
            );
            job.group.arm_timeout();
            return Ok(Some(done_seqno));
        }

        let mut space = self.can_append(job.stream.len());
        if matches!(space, Err(RingBufferError::Full)) {
            space = self.request_ring_space(job);
        }
        if let Err(err) = space {
            if matches!(err, RingBufferError::Full) {
                return Err(RingFull);
            }
            self.fail_queue(job, fence_seqno, err);
            return Ok(None);
        }

        let ringbuf_range = match self.claim_ringbuf_range(&job.stream) {
            Ok(range) => range,
            Err(err) => {
                self.fail_queue(job, fence_seqno, err);
                return Ok(None);
            }
        };

        // Jobs run one at a time in submit order, so the seqnos follow the
        // ring.
        let done_seqno = self.claim_seqno();
        let profiling_slot = self.push_submit_fence(
            done_seqno,
            ringbuf_range.clone(),
            fence_seqno,
            None,
            baseline,
            job.profiling_mask,
        );
        if let Some(slot) = profiling_slot {
            self.relocate_profiling(job, ringbuf_range.end, slot);
        }
        job.group.arm_timeout();

        if let Err(err) = self.commit_ringbuf_range(ringbuf_range.end) {
            pr_warn_once!("queue ring commit failed: {}\n", err.to_errno());
            self.fail_submit_fence(done_seqno, err);
            return Ok(Some(done_seqno));
        }

        trace::job_submit(
            done_seqno,
            self.group_id(),
            self.group_uid(),
            self.cs_id,
            job.stream.len() as u32,
        );

        // `Scheduler::program_csg_activate` and `CsgSlotOps::evict` update
        // `csg_id` and the per-queue `doorbell_id` together under this lock,
        // so a bound group observed here keeps its doorbell for the whole
        // kick. Ringing outside the lock would race an eviction and fail the
        // kick for committed ringbuf bytes.
        //
        // Ring only while the device is runtime-active. When it is not, a
        // suspend is evicting the group and the rebind re-rings the
        // committed bytes.
        let group = &job.group;
        let awake = group.tdev.pm_get_if_active();
        let device_active = awake.is_some();
        let queue_index = job.queue_index;
        let resident = group.tdev.with_locked_scheduler(|sched| {
            let (active, kick_err, blocked, resume_tick) = group.with_locked_inner(|inner| {
                if inner.csg_id.is_none() || inner.state != State::Active {
                    return (false, Ok(()), false, false);
                }
                let group_idle = inner.is_idle();
                let blocked = inner.blocked_queues() & queue_index.bit() != 0;
                let queue_idle = inner.set_queue_idle(queue_index, false);
                let resume_tick = group_idle && queue_idle && !blocked;
                if awake.is_none() {
                    return (true, Ok(()), blocked, resume_tick);
                }
                let kick_res = self.kick();
                (true, kick_res, blocked, resume_tick)
            });
            if !active {
                return Ok(None);
            }
            kick_err?;
            if let Some(doorbell) = self.doorbell_id() {
                trace::queue_doorbell(self.group_id(), self.cs_id, doorbell as u32);
            }
            if device_active {
                self.resume_timeout();
            }
            if !blocked {
                // This path does not always schedule a tick, so record the busy
                // edge here.
                group.tdev.devfreq_data.devfreq_state.lock().mark_busy();
                if sched.pm_ref.is_none() {
                    sched.pm_ref = group.tdev.sched_pm_get();
                    trace::pm_usage(trace::PmUsageEvent::Acquire, sched.pm_ref.is_some());
                }
            }
            let tick = if resume_tick {
                sched.resident_submit_tick()
            } else {
                SubmitTick::None
            };
            Ok(Some(tick))
        });
        drop(awake);

        let resident = match resident {
            Ok(resident) => resident,
            Err(err) => {
                pr_warn_once!("queue doorbell kick failed: {}\n", err.to_errno());
                self.fail_submit_fence(done_seqno, err);
                return Ok(Some(done_seqno));
            }
        };

        if let Some(tick) = resident {
            tick.dispatch(&group.tdev);
        } else {
            // A concurrent eviction requeues by live ring state, so the
            // bytes committed above are still kicked.
            let tick = match group.tdev.with_locked_scheduler(|sched| {
                let blocked = group.with_locked_inner(|inner| {
                    inner.set_queue_idle(queue_index, false);
                    inner.blocked_queues() & queue_index.bit() != 0
                });
                // The bind after the wait resolves kicks this queue.
                if blocked {
                    TyrDrmDeviceData::schedule_sync_upd(&group.tdev);
                    return Ok(SubmitTick::None);
                }
                sched.mark_group_runnable(group);
                Ok(sched.submit_tick(&group.tdev, group.priority))
            }) {
                Ok(tick) => tick,
                Err(err) => {
                    pr_warn_once!("queue group scheduling failed: {}\n", err.to_errno());
                    self.fail_submit_fence(done_seqno, err);
                    return Ok(Some(done_seqno));
                }
            };
            tick.dispatch(&group.tdev);
        }

        Ok(Some(done_seqno))
    }

    /// Completes the jobs the syncobj of `group`'s queue `queue_index` shows
    /// complete, as a backstop for a missed sync-update IRQ. A failed read
    /// fails the job that completes at `done_seqno`.
    pub(super) fn complete_from_syncobj(
        &self,
        group: &Group,
        queue_index: QueueIdx,
        done_seqno: u64,
    ) {
        match group.read_syncobj_raw(queue_index.get()) {
            Ok((seqno, status)) => self.complete_submit_fences(group, seqno, status),
            Err(err) => self.fail_submit_fence(done_seqno, err),
        }
    }
}

/// Requests an `EXTRACT_EVENT` from CS `cs_id` of CSG slot `csg_id`, unless
/// one is pending.
fn arm_extract_event(fw: &Firmware<'_>, csg_id: usize, cs_id: QueueIdx) -> Result {
    let requested = fw.with_csg_mut(csg_id, |csg| {
        csg.cs_mut(cs_id.get())
            .ok_or(EINVAL)?
            .request_extract_event()
    })?;
    if requested {
        fw.with_csg_mut_ring_doorbell(csg_id, |csg| {
            csg.toggle_input_db_req(CsDbMask::from_raw(cs_id.bit()))
        })?;
    }
    Ok(())
}

impl JobQueueOps for TyrQueueOps {
    type JobDataType = QueueJob;

    const SERIAL_EXECUTION: bool = true;

    fn run_job<'a>(&self, job: JobRunnable<'a, QueueJob>) -> RunResult {
        let _section = SignallingSection::begin();
        let JobRunnable { seqno, data: job } = job;
        let queue = &job.queue;

        match queue.submit_job(job, seqno) {
            Ok(Some(done_seqno)) => {
                queue.complete_from_syncobj(&job.group, job.queue_index, done_seqno)
            }
            Ok(None) => {}
            Err(RingFull) => return RunResult::NoResources,
        }
        RunResult::Ran
    }

    fn workqueue(&self) -> &workqueue::Queue {
        self.wq.queue()
    }

    fn kill(&self, _jq_id: u64, _err: Error) {
        // A dependency of one of this queue's jobs failed. Tyr goes on, as
        // panthor does under drm_sched: the job still runs, and if it faults
        // on the GPU, that fails it like any other job.
    }
}

pub(super) type PreparedQueueJob<'a> = PreparedJob<'a, TyrQueueOps>;

pub(super) struct QueueJob {
    stream: KVec<u8>,
    /// The queue that runs the job. Drops before `group`, which owns the
    /// queue, so a queue never drops from its own JobQueue's DropWorker.
    queue: Arc<QueueData>,
    /// The owning group, which `TyrQueueOps::run_job` uses to submit, cancel
    /// or complete the job.
    pub(super) group: Arc<Group>,
    /// Index of the owning queue inside `Group::queues`.
    queue_index: QueueIdx,
    /// Snapshot of the device profile mask taken at submit time. Selects
    /// which sample deltas the completion path accumulates. `0` when the
    /// job carries no profiling slot.
    profiling_mask: u32,
    /// Offsets in `stream` of the `MOV48`s that load the profiling sample
    /// addresses, moved from slot 0 to the job's slot when the job is
    /// written to the ring.
    profiling_relocs: KVec<usize>,
}

impl QueueJob {
    pub(super) fn new(
        stream: KVec<u8>,
        queue: &Queue,
        group: Arc<Group>,
        queue_index: QueueIdx,
        profiling_mask: u32,
        profiling_relocs: KVec<usize>,
    ) -> Self {
        Self {
            stream,
            queue: queue.data.clone(),
            group,
            queue_index,
            profiling_mask,
            profiling_relocs,
        }
    }
}

/// Per-queue accounting of time spent off the CSG slot.
struct SuspendState {
    /// `Some(t)` when the queue is currently suspended off its CSG
    /// slot. `t` is the monotonic instant at which the suspend began.
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

/// Per-queue snapshot of the active GPU sync-wait. Populated when the
/// firmware reports `BlockedReason::SyncWait` for the queue's CS.
///
/// `cached` carries a BO resolution from a prior evaluation. It
/// stores its own `(gpu_va, sync64)` so the next evaluation can
/// detect when the live wait has moved on and rebuild rather than
/// read from a stale BO.
#[derive(Default, Clone)]
pub(crate) struct SyncWait {
    /// GPU virtual address of the awaited sync object.
    pub(crate) gpu_va: u64,
    /// Reference value the wait compares against.
    pub(crate) ref_val: u64,
    /// Whether the awaited sync object is 64-bit (`true`) or 32-bit.
    pub(crate) sync64: bool,
    /// Wait condition, or `None` for a reserved encoding.
    pub(crate) condition: Option<CsWaitCondition>,
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
    /// considered complete. Matches the seqno claimed by
    /// `QueueData::claim_seqno` for the wrapped job. A sync-only entry
    /// shares the seqno of the command-stream job before it. The firmware's
    /// `SYNC_ADD64` retires after the wrapper's `WAIT(all scoreboards)`
    /// so the syncobj only reaches this value once every dispatched
    /// async sub-job has landed in memory.
    done_seqno: u64,
    /// Ring buffer offsets of the job's wrapped stream. Empty for a
    /// sync-only job.
    ringbuf_range: Range<u64>,
    /// Profiling slot the wrapped stream sampled into, read back at
    /// completion to accumulate the group's GPU usage.
    profiling_slot: u32,
    /// Profiling flags the wrapped stream emitted samples for. `0` when
    /// profiling was disabled for this job or the job failed.
    profiling_mask: u32,
    /// The job's fence sequence number in `QueueData::job_queue`, taken
    /// once the fence is signaled.
    fence: Option<u64>,
    /// Error staged by `QueueData::fail_submit_fence` or
    /// `QueueData::fail_job_at_extract` for the in-order drain.
    error: Option<Error>,
    /// Set for a job `QueueData::signal_unpushed_fence` queued behind an
    /// older live one. It signals with its own error.
    unpushed: bool,
    /// When the job was pushed, or reached the queue head if that was later,
    /// for the job timeout.
    started: Instant<Monotonic>,
    /// `QueueData::suspend_snapshot` at `started`, folded with any in-flight
    /// suspend interval, so the job is not faulted for time the queue spent
    /// suspended off its CSG slot before then.
    baseline_suspend: Delta,
}

impl PendingSubmitFence {
    /// Returns true for a live job the queue ran, which the job timeout
    /// covers.
    fn is_timed(&self) -> bool {
        self.fence.is_some() && !self.unpushed
    }

    /// Takes the fence, with the result to signal it with: `result`, or the
    /// staged error when `result` is `Ok`. An unpushed job keeps its own
    /// error.
    fn take_fence(&mut self, result: Result) -> Option<(u64, Result)> {
        let fence = self.fence.take()?;
        let result = if self.unpushed { Ok(()) } else { result };
        Some((fence, result.and(self.error.map_or(Ok(()), Err))))
    }
}

/// State protected by the pending-submit-fences spinlock.
///
/// `vec` carries the live ordered list of in-flight per-job fences.
///
/// `head` is the cursor into `vec` past which entries are live. The
/// prefix `vec[..head]` is drained but not yet truncated and every
/// such entry has `fence == None`. The suffix `vec[head..]` is the
/// live ordered list.
/// `Queue::maybe_truncate_pending` compacts the prefix away once
/// `head` reaches `max(len / 2, 16)`, or once `head` is non-zero in a
/// full vec.
///
/// `next_profiling_slot` is the sample slot the next profiled job takes
/// when its fence is pushed. Slots are assigned round robin.
struct PendingFences {
    vec: KVec<PendingSubmitFence>,
    head: usize,
    next_profiling_slot: u32,
    /// Number of `JobProfilingData` records in `QueueData::profiling_slots`.
    /// Sized to the queue's credits.
    profiling_slot_count: u32,
    /// `done_seqno` and error of the last job a CS fault failed. A sync-only
    /// job pushed later with the same seqno takes the error.
    fault: Option<(u64, Error)>,
}

/// A minimal hardware queue object owned by a scheduling group.
pub(crate) struct Queue {
    data: Arc<QueueData>,
}

impl Queue {
    pub(crate) fn new(
        tdev: &TyrDrmDevice,
        reg_data: &TyrDrmRegistrationData<'_>,
        queue_args: &QueueCreate,
        vm: Arc<Vm>,
        cs_id: u32,
    ) -> Result<Self> {
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let ringbuf = gem::new_kernel_object(
            reg_data.pdev.as_ref(),
            tdev,
            &vm,
            queue_args.ringbuf_size() as usize,
            flags,
            tdev.coherent,
            GFP_KERNEL_ACCOUNT,
        )?;
        let iface_mem = reg_data.fw.alloc_queue_mem(tdev, GFP_KERNEL_ACCOUNT)?;
        let interfaces = Interfaces::new(iface_mem)?;

        // One credit per wrapper the ring holds, less one for the job being
        // claimed and `EXTRACT_LAG_WRAPPERS` for the lag of `EXTRACT`.
        let max_jobs = (queue_args.ringbuf_size() as usize - RINGBUF_RESERVED_BYTES)
            / WRAPPER_RINGBUF_BYTES
            - 1
            - EXTRACT_LAG_WRAPPERS;
        let pending_fence_vec = KVec::with_capacity(max_jobs, GFP_KERNEL)?;

        // One profiling slot per pending submit fence, so a slot is not reused
        // before its sample is read.
        let profiling_slot_count = u32::try_from(pending_fence_vec.capacity())?;
        let profiling_slots = gem::new_kernel_object(
            reg_data.pdev.as_ref(),
            tdev,
            &vm,
            profiling_slot_count as usize * size_of::<JobProfilingData>(),
            flags,
            tdev.coherent,
            GFP_KERNEL_ACCOUNT,
        )?;

        let data = Arc::pin_init(
            try_pin_init!(QueueData {
                job_queue <- JobQueue::new(
                    CString::try_from_fmt(fmt!("tyr"))?,
                    CString::try_from_fmt(fmt!("tyr_queue"))?,
                    max_jobs as u64,
                    TyrQueueOps {
                        wq: reg_data.wq.clone(),
                        _hold: cleanup::JobQueueHold::new(),
                    },
                ),
                priority: queue_args.priority(),
                cs_id,
                group_id: Atomic::new(0),
                group_uid: Atomic::new(0),
                ringbuf,
                interfaces,
                doorbell_id: Atomic::new(UNASSIGNED_DOORBELL_ID),
                ring_full: Atomic::new(false),
                next_seqno: Atomic::new(0),
                profiling_slots,
                iomem: reg_data.iomem.clone(),
                pending_submit_fences <- new_spinlock!(PendingFences {
                    vec: pending_fence_vec,
                    head: 0,
                    next_profiling_slot: 0,
                    profiling_slot_count,
                    fault: None,
                }),
                last_job_fence <- new_mutex!(None),
                syncwait <- new_mutex!(SyncWait::default()),
                suspend_state <- new_spinlock!(SuspendState {
                    since: Some(Instant::<Monotonic>::now()),
                    accumulated: Delta::ZERO,
                }),
                parked: Atomic::new(false),
            }? Error),
            GFP_KERNEL,
        )?;

        Ok(Self { data })
    }

    pub(super) fn prepare_job(
        &self,
        job: QueueJob,
        deps: &[ARef<Fence>],
        extra_dep_capacity: usize,
    ) -> Result<PreparedQueueJob<'_>> {
        let cost = u32::try_from(job.stream.len().div_ceil(WRAPPER_RINGBUF_BYTES).max(1))?;
        PreparedJob::new(&self.data.job_queue, cost, job, deps, extra_dep_capacity)
    }

    /// Returns the seqno of the fence of the last committed job, or 0 before
    /// the first commit.
    pub(super) fn last_fence_seqno(&self) -> u64 {
        self.data
            .last_job_fence
            .lock()
            .as_ref()
            .map_or(0, |fence| fence.seqno())
    }

    pub(super) fn commit_job(&self, prepared: PreparedQueueJob<'_>) -> ARef<Fence> {
        let fence = prepared.submit();
        *self.data.last_job_fence.lock() = Some(fence.clone());
        fence
    }

    /// Stops the queue from handing any further job to the firmware,
    /// and the group's timeout work from failing one. Jobs keep resolving
    /// their dependencies and pile up in the queue. Returns once no job is
    /// being handed over.
    pub(crate) fn park(&self) {
        self.data.parked.store(true, Relaxed);
        self.data.job_queue.park();
    }

    /// Releases a park, so jobs that piled up behind it are submitted
    /// without waiting for another event. The caller re-arms the group's
    /// timeout work.
    pub(crate) fn unpark(&self) {
        self.data.job_queue.unpark();
        self.data.parked.store(false, Relaxed);
    }

    /// Schedules a retry of a submit that found the ring full. The caller
    /// must hold the slot-manager mutex.
    pub(crate) fn wake_ring_full(&self) {
        if self.data.ring_full.xchg(false, Relaxed) {
            self.data.job_queue.wake();
        }
    }

    /// Returns whether a submit waits for ring space. The caller must hold
    /// the slot-manager mutex.
    pub(crate) fn ring_full(&self) -> bool {
        self.data.ring_full.load(Relaxed)
    }

    /// Signals every pending submit fence with `err`.
    ///
    /// The caller must have made the group unrunnable first, so the jobs
    /// left in the queue fail at submit.
    pub(crate) fn cancel(&self, err: Error) {
        self.data.job_queue.park();
        self.data
            .signal_submit_fences_up_to(u64::MAX, Err(err), |_| ());
        self.data.job_queue.unpark();
    }

    /// Waits for the last committed job to complete.
    ///
    /// The group no longer takes commits, so no job is left in the queue
    /// afterwards. Waits on fences, so it must not be called from a
    /// dma-fence signalling section.
    pub(crate) fn drain(&self) {
        let last = self.data.last_job_fence.lock().clone();
        if let Some(fence) = last {
            wait_for_fence(&fence);
        }
    }
}

/// Waits for `fence` to signal, in `JOB_TIMEOUT_MS` steps so the wait does
/// not trip the hung-task detector.
pub(crate) fn wait_for_fence(fence: &Fence) {
    let step = msecs_to_jiffies(JOB_TIMEOUT_MS);
    while let Ok(FenceWaitResult::TimedOut) = fence.wait_timeout(step) {
        pr_warn_once!("still waiting for job dependencies during teardown\n");
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
struct RingBufferInput {
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
struct RingBufferOutput {
    extract: u64,
}

impl RingBufferOutput {
    const EXTRACT: usize = core::mem::offset_of!(Self, extract);
}

/// Failure to claim ring buffer space for a job.
pub(super) enum RingBufferError {
    /// The ring has no room for the job yet.
    Full,
    /// `EXTRACT` is past `INSERT` or more than the ring capacity behind it.
    Inconsistent { insert: u64, extract: u64 },
    /// Any other failure.
    Other,
}

impl From<Error> for RingBufferError {
    fn from(_: Error) -> Self {
        Self::Other
    }
}

/// The ring has no room for a job yet.
struct RingFull;

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

    pub(super) fn mem_size(&self) -> usize {
        self.mem.size()
    }

    pub(super) fn read_insert(&self) -> Result<u64> {
        self.mem
            .vmap()
            .try_read64(self.input_offset + RingBufferInput::INSERT)
    }

    pub(super) fn write_insert(&self, insert: u64) -> Result {
        self.mem
            .vmap()
            .try_write64(insert, self.input_offset + RingBufferInput::INSERT)
    }

    pub(super) fn read_extract_init(&self) -> Result<u64> {
        self.mem
            .vmap()
            .try_read64(self.input_offset + RingBufferInput::EXTRACT_INIT)
    }

    pub(super) fn write_extract_init(&self, extract_init: u64) -> Result {
        self.mem.vmap().try_write64(
            extract_init,
            self.input_offset + RingBufferInput::EXTRACT_INIT,
        )
    }

    pub(super) fn read_extract(&self) -> Result<u64> {
        self.mem
            .vmap()
            .try_read64(self.output_offset + RingBufferOutput::EXTRACT)
    }
}
