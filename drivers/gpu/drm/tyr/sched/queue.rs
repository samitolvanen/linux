// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;
use core::sync::atomic::{
    AtomicBool,
    AtomicI64,
    AtomicU64,
    Ordering, //
};

use kernel::{
    devres::Devres,
    dma_fence::{
        Fence, //
    },
    drm::{
        gem::BaseObject,
        job_queue::{
            JobQueue,
            PipelineBuilder,
            StageAdvance,
            StageContext,
            StageOps, //
        },
    },
    io::{
        register::Array,
        Io, //
    },
    prelude::*,
    sizes::{
        SZ_4K,
        SZ_64K, //
    },
    sync::{
        barrier::wmb,
        Arc, //
    },
    time::{
        hrtimer::HrTimerExpires,
        msecs_to_jiffies,
        Instant,
        Jiffies,
        Monotonic, //
    }, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice, //
    },
    file::QueueCreate,
    fw::global::cs::{
        RingBufferInput,
        RingBufferOutput, //
    },
    gem,
    regs::doorbell_block,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    }, //
};

use super::job;

const JOB_TIMEOUT_MS: usize = 5000;
pub(crate) const CSF_MAX_QUEUE_PRIO: u32 = 15;

/// Minimum head advance before [`Queue::compact_pending_fences`]
/// shifts trailing entries to index 0.
const PENDING_FENCES_COMPACT_THRESHOLD: usize = 16;

/// Synchronization wait parameters.
#[derive(Default, Clone)]
pub(crate) struct SyncWait {
    /// The GPU virtual address of the sync object.
    pub(crate) gpu_va: u64,
    /// The reference value to wait for.
    pub(crate) ref_val: u64,
    /// Whether the sync object is 64-bit.
    pub(crate) sync64: bool,
    /// Whether the wait condition is greater-than (true) or less-than-or-equal (false).
    pub(crate) gt: bool,
    /// The cached mapped BO.
    pub(crate) bo: Option<Arc<crate::gem::MappedBo>>,
    /// The offset within the BO.
    pub(crate) bo_offset: usize,
}

/// A pending fence for a submitted job.
pub(crate) struct PendingSubmitFence {
    /// The sequence number of the job.
    pub(crate) seqno: u64,
    /// The start offset of the job in the ring buffer.
    pub(crate) ringbuf_start: u64,
    /// The end offset of the job in the ring buffer.
    pub(crate) ringbuf_end: u64,
    /// The fence that will be signaled when the job completes.
    pub(crate) fence: Option<Fence>,
}

struct HwTimeoutStage {
    timeout: Jiffies,
}

impl StageOps<job::TyrJobHandler> for HwTimeoutStage {
    fn process(&self, ctx: &StageContext<'_, job::TyrJobHandler>) -> StageAdvance {
        if ctx.submit_fence.is_signaled() {
            return StageAdvance::Advance;
        }

        let mut suspended_time = 0;
        let mut is_suspended = false;
        let mut start = 0;

        let _ = ctx.job.group.with_locked_inner(|inner| {
            if let Some(queue) = inner.queues.get_mut(ctx.job.queue_idx()) {
                suspended_time = queue.accumulated_suspend_nanos.load(Ordering::Relaxed);
                // Acquire pairs with the Release-store in `suspend_timeout`,
                // so when `is_suspended` is true the load of
                // `suspend_start_nanos` below sees the matching start time.
                is_suspended = queue.timeout_suspended.load(Ordering::Acquire);
                start = queue.suspend_start_nanos.load(Ordering::Relaxed);
            }
            Ok(())
        });

        if is_suspended {
            let now = HrTimerExpires::as_nanos(&Instant::<Monotonic>::now());
            if now > start {
                suspended_time += now - start;
            }
        }

        let baseline = ctx.job.baseline_suspend_nanos.load(Ordering::Relaxed);
        let suspend_allowance = suspended_time.saturating_sub(baseline);
        let suspend_allowance_jiffies = msecs_to_jiffies((suspend_allowance / 1_000_000) as u32);

        let elapsed = msecs_to_jiffies(ctx.stage_elapsed().as_millis().max(0) as u32);
        let adjusted_elapsed = elapsed.saturating_sub(suspend_allowance_jiffies);

        if adjusted_elapsed >= self.timeout {
            return StageAdvance::TimedOut(ETIMEDOUT);
        }
        StageAdvance::WaitFor(self.timeout - adjusted_elapsed)
    }
}

/// Represents a hardware execution queue.
pub(crate) struct Queue {
    /// The JobQueue used for this queue.
    pub(super) job_queue: JobQueue<job::TyrJobHandler>,

    /// A priority number, between 0 and 15.
    pub(crate) priority: u8,

    /// Doorbell assigned to this queue, if any.
    pub(crate) doorbell_id: Option<usize>,

    /// The ring buffer used to communicate with the firmware.
    pub(super) ringbuf: Arc<gem::MappedBo>,

    pub(super) interfaces: Interfaces,

    iomem: Arc<Devres<IoMem>>,

    #[expect(dead_code)]
    pub(crate) syncwait: SyncWait,

    pub(crate) timeout_suspended: AtomicBool,
    #[expect(dead_code)]
    pub(crate) parked: bool,
    pub(crate) suspend_start_nanos: AtomicI64,
    pub(crate) accumulated_suspend_nanos: AtomicI64,

    #[expect(dead_code)]
    pub(super) next_seqno: AtomicU64,
    pub(crate) pending_submit_fences: KVec<PendingSubmitFence>,
    /// Head index into [`Self::pending_submit_fences`].
    pub(crate) pending_submit_fences_head: usize,
}

impl Queue {
    pub(crate) fn new(tdev: &TyrDrmDevice, queue_args: &QueueCreate, vm: Arc<Vm>) -> Result<Self> {
        // ugh..
        let queue_args = &queue_args.0;

        if queue_args.pad[0] != 0 || queue_args.pad[1] != 0 || queue_args.pad[2] != 0 {
            return Err(EINVAL);
        }

        if queue_args.ringbuf_size < SZ_4K as u32
            || queue_args.ringbuf_size > SZ_64K as u32
            || !queue_args.ringbuf_size.is_power_of_two()
        {
            pr_err!("Invalid ring buffer size: {:#x}\n", queue_args.ringbuf_size);
            return Err(EINVAL);
        }

        if u32::from(queue_args.priority) > CSF_MAX_QUEUE_PRIO {
            pr_err!("Invalid queue priority: {:#x}\n", queue_args.priority);
            return Err(EINVAL);
        }

        let priority = queue_args.priority;

        let wq = tdev.job_wq.clone();
        let pipeline = PipelineBuilder::new()
            .add_stage(HwTimeoutStage {
                timeout: msecs_to_jiffies(JOB_TIMEOUT_MS as u32),
            })?
            .set_cancel_timeout(msecs_to_jiffies(JOB_TIMEOUT_MS as u32));
        let job_queue = JobQueue::new(job::TyrJobHandler, wq.clone(), wq, pipeline)?;
        let iomem = tdev.iomem.clone();
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let ringbuf = gem::new_kernel_object(tdev, &vm, queue_args.ringbuf_size as usize, flags)?;

        let mem = tdev.fw.alloc_queue_mem(tdev)?;

        let input_va = mem.kernel_va().ok_or(EINVAL)?;
        let output_start = input_va.start + SZ_4K as u64;
        let output_end = output_start + SZ_4K as u64;
        let output_va = output_start..output_end;

        let interfaces = Interfaces {
            mem,
            input_va,
            output_va,
            input_offset: 0,
            output_offset: SZ_4K,
        };

        let max_jobs = queue_args.ringbuf_size as usize / 64;

        Ok(Queue {
            job_queue,
            doorbell_id: None,
            priority,
            ringbuf,
            interfaces,
            iomem,
            syncwait: Default::default(),
            timeout_suspended: AtomicBool::new(false),
            parked: false,
            suspend_start_nanos: AtomicI64::new(0),
            accumulated_suspend_nanos: AtomicI64::new(0),
            next_seqno: AtomicU64::new(0),
            pending_submit_fences: KVec::with_capacity(max_jobs, GFP_KERNEL)?,
            pending_submit_fences_head: 0,
        })
    }

    /// Records a pending fence. Called from the dma-fence signalling
    /// section; capacity is pre-reserved by [`Queue::new`] so this
    /// cannot allocate.
    pub(crate) fn add_pending_submit_fence(
        &mut self,
        seqno: u64,
        ringbuf_start: u64,
        ringbuf_end: u64,
        fence: Fence,
    ) -> Result<()> {
        self.pending_submit_fences.push(
            PendingSubmitFence {
                seqno,
                ringbuf_start,
                ringbuf_end,
                fence: Some(fence),
            },
            GFP_NOWAIT,
        )?;
        Ok(())
    }

    /// Pop the next pending fence with sequence number `<= seqno`.
    /// Caller loops to drain all completed entries.
    pub(crate) fn pop_pending_fence_up_to(&mut self, seqno: u64) -> Option<Fence> {
        while let Some(first_fence) = self
            .pending_submit_fences
            .get_mut(self.pending_submit_fences_head)
        {
            if first_fence.seqno <= seqno {
                let fence = first_fence.fence.take();
                self.pending_submit_fences_head += 1;
                self.compact_pending_fences();

                if fence.is_some() {
                    return fence;
                }
            } else {
                break;
            }
        }
        None
    }

    /// Shift live entries down to index 0. Only runs once the head has
    /// drained past [`PENDING_FENCES_COMPACT_THRESHOLD`] and past half
    /// the vector, to avoid copying on every pop.
    fn compact_pending_fences(&mut self) {
        let head = self.pending_submit_fences_head;
        let len = self.pending_submit_fences.len();
        if head >= len / 2 && head >= PENDING_FENCES_COMPACT_THRESHOLD {
            for i in 0..(len - head) {
                self.pending_submit_fences.swap(i, head + i);
            }
            self.pending_submit_fences.truncate(len - head);
            self.pending_submit_fences_head = 0;
        }
    }

    /// Take ownership of the pending-fence FIFO so teardown or fault
    /// recovery can signal each fence with the queue lock dropped.
    pub(crate) fn take_all_fences(&mut self) -> KVec<PendingSubmitFence> {
        self.pending_submit_fences_head = 0;
        core::mem::take(&mut self.pending_submit_fences)
    }

    /// Bytes free in the ringbuffer. Uses the oldest pending fence's
    /// `ringbuf_start` instead of the firmware's EXTRACT, so we don't
    /// reuse the slots of jobs the host hasn't yet retired.
    pub(crate) fn ringbuf_space(&mut self) -> Result<u64> {
        let ringbuf_input = self.interfaces.read_input()?;
        let ringbuf_sz = self.ringbuf.size() as u64;

        let extract = if self.pending_submit_fences_head < self.pending_submit_fences.len() {
            self.pending_submit_fences[self.pending_submit_fences_head].ringbuf_start
        } else {
            ringbuf_input.insert
        };

        let used = ringbuf_input.insert.wrapping_sub(extract);
        const CSF_CACHE_LINE_BYTES: u64 = 64;
        let max_used = ringbuf_sz.saturating_sub(CSF_CACHE_LINE_BYTES); // The hardware requires at least one cache line of margin
        if used >= max_used {
            Ok(0)
        } else {
            Ok(max_used - used)
        }
    }

    /// Write instructions into the ringbuffer and return the range
    /// they occupy. The caller must register a pending fence with that
    /// range, then call [`Self::commit_instrs`] and ring the doorbell.
    pub(crate) fn append_instrs(&mut self, instrs: &[u8]) -> Result<(u64, u64)> {
        let ringbuf_input = self.interfaces.read_input()?;
        let ringbuf_sz = self.ringbuf.size() as u64;

        let space = self.ringbuf_space()?;
        // The firmware cannot distinguish between a completely full ring buffer
        // (insert == extract + ringbuf_sz) and an empty one (insert == extract).
        // Therefore, we must never fill the ring buffer completely. We require
        // strictly more space than what we need.
        if space <= instrs.len() as u64 {
            pr_err!(
                "append_instrs: ringbuffer full (space={}, needed={})\n",
                space,
                instrs.len()
            );
            return Err(EBUSY);
        }

        let ringbuf_start = ringbuf_input.insert;
        let ringbuf_end = ringbuf_start.wrapping_add(instrs.len() as u64);

        let cs_insert = (ringbuf_input.insert & (ringbuf_sz - 1)) as usize;

        let ringbuf = self.ringbuf.vmap();
        let size = ringbuf.owner().size();
        // SAFETY: VMap guarantees the mapped region is valid for `size` bytes.
        let bytes = unsafe { core::slice::from_raw_parts_mut(ringbuf.addr() as *mut u8, size) };

        // Handle wrap-around: split the copy if instructions cross the buffer
        // boundary, matching panthor's copy_instrs_to_ringbuf().
        let first_chunk = core::cmp::min(size - cs_insert, instrs.len());
        bytes[cs_insert..cs_insert + first_chunk].copy_from_slice(&instrs[..first_chunk]);
        if first_chunk < instrs.len() {
            bytes[..instrs.len() - first_chunk].copy_from_slice(&instrs[first_chunk..]);
        }

        Ok((ringbuf_start, ringbuf_end))
    }

    /// Update the ringbuffer pointers to make the instructions written
    /// by [`append_instrs`](Queue::append_instrs) visible to the
    /// firmware. Runs inside the dma-fence signalling section.
    pub(crate) fn commit_instrs(&mut self, ringbuf_end: u64) -> Result {
        // Make sure that the ring buffer is updated before the INSERT register.
        wmb();

        // We need to always save the latest extract point in case the CS is
        // stopped and then resumed.
        let ringbuf_output = self.interfaces.read_output()?;
        self.interfaces.write_extract_init(ringbuf_output.extract);
        self.interfaces.write_insert(ringbuf_end);
        Ok(())
    }

    /// Kick the queue. This will notify CSF that new instructions are ready to
    /// be executed.
    pub(crate) fn kick(&self, group_id: u64, queue_id: u32) -> Result {
        let io = self.iomem.try_access().ok_or(EINVAL)?;
        let doorbell_id = self.doorbell_id.ok_or(EINVAL)?;
        let doorbell_reg = doorbell_block::DOORBELL::try_at(doorbell_id).ok_or(EINVAL)?;

        crate::trace::queue_doorbell(group_id, queue_id, doorbell_id as u32);

        // Use try_write (runtime bounds check) because the doorbell index is
        // determined at runtime and cannot be validated at compile time.
        io.try_write(
            doorbell_reg,
            doorbell_block::DOORBELL::zeroed().with_ring(true),
        )
    }

    /// Pause the per-job timeout while the queue is not bound to a
    /// CSG slot. Idempotent.
    pub(crate) fn suspend_timeout(&self) {
        if self.timeout_suspended.load(Ordering::Relaxed) {
            return;
        }
        let now = HrTimerExpires::as_nanos(&Instant::<Monotonic>::now());
        self.suspend_start_nanos.store(now, Ordering::Relaxed);
        self.timeout_suspended.store(true, Ordering::Release);
    }

    /// Resume the per-job timeout. The suspended interval is credited
    /// toward the deadline. Idempotent.
    pub(crate) fn resume_timeout(&self) {
        if self.timeout_suspended.swap(false, Ordering::Acquire) {
            let start = self.suspend_start_nanos.load(Ordering::Relaxed);
            let now = HrTimerExpires::as_nanos(&Instant::<Monotonic>::now());
            if now > start {
                self.accumulated_suspend_nanos
                    .fetch_add(now - start, Ordering::Relaxed);
            }
        }
    }
}

/// The interface for ring buffer control.
pub(crate) struct Interfaces {
    /// The memory used to hold the user input/output blocks.
    mem: Arc<gem::MappedBo>,

    /// The input VA range for the interface.
    pub(super) input_va: Range<u64>,

    /// The output VA range for the interface.
    pub(super) output_va: Range<u64>,

    /// The input area for the ring buffer control.
    input_offset: usize,
    /// The output area for the ring buffer control.
    output_offset: usize,
}

impl Interfaces {
    /// Reads the ring buffer input state.
    pub(super) fn read_input(&mut self) -> Result<RingBufferInput> {
        let vmap = self.mem.vmap();
        // SAFETY: The queue memory is allocated to be large enough to contain the input structure at input_offset.
        let input = unsafe {
            (vmap.addr() as *mut u8)
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .read_volatile()
        };

        Ok(input)
    }

    /// Volatile-stores `val` to a field of `RingBufferInput` at `field_offset`
    /// bytes from the start of the input record.
    ///
    /// The mapping is shared with the GPU, so the store is volatile to
    /// match the agreed publication primitive. Ordering against the
    /// surrounding `wmb()` / `smp_wmb()` is the caller's responsibility.
    fn write_input_field<T>(&mut self, field_offset: usize, val: T) {
        let vmap = self.mem.vmap();
        // SAFETY: `self.mem` is large enough to contain a `RingBufferInput`
        // at `self.input_offset` (verified by `Interfaces::new`), so the
        // byte offset `input_offset + field_offset` is in bounds of the
        // same allocated object. Callers pass `offset_of!` of a `T`-typed
        // field so the resulting pointer is naturally aligned for `T`.
        // No `&mut RingBufferInput` is created, so the volatile store
        // does not race a concurrent reader through Rust's aliasing rules.
        unsafe {
            (vmap.addr() as *mut u8)
                .add(self.input_offset + field_offset)
                .cast::<T>()
                .write_volatile(val)
        };
    }

    /// Writes the `extract_init` field of the ring buffer input state.
    pub(super) fn write_extract_init(&mut self, val: u64) {
        self.write_input_field::<u64>(core::mem::offset_of!(RingBufferInput, extract_init), val);
    }

    /// Writes the `insert` field of the ring buffer input state.
    pub(super) fn write_insert(&mut self, val: u64) {
        self.write_input_field::<u64>(core::mem::offset_of!(RingBufferInput, insert), val);
    }

    /// Reads the ring buffer output state.
    pub(super) fn read_output(&mut self) -> Result<RingBufferOutput> {
        let vmap = self.mem.vmap();
        // SAFETY: The queue memory is allocated to be large enough to contain the output structure at output_offset.
        let output = unsafe {
            (vmap.addr() as *mut u8)
                .add(self.output_offset)
                .cast::<RingBufferOutput>()
                .read_volatile()
        };

        Ok(output)
    }
}
