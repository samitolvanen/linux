// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;
use core::sync::atomic::AtomicU64;

use kernel::dma_fence::{DriverDmaFence, Published};
use kernel::drm::gem::shmem::VMap;
use kernel::drm::gem::BaseObject;
use kernel::drm::job_queue::{JobQueue, PipelineBuilder, StageAdvance, StageContext, StageOps};
use kernel::prelude::*;
use kernel::sizes::SZ_4K;
use kernel::sizes::SZ_64K;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::time::{msecs_to_jiffies, Jiffies};

use super::job;
use crate::driver::TyrDevice;
use crate::file::QueueCreate;
use crate::fw::global::cs::RingBufferInput;
use crate::fw::global::cs::RingBufferOutput;
use crate::gem;
use crate::gem::TyrObject;
use crate::mmu::vm::map_flags;
use crate::mmu::vm::Vm;

const JOB_TIMEOUT_MS: usize = 5000;
pub(crate) const CSF_MAX_QUEUE_PRIO: u32 = 15;

/// Describes a firmware synchronization wait operation that caused a queue to block.
///
/// When a queue executes a `SYNC_WAIT` instruction and the condition is not met,
/// the firmware blocks the queue and reports the wait parameters. The driver must
/// manually evaluate this condition when the sync object is updated to determine
/// when the queue can be unblocked and rescheduled.
#[derive(Default, Clone, Copy)]
pub(crate) struct SyncWait {
    /// The GPU virtual address of the sync object being evaluated.
    pub(crate) gpu_va: u64,
    /// The reference value to compare the sync object against.
    pub(crate) ref_val: u64,
    /// If `true`, the sync object is 64-bit; if `false`, it is 32-bit.
    pub(crate) sync64: bool,
    /// The comparison operator: `true` means wait until `sync_val > ref_val`,
    /// `false` means wait until `sync_val <= ref_val`.
    pub(crate) gt: bool,
}

pub(crate) struct PendingSubmitFence {
    pub(crate) seqno: u64,
    pub(crate) ringbuf_start: u64,
    pub(crate) ringbuf_end: u64,
    pub(crate) fence: Option<DriverDmaFence<job::TyrJobFenceData, Published>>,
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
        let mut insert = 0;
        let mut extract = 0;

        let _ = ctx.job.group.with_locked_inner(|inner| {
            if let Some(queue) = inner.queues.get_mut(ctx.job.queue_idx() as usize) {
                suspended_time = queue
                    .accumulated_suspend_nanos
                    .load(core::sync::atomic::Ordering::Relaxed);
                is_suspended = queue
                    .timeout_suspended
                    .load(core::sync::atomic::Ordering::Relaxed);
                start = queue
                    .suspend_start_nanos
                    .load(core::sync::atomic::Ordering::Relaxed);
                insert = queue.interfaces.read_input().map(|i| i.insert).unwrap_or(0);
                extract = queue
                    .interfaces
                    .read_output()
                    .map(|o| o.extract)
                    .unwrap_or(0);
            }
            Ok(())
        });

        if is_suspended {
            let now = kernel::time::hrtimer::HrTimerExpires::as_nanos(&kernel::time::Instant::<
                kernel::time::Monotonic,
            >::now());
            if now > start {
                suspended_time += now - start;
            }
        }

        let baseline = ctx
            .job
            .baseline_suspend_nanos
            .load(core::sync::atomic::Ordering::Relaxed);
        let suspend_allowance = suspended_time.saturating_sub(baseline);
        let suspend_allowance_jiffies = msecs_to_jiffies((suspend_allowance / 1_000_000) as u32);

        let elapsed = msecs_to_jiffies(ctx.stage_elapsed().as_millis().max(0) as u32);
        let adjusted_elapsed = elapsed.saturating_sub(suspend_allowance_jiffies);

        if adjusted_elapsed >= self.timeout {
            crate::trace::job_status(
                ctx.submit_fence.seqno(),
                ctx.job.group_id(),
                ctx.job.queue_idx(),
                kernel::c_str!("hw_timeout"),
            );
            crate::trace::cs_ring_ptrs(ctx.job.group_id(), ctx.job.queue_idx(), insert, extract);
            return StageAdvance::TimedOut(ETIMEDOUT);
        }
        StageAdvance::WaitFor(self.timeout - adjusted_elapsed)
    }
}

/// Represents a hardware executiion queue.
pub(crate) struct Queue {
    /// The JobQueue used to track dependencies and call us when a job is ready
    /// to run.
    pub(super) job_queue: Arc<JobQueue<job::TyrJobHandler>>,

    /// A priority number, between 0 and 15.
    pub(crate) priority: u8,

    // Doorbell assigned to this queue, if any.
    //
    // Doorbell assignment happens when the group that owns this queue is bound
    // to a specific hardware slot.
    //
    // Right now, all groups share the same doorbell, and the doorbell ID
    // is assigned to `group_slot + 1` when the group is assigned a slot.
    // However, we might decide to provide fine-grained doorbell assignment
    // at some point, so we don't have to wake up all queues in a group
    // every time one of them is updated.
    pub(crate) doorbell_id: Option<usize>,

    /// The ring buffer used to communicate with the firmware.
    pub(super) ringbuf: gem::ObjectRef,
    pub(super) ringbuf_vmap: VMap<TyrObject, u8>,

    pub(super) interfaces: Interfaces,

    /// Monotonically increasing sequence number counter. Each submitted job
    /// claims the next value; `signal_submit_fences_up_to` uses it to match
    /// completions reported by the firmware sync object.
    pub(super) next_seqno: AtomicU64,

    /// Submit fences waiting to be signaled when the corresponding sequence
    /// number is reached.  Entries are appended in seqno order and consumed
    /// by `pop_pending_fence_up_to`.
    pub(crate) pending_submit_fences: KVec<PendingSubmitFence>,
    pub(crate) pending_submit_fences_head: usize,

    pub(crate) syncwait: SyncWait,

    pub(crate) timeout_suspended: core::sync::atomic::AtomicBool,
    pub(crate) parked: bool,
    pub(crate) suspend_start_nanos: core::sync::atomic::AtomicI64,
    pub(crate) accumulated_suspend_nanos: core::sync::atomic::AtomicI64,
}

impl Queue {
    pub(crate) fn new(
        tdev: &TyrDevice,
        queue_args: &QueueCreate,
        vm: Arc<Mutex<Vm>>,
    ) -> Result<Self> {
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

        let pipeline = PipelineBuilder::new()
            .add_stage(HwTimeoutStage {
                timeout: msecs_to_jiffies(JOB_TIMEOUT_MS as u32),
            })?
            .set_cancel_timeout(msecs_to_jiffies(JOB_TIMEOUT_MS as u32));
        let job_queue = Arc::new(
            JobQueue::new(
                job::TyrJobHandler,
                tdev.wq.clone(),
                tdev.wq.clone(),
                pipeline,
            )?,
            GFP_KERNEL,
        )?;

        let iomem = tdev.iomem.clone();
        let mut ringbuf = {
            let mut vm_guard = vm.lock();
            gem::new_kernel_object(
                tdev,
                iomem.clone(),
                &mut vm_guard,
                gem::KernelVaPlacement::Auto {
                    size: queue_args.ringbuf_size as usize,
                },
                map_flags::Flags::from(map_flags::NOEXEC)
                    | map_flags::Flags::from(map_flags::UNCACHED),
            )?
        };

        let ringbuf_vmap = ringbuf.vmap()?.clone();

        let mut mem = tdev.fw.alloc_queue_mem(tdev)?;
        let mem_vmap = mem.vmap()?;
        let mem_size = mem_vmap.owner().size();
        unsafe { mem_vmap.get().as_mut_slice(0, mem_size)?.fill(0) };

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
            ringbuf_vmap,
            interfaces,
            next_seqno: AtomicU64::new(0),
            pending_submit_fences: KVec::with_capacity(max_jobs, GFP_KERNEL)?,
            pending_submit_fences_head: 0,
            syncwait: Default::default(),
            timeout_suspended: core::sync::atomic::AtomicBool::new(false),
            parked: false,
            suspend_start_nanos: core::sync::atomic::AtomicI64::new(0),
            accumulated_suspend_nanos: core::sync::atomic::AtomicI64::new(0),
        })
    }

    pub(crate) fn active_seqno(&self) -> u64 {
        if self.pending_submit_fences_head < self.pending_submit_fences.len() {
            self.pending_submit_fences[self.pending_submit_fences_head].seqno
        } else {
            0
        }
    }

    /// Store a submit fence to be signaled when `seqno` is reached.
    pub(crate) fn add_pending_submit_fence(
        &mut self,
        seqno: u64,
        ringbuf_start: u64,
        ringbuf_end: u64,
        fence: DriverDmaFence<job::TyrJobFenceData, Published>,
    ) -> core::result::Result<(), (Error, DriverDmaFence<job::TyrJobFenceData, Published>)> {
        // The pending_submit_fences KVec is preallocated to the maximum number
        // of jobs in flight. This push should never fail in practice. If it does,
        // we return the fence so the caller can signal the error.
        if let Err(e) = self.pending_submit_fences.push(
            PendingSubmitFence {
                seqno,
                ringbuf_start,
                ringbuf_end,
                fence: None,
            },
            GFP_NOWAIT,
        ) {
            return Err((e.into(), fence));
        }
        let len = self.pending_submit_fences.len();
        self.pending_submit_fences[len - 1].fence = Some(fence);
        Ok(())
    }

    pub(crate) fn pop_pending_fence_up_to(
        &mut self,
        seqno: u64,
    ) -> Option<DriverDmaFence<job::TyrJobFenceData, Published>> {
        while let Some(first_fence) = self
            .pending_submit_fences
            .get_mut(self.pending_submit_fences_head)
        {
            if first_fence.seqno <= seqno {
                let fence = first_fence.fence.take();
                self.pending_submit_fences_head += 1;

                let len = self.pending_submit_fences.len();
                if self.pending_submit_fences_head >= len / 2
                    && self.pending_submit_fences_head >= 16
                {
                    let head = self.pending_submit_fences_head;
                    let mut i = 0;
                    self.pending_submit_fences.retain(|_| {
                        let keep = i >= head;
                        i += 1;
                        keep
                    });
                    self.pending_submit_fences_head = 0;
                }

                if fence.is_some() {
                    return fence;
                }
            } else {
                break;
            }
        }
        None
    }

    pub(crate) fn take_all_fences(&mut self) -> KVec<PendingSubmitFence> {
        let head = self.pending_submit_fences_head;
        self.pending_submit_fences_head = 0;
        let mut i = 0;
        self.pending_submit_fences.retain(|_| {
            let keep = i >= head;
            i += 1;
            keep
        });
        core::mem::take(&mut self.pending_submit_fences)
    }

    /// Returns the number of bytes available in the ring buffer.
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

    /// Append instructions to this queue for execution.
    ///
    /// The queue's doorbell needs to be rung after this function is called in
    /// order to get CSF to act on the new values.
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

        let start = ringbuf_input.insert;
        let end = start.wrapping_add(instrs.len() as u64);

        let cs_insert = (ringbuf_input.insert & (ringbuf_sz - 1)) as usize;

        let ringbuf = &self.ringbuf_vmap;
        let size = ringbuf.owner().size();
        let mut ringbuf = ringbuf.get();
        let bytes = unsafe { ringbuf.as_mut_slice(0, size)? };

        if cs_insert + instrs.len() <= ringbuf_sz as usize {
            bytes[cs_insert..cs_insert + instrs.len()].copy_from_slice(instrs);
        } else {
            let first_part = ringbuf_sz as usize - cs_insert;
            bytes[cs_insert..ringbuf_sz as usize].copy_from_slice(&instrs[..first_part]);
            bytes[..instrs.len() - first_part].copy_from_slice(&instrs[first_part..]);
        }

        Ok((start, end))
    }

    pub(crate) fn commit_instrs(&mut self, end: u64) -> Result {
        // Make sure that the ring buffer is updated before we update the insert
        // value.
        kernel::sync::barrier::wmb();

        // We need to always save the latest extract point in case the CS is
        // stopped and then resumed.
        let ringbuf_output = self.interfaces.read_output()?;
        self.interfaces.write_extract_init(ringbuf_output.extract)?;
        self.interfaces.write_insert(end)?;
        Ok(())
    }

    /// Kick the queue. This will notify CSF that new instructions are ready to
    /// be executed.
    pub(crate) fn kick(
        &self,
        tdev: &crate::driver::TyrData,
        group_id: u64,
        queue_id: u32,
    ) -> Result {
        // Make sure that all previous writes are visible to the CSF before it
        // can be awaken.
        kernel::sync::barrier::wmb();

        let doorbell_id = self.doorbell_id.ok_or(EINVAL)?;
        crate::trace::queue_doorbell(group_id, queue_id, doorbell_id as u32);
        crate::regs::Doorbell::new(doorbell_id).write(&tdev.iomem, 1)
    }

    pub(crate) fn suspend_timeout(&self) {
        if !self
            .timeout_suspended
            .swap(true, core::sync::atomic::Ordering::Relaxed)
        {
            self.suspend_start_nanos.store(
                kernel::time::hrtimer::HrTimerExpires::as_nanos(&kernel::time::Instant::<
                    kernel::time::Monotonic,
                >::now()),
                core::sync::atomic::Ordering::Relaxed,
            );
        }
    }

    pub(crate) fn resume_timeout(&self) {
        if self
            .timeout_suspended
            .swap(false, core::sync::atomic::Ordering::Relaxed)
        {
            let start = self
                .suspend_start_nanos
                .load(core::sync::atomic::Ordering::Relaxed);
            let now = kernel::time::hrtimer::HrTimerExpires::as_nanos(&kernel::time::Instant::<
                kernel::time::Monotonic,
            >::now());
            if now > start {
                self.accumulated_suspend_nanos
                    .fetch_add(now - start, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// The interface for ring buffer control.
pub(crate) struct Interfaces {
    /// The memory used to hold the user input/output blocks.
    mem: gem::ObjectRef,

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
    pub(super) fn read_input(&mut self) -> Result<RingBufferInput> {
        let vmap = self.mem.vmap()?;
        let input = unsafe {
            vmap.get()
                .as_mut_ptr()
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .read_volatile()
        };

        Ok(input)
    }

    pub(super) fn write_insert(&mut self, insert: u64) -> Result {
        let vmap = self.mem.vmap()?;
        // SAFETY: `vmap` provides a valid pointer to the shared memory region.
        unsafe {
            vmap.get()
                .as_mut_ptr()
                .add(self.input_offset + core::mem::offset_of!(RingBufferInput, insert))
                .cast::<u64>()
                .write_volatile(insert)
        };

        Ok(())
    }

    pub(super) fn write_extract_init(&mut self, extract_init: u64) -> Result {
        let vmap = self.mem.vmap()?;
        // SAFETY: `vmap` provides a valid pointer to the shared memory region.
        unsafe {
            vmap.get()
                .as_mut_ptr()
                .add(self.input_offset + core::mem::offset_of!(RingBufferInput, extract_init))
                .cast::<u64>()
                .write_volatile(extract_init)
        };

        Ok(())
    }

    pub(super) fn read_output(&mut self) -> Result<RingBufferOutput> {
        let vmap = self.mem.vmap()?;
        let output = unsafe {
            vmap.get()
                .as_mut_ptr()
                .add(self.output_offset)
                .cast::<RingBufferOutput>()
                .read_volatile()
        };

        Ok(output)
    }
}
