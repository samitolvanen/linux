// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;

use super::job;
use crate::driver::IoMem;
use crate::driver::TyrDevice;
use crate::file::QueueCreate;
use crate::fw::global::cs::RingBufferInput;
use crate::fw::global::cs::RingBufferOutput;
use crate::gem;
use crate::mmu::vm::map_flags;
use crate::mmu::vm::Vm;
use crate::regs::Doorbell;
use kernel::devres::Devres;
use core::sync::atomic::AtomicU64;
use kernel::dma_fence::DmaFenceWorkqueue;
use kernel::dma_fence::DriverDmaFence;
use kernel::dma_fence::Published;
use kernel::drm::gem::BaseObject;
use kernel::drm::job_queue::JobQueue;
use kernel::drm::job_queue::PipelineBuilder;
use kernel::drm::job_queue::StageAdvance;
use kernel::drm::job_queue::StageContext;
use kernel::drm::job_queue::StageOps;
use kernel::prelude::*;
use kernel::sizes::SZ_4K;
use kernel::sizes::SZ_64K;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::time::msecs_to_jiffies;
use kernel::time::Jiffies;

const JOB_TIMEOUT_MS: usize = 5000;
pub(crate) const CSF_MAX_QUEUE_PRIO: u32 = 15;

/// Pipeline stage that waits for hardware completion and retires the job if
/// it takes longer than `timeout` jiffies.
struct HwTimeoutStage {
    timeout: Jiffies,
}

impl StageOps<job::TyrJobHandler> for HwTimeoutStage {
    fn process(&self, ctx: &StageContext<'_, job::TyrJobHandler>) -> StageAdvance {
        if ctx.submit_fence.is_signaled() {
            return StageAdvance::Advance;
        }
        let elapsed = msecs_to_jiffies(ctx.stage_elapsed().as_millis().max(0) as u32);
        if elapsed >= self.timeout {
            pr_err!("Job {} timed out\n", ctx.counter);
            return StageAdvance::TimedOut(ETIMEDOUT);
        }
        StageAdvance::WaitFor(self.timeout - elapsed)
    }
}

/// Represents a hardware executiion queue.
pub(crate) struct Queue {
    /// The JobQueue used to track dependencies and call us when a job is ready
    /// to run.
    pub(super) job_queue: JobQueue<job::TyrJobHandler>,

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

    pub(super) interfaces: Interfaces,

    iomem: Arc<Devres<IoMem>>,

    /// Monotonically increasing sequence number counter. Each submitted job
    /// claims the next value; `signal_submit_fences_up_to` uses it to match
    /// completions reported by the firmware sync object.
    pub(super) next_seqno: AtomicU64,

    /// Submit fences waiting to be signaled when the corresponding sequence
    /// number is reached.  Entries are appended in seqno order and consumed
    /// (signaled) by `signal_submit_fences_up_to`.
    pub(super) pending_submit_fences: KVec<(u64, DriverDmaFence<job::TyrJobFenceData, Published>)>,
}

impl Queue {
    pub(crate) fn new(
        tdev: &TyrDevice,
        queue_args: &QueueCreate,
        vm: Arc<Mutex<Vm>>,
        wq: Arc<DmaFenceWorkqueue>,
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

        let pipeline = PipelineBuilder::new().add_stage(HwTimeoutStage {
            timeout: msecs_to_jiffies(JOB_TIMEOUT_MS as u32),
        })?;
        let job_queue = JobQueue::new(job::TyrJobHandler, wq.clone(), wq, pipeline)?;

        let iomem = tdev.iomem.clone();
        let ringbuf = {
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

        Ok(Queue {
            job_queue,
            doorbell_id: None,
            priority,
            ringbuf,
            interfaces,
            iomem,
            next_seqno: AtomicU64::new(0),
            pending_submit_fences: KVec::new(),
        })
    }

    /// Store a submit fence to be signaled when `seqno` is reached.
    pub(super) fn add_pending_submit_fence(
        &mut self,
        seqno: u64,
        fence: DriverDmaFence<job::TyrJobFenceData, Published>,
    ) -> Result {
        self.pending_submit_fences
            .push((seqno, fence), GFP_KERNEL)
            .map_err(|_| ENOMEM)
    }

    /// Signal and drain all pending submit fences with seqno <= `seqno`.
    pub(super) fn signal_submit_fences_up_to(&mut self, seqno: u64, result: Result) {
        while let Some(&(s, _)) = self.pending_submit_fences.first() {
            if s > seqno {
                break;
            }
            let (_, fence) = self.pending_submit_fences.remove(0).unwrap();
            fence.signal(result);
        }
    }

    /// Append instructions to this queue for execution.
    ///
    /// The queue's doorbell needs to be rung after this function is called in
    /// order to get CSF to act on the new values.
    pub(crate) fn append_instrs(&mut self, instrs: &[u8]) -> Result {
        let mut ringbuf_input = self.interfaces.read_input()?;
        let ringbuf_sz = self.ringbuf.size() as u64;

        let cs_insert = ringbuf_input.insert & (ringbuf_sz - 1);
        let cs_insert = cs_insert as usize;

        let range = cs_insert..cs_insert + instrs.len();

        let ringbuf = self.ringbuf.vmap()?;
        let size = ringbuf.owner().size();
        let mut ringbuf = ringbuf.get();
        let bytes = unsafe { ringbuf.as_mut_slice(0, size)? };

        bytes[range].copy_from_slice(instrs);

        // Make sure that the ring buffer is updated before the INSERT register.
        kernel::sync::barrier::smp_wmb();

        // We need to always save the latest extract point in case the CS is
        // stopped and then resumed.
        let ringbuf_output = self.interfaces.read_output()?;
        ringbuf_input.extract_init = ringbuf_output.extract;
        ringbuf_input.insert += instrs.len() as u64;

        self.interfaces.write_input(ringbuf_input)?;
        kernel::sync::barrier::smp_wmb();
        Ok(())
    }

    /// Kick the queue. This will notify CSF that new instructions are ready to
    /// be executed.
    pub(crate) fn kick(&self) -> Result {
        Doorbell::new(self.doorbell_id.ok_or(EINVAL)?).write(&self.iomem, 1)
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

    pub(super) fn write_input(&mut self, value: RingBufferInput) -> Result {
        let vmap = self.mem.vmap()?;
        unsafe {
            vmap.get()
                .as_mut_ptr()
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .write_volatile(value)
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
