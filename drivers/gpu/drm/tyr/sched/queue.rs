// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;

use kernel::{
    c_str,
    devres::Devres,
    dma_fence::{
        FenceContexts,
        UserFence, //
    },
    drm::{
        gem::BaseObject,
        job_queue::JobQueue, //
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
    sync::Arc, //
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
    sched::job::Job,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    }, //
};

use super::job;

const JOB_TIMEOUT_MS: usize = 5000;
pub(crate) const CSF_MAX_QUEUE_PRIO: u32 = 15;

/// Represents a hardware executiion queue.
pub(crate) struct Queue {
    /// The JobQueue used for this queue.
    pub(super) job_queue: JobQueue<job::TyrJobHandler>,

    /// A priority number, between 0 and 15.
    pub(crate) priority: u8,

    // Doorbell assigned to this queue, if any.
    pub(crate) doorbell_id: Option<usize>,

    /// The ring buffer used to communicate with the firmware.
    pub(super) ringbuf: Arc<gem::MappedBo>,

    pub(super) interfaces: Interfaces,

    iomem: Arc<Devres<IoMem>>,

    pub(super) in_flight_jobs: KVec<kernel::dma_fence::Fence>,

    pub(super) fence_ctx: kernel::dma_fence::FenceContexts,
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

        let wq = Arc::new(
            kernel::dma_fence::DmaFenceWorkqueue::new(
                kernel::c_str!("queue_wq"),
                kernel::workqueue::WqFlags::HIGHPRI,
                0,
            )?,
            GFP_KERNEL,
        )?;
        let job_queue = JobQueue::new(
            job::TyrJobHandler,
            wq.clone(),
            wq,
            kernel::drm::job_queue::PipelineBuilder::new(),
        )?;
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

        let fence_ctx = kernel::dma_fence::FenceContexts::new(1, c_str!("tyr_fence"), None, 1)?;

        Ok(Queue {
            job_queue,
            doorbell_id: None,
            priority,
            ringbuf,
            interfaces,
            iomem,
            in_flight_jobs: KVec::new(),
            fence_ctx,
        })
    }

    /// Append instructions to this queue for execution.
    ///
    /// The queue's doorbell needs to be rung after this function is called in
    /// order to get CSF to act on the new values.
    pub(crate) fn append_instrs(&mut self, instrs: &[u8]) -> Result {
        let ringbuf_input = self.interfaces.read_input()?;
        let ringbuf_sz = self.ringbuf.size() as u64;

        let cs_insert = (ringbuf_input.insert & (ringbuf_sz - 1)) as usize;

        let ringbuf = self.ringbuf.vmap();
        let size = ringbuf.owner().size();
        let bytes = unsafe { core::slice::from_raw_parts_mut(ringbuf.addr() as *mut u8, size) };

        // Handle wrap-around: split the copy if instructions cross the buffer
        // boundary, matching panthor's copy_instrs_to_ringbuf().
        let first_chunk = core::cmp::min(size - cs_insert, instrs.len());
        bytes[cs_insert..cs_insert + first_chunk].copy_from_slice(&instrs[..first_chunk]);
        if first_chunk < instrs.len() {
            bytes[..instrs.len() - first_chunk].copy_from_slice(&instrs[first_chunk..]);
        }

        // Make sure that the ring buffer is updated before the INSERT register.
        kernel::sync::barrier::smp_wmb();

        // We need to always save the latest extract point in case the CS is
        // stopped and then resumed.
        let ringbuf_output = self.interfaces.read_output()?;
        self.interfaces.write_extract_init(ringbuf_output.extract);
        self.interfaces
            .write_insert(ringbuf_input.insert + instrs.len() as u64);
        kernel::sync::barrier::smp_wmb();
        Ok(())
    }

    /// Kick the queue. This will notify CSF that new instructions are ready to
    /// be executed.
    pub(crate) fn kick(&self) -> Result {
        let io = self.iomem.try_access().ok_or(EINVAL)?;
        let doorbell_reg =
            doorbell_block::DOORBELL::try_at(self.doorbell_id.ok_or(EINVAL)?).ok_or(EINVAL)?;
        // Use try_write (runtime bounds check) because the doorbell index is
        // determined at runtime and cannot be validated at compile time.
        io.try_write(
            doorbell_reg,
            doorbell_block::DOORBELL::zeroed().with_ring(true),
        )
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
    pub(super) fn read_input(&mut self) -> Result<RingBufferInput> {
        let vmap = self.mem.vmap();
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

    pub(super) fn read_output(&mut self) -> Result<RingBufferOutput> {
        let vmap = self.mem.vmap();
        let output = unsafe {
            (vmap.addr() as *mut u8)
                .add(self.output_offset)
                .cast::<RingBufferOutput>()
                .read_volatile()
        };

        Ok(output)
    }
}
