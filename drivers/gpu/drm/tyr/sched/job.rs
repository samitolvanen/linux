// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::bits::genmask_u32;
use kernel::bits::genmask_u64;
use kernel::c_str;
use kernel::dma_fence;
use kernel::dma_fence::FenceObject;
use kernel::dma_fence::FenceOps;
use kernel::dma_fence::RawDmaFence;
use kernel::drm::sched::JobImpl;
use kernel::kvec;
use kernel::prelude::*;
use kernel::sync::Arc;

use crate::sched::group::Group;

pub(crate) struct Job {
    /// The group whose queue this job will be pushed to.
    group: Arc<Group>,

    /// Index of the queue inside the group.
    queue_idx: usize,

    /// Start address of the userspace command stream.
    stream_addr: u64,

    /// Size of the userspace command stream.
    stream_size: u32,

    /// The position of the job in the ringbuffer, if any.
    ringbuf_pos: Option<RingBufferPosition>,

    /// The fence to signal when the job is done.
    done_fence: dma_fence::UserFence<Fence>,

    /// The address of the sync object for the queue.
    ///
    /// This is here for convenience, so it's ready to be consumed in the run
    /// callback.
    sync_addr: u64,
}

impl Job {
    pub(crate) fn create(
        qsubmit: crate::file::QueueSubmit,
        group: Arc<Group>,
        done_fence: dma_fence::UserFence<Fence>,
        sync_addr: u64,
    ) -> Result<Self> {
        if qsubmit.pad != 0 {
            pr_err!("job_create: invalid padding {}\n", qsubmit.pad);
            return Err(EINVAL);
        }

        if (qsubmit.stream_size == 0) != (qsubmit.stream_addr == 0) {
            pr_err!("job_create: stream address and stream size must be both 0 or non-zero\n");
            return Err(EINVAL);
        }

        if qsubmit.stream_addr & 63 != 0 || qsubmit.stream_size & 7 != 0 {
            pr_err!("job_create: stream address must be aligned to 64 bytes and stream size must be aligned to 8 bytes\n");
            return Err(EINVAL);
        }

        if qsubmit.latest_flush & genmask_u32(24..=30) != 0 {
            pr_err!("job_create: latest_flust[30:24] must be zero\n");
            return Err(EINVAL);
        }

        Ok(Job {
            group: group.clone(),
            queue_idx: qsubmit.queue_index as usize,
            stream_addr: qsubmit.stream_addr,
            stream_size: qsubmit.stream_size,
            ringbuf_pos: None,
            done_fence,
            sync_addr,
        })
    }
}

impl JobImpl for Job {
    // This is in the dma signalling path. Do _not_ allocate here.
    fn run(job: &mut kernel::drm::sched::Job<Self>) -> Result<Option<kernel::dma_fence::Fence>> {
        // TODO: use a fixed-size array instead.
        let mut instrs = kvec![];

        // We are choosing these registers arbitrarily, but they might be used
        // by userspace. Down the line, we will have to address this.
        let addr_reg = 92;
        let val_reg = 94;

        let opcode = 2; // MOV32
        let latest_flush_regnum = val_reg;
        let latest_flush = 0;
        let mov_latest_flush: u64 = opcode << 56 | latest_flush_regnum << 48 | latest_flush;

        let opcode = 36; //FLUSH_CACHE2
        let flush_cache: u64 = opcode << 56 | 0 << 48 | latest_flush_regnum << 40 | 0 << 16 | 0x233;

        let opcode = 1; // MOV48
        let cs_start_regnum = addr_reg;
        let mov_cs_start: u64 = opcode << 56 | cs_start_regnum << 48 | job.stream_addr;

        let opcode = 2; // MOV32
        let cs_size_regnum = val_reg;
        let mov_cs_size: u64 = opcode << 56 | cs_size_regnum << 48 | u64::from(job.stream_size);

        let opcode = 32; // CALL
        let call: u64 = opcode << 56 | cs_start_regnum << 40 | cs_size_regnum << 32;

        let opcode = 1; // MOV48
        let sync_addr_regnum = addr_reg;
        let mov_sync_addr: u64 = opcode << 56 | sync_addr_regnum << 48 | job.sync_addr;

        // Load the actual "1" constant into a register. SYNC_ADD cannot take
        // this as an immediate.
        let opcode = 1; // MOV48
        let sync_val_regnum = val_reg;
        let mov_sync_val: u64 = opcode << 56 | sync_val_regnum << 48 | 1;

        // Wait before _all_ assynchronous work spawned by the user CS is done.
        let opcode = 3; // WAIT(all)

        // Use this default for now. This should work for the rk3588 where it's
        // being tested.
        let wait_all_mask = genmask_u64(0..=7);
        let wait_all: u64 = opcode << 56 | wait_all_mask << 16;

        let opcode = 51; // SYNC_ADD64
        let sync_sb_entry = 0;
        let sync_sb_mask = 0;
        let sync_scope = 0;
        let sync_err_propagate = 1;
        let sync_add: u64 = opcode << 56
            | sync_sb_entry << 48
            | sync_addr_regnum << 40
            | sync_val_regnum << 32
            | sync_sb_mask << 16
            | sync_scope << 1
            | sync_err_propagate;

        let opcode = 47; // ERROR_BARRIER
        let error_barrier: u64 = opcode << 56;

        instrs.extend_from_slice(&mov_latest_flush.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&flush_cache.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&mov_cs_start.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&mov_cs_size.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&call.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&mov_sync_addr.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&mov_sync_val.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&wait_all.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&sync_add.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&error_barrier.to_le_bytes(), GFP_KERNEL)?;

        let pad = instrs.len().next_multiple_of(8) - instrs.len();

        // Pad until the next 8-byte boundary with NOPs to please the
        // prefetcher.
        for _ in 0..pad {
            instrs.push(0, GFP_KERNEL)?;
        }

        let ringbuf_pos = job.group.with_locked_inner(|inner| {
            let queue = inner.queues.get_mut(job.queue_idx).ok_or(EINVAL)?;
            let input = queue.interfaces.read_input()?;

            let ringbuf_pos = RingBufferPosition {
                start: input.insert,
                end: input.insert + instrs.len() as u64,
            };

            queue.append_instrs(&instrs)?;

            // Push the fence before kicking the queue.
            queue
                .in_flight_jobs
                .push(job.done_fence.clone(), GFP_KERNEL)?;

            queue.kick()?;
            Ok(ringbuf_pos)
        })?;

        job.ringbuf_pos = Some(ringbuf_pos);

        Ok(Some(kernel::dma_fence::Fence::from_fence(&job.done_fence)))
    }

    fn timed_out(job: &mut kernel::drm::sched::Job<Self>) -> kernel::drm::sched::Status {
        pr_err!("Job timed out\n");

        job.done_fence.set_error(ETIMEDOUT);
        let _ = job.done_fence.signal();

        kernel::drm::sched::Status::NoDevice
    }
}

struct RingBufferPosition {
    start: u64,
    end: u64,
}

pub(crate) struct Fence;

#[vtable]
impl FenceOps for Fence {
    const USE_64BIT_SEQNO: bool = true;

    fn get_driver_name<'a>(self: &'a FenceObject<Self>) -> &'a CStr {
        c_str!("tyr")
    }

    fn get_timeline_name<'a>(self: &'a FenceObject<Self>) -> &'a CStr {
        c_str!("tyr_fence")
    }
}
