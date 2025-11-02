// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    bits::genmask_u64,
    c_str,
    dma_fence,
    dma_fence::{
        FenceObject,
        FenceOps, //
    },
    drm::sched::JobImpl,
    kvec,
    prelude::*,
    sync::Arc, //
};

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

    latest_flush: u32,

    /// The address of the sync object for the queue.
    sync_addr: u64,
}

impl Job {
    pub(crate) fn create(
        qsubmit: crate::file::QueueSubmit,
        group: Arc<Group>,
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

        Ok(Job {
            group: group.clone(),
            queue_idx: qsubmit.queue_index as usize,
            stream_addr: qsubmit.stream_addr,
            stream_size: qsubmit.stream_size,
            latest_flush: qsubmit.latest_flush,
            sync_addr,
        })
    }

    pub(crate) fn queue_idx(&self) -> usize {
        self.queue_idx
    }

    pub(crate) fn submit_to_hw(&self, submit_fence: &kernel::dma_fence::Fence) -> Result {
        let mut instrs = kvec![];

        let addr_reg = 92;
        let val_reg = 94;

        let opcode = 2; // MOV32
        let latest_flush_regnum = val_reg;
        let latest_flush: u64 = self.latest_flush.into();
        let mov_latest_flush: u64 = opcode << 56 | latest_flush_regnum << 48 | latest_flush;

        let opcode = 36; //FLUSH_CACHE2
        let flush_cache: u64 = opcode << 56 | 0 << 48 | latest_flush_regnum << 40 | 0 << 16 | 0x233;

        let opcode = 1; // MOV48
        let cs_start_regnum = addr_reg;
        let mov_cs_start: u64 = opcode << 56 | cs_start_regnum << 48 | self.stream_addr;

        let opcode = 2; // MOV32
        let cs_size_regnum = val_reg;
        let mov_cs_size: u64 = opcode << 56 | cs_size_regnum << 48 | u64::from(self.stream_size);

        let opcode = 3;
        let wait0: u64 = opcode << 56 | (1 << 16); // WAIT(0)

        let opcode = 32; // CALL
        let call: u64 = opcode << 56 | cs_start_regnum << 40 | cs_size_regnum << 32;

        let opcode = 1; // MOV48
        let sync_addr_regnum = addr_reg;
        let mov_sync_addr: u64 = opcode << 56 | sync_addr_regnum << 48 | self.sync_addr;

        let opcode = 1; // MOV48
        let sync_val_regnum = val_reg;
        let mov_sync_val: u64 = opcode << 56 | sync_val_regnum << 48 | 1;

        let opcode = 3; // WAIT(all)
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
        instrs.extend_from_slice(&wait0.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&call.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&mov_sync_addr.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&mov_sync_val.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&wait_all.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&sync_add.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&error_barrier.to_le_bytes(), GFP_KERNEL)?;

        let pad = instrs.len().next_multiple_of(64) - instrs.len();
        for _ in 0..pad {
            instrs.push(0, GFP_KERNEL)?;
        }

        self.group.with_locked_inner(|inner| {
            let queue = inner.queues.get_mut(self.queue_idx).ok_or(EINVAL)?;
            queue.append_instrs(&instrs)?;

            queue
                .in_flight_jobs
                .push(submit_fence.clone(), GFP_KERNEL)?;
            queue.kick()?;
            Ok(())
        })?;

        Ok(())
    }
}

pub(crate) struct TyrJobHandler;

impl kernel::drm::job_queue::QueueOps for TyrJobHandler {
    type Job = Job;

    fn submit(
        &self,
        job: &kernel::drm::job_queue::JobRef<'_, Self::Job>,
    ) -> Result<kernel::drm::job_queue::SubmitResult> {
        job.job.submit_to_hw(job.submit_fence)?;
        Ok(kernel::drm::job_queue::SubmitResult::Submitted)
    }
}

unsafe impl Send for Job {}
unsafe impl Sync for Job {}

pub(crate) struct Fence;

#[vtable]
impl FenceOps for Fence {
    const USE_64BIT_SEQNO: bool = true;

    fn get_driver_name<'a>(self: &'a kernel::dma_fence::FenceObject<Self>) -> &'a CStr {
        c_str!("tyr")
    }

    fn get_timeline_name<'a>(self: &'a kernel::dma_fence::FenceObject<Self>) -> &'a CStr {
        c_str!("tyr_fence")
    }
}
