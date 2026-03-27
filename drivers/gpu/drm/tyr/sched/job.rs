// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::Ordering;
use kernel::bits::genmask_u64;
use kernel::c_str;
use kernel::dma_fence::{
    DmaFenceWorkqueue, DriverDmaFence, DriverDmaFenceOps, Published,
};
use kernel::drm::job_queue::{JobRef, QueueOps, SubmitResult};
use kernel::kvec;
use kernel::prelude::*;
use kernel::sync::Arc;

use crate::sched::group::Group;

/// Driver data for GPU job submit fences.
#[derive(Default)]
pub(crate) struct TyrJobFenceData;

#[vtable]
impl DriverDmaFenceOps for TyrJobFenceData {
    fn driver_name(&self) -> &'static CStr {
        c_str!("tyr")
    }

    fn timeline_name(&self) -> &'static CStr {
        c_str!("tyr_sched")
    }
}

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
    ///
    /// This is here for convenience, so it's ready to be consumed in the run
    /// callback.
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
}

impl Job {
    /// Submit this job to the hardware, taking ownership of the submit fence.
    ///
    /// The fence is stored on the queue and signaled when the firmware's
    /// SYNC_ADD64 instruction fires for this job's seqno.
    fn submit_to_hw_with_fence(
        &self,
        fence: DriverDmaFence<TyrJobFenceData, Published>,
    ) -> Result<SubmitResult<TyrJobFenceData>> {
        // TODO: use a fixed-size array instead.
        let mut instrs = kvec![];

        // We are choosing these registers arbitrarily, but they might be used
        // by userspace. Down the line, we will have to address this.
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
        instrs.extend_from_slice(&wait0.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&call.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&mov_sync_addr.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&mov_sync_val.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&wait_all.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&sync_add.to_le_bytes(), GFP_KERNEL)?;
        instrs.extend_from_slice(&error_barrier.to_le_bytes(), GFP_KERNEL)?;

        let pad = instrs.len().next_multiple_of(64) - instrs.len();

        // Pad until the next 64-byte boundary with NOPs to please the
        // prefetcher.
        for _ in 0..pad {
            instrs.push(0, GFP_KERNEL)?;
        }

        self.group.with_locked_inner(|inner| {
            let queue = inner.queues.get_mut(self.queue_idx).ok_or(EINVAL)?;

            if queue.doorbell_id.is_none() {
                pr_err!("submit_to_hw: group has no CSG slot assigned, NoResources (queue_idx={}, csg_id={:?})\n",
                        self.queue_idx, inner.csg_id);
                return Ok(SubmitResult::NoResources(fence));
            }

            queue.append_instrs(&instrs)?;

            // Claim the next sequence number for this job.
            let seqno = queue.next_seqno.fetch_add(1, Ordering::Relaxed) + 1;

            // Store the submit fence so it can be signaled when
            // signal_submit_fences_up_to fires for this seqno in events.rs.
            queue.add_pending_submit_fence(seqno, fence)?;

            queue.kick()?;
            Ok(SubmitResult::Submitted)
        })
    }
}

/// Zero-sized handler that delegates to [`Job::submit_to_hw_with_fence`].
pub(crate) struct TyrJobHandler;

impl QueueOps for TyrJobHandler {
    type Job = Job;
    type FenceData = TyrJobFenceData;

    fn submit(
        &self,
        job: &JobRef<'_, Job>,
        fence: DriverDmaFence<TyrJobFenceData, Published>,
        _wq: &DmaFenceWorkqueue,
    ) -> Result<SubmitResult<TyrJobFenceData>> {
        job.job.submit_to_hw_with_fence(fence)
    }

}

unsafe impl Send for Job {}
unsafe impl Sync for Job {}
