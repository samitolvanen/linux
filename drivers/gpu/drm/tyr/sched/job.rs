// SPDX-License-Identifier: GPL-2.0 or MIT

use crate::devfreq;
use core::sync::atomic::Ordering;
use kernel::c_str;
use kernel::dma_fence::{DmaFenceWorkqueue, DriverDmaFence, DriverDmaFenceOps, Published};
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
    pub(crate) group: Arc<Group>,

    /// Index of the queue inside the group.
    pub(crate) queue_idx: usize,

    /// Start address of the userspace command stream.
    pub(crate) stream_addr: u64,

    /// Size of the userspace command stream.
    pub(crate) stream_size: u32,

    pub(crate) latest_flush: u32,

    /// The address of the sync object for the queue.
    ///
    /// This is here for convenience, so it's ready to be consumed in the run
    /// callback.
    pub(crate) sync_addr: u64,

    pub(crate) baseline_suspend_nanos: core::sync::atomic::AtomicI64,
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
            baseline_suspend_nanos: core::sync::atomic::AtomicI64::new(0),
        })
    }

    pub(crate) fn queue_idx(&self) -> u32 {
        self.queue_idx as u32
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

        let (cs_reg_count, unpreserved_cs_reg_count) = {
            let csif = self.group.tdev.csif_info.lock();
            (
                csif.cs_reg_count as u64,
                csif.unpreserved_cs_reg_count as u64,
            )
        };

        let addr_reg = cs_reg_count - unpreserved_cs_reg_count;
        let val_reg = addr_reg + 2;

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
        let sb_slot_count = self.group.tdev.csif_info.lock().scoreboard_slot_count;
        let wait_all_mask = (1u64 << sb_slot_count) - 1;
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

        let mut needs_runnable = false;
        let mut needs_tick = false;

        let submit_result = self.group.with_locked_inner(|inner| {
            if !inner.can_run() {
                fence.signal(Err(ECANCELED));
                return Err(ECANCELED);
            }

            let queue = match inner.queues.get_mut(self.queue_idx) {
                Some(q) => q,
                None => {
                    fence.signal(Err(EINVAL));
                    return Err(EINVAL);
                }
            };

            let (ringbuf_start, ringbuf_end) = match queue.append_instrs(&instrs) {
                Ok(bounds) => bounds,
                Err(e) => {
                    if e == EBUSY {
                        // Let JobQueue know that the ring buffer is full.
                        return Ok(SubmitResult::NoResources(fence));
                    } else {
                        fence.signal(Err(e));
                        return Err(e);
                    }
                }
            };

            self.baseline_suspend_nanos.store(
                queue
                    .accumulated_suspend_nanos
                    .load(core::sync::atomic::Ordering::Relaxed),
                core::sync::atomic::Ordering::Relaxed,
            );

            // Claim the next sequence number for this job.
            let seqno = queue.next_seqno.fetch_add(1, Ordering::Relaxed) + 1;

            // Store the submit fence so it can be signaled when
            // signal_submit_fences_up_to fires for this seqno in events.rs.
            if let Err((e, fence)) =
                queue.add_pending_submit_fence(seqno, ringbuf_start, ringbuf_end, fence)
            {
                fence.signal(Err(e));
                return Err(e);
            }

            // Update the user input block to let the firmware know about the new
            // instructions to execute.
            if let Err(e) = queue.commit_instrs(ringbuf_end) {
                if let Some(mut pending) = queue.pending_submit_fences.pop() {
                    if let Some(fence) = pending.fence.take() {
                        fence.signal(Err(e));
                    }
                }
                return Err(e);
            }

            if inner.csg_id.is_none() {
                inner.sync_queue_state(self.queue_idx);

                if !inner.is_queue_blocked(self.queue_idx) {
                    let was_idle = inner.is_idle();
                    inner.set_queue_idle(self.queue_idx, false);

                    if was_idle && !inner.is_idle() {
                        needs_runnable = true;
                    }
                    needs_tick = true;
                }
            } else {
                let _ = queue.kick(&self.group.tdev);
                devfreq::record_busy(&self.group.tdev);
            }

            Ok(SubmitResult::Submitted)
        })?;

        if needs_runnable || needs_tick {
            self.group.tdev.with_locked_scheduler(|sched| {
                if needs_runnable {
                    sched.mark_group_runnable(&self.group);
                }
                if needs_tick {
                    sched.schedule_group(&self.group.tdev, Some(self.group.priority));
                }
                Ok(())
            })?;
        }

        Ok(submit_result)
    }
}

/// Zero-sized handler that delegates to [`Job::submit_to_hw_with_fence`].
#[derive(Clone)]
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
