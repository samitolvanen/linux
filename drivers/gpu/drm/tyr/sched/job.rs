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

/// Encoder for Mali CSF command-stream instructions used by the
/// kernel-side submit path. Opcodes match the Mali CSF programming manual.
pub(crate) struct Instr;

impl Instr {
    // Mali CSF opcodes.
    const MOV48: u64 = 1;
    const MOV32: u64 = 2;
    const WAIT: u64 = 3;
    const CALL: u64 = 32;
    const FLUSH_CACHE2: u64 = 36;
    const ERROR_BARRIER: u64 = 47;
    const SYNC_ADD64: u64 = 51;

    /// `MOV32 reg, val` — load the low 32 bits of `val` into `reg`.
    pub(crate) fn mov32(reg: u64, val: u64) -> u64 {
        (Self::MOV32 << 56) | (reg << 48) | (val & 0xFFFF_FFFF)
    }

    /// `MOV48 reg, val` — load the low 48 bits of `val` into `reg`.
    /// Used to splat 48-bit GPU addresses in a single instruction.
    pub(crate) fn mov48(reg: u64, val: u64) -> u64 {
        (Self::MOV48 << 56) | (reg << 48) | (val & 0xFFFF_FFFF_FFFF)
    }

    /// `FLUSH_CACHE2 reg` — flush the GPU caches against the
    /// LATEST_FLUSH counter held in `reg`.  L2 and LSC are
    /// clean-invalidated; other caches are invalidated only.
    pub(crate) fn flush_cache2(reg: u64) -> u64 {
        const L2_CLEAN_INVALIDATE: u64 = 3;
        const LSC_CLEAN_INVALIDATE: u64 = 3;
        const OTHER_INVALIDATE: u64 = 2;

        let flush_modes =
            (OTHER_INVALIDATE << 8) | (LSC_CLEAN_INVALIDATE << 4) | L2_CLEAN_INVALIDATE;

        (Self::FLUSH_CACHE2 << 56) | (reg << 40) | flush_modes
    }

    /// `WAIT mask` — block the command stream until every scoreboard
    /// entry indicated by `mask` has retired.
    pub(crate) fn wait(mask: u64) -> u64 {
        (Self::WAIT << 56) | (mask << 16)
    }

    /// `CALL addr_reg, size_reg` — call into the indirect command
    /// buffer whose base is in `addr_reg` and whose length is in
    /// `size_reg`.
    pub(crate) fn call(addr_reg: u64, size_reg: u64) -> u64 {
        (Self::CALL << 56) | (addr_reg << 40) | (size_reg << 32)
    }

    /// `SYNC_ADD64 *addr_reg += val_reg`. Error-propagating so a
    /// prior fault surfaces in the sync status word.
    pub(crate) fn sync_add64(addr_reg: u64, val_reg: u64) -> u64 {
        // No scoreboard wait — a prior `WAIT` already drained.
        const SB_ENTRY: u64 = 0;
        const SB_MASK: u64 = 0;
        const SCOPE: u64 = 0;
        // Surface a prior fault in the sync status word.
        const ERR_PROPAGATE: u64 = 1;

        (Self::SYNC_ADD64 << 56)
            | (SB_ENTRY << 48)
            | (addr_reg << 40)
            | (val_reg << 32)
            | (SB_MASK << 16)
            | (SCOPE << 1)
            | ERR_PROPAGATE
    }

    /// `ERROR_BARRIER` — terminate any pending error propagation so a
    /// later [`sync_add64`](Self::sync_add64) does not inherit a stale
    /// error state.
    pub(crate) fn error_barrier() -> u64 {
        Self::ERROR_BARRIER << 56
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
        let wait_all_mask = genmask_u64(0..=7);

        let mov_latest_flush = Instr::mov32(val_reg, self.latest_flush.into());
        let flush_cache = Instr::flush_cache2(val_reg);
        let mov_cs_start = Instr::mov48(addr_reg, self.stream_addr);
        let mov_cs_size = Instr::mov32(val_reg, self.stream_size.into());
        let wait0 = Instr::wait(1);
        let call = Instr::call(addr_reg, val_reg);
        let mov_sync_addr = Instr::mov48(addr_reg, self.sync_addr);
        let mov_sync_val = Instr::mov48(val_reg, 1);
        let wait_all = Instr::wait(wait_all_mask);
        let sync_add = Instr::sync_add64(addr_reg, val_reg);
        let error_barrier = Instr::error_barrier();

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
