// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::AtomicI64;

use kernel::{
    bindings::ECANCELED,
    dma_fence::Fence,
    drm::job_queue::{
        JobRef,
        QueueOps,
        SubmitResult, //
    },
    prelude::*,
    sync::Arc, //
};

use core::{mem::size_of, sync::atomic::Ordering};

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

/// A hardware execution job.
pub(crate) struct Job {
    /// The group whose queue this job will be pushed to.
    pub(crate) group: Arc<Group>,

    /// Index of the queue inside the group.
    queue_idx: usize,

    /// Start address of the userspace command stream.
    stream_addr: u64,

    /// Size of the userspace command stream.
    stream_size: u32,

    /// Latest flush value.
    latest_flush: u32,

    /// The address of the sync object for the queue.
    sync_addr: u64,

    /// The baseline accumulated suspend time when this job was submitted.
    pub(crate) baseline_suspend_nanos: AtomicI64,
}

impl Job {
    pub(crate) fn queue_idx(&self) -> usize {
        self.queue_idx
    }

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
            baseline_suspend_nanos: AtomicI64::new(0),
        })
    }

    /// Submits the job to the hardware by generating instructions and appending them to the queue.
    pub(crate) fn submit_to_hw(&self, submit_fence: &Fence) -> Result {
        let mut instrs = [0u8; 128];

        // Snapshot CSIF info under one lock acquisition so all the values
        // used below come from the same observation.
        let csif = *self.group.tdev.csif_info.lock();
        let cs_reg_count = u64::from(csif.cs_reg_count);
        let unpreserved_cs_reg_count = u64::from(csif.unpreserved_cs_reg_count);
        let sb_slot_count = csif.scoreboard_slot_count;

        let addr_reg = cs_reg_count - unpreserved_cs_reg_count;
        let val_reg = addr_reg + 2;

        let wait_all_mask = (1u64 << sb_slot_count) - 1;

        let instrs_u64 = [
            Instr::mov32(val_reg, self.latest_flush.into()),
            Instr::flush_cache2(val_reg),
            Instr::mov48(addr_reg, self.stream_addr),
            Instr::mov32(val_reg, self.stream_size.into()),
            Instr::wait(1),
            Instr::call(addr_reg, val_reg),
            Instr::mov48(addr_reg, self.sync_addr),
            Instr::mov48(val_reg, 1),
            Instr::wait(wait_all_mask),
            Instr::sync_add64(addr_reg, val_reg),
            Instr::error_barrier(),
        ];

        // Size is 128 bytes to accommodate 11 instructions (88 bytes) and pad to the required 64-byte boundary.
        let instr_size = size_of::<u64>();
        for (i, instr) in instrs_u64.iter().enumerate() {
            let start = i * instr_size;
            instrs[start..start + instr_size].copy_from_slice(&instr.to_le_bytes());
        }
        // The remaining 40 bytes serve as the required padding.

        let mut needs_runnable = false;
        let mut needs_tick = false;

        self.group.with_locked_inner(|inner| {
            if !inner.can_run() {
                return Err(Error::from_errno(-(ECANCELED as i32)));
            }

            let queue = inner.queues.get_mut(self.queue_idx).ok_or(EINVAL)?;

            self.baseline_suspend_nanos.store(
                queue.accumulated_suspend_nanos.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );

            let (ringbuf_start, ringbuf_end) = queue.append_instrs(&instrs)?;

            let seqno = queue.next_seqno.fetch_add(1, Ordering::Relaxed) + 1;
            queue.add_pending_submit_fence(
                seqno,
                ringbuf_start,
                ringbuf_end,
                submit_fence.clone(),
            )?;

            queue.commit_instrs(ringbuf_end)?;

            if inner.csg_id.is_none() {
                // The framework holds this queue's pipeline-state mutex,
                // so a park/unpark action here would self-deadlock.
                // `can_run()` above rules out park-triggering states and
                // the framework only invokes `submit()` on an unparked
                // queue, so `sync_queue_state` returns `None`; the
                // useful side effect is settling `timeout_suspended`.
                let _ = inner.sync_queue_state(self.queue_idx);

                if !inner.is_queue_blocked(self.queue_idx) {
                    let was_idle = inner.is_idle();
                    inner.set_queue_idle(self.queue_idx, false);

                    if was_idle && !inner.is_idle() {
                        needs_runnable = true;
                    }
                    needs_tick = true;
                }
            } else {
                queue.kick()?;
            }

            Ok(())
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

        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct TyrJobHandler;

impl QueueOps for TyrJobHandler {
    type Job = Job;

    fn submit(&self, job: &JobRef<'_, Self::Job>) -> Result<SubmitResult> {
        match job.job.submit_to_hw(job.submit_fence) {
            Ok(()) => Ok(SubmitResult::Submitted),
            Err(e) if e == EBUSY => Ok(SubmitResult::NoResources),
            Err(e) => Err(e),
        }
    }
}

// SAFETY: Jobs are safe to send across threads.
unsafe impl Send for Job {}
// SAFETY: Jobs are safe to share across threads.
unsafe impl Sync for Job {}
