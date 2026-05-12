// SPDX-License-Identifier: GPL-2.0 or MIT

//! Queue submission helpers for scheduler groups.
//!
//! Group submission batches user queue streams and writes the corresponding
//! firmware sync objects. Keeping that queue-side submit flow here lets the
//! group object focus on group state and scheduler coordination.

use kernel::{
    alloc::KVec,
    bits::genmask_checked_u64,
    dma_buf::dma_fence::PublicDmaFence,
    prelude::*,
    sync::{aref::ARef, Arc},
    transmute::FromBytes,
    uaccess::UserSlice,
    uapi,
    //
};

use super::{
    deps::{self, SyncOp, SyncSignal},
    group::Group,
    queue::{PreparedQueueJob, QueueJob},
    //
};

/// Encoder for Mali CSF command-stream instructions. Opcodes match the
/// Mali CSF programming manual, and value operands are masked to their
/// architectural width so out-of-range arguments truncate cleanly.
struct Instr;

impl Instr {
    // Mali CSF opcodes.
    const MOV48: u64 = 1;
    const MOV32: u64 = 2;
    const WAIT: u64 = 3;
    const CALL: u64 = 32;
    const FLUSH_CACHE2: u64 = 36;
    const ERROR_BARRIER: u64 = 47;
    const SYNC_ADD64: u64 = 51;

    /// `MOV32 reg, val`: load the low 32 bits of `val` into `reg`.
    fn mov32(reg: u64, val: u64) -> u64 {
        (Self::MOV32 << 56) | (reg << 48) | (val & 0xFFFF_FFFF)
    }

    /// `MOV48 reg, val`: load the low 48 bits of `val` into `reg`.
    fn mov48(reg: u64, val: u64) -> u64 {
        (Self::MOV48 << 56) | (reg << 48) | (val & 0xFFFF_FFFF_FFFF)
    }

    /// `FLUSH_CACHE2 reg`: flush the GPU caches against the LATEST_FLUSH
    /// counter held in `reg`. L2 and LSC are clean-invalidated; other
    /// caches are invalidated only.
    fn flush_cache2(reg: u64) -> u64 {
        const L2_CLEAN_INVALIDATE: u64 = 3;
        const LSC_CLEAN_INVALIDATE: u64 = 3;
        const OTHER_INVALIDATE: u64 = 2;

        let flush_modes =
            (OTHER_INVALIDATE << 8) | (LSC_CLEAN_INVALIDATE << 4) | L2_CLEAN_INVALIDATE;

        (Self::FLUSH_CACHE2 << 56) | (reg << 40) | flush_modes
    }

    /// `WAIT mask`: block the command stream until every scoreboard entry
    /// indicated by `mask` has retired.
    fn wait(mask: u64) -> u64 {
        (Self::WAIT << 56) | (mask << 16)
    }

    /// `CALL addr_reg, size_reg`: call into the indirect command buffer
    /// whose base GPU VA is in `addr_reg` and whose length is in
    /// `size_reg`.
    fn call(addr_reg: u64, size_reg: u64) -> u64 {
        (Self::CALL << 56) | (addr_reg << 40) | (size_reg << 32)
    }

    /// `SYNC_ADD64 *addr_reg += val_reg`. Error-propagating so a prior
    /// fault surfaces in the sync-object status word.
    fn sync_add64(addr_reg: u64, val_reg: u64) -> u64 {
        // No scoreboard wait: a prior `WAIT` already drained.
        const SB_ENTRY: u64 = 0;
        const SB_MASK: u64 = 0;
        const SCOPE: u64 = 0;
        const ERR_PROPAGATE: u64 = 1;

        (Self::SYNC_ADD64 << 56)
            | (SB_ENTRY << 48)
            | (addr_reg << 40)
            | (val_reg << 32)
            | (SB_MASK << 16)
            | (SCOPE << 1)
            | ERR_PROPAGATE
    }

    /// `ERROR_BARRIER`: terminate any pending error propagation so a
    /// later [`sync_add64`](Self::sync_add64) does not inherit a stale
    /// error state.
    fn error_barrier() -> u64 {
        Self::ERROR_BARRIER << 56
    }
}

#[repr(transparent)]
struct RawQueueSubmit(uapi::drm_panthor_queue_submit);

// SAFETY: This wrapper is layout-identical to the UAPI queue-submit record
// read from userspace.
unsafe impl FromBytes for RawQueueSubmit {}

/// One userspace command stream as described by a single
/// `drm_panthor_queue_submit` record.
///
/// `stream_size == 0` (and `stream_addr == 0`) describes a sync-only
/// submit that runs no GPU work; only the dependency / signal
/// `SyncOp`s carried alongside the piece are honoured.
#[derive(Copy, Clone)]
struct StreamPiece {
    /// GPU virtual address of the userspace command stream the wrapper
    /// `CALL`s into. Validated as 64-byte aligned by
    /// [`RawQueueSubmit::validate`].
    stream_addr: u64,
    /// Length of the userspace command stream in bytes. Validated as
    /// 8-byte aligned by [`RawQueueSubmit::validate`].
    stream_size: u32,
    /// FLUSH_ID counter snapshot the userspace ABI passes through so the
    /// wrapper's `FLUSH_CACHE2` is conditional on the GPU not having
    /// already flushed at or beyond this point.
    latest_flush: u32,
}

pub(crate) struct QueueSubmit {
    queue_index: usize,
    piece: StreamPiece,
    syncs: KVec<SyncOp>,
}

impl QueueSubmit {
    pub(crate) fn from_uapi(uapi_submit: &uapi::drm_panthor_queue_submit) -> Result<Self> {
        let mut syncs = KVec::new();

        deps::append_syncops(
            &mut syncs,
            uapi_submit.syncs.array,
            uapi_submit.syncs.count,
            uapi_submit.syncs.stride,
        )?;

        Ok(Self {
            queue_index: uapi_submit.queue_index as usize,
            piece: StreamPiece {
                stream_addr: uapi_submit.stream_addr,
                stream_size: uapi_submit.stream_size,
                latest_flush: uapi_submit.latest_flush,
            },
            syncs,
        })
    }

    pub(crate) fn queue_index(&self) -> usize {
        self.queue_index
    }

    fn into_parts(self) -> (StreamPiece, KVec<SyncOp>) {
        (self.piece, self.syncs)
    }
}

impl RawQueueSubmit {
    fn validate(&self, queue_count: usize) -> Result {
        if self.0.queue_index as usize >= queue_count {
            return Err(EINVAL);
        }

        if self.0.pad != 0 {
            return Err(EINVAL);
        }

        if (self.0.stream_size == 0) != (self.0.stream_addr == 0) {
            return Err(EINVAL);
        }

        if self.0.stream_addr & 63 != 0 || self.0.stream_size & 7 != 0 {
            return Err(EINVAL);
        }

        Ok(())
    }

    fn capture(self) -> Result<QueueSubmit> {
        QueueSubmit::from_uapi(&self.0)
    }
}

pub(crate) fn append_queue_submits(
    queue_submits: &mut KVec<QueueSubmit>,
    array: u64,
    count: u32,
    stride: u32,
    queue_count: usize,
) -> Result {
    if stride as usize != core::mem::size_of::<uapi::drm_panthor_queue_submit>() {
        return Err(ENOTSUPP);
    }

    let mut reader = UserSlice::new(
        UserPtr::from_addr(array as usize),
        stride as usize * count as usize,
    )
    .reader();

    for _ in 0..count {
        let queue: RawQueueSubmit = reader.read()?;
        queue.validate(queue_count)?;
        queue_submits.push(queue.capture()?, GFP_KERNEL)?;
    }

    Ok(())
}

pub(crate) struct Job {
    queue_index: usize,
    /// Per-`QueueSubmit` stream descriptors. Empty pieces (sync-only
    /// submits) are dropped at merge time, so every entry here
    /// corresponds to one wrapper the prepare path emits.
    pieces: KVec<StreamPiece>,
    syncs: KVec<SyncOp>,
}

pub(crate) struct PreparedQueueSubmit {
    queue_index: usize,
    prepared: PreparedQueueJob,
    signals: KVec<SyncSignal>,
}

impl PreparedQueueSubmit {
    pub(crate) fn commit(self, group: &Group) -> Result<ARef<PublicDmaFence>> {
        let queue = group.queues.get(self.queue_index).ok_or(EINVAL)?;

        // The per-queue syncobj is zeroed once at group creation and
        // then advanced exclusively by the GPU through the per-wrapper
        // `SYNC_ADD64`. Do not seed it from the CPU here: a back-to-
        // back commit on the same queue would otherwise overwrite GPU
        // progress for the previous Job that has not yet retired.

        let submit_fence = queue.commit_job(self.prepared);

        for signal in self.signals.into_iter() {
            signal.publish(&submit_fence);
        }

        Ok(submit_fence)
    }
}

impl Job {
    fn new(queue_index: usize, pieces: KVec<StreamPiece>, syncs: KVec<SyncOp>) -> Self {
        Self {
            queue_index,
            pieces,
            syncs,
        }
    }

    pub(crate) fn from_queue_submits(queue_submits: KVec<QueueSubmit>) -> Result<KVec<Self>> {
        let mut jobs = KVec::<Self>::new();

        for queue_submit in queue_submits.into_iter() {
            let queue_index = queue_submit.queue_index();
            let (piece, syncs) = queue_submit.into_parts();
            let has_stream = piece.stream_size != 0;
            let mut syncs = Some(syncs);

            if !has_stream && syncs.as_ref().is_some_and(KVec::is_empty) {
                continue;
            }

            let mut merged = false;
            for job in jobs.iter_mut() {
                if job.queue_index == queue_index {
                    if has_stream {
                        job.pieces.push(piece, GFP_KERNEL)?;
                    }
                    let Some(syncs) = syncs.take() else {
                        return Err(EINVAL);
                    };
                    for sync in syncs.into_iter() {
                        job.syncs.push(sync, GFP_KERNEL)?;
                    }
                    merged = true;
                    break;
                }
            }

            if merged {
                continue;
            }

            let mut pieces = KVec::new();
            if has_stream {
                pieces.push(piece, GFP_KERNEL)?;
            }
            jobs.push(
                Self::new(queue_index, pieces, syncs.take().ok_or(EINVAL)?),
                GFP_KERNEL,
            )?;
        }

        Ok(jobs)
    }

    /// Builds the wrapped command-stream buffer for this Job.
    ///
    /// Each piece in `self.pieces` becomes one wrapper sequence in the
    /// returned KVec, in submit order. A wrapper consists of a
    /// LATEST_FLUSH-conditional cache flush, a `CALL` into the
    /// userspace stream at `piece.stream_addr`, and a
    /// `SYNC_ADD64` / `ERROR_BARRIER` epilogue that bumps the per-queue
    /// syncobj at `sync_va` by one. The concatenation is padded to a
    /// 64-byte boundary so the firmware prefetcher sees cacheline-
    /// aligned trailing storage.
    fn build_wrapped_stream(&self, group: &Group, sync_va: u64) -> Result<KVec<u8>> {
        const INSTR_BYTES: usize = 8;
        const INSTRS_PER_WRAPPER: usize = 11;
        const WRAPPER_BYTES: usize = INSTR_BYTES * INSTRS_PER_WRAPPER;
        // Kernel-reserved CSF work registers: top 4 (matches Panthor's
        // CSF_UNPRESERVED_REG_COUNT).
        const CSF_UNPRESERVED_REG_COUNT: u32 = 4;

        // Pull CSF working-register and scoreboard counts from the
        // firmware so the wrapper adapts to the per-chip CSIF
        // configuration. `work_regs` is the total CS register count;
        // the firmware reserves the top `CSF_UNPRESERVED_REG_COUNT`
        // for the kernel-side wrapper, so `addr_reg` and `val_reg`
        // land at the canonical `(work_regs - 4, work_regs - 2)` pair.
        let (_csg_slot_count, _cs_slot_count, work_regs, scoreboards) =
            group.tdev.fw.csif_info_counts()?;
        let addr_reg = u64::from(work_regs - CSF_UNPRESERVED_REG_COUNT);
        let val_reg = addr_reg + 2;
        let top_sb = scoreboards.checked_sub(1).ok_or(EINVAL)?;
        let wait_all_mask = genmask_checked_u64(0..=top_sb).ok_or(EINVAL)?;

        let total = self
            .pieces
            .len()
            .checked_mul(WRAPPER_BYTES)
            .ok_or(EOVERFLOW)?;
        let padded = total.next_multiple_of(64);
        let mut buf = KVec::<u8>::with_capacity(padded, GFP_KERNEL)?;

        for piece in self.pieces.iter() {
            for word in [
                Instr::mov32(val_reg, piece.latest_flush.into()),
                Instr::flush_cache2(val_reg),
                Instr::mov48(addr_reg, piece.stream_addr),
                Instr::mov32(val_reg, piece.stream_size.into()),
                Instr::wait(1),
                Instr::call(addr_reg, val_reg),
                Instr::mov48(addr_reg, sync_va),
                Instr::mov48(val_reg, 1),
                Instr::wait(wait_all_mask),
                Instr::sync_add64(addr_reg, val_reg),
                Instr::error_barrier(),
            ] {
                buf.extend_from_slice(&word.to_le_bytes(), GFP_KERNEL)?;
            }
        }

        // Pad to a 64-byte boundary so the trailing instruction sits
        // entirely within a cache line the firmware prefetcher already
        // owns. Within capacity by construction, but ask for
        // `GFP_KERNEL` anyway: this runs at prepare time, outside any
        // dma-fence signalling section.
        while buf.len() < padded {
            buf.push(0, GFP_KERNEL)?;
        }

        Ok(buf)
    }

    pub(crate) fn prepare(
        self,
        group: &Arc<Group>,
        file: &crate::file::TyrDrmFile,
    ) -> Result<PreparedQueueSubmit> {
        let queue = group.queues.get(self.queue_index).ok_or(EINVAL)?;

        let deps = deps::wait_fences(file, &self.syncs)?;
        let signals = deps::signal_syncs(file, &self.syncs)?;
        let has_stream = !self.pieces.is_empty();

        // Build the wrapped command-stream buffer at prepare time so
        // every `GFP_KERNEL` allocation it does happens outside the
        // dma-fence signalling section that wraps `commit`.
        let wrapped = if has_stream {
            let sync_va = group.syncobj_va(self.queue_index)?;
            self.build_wrapped_stream(group, sync_va)?
        } else {
            KVec::new()
        };

        let prepared = queue.prepare_job(QueueJob::new(wrapped, group.clone()), &deps)?;

        // Claim one per-queue seqno per emitted wrapper, in a single
        // atomic step, only after every fallible prepare step has
        // succeeded. An earlier `claim_seqnos` followed by a failure
        // in `prepare_job` would advance `next_seqno` without ever
        // queueing the matching wrappers, leaving a gap that
        // `cancel_queues` would then mark dead with the wrong upper
        // bound. Stream-less jobs never reach the GPU and so do not
        // consume a seqno.
        queue.claim_seqnos(self.pieces.len());

        Ok(PreparedQueueSubmit {
            queue_index: self.queue_index,
            prepared,
            signals,
        })
    }
}
