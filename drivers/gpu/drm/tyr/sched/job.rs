// SPDX-License-Identifier: GPL-2.0 or MIT

//! Queue submission helpers for scheduler groups.
//!
//! Group submission batches user queue streams and writes the corresponding
//! firmware sync objects. Keeping that queue-side submit flow here lets the
//! group object focus on group state and scheduler coordination.

use core::mem::offset_of;

use kernel::{
    alloc::KVec,
    bits::{
        genmask_checked_u64,
        genmask_u32,
        //
    },
    io::Io,
    prelude::*,
    transmute::FromBytes,
    uaccess::UserSlice,
    uapi,
    //
};

use crate::driver::{
    DEVICE_PROFILING_CYCLES,
    DEVICE_PROFILING_TIMESTAMP, //
};
use crate::file::read_padding_zero;

use super::{
    deps::{
        self,
        SyncOp, //
    },
    group::Group,
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
    const STORE_STATE: u64 = 40;
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

    /// `STORE_STATE reg, type_sel`: write a GPU state value to the address
    /// in `reg`. `type_sel` is `1` for the cycle counter or `0` for the
    /// timestamp.
    fn store_state(reg: u64, type_sel: u64) -> u64 {
        (Self::STORE_STATE << 56) | (reg << 40) | (type_sel << 32)
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
    /// later `sync_add64` does not inherit a stale
    /// error state.
    fn error_barrier() -> u64 {
        Self::ERROR_BARRIER << 56
    }
}

/// Per-job GPU profiling sample slot. The wrapped command stream writes
/// the cycle counter and timestamp before the job's first piece and
/// after its last. Job completion reads back the deltas.
#[repr(C)]
pub(crate) struct JobProfilingData {
    pub(crate) cycles_before: u64,
    pub(crate) cycles_after: u64,
    pub(crate) time_before: u64,
    pub(crate) time_after: u64,
}

impl JobProfilingData {
    /// Reads the profiling slot at `offset` from a mapped BO.
    pub(super) fn read<M: super::syncs::BoMapping>(mem: &M, offset: usize) -> Result<Self> {
        mem.check_offset::<Self>(offset)?;

        let vmap = mem.vmap();
        // SAFETY: `check_offset` verified bounds and alignment for `Self`
        // at `offset`.
        let ptr = unsafe { (vmap.addr() as *mut u8).add(offset).cast::<Self>() };

        // SAFETY: `ptr` is aligned, in-bounds (see above), and the slot is
        // written by the GPU.
        Ok(unsafe { core::ptr::read_volatile(ptr) })
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
    /// `RawQueueSubmit::validate`.
    stream_addr: u64,
    /// Length of the userspace command stream in bytes. Validated as
    /// 8-byte aligned by `RawQueueSubmit::validate`.
    stream_size: u32,
    /// FLUSH_ID counter snapshot the userspace ABI passes through so the
    /// wrapper's `FLUSH_CACHE2` is conditional on the GPU not having
    /// already flushed at or beyond this point. Validated as having
    /// bits 30:24 clear by `RawQueueSubmit::validate`.
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

        if self.0.latest_flush & genmask_u32(24..=30) != 0 {
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
    static_assert!(
        size_of::<uapi::drm_panthor_queue_submit>()
            == offset_of!(uapi::drm_panthor_queue_submit, syncs)
                + size_of::<uapi::drm_panthor_obj_array>()
    );
    let min_size = offset_of!(uapi::drm_panthor_queue_submit, syncs)
        + size_of::<uapi::drm_panthor_obj_array>();
    let stride = stride as usize;
    if stride < min_size {
        return Err(EINVAL);
    }

    let mut reader = UserSlice::new(
        UserPtr::from_addr(array as usize),
        stride.checked_mul(count as usize).ok_or(EINVAL)?,
    )
    .reader();

    for _ in 0..count {
        let queue: RawQueueSubmit = reader.read()?;
        read_padding_zero(&mut reader, stride - min_size)?;
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
}

impl Job {
    fn new(queue_index: usize, pieces: KVec<StreamPiece>) -> Self {
        Self {
            queue_index,
            pieces,
        }
    }

    /// Merges `queue_submits` into one `Job` per queue index, paired
    /// with the flattened sync-op stream for that queue. The
    /// per-(queue, batch) merge invariant lets the rest of the submit
    /// path assume there is exactly one pending-submit-fence
    /// reservation and one wrapped-stream allocation per Job.
    pub(crate) fn from_queue_submits(
        queue_submits: KVec<QueueSubmit>,
    ) -> Result<KVec<(Self, KVec<SyncOp>)>> {
        let mut jobs = KVec::<(Self, KVec<SyncOp>)>::new();

        for queue_submit in queue_submits.into_iter() {
            let queue_index = queue_submit.queue_index();
            let (piece, syncs) = queue_submit.into_parts();
            let has_stream = piece.stream_size != 0;
            let mut syncs = Some(syncs);

            if !has_stream && syncs.as_ref().is_some_and(KVec::is_empty) {
                continue;
            }

            let mut merged = false;
            for (job, job_syncs) in jobs.iter_mut() {
                if job.queue_index == queue_index {
                    if has_stream {
                        job.pieces.push(piece, GFP_KERNEL)?;
                    }
                    let Some(syncs) = syncs.take() else {
                        return Err(EINVAL);
                    };
                    for sync in syncs.into_iter() {
                        job_syncs.push(sync, GFP_KERNEL)?;
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
                (Self::new(queue_index, pieces), syncs.take().ok_or(EINVAL)?),
                GFP_KERNEL,
            )?;
        }

        Ok(jobs)
    }

    pub(crate) fn queue_index(&self) -> usize {
        self.queue_index
    }

    pub(crate) fn piece_count(&self) -> usize {
        self.pieces.len()
    }

    pub(crate) fn has_stream(&self) -> bool {
        !self.pieces.is_empty()
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
    ///
    /// When `profiling_mask` enables sampling, `STORE_STATE` pairs
    /// record the GPU cycle counter and/or timestamp into the per-job
    /// slot at `profiling_va`, before the first piece's `CALL` and
    /// after the last piece's, so the before/after delta covers the
    /// whole job.
    pub(crate) fn build_wrapped_stream(
        &self,
        group: &Group,
        sync_va: u64,
        profiling_va: u64,
        profiling_mask: u32,
    ) -> Result<KVec<u8>> {
        const INSTR_BYTES: usize = 8;
        // Instructions in the base wrapper emitted for every piece, and
        // the per-job `MOV48`/`STORE_STATE` pairs emitted for each enabled
        // profiling flag, one pair before the first piece's `CALL` and one
        // after the last piece's.
        const BASE_INSTRS: usize = 11;
        const INSTRS_PER_FLAG: usize = 4;

        // Pull CSF working-register and scoreboard counts from the
        // firmware so the wrapper adapts to the per-chip CSIF
        // configuration. `work_regs` is the total CS register count;
        // the firmware reserves the top `UNPRESERVED_CS_REG_COUNT` for
        // the kernel-side wrapper.
        let (_csg_slot_count, _cs_slot_count, work_regs, scoreboards) =
            group.tdev.fw.csif_info_counts()?;
        let addr_reg = u64::from(
            work_regs
                .checked_sub(crate::gpu::UNPRESERVED_CS_REG_COUNT)
                .ok_or(EINVAL)?,
        );
        let val_reg = addr_reg + 2;
        // The cycle and timestamp samplers reuse the wrapper's address
        // and value registers.
        let cycle_reg = addr_reg;
        let time_reg = val_reg;
        let top_sb = scoreboards.checked_sub(1).ok_or(EINVAL)?;
        let wait_all_mask = genmask_checked_u64(0..=top_sb).ok_or(EINVAL)?;

        let cycles = profiling_mask & DEVICE_PROFILING_CYCLES != 0;
        let timestamp = profiling_mask & DEVICE_PROFILING_TIMESTAMP != 0;
        let cycles_before_va = profiling_va + offset_of!(JobProfilingData, cycles_before) as u64;
        let cycles_after_va = profiling_va + offset_of!(JobProfilingData, cycles_after) as u64;
        let time_before_va = profiling_va + offset_of!(JobProfilingData, time_before) as u64;
        let time_after_va = profiling_va + offset_of!(JobProfilingData, time_after) as u64;

        // Size to the instructions emitted for the enabled flags, so an
        // unprofiled wrapper stays compact.
        let profiling_bytes = if self.pieces.is_empty() {
            0
        } else {
            INSTR_BYTES * INSTRS_PER_FLAG * (usize::from(cycles) + usize::from(timestamp))
        };
        let total = self
            .pieces
            .len()
            .checked_mul(INSTR_BYTES * BASE_INSTRS)
            .and_then(|bytes| bytes.checked_add(profiling_bytes))
            .ok_or(EOVERFLOW)?;
        let padded = total.next_multiple_of(64);
        let mut buf = KVec::<u8>::with_capacity(padded, GFP_KERNEL)?;

        {
            let mut emit = |word: u64| buf.extend_from_slice(&word.to_le_bytes(), GFP_KERNEL);

            for (i, piece) in self.pieces.iter().enumerate() {
                let first = i == 0;
                let last = i + 1 == self.pieces.len();

                emit(Instr::mov32(val_reg, piece.latest_flush.into()))?;
                emit(Instr::flush_cache2(val_reg))?;
                if cycles && first {
                    emit(Instr::mov48(cycle_reg, cycles_before_va))?;
                    emit(Instr::store_state(cycle_reg, 1))?;
                }
                if timestamp && first {
                    emit(Instr::mov48(time_reg, time_before_va))?;
                    emit(Instr::store_state(time_reg, 0))?;
                }
                emit(Instr::mov48(addr_reg, piece.stream_addr))?;
                emit(Instr::mov32(val_reg, piece.stream_size.into()))?;
                emit(Instr::wait(1))?;
                emit(Instr::call(addr_reg, val_reg))?;
                if cycles && last {
                    emit(Instr::mov48(cycle_reg, cycles_after_va))?;
                    emit(Instr::store_state(cycle_reg, 1))?;
                }
                if timestamp && last {
                    emit(Instr::mov48(time_reg, time_after_va))?;
                    emit(Instr::store_state(time_reg, 0))?;
                }
                emit(Instr::mov48(addr_reg, sync_va))?;
                emit(Instr::mov48(val_reg, 1))?;
                emit(Instr::wait(wait_all_mask))?;
                emit(Instr::sync_add64(addr_reg, val_reg))?;
                emit(Instr::error_barrier())?;
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
}
