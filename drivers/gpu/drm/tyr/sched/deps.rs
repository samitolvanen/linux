// SPDX-License-Identifier: GPL-2.0 or MIT

//! Scheduler-owned synchronization operation types.
//!
//! Group submission consumes parsed sync operations as scheduler input, so the
//! internal sync handle and operation vocabulary lives here instead of in the
//! UAPI parsing layer.

use kernel::{
    alloc::KVec,
    dma_buf::dma_fence::{FenceChain, PublicDmaFence},
    drm::syncobj::SyncObj,
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    },
    transmute::FromBytes,
    uaccess::UserSlice,
    uapi,
};

use crate::{driver::TyrDrmDriver, file::TyrDrmFile};

use super::{
    group::Group,
    job::Job,
    queue::{
        PreparedQueueJob,
        QueueJob, //
    },
    //
};

#[repr(transparent)]
struct RawSyncOp(uapi::drm_panthor_sync_op);

// SAFETY: This wrapper is layout-identical to the UAPI sync-op record read
// from userspace.
unsafe impl FromBytes for RawSyncOp {}

#[repr(i32)]
pub(crate) enum SyncOpType {
    Wait = kernel::uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_WAIT,
    Signal = kernel::uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_SIGNAL,
}

pub(crate) enum SyncHandle {
    Binary { handle: u32 },
    Timeline { handle: u32, timeline_value: u64 },
}

impl SyncHandle {
    pub(crate) fn handle(&self) -> u32 {
        match self {
            Self::Binary { handle } | Self::Timeline { handle, .. } => *handle,
        }
    }

    pub(crate) fn timeline_value(&self) -> u64 {
        match self {
            Self::Binary { .. } => 0,
            Self::Timeline { timeline_value, .. } => *timeline_value,
        }
    }
}

pub(crate) struct SyncOp {
    pub(crate) ty: SyncOpType,
    pub(crate) handle: SyncHandle,
}

pub(crate) enum SyncSignal {
    Binary(SyncObj<TyrDrmDriver>),
    Timeline {
        syncobj: SyncObj<TyrDrmDriver>,
        point: u64,
        chain: FenceChain,
    },
}

impl SyncSignal {
    pub(crate) fn publish(self, fence: &PublicDmaFence) {
        match self {
            Self::Binary(syncobj) => syncobj.replace_fence(Some(fence)),
            Self::Timeline {
                syncobj,
                point,
                chain,
            } => syncobj.add_point(chain, fence, point),
        }
    }
}

/// An entry in `Context`'s per-batch signal registry. The `fence`
/// slot is `None` until the producing job has been committed;
/// `Context::push_fences` publishes whatever fences are present once
/// every commit has succeeded.
enum PendingSignal {
    Binary {
        syncobj: SyncObj<TyrDrmDriver>,
        handle: u32,
        fence: Option<ARef<PublicDmaFence>>,
    },
    Timeline {
        syncobj: SyncObj<TyrDrmDriver>,
        handle: u32,
        point: u64,
        chain: FenceChain,
        fence: Option<ARef<PublicDmaFence>>,
    },
}

impl PendingSignal {
    fn key(&self) -> (u32, u64) {
        match self {
            Self::Binary { handle, .. } => (*handle, 0),
            Self::Timeline { handle, point, .. } => (*handle, *point),
        }
    }

    fn fence(&self) -> Option<&ARef<PublicDmaFence>> {
        match self {
            Self::Binary { fence, .. } | Self::Timeline { fence, .. } => fence.as_ref(),
        }
    }

    fn set_fence(&mut self, new_fence: ARef<PublicDmaFence>) {
        match self {
            Self::Binary { fence, .. } | Self::Timeline { fence, .. } => *fence = Some(new_fence),
        }
    }

    fn publish(self) {
        match self {
            Self::Binary { syncobj, fence, .. } => {
                if let Some(fence) = fence {
                    syncobj.replace_fence(Some(&fence));
                }
            }
            Self::Timeline {
                syncobj,
                point,
                chain,
                fence,
                ..
            } => {
                if let Some(fence) = fence {
                    syncobj.add_point(chain, &fence, point);
                }
            }
        }
    }
}

impl SyncOp {
    pub(crate) fn is_signal(&self) -> bool {
        matches!(self.ty, SyncOpType::Signal)
    }

    pub(crate) fn is_wait(&self) -> bool {
        matches!(self.ty, SyncOpType::Wait)
    }
}

impl TryFrom<&uapi::drm_panthor_sync_op> for SyncOp {
    type Error = Error;

    fn try_from(uapi_sync: &uapi::drm_panthor_sync_op) -> Result<Self> {
        let valid_flags = (uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_SIGNAL
            | uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_WAIT
            | uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK)
            as u32;

        if uapi_sync.flags & !valid_flags != 0 {
            return Err(EINVAL);
        }

        let handle_type = uapi_sync.flags
            & uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK as u32;

        if handle_type
            != uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ as u32
            && handle_type
                != uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ
                    as u32
        {
            return Err(EINVAL);
        }

        let ty = if uapi_sync.flags
            & uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_SIGNAL as u32
            != 0
        {
            SyncOpType::Signal
        } else {
            SyncOpType::Wait
        };

        let handle = if handle_type
            == uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ
                as u32
        {
            SyncHandle::Timeline {
                handle: uapi_sync.handle,
                timeline_value: uapi_sync.timeline_value,
            }
        } else {
            if uapi_sync.timeline_value != 0 {
                return Err(EINVAL);
            }

            SyncHandle::Binary {
                handle: uapi_sync.handle,
            }
        };

        Ok(Self { ty, handle })
    }
}

pub(crate) fn wait_fences(
    file: &TyrDrmFile,
    syncops: &[SyncOp],
) -> Result<KVec<ARef<PublicDmaFence>>> {
    let mut fences = KVec::new();

    for sync in syncops.iter().filter(|sync| sync.is_wait()) {
        let fence = SyncObj::<TyrDrmDriver>::find_fence(
            file,
            sync.handle.handle(),
            sync.handle.timeline_value(),
            0,
        )?
        .ok_or(EINVAL)?;
        fences.push(fence, GFP_KERNEL)?;
    }

    Ok(fences)
}

pub(crate) fn signal_syncs(file: &TyrDrmFile, syncops: &[SyncOp]) -> Result<KVec<SyncSignal>> {
    let mut signals = KVec::new();

    for sync in syncops.iter().filter(|sync| sync.is_signal()) {
        let syncobj = SyncObj::<TyrDrmDriver>::lookup_handle(file, sync.handle.handle())?;
        let signal = match sync.handle {
            SyncHandle::Binary { .. } => SyncSignal::Binary(syncobj),
            SyncHandle::Timeline { timeline_value, .. } => SyncSignal::Timeline {
                syncobj,
                point: timeline_value,
                chain: FenceChain::new()?,
            },
        };
        signals.push(signal, GFP_KERNEL)?;
    }

    Ok(signals)
}

pub(crate) fn append_syncops(
    syncops: &mut KVec<SyncOp>,
    array: u64,
    count: u32,
    stride: u32,
) -> Result {
    if count == 0 {
        return Ok(());
    }

    if stride as usize != core::mem::size_of::<uapi::drm_panthor_sync_op>() {
        return Err(ENOTSUPP);
    }

    let mut reader = UserSlice::new(
        UserPtr::from_addr(array as usize),
        stride as usize * count as usize,
    )
    .reader();

    for _ in 0..count {
        let sync: RawSyncOp = reader.read()?;
        syncops.push(SyncOp::try_from(&sync.0)?, GFP_KERNEL)?;
    }

    Ok(())
}

/// Dependencies collected for one job's WAIT syncops.
struct CollectedDeps {
    /// External fences passed to `JobQueue::prepare`.
    external: KVec<ARef<PublicDmaFence>>,
    /// (handle, point) keys of WAITs resolved against the per-batch
    /// signal registry.
    intra_batch: KVec<(u32, u64)>,
}

/// Per-job tracking state inside `Context`.
enum JobState {
    Pending(Job),
    Prepared {
        queue_index: usize,
        prepared: PreparedQueueJob,
        has_stream: bool,
        /// (handle, point) pairs of WAIT syncops resolved at prepare time
        /// to a SIGNAL produced earlier in the same batch. The producer's
        /// submit fence is looked up from `Context::signals` at commit
        /// time and pushed into `prepared` via
        /// `PreparedQueueJob::add_dep`.
        intra_batch_deps: KVec<(u32, u64)>,
    },
}

struct JobContext {
    /// `None` once the job has been moved out by `Context::prepare` or
    /// `Context::commit`.
    state: Option<JobState>,
    /// Shared so `Context::update_job_syncs` can scan the signal ops
    /// while `Context::signals` is borrowed mutably.
    syncops: Arc<KVec<SyncOp>>,
}

/// Tracks intra-batch dependencies across a single group submit.
///
/// Userspace can submit several queue jobs in one `DRM_IOCTL_PANTHOR_GROUP_SUBMIT`
/// where a later job WAITs on a syncobj a producer earlier in the same
/// batch SIGNALs. The producer's submit fence does not exist until its
/// own commit returns it, so plain `drm_syncobj_find_fence` at prepare
/// time would return `None` and the wait would fail.
///
/// The Context resolves this in three phases:
///
/// 1. `Self::add_job` is called for every Job in the batch.
/// 2. `Self::collect_signal_ops` registers every (handle, point) the
///    batch SIGNALs, building the per-batch signal registry.
/// 3. `Self::prepare` is called per Job and looks WAITs up first in
///    the signal registry (intra-batch) and falls back to
///    `drm_syncobj_find_fence` (external). External fences are pushed
///    straight into the underlying `PreparedQueueJob`; intra-batch
///    deps are stashed for the commit step.
///
/// `Self::commit` then walks the stashed intra-batch deps for each
/// Job, resolves them via the signal registry, appends them to the
/// prepared job (allocation-free thanks to the capacity reserved at
/// prepare time), and finally calls into the queue. Once every commit
/// has succeeded, `Self::push_fences` advances the producer fences
/// onto their syncobjs.
pub(crate) struct Context<'a> {
    file: &'a TyrDrmFile,
    jobs: KVec<JobContext>,
    signals: KVec<PendingSignal>,
}

impl<'a> Context<'a> {
    pub(crate) fn new(file: &'a TyrDrmFile) -> Self {
        Self {
            file,
            jobs: KVec::new(),
            signals: KVec::new(),
        }
    }

    pub(crate) fn add_job(&mut self, job: Job, syncops: Arc<KVec<SyncOp>>) -> Result {
        self.jobs.push(
            JobContext {
                state: Some(JobState::Pending(job)),
                syncops,
            },
            GFP_KERNEL,
        )?;
        Ok(())
    }

    /// Builds the per-batch signal registry. Must be called once, after
    /// every `Self::add_job`, and before any `Self::prepare`.
    pub(crate) fn collect_signal_ops(&mut self) -> Result {
        let mut to_add = KVec::new();
        for job_ctx in self.jobs.iter() {
            for syncop in job_ctx.syncops.iter() {
                if !syncop.is_signal() {
                    continue;
                }
                let key = (syncop.handle.handle(), syncop.handle.timeline_value());
                to_add.push(key, GFP_KERNEL)?;
            }
        }
        for (handle, point) in to_add.into_iter() {
            self.add_sync_signal(handle, point)?;
        }
        Ok(())
    }

    /// Prepares the Job at `job_idx` for submission.
    ///
    /// Allocates the wrapped command stream, reserves the pending submit
    /// fence slot, resolves WAIT syncops against the in-batch signal
    /// registry (intra-batch) and `drm_syncobj_find_fence` (external),
    /// and hands the job to the queue with enough dep capacity reserved
    /// to absorb every intra-batch fence at commit time.
    pub(crate) fn prepare(&mut self, job_idx: usize, group: &Arc<Group>) -> Result {
        let job = match self.jobs[job_idx].state.take() {
            Some(JobState::Pending(job)) => job,
            _ => return Err(EINVAL),
        };

        let queue_index = job.queue_index();
        let queue = group.queues.get(queue_index).ok_or(EINVAL)?;

        let CollectedDeps {
            external: external_deps,
            intra_batch: intra_batch_deps,
        } = self.collect_job_deps(job_idx)?;
        let has_stream = job.has_stream();

        let reservation = if has_stream {
            Some(queue.reserve_pending_submit_fence()?)
        } else {
            None
        };

        let wrapped = if has_stream {
            let sync_va = group.syncobj_va(queue_index)?;
            job.build_wrapped_stream(group, sync_va)?
        } else {
            KVec::new()
        };

        let prepared = queue.prepare_job(
            QueueJob::new(wrapped, group.clone(), queue_index, reservation),
            &external_deps,
            intra_batch_deps.len(),
        )?;

        // Claim the per-queue seqno range only after prepare_job has
        // succeeded, then thread it into the prepared job. Claiming
        // earlier would advance next_seqno even when a fallible prepare
        // step fails, leaving a range of seqnos that no piece reaches
        // the GPU to retire; the GPU-relative syncobj would then stay
        // permanently behind every later job's completion threshold.
        // The wrapped stream emits exactly one `SYNC_ADD64(+1)` per
        // piece, so the syncobj reaches the highest claimed seqno
        // precisely when every piece has retired.
        if has_stream {
            let done_seqno = queue.claim_seqnos(job.piece_count());
            prepared.job().ok_or(EINVAL)?.set_done_seqno(done_seqno);
        }

        self.jobs[job_idx].state = Some(JobState::Prepared {
            queue_index,
            prepared,
            has_stream,
            intra_batch_deps,
        });

        Ok(())
    }

    /// Commits the Job at `job_idx` and returns the fence that gates its
    /// completion: the job's own submit fence for a command-stream job,
    /// or the adopted prior command-stream fence for a stream-less job.
    /// This is the same fence wired to the job's signal syncobjs, so the
    /// caller can add it to the VM resv in agreement with the syncobjs.
    ///
    /// Runs inside the caller's dma-fence signalling section. The path
    /// is allocation-free: intra-batch fences are appended via
    /// `PreparedQueueJob::add_dep` (within the capacity reserved at
    /// prepare time), `JobQueue::commit` is itself allocation-free,
    /// and `Self::update_job_syncs` only writes into a pre-allocated
    /// slot.
    pub(crate) fn commit(&mut self, job_idx: usize, group: &Group) -> Result<ARef<PublicDmaFence>> {
        let (queue_index, mut prepared, has_stream, intra_batch_deps) =
            match self.jobs[job_idx].state.take() {
                Some(JobState::Prepared {
                    queue_index,
                    prepared,
                    has_stream,
                    intra_batch_deps,
                }) => (queue_index, prepared, has_stream, intra_batch_deps),
                _ => return Err(EINVAL),
            };

        for (handle, point) in intra_batch_deps.iter() {
            let fence = self
                .search_sync_signal(*handle, *point)
                .and_then(PendingSignal::fence)
                .ok_or(EINVAL)?
                .clone();
            prepared.add_dep(fence)?;
        }

        let queue = group.queues.get(queue_index).ok_or(EINVAL)?;
        let submit_fence = queue.commit_job(prepared);

        let signal_fence = if has_stream {
            queue.set_last_submit_fence(submit_fence.clone());
            submit_fence.clone()
        } else {
            queue
                .last_submit_fence()
                .unwrap_or_else(|| submit_fence.clone())
        };

        self.update_job_syncs(job_idx, signal_fence.clone())?;
        Ok(signal_fence)
    }

    /// Publishes each registered producer fence to its syncobj.
    ///
    /// Must be called only after every `Self::commit` in the batch has
    /// succeeded so an early failure leaves every syncobj untouched.
    pub(crate) fn push_fences(self) {
        for signal in self.signals.into_iter() {
            signal.publish();
        }
    }

    fn search_sync_signal(&self, handle: u32, point: u64) -> Option<&PendingSignal> {
        self.signals.iter().find(|sig| sig.key() == (handle, point))
    }

    fn add_sync_signal(&mut self, handle: u32, point: u64) -> Result {
        if self.search_sync_signal(handle, point).is_some() {
            return Ok(());
        }

        let syncobj = SyncObj::<TyrDrmDriver>::lookup_handle(self.file, handle)?;
        let signal = if point > 0 {
            PendingSignal::Timeline {
                syncobj,
                handle,
                point,
                chain: FenceChain::new()?,
                fence: None,
            }
        } else {
            PendingSignal::Binary {
                syncobj,
                handle,
                fence: None,
            }
        };

        self.signals.push(signal, GFP_KERNEL)?;
        Ok(())
    }

    fn collect_job_deps(&self, job_idx: usize) -> Result<CollectedDeps> {
        let mut external = KVec::new();
        let mut intra_batch = KVec::new();

        for syncop in self.jobs[job_idx].syncops.iter() {
            if !syncop.is_wait() {
                continue;
            }

            let handle = syncop.handle.handle();
            let point = syncop.handle.timeline_value();

            if self.search_sync_signal(handle, point).is_some() {
                intra_batch.push((handle, point), GFP_KERNEL)?;
                continue;
            }

            let fence =
                SyncObj::<TyrDrmDriver>::find_fence(self.file, handle, point, 0)?.ok_or(EINVAL)?;
            external.push(fence, GFP_KERNEL)?;
        }

        Ok(CollectedDeps {
            external,
            intra_batch,
        })
    }

    fn update_job_syncs(&mut self, job_idx: usize, done_fence: ARef<PublicDmaFence>) -> Result {
        let syncops = self.jobs[job_idx].syncops.clone();

        for syncop in syncops.iter() {
            if !syncop.is_signal() {
                continue;
            }

            let key = (syncop.handle.handle(), syncop.handle.timeline_value());
            let signal = self
                .signals
                .iter_mut()
                .find(|sig| sig.key() == key)
                .ok_or(EINVAL)?;
            signal.set_fence(done_fence.clone());
        }

        Ok(())
    }
}
