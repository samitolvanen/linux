// SPDX-License-Identifier: GPL-2.0 or MIT

//! Scheduler-owned synchronization operation types.
//!
//! Group submission and async VM bind consume parsed sync operations, so
//! the internal sync handle and operation vocabulary lives here instead of
//! in the UAPI parsing layer.

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

/// An entry in `Context`'s per-batch signal registry.
///
/// The `fence` slot starts as the fence the syncobj carries when the
/// entry is created, and the commit of the producing job replaces it.
/// Every entry comes from a SIGNAL syncop, and `Context::push_fences`
/// runs only after every commit in the batch has succeeded. The starting
/// fence is therefore never published back to the syncobj.
enum PendingSignal {
    Binary {
        syncobj: SyncObj<TyrDrmDriver>,
        handle: u32,
        job_idx: usize,
        fence: Option<ARef<PublicDmaFence>>,
    },
    Timeline {
        syncobj: SyncObj<TyrDrmDriver>,
        handle: u32,
        point: u64,
        job_idx: usize,
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

    /// Index of the first job in the batch that signals this key.
    fn job_idx(&self) -> usize {
        match self {
            Self::Binary { job_idx, .. } | Self::Timeline { job_idx, .. } => *job_idx,
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

/// How one job of a batch reaches its queue.
///
/// A group submit and an async VM bind track dependencies the same way
/// and differ only in the queue a job goes to, so each path implements
/// this and shares `Context`.
///
/// `Context` prepares each job at most once. The caller drives prepare
/// and then commit in ascending job index, and a caller that shares a
/// queue with another batch serializes the whole window from the first
/// prepare to the last commit. The queue fixes the order it runs jobs
/// in at prepare time and their fence sequence numbers at commit time.
pub(crate) trait BatchOps {
    /// Job description the context holds until it is prepared.
    type Job;
    /// Handle to a prepared job, consumed by `Self::commit`.
    type Prepared;

    /// Queues `job` behind `deps` and reserves `extra_dep_capacity`
    /// dependency slots for `Self::add_dep` to fill.
    fn prepare(
        &self,
        job: Self::Job,
        deps: &[ARef<PublicDmaFence>],
        extra_dep_capacity: usize,
    ) -> Result<Self::Prepared>;

    /// Appends `fence` to the dependencies of a prepared job. Must not
    /// allocate. Later calls in a batch run with earlier fences already
    /// installed in a reservation, so they run inside a dma-fence
    /// signalling section.
    fn add_dep(&self, prepared: &mut Self::Prepared, fence: ARef<PublicDmaFence>) -> Result;

    /// Submits a prepared job and returns the fence that gates its
    /// completion. Must not allocate, for the same reason as
    /// `Self::add_dep`.
    fn commit(&self, prepared: Self::Prepared) -> Result<ARef<PublicDmaFence>>;
}

/// Dependencies collected for one job's WAIT syncops.
struct CollectedDeps {
    /// Fences that already exist when the job is prepared, passed to
    /// `BatchOps::prepare`.
    external: KVec<ARef<PublicDmaFence>>,
    /// (handle, point) keys of WAITs met by a producer earlier in the
    /// batch.
    intra_batch: KVec<(u32, u64)>,
}

/// One SIGNAL syncop held by `Context::collect_signal_ops` while the job
/// list is borrowed, then consumed to build the signal registry.
struct StagedSignal {
    /// Index of the job that carries this syncop.
    job_idx: usize,
    handle: u32,
    point: u64,
}

/// Per-job tracking state inside `Context`.
enum JobState<T: BatchOps> {
    Pending(T::Job),
    Prepared {
        prepared: T::Prepared,
        /// (handle, point) pairs of WAIT syncops resolved at prepare time
        /// to a SIGNAL produced earlier in the same batch. The producer's
        /// fence is looked up from `Context::signals` at commit time and
        /// pushed into `prepared` via `BatchOps::add_dep`.
        intra_batch_deps: KVec<(u32, u64)>,
    },
}

struct JobContext<T: BatchOps> {
    /// `None` once the job has been moved out by `Context::prepare` or
    /// `Context::commit`.
    state: Option<JobState<T>>,
    /// Shared so `Context::update_job_syncs` can scan the signal ops
    /// while `Context::signals` is borrowed mutably.
    syncops: Arc<KVec<SyncOp>>,
}

/// Tracks intra-batch dependencies across a single batch of jobs.
///
/// Userspace can submit several jobs in one batch where a later job
/// WAITs on a syncobj a producer earlier in the same batch SIGNALs. The
/// producer's fence does not exist until its own commit returns it, so
/// plain `drm_syncobj_find_fence` at prepare time would return `None`
/// and the wait would fail.
///
/// The Context resolves this in three phases:
///
/// 1. `Self::add_job` is called for every job in the batch.
/// 2. `Self::collect_signal_ops` registers every (handle, point) the
///    batch SIGNALs together with the fence it carries at that moment,
///    building the per-batch signal registry.
/// 3. `Self::prepare` is called per job and looks WAITs up first in
///    the signal registry (intra-batch) and falls back to
///    `drm_syncobj_find_fence` (external). External fences go straight
///    to `BatchOps::prepare`. Intra-batch deps are stashed for the
///    commit step.
///
/// `Self::commit` then walks the stashed intra-batch deps for each
/// job, resolves them via the signal registry, appends them to the
/// prepared job (allocation-free thanks to the capacity reserved at
/// prepare time), and finally calls into the queue. Once every commit
/// has succeeded, `Self::push_fences` advances the producer fences
/// onto their syncobjs.
pub(crate) struct Context<'a, T: BatchOps> {
    file: &'a TyrDrmFile,
    ops: T,
    jobs: KVec<JobContext<T>>,
    signals: KVec<PendingSignal>,
}

impl<'a, T: BatchOps> Context<'a, T> {
    pub(crate) fn new(file: &'a TyrDrmFile, ops: T) -> Self {
        Self {
            file,
            ops,
            jobs: KVec::new(),
            signals: KVec::new(),
        }
    }

    pub(crate) fn add_job(&mut self, job: T::Job, syncops: Arc<KVec<SyncOp>>) -> Result {
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
        for (job_idx, job_ctx) in self.jobs.iter().enumerate() {
            for syncop in job_ctx.syncops.iter() {
                if !syncop.is_signal() {
                    continue;
                }
                let staged = StagedSignal {
                    job_idx,
                    handle: syncop.handle.handle(),
                    point: syncop.handle.timeline_value(),
                };
                to_add.push(staged, GFP_KERNEL)?;
            }
        }
        for staged in to_add.into_iter() {
            self.add_sync_signal(staged.job_idx, staged.handle, staged.point)?;
        }
        Ok(())
    }

    /// Prepares the job at `job_idx` for submission.
    ///
    /// Resolves WAIT syncops against the in-batch signal registry
    /// (intra-batch) and `drm_syncobj_find_fence` (external), then hands
    /// the job to `BatchOps::prepare` with enough dep capacity reserved
    /// to absorb every intra-batch fence at commit time.
    pub(crate) fn prepare(&mut self, job_idx: usize) -> Result {
        let job = match self.jobs[job_idx].state.take() {
            Some(JobState::Pending(job)) => job,
            _ => return Err(EINVAL),
        };

        let CollectedDeps {
            external: external_deps,
            intra_batch: intra_batch_deps,
        } = self.collect_job_deps(job_idx)?;

        let prepared = self
            .ops
            .prepare(job, &external_deps, intra_batch_deps.len())?;

        self.jobs[job_idx].state = Some(JobState::Prepared {
            prepared,
            intra_batch_deps,
        });

        Ok(())
    }

    /// Commits the job at `job_idx` and returns the fence that gates its
    /// completion. This is the same fence wired to the job's signal
    /// syncobjs, so the caller can add it to a reservation object in
    /// agreement with the syncobjs.
    ///
    /// The path is allocation-free, so it may run in a dma-fence
    /// signalling section. Intra-batch fences are appended via
    /// `BatchOps::add_dep` within the capacity reserved at prepare time,
    /// and `Self::update_job_syncs` only writes into a pre-allocated
    /// slot. Neither caller opens an annotation of its own. Both hold a
    /// reservation lock, and every fence they have already installed
    /// there is in a signalling section from that point on.
    ///
    /// A batch commits in prepare order, and the caller holds the lock
    /// that serializes the whole prepare-to-commit window, so a queue
    /// claims its seqno ranges in the order its pipeline runs the jobs.
    pub(crate) fn commit(&mut self, job_idx: usize) -> Result<ARef<PublicDmaFence>> {
        let (mut prepared, intra_batch_deps) = match self.jobs[job_idx].state.take() {
            Some(JobState::Prepared {
                prepared,
                intra_batch_deps,
            }) => (prepared, intra_batch_deps),
            _ => return Err(EINVAL),
        };

        for (handle, point) in intra_batch_deps.iter() {
            let fence = self
                .search_sync_signal(*handle, *point)
                .and_then(PendingSignal::fence)
                .ok_or(EINVAL)?
                .clone();
            self.ops.add_dep(&mut prepared, fence)?;
        }

        let signal_fence = self.ops.commit(prepared)?;

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

    fn add_sync_signal(&mut self, job_idx: usize, handle: u32, point: u64) -> Result {
        if self.search_sync_signal(handle, point).is_some() {
            return Ok(());
        }

        let syncobj = SyncObj::<TyrDrmDriver>::lookup_handle(self.file, handle)?;

        // A syncobj the batch signals often carries no fence yet, so a
        // failed lookup is expected and leaves the slot empty.
        let fence = SyncObj::<TyrDrmDriver>::find_fence(self.file, handle, point, 0)
            .ok()
            .flatten();

        let signal = if point > 0 {
            PendingSignal::Timeline {
                syncobj,
                handle,
                point,
                job_idx,
                chain: FenceChain::new()?,
                fence,
            }
        } else {
            PendingSignal::Binary {
                syncobj,
                handle,
                job_idx,
                fence,
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

            if let Some(signal) = self.search_sync_signal(handle, point) {
                if signal.job_idx() < job_idx {
                    intra_batch.push((handle, point), GFP_KERNEL)?;
                    continue;
                }

                // The producer commits at or after this job, so only the
                // fence the syncobj carried at registration can meet
                // the wait.
                external.push(signal.fence().ok_or(EINVAL)?.clone(), GFP_KERNEL)?;
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
