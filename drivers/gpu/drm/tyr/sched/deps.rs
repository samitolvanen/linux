// SPDX-License-Identifier: GPL-2.0 or MIT

//! A way to track the internal dependencies of a group submit.

use crate::mmu::vm::bind_job::{VmBindFenceData, VmBindJobHandler};
use crate::sched::job::TyrJobFenceData;
use kernel::alloc::KVec;
use kernel::dma_fence::FenceChain;
use kernel::dma_fence::PublicDmaFence;
use kernel::drm::job_queue::JobQueue;
use kernel::drm::syncobj::SyncObj;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::types::ARef;
use kernel::uapi;

use crate::driver::TyrDriver;
use crate::file::DrmFile;
use crate::mmu::vm::VmBindJob;
use crate::sched::job::Job;

/// Represents either a GPU job or a VM bind job
pub(crate) enum JobType {
    Gpu(Job),
    VmBind(VmBindJob),
}

pub(crate) enum SyncHandle {
    Binary { handle: u32 },
    Timeline { handle: u32, timeline_value: u64 },
}

impl SyncHandle {
    /// Get the handle for this sync operation
    pub(crate) fn handle(&self) -> u32 {
        match self {
            SyncHandle::Binary { handle } => *handle,
            SyncHandle::Timeline { handle, .. } => *handle,
        }
    }

    /// Get the timeline value, or 0 for binary syncobjs
    pub(crate) fn timeline_value(&self) -> u64 {
        match self {
            SyncHandle::Binary { .. } => 0,
            SyncHandle::Timeline { timeline_value, .. } => *timeline_value,
        }
    }
}

pub(crate) struct SyncOp {
    ty: SyncOpType,
    /// The sync handle.
    handle: SyncHandle,
}

impl TryFrom<&crate::file::SyncOp> for SyncOp {
    type Error = Error;

    fn try_from(uapi_sync: &crate::file::SyncOp) -> Result<Self> {
        let handle_type = uapi_sync.flags
            & uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK as u32;

        let ty = if uapi_sync.flags
            & uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_SIGNAL as u32
            != 0
        {
            SyncOpType::Signal
        } else {
            SyncOpType::Wait
        };

        // Create appropriate SyncHandle based on handle type
        let handle = if handle_type
            == uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ
                as u32
        {
            SyncHandle::Timeline {
                handle: uapi_sync.handle,
                timeline_value: uapi_sync.timeline_value,
            }
        } else if handle_type
            == uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ as u32
        {
            // Binary syncobjs should have timeline_value == 0
            if uapi_sync.timeline_value != 0 {
                return Err(EINVAL);
            }
            SyncHandle::Binary {
                handle: uapi_sync.handle,
            }
        } else {
            return Err(EINVAL);
        };

        Ok(SyncOp { ty, handle })
    }
}

impl SyncOp {
    /// Convert a slice of UAPI sync operations to internal representation
    pub(crate) fn from_uapi_slice(uapi_syncs: &[crate::file::SyncOp]) -> Result<Arc<KVec<Self>>> {
        let mut syncs = KVec::with_capacity(uapi_syncs.len(), GFP_KERNEL)?;
        for uapi_sync in uapi_syncs.iter() {
            syncs.push(Self::try_from(uapi_sync)?, GFP_KERNEL)?;
        }
        Ok(Arc::new(syncs, GFP_KERNEL)?)
    }
}

/// Fence type for sync signals
enum SyncFence {
    /// Binary syncobj - just a fence
    Binary(Option<ARef<PublicDmaFence>>),
    /// Timeline syncobj - uses a fence chain, and stores current fence at this point
    Timeline {
        chain: FenceChain,
        current_fence: Option<ARef<PublicDmaFence>>,
    },
}

/// Internal sync signal tracking structure
struct SyncSignal {
    /// The syncobj handle
    handle: u32,
    /// The syncobj point (0 for regular syncobjs, non-zero for timeline syncobjs)
    point: u64,
    /// The syncobj reference
    syncobj: SyncObj<TyrDriver>,
    /// The fence or fence chain for this signal
    fence_type: SyncFence,
}

impl SyncSignal {
    /// Get the current fence for this signal (if any)
    fn current_fence(&self) -> Option<&ARef<PublicDmaFence>> {
        match &self.fence_type {
            SyncFence::Binary(fence) => fence.as_ref(),
            SyncFence::Timeline { current_fence, .. } => current_fence.as_ref(),
        }
    }
}

/// Job state tracking for a job in the submission context
enum JobState {
    /// Job is ready to be processed
    Pending(JobType),
    /// Job has been taken out and is being processed
    Taken,
}

pub(crate) struct JobContext {
    state: JobState,

    // The sync operations for the submission.
    syncops: Arc<KVec<SyncOp>>,
}

#[repr(i32)]
pub(crate) enum SyncOpType {
    Wait = kernel::uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_WAIT,
    Signal = kernel::uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_SIGNAL,
}

/// A context for intra-batch job synchronization.
///
/// This implements roughly the same algorithms as Panthor:
///
/// - First the jobs need to be added to the context.
///
/// - Once all jobs are added, `collect_signal_ops` must be called to gather
///   all signal operations in the batch.
///
/// - Then `add_deps_and_push_jobs` can be called to process all jobs:
///
/// - This will collect all dependency fences for each job, arm the job, update
///   the signal operations with the job's done fence, and push the job to the
///   scheduler.
///
/// - The dependencies come from either the signals collected in the context
///   itself, or from a previously submitted job (in which case, we find the fence
///   with `drm_syncobj_find_fence`).
pub(crate) struct Context<'a> {
    /// The DRM file that this submission happens on.
    file: &'a DrmFile,

    /// The list of jobs in this submission.
    jobs: KVec<JobContext>,

    /// Internal signal registry for intra-batch dependencies
    ///
    /// This tracks all signal operations that will be produced by jobs in this batch,
    /// allowing later jobs to depend on earlier jobs' completion fences.
    signals: KVec<SyncSignal>,
}

impl<'a> Context<'a> {
    pub(crate) fn new(file: &'a DrmFile) -> Self {
        Context {
            file,
            jobs: KVec::new(),
            signals: KVec::new(),
        }
    }

    pub(crate) fn add_job(&mut self, job: Job, syncops: Arc<KVec<SyncOp>>) -> Result {
        self.jobs
            .push(
                JobContext {
                    state: JobState::Pending(JobType::Gpu(job)),
                    syncops,
                },
                GFP_KERNEL,
            )
            .map_err(Into::into)
    }

    pub(crate) fn add_vm_bind_job(&mut self, job: VmBindJob, syncops: Arc<KVec<SyncOp>>) -> Result {
        self.jobs
            .push(
                JobContext {
                    state: JobState::Pending(JobType::VmBind(job)),
                    syncops,
                },
                GFP_KERNEL,
            )
            .map_err(Into::into)
    }

    /// Collect all signal operations in a batch.
    pub(crate) fn collect_signal_ops(&mut self, syncops: &[SyncOp]) -> Result {
        for syncop in syncops.iter() {
            if matches!(syncop.ty, SyncOpType::Signal) {
                self.get_sync_signal(syncop.handle.handle(), syncop.handle.timeline_value())?;
            }
        }
        Ok(())
    }

    /// Add jobs dependencies and submit them to the job queue.
    ///
    /// Returns a vector of finished fences that need to be added to reservation objects.
    pub(crate) fn add_deps_and_push_jobs(
        &mut self,
        job_queue: &JobQueue<super::job::TyrJobHandler>,
        queue_idx: usize,
    ) -> Result<KVec<ARef<PublicDmaFence>>> {
        let mut finished_fences = KVec::new();

        for job_idx in 0..self.jobs.len() {
            // Only process GPU jobs for this queue
            match &self.jobs[job_idx].state {
                JobState::Pending(JobType::Gpu(job)) => {
                    if job.queue_idx() != queue_idx {
                        continue;
                    }
                }
                JobState::Pending(JobType::VmBind(_)) => continue,
                JobState::Taken => continue,
            }

            let fences = self.collect_job_deps(job_idx)?;

            let job = match core::mem::replace(&mut self.jobs[job_idx].state, JobState::Taken) {
                JobState::Pending(JobType::Gpu(job)) => job,
                _ => {
                    return Err(EINVAL);
                }
            };

            let finished_fence = job_queue.submit(job, TyrJobFenceData, &fences)?;

            // Update the sync signal fences with the job's completion fence
            self.update_job_syncs(job_idx, finished_fence.clone())?;

            finished_fences.push(finished_fence, GFP_KERNEL)?;
        }

        Ok(finished_fences)
    }

    /// Add VM bind job dependencies and submit them to the job queue.
    ///
    /// Returns a vector of finished fences that need to be added to reservation objects.
    pub(crate) fn add_deps_and_push_vm_bind_jobs(
        &mut self,
        job_queue: &JobQueue<VmBindJobHandler>,
    ) -> Result<KVec<ARef<PublicDmaFence>>> {
        let mut finished_fences = KVec::new();

        for job_idx in 0..self.jobs.len() {
            // Only process VM bind jobs
            match &self.jobs[job_idx].state {
                JobState::Pending(JobType::VmBind(_)) => {}
                JobState::Pending(JobType::Gpu(_)) => continue,
                JobState::Taken => continue,
            }

            let fences = self.collect_job_deps(job_idx)?;

            let job = match core::mem::replace(&mut self.jobs[job_idx].state, JobState::Taken) {
                JobState::Pending(JobType::VmBind(job)) => job,
                _ => {
                    return Err(EINVAL);
                }
            };

            let finished_fence = job_queue.submit(job, VmBindFenceData, &fences)?;

            // Update the sync signal fences with the job's completion fence
            self.update_job_syncs(job_idx, finished_fence.clone())?;

            finished_fences.push(finished_fence, GFP_KERNEL)?;
        }

        Ok(finished_fences)
    }

    /// Push signal fences to their associated syncobjs
    ///
    /// This is the last step of a submission procedure, and is done once we know
    /// the submission is effective and job fences are guaranteed to be signaled
    /// in finite time.
    pub(crate) fn push_fences(self) {
        for sig_sync in self.signals.into_iter() {
            match sig_sync.fence_type {
                SyncFence::Binary(fence) => {
                    // For binary syncobjs, replace the fence
                    if let Some(fence) = fence {
                        sig_sync.syncobj.replace_fence(Some(&*fence));
                    }
                }
                SyncFence::Timeline {
                    chain,
                    current_fence,
                } => {
                    // For timeline syncobjs, add a point using the fence chain
                    if let Some(fence) = current_fence {
                        sig_sync.syncobj.add_point(chain, &*fence, sig_sync.point);
                    }
                }
            }
        }
    }

    fn search_sync_signal(&self, handle: u32, point: u64) -> Option<&SyncSignal> {
        self.signals
            .iter()
            .find(|sig| sig.handle == handle && sig.point == point)
    }

    fn add_sync_signal(&mut self, handle: u32, point: u64) -> Result {
        let syncobj = SyncObj::lookup_handle(self.file, handle)?;

        // Retrieve the current fence attached to that point.
        //
        // If we get a None here it just means there's no fence attached to that
        // point yet.
        //
        // For binary syncobjs, point will be 0; for timeline syncobjs, it's the
        // actual point
        let current_fence =
            SyncObj::<TyrDriver>::find_fence(self.file, handle, point, 0).unwrap_or(None);

        let fence_type = if point > 0 {
            let chain = FenceChain::new()?;
            SyncFence::Timeline {
                chain,
                current_fence,
            }
        } else {
            SyncFence::Binary(current_fence)
        };

        let signal = SyncSignal {
            handle,
            point,
            syncobj,
            fence_type,
        };

        self.signals.push(signal, GFP_KERNEL)?;
        Ok(())
    }

    fn get_sync_signal(&mut self, handle: u32, point: u64) -> Result {
        if self.search_sync_signal(handle, point).is_some() {
            return Ok(());
        }

        self.add_sync_signal(handle, point)
    }

    fn collect_job_deps(&self, job_idx: usize) -> Result<KVec<ARef<PublicDmaFence>>> {
        let syncops = &self.jobs[job_idx].syncops;
        let mut deps = KVec::new();

        for syncop in syncops.iter() {
            if !matches!(syncop.ty, SyncOpType::Wait) {
                continue;
            }

            let handle = syncop.handle.handle();
            let point = syncop.handle.timeline_value();

            // First check if we have this signal in our internal context.
            let fence = if let Some(sig_sync) = self.search_sync_signal(handle, point) {
                match sig_sync.current_fence() {
                    Some(f) => f.clone(),
                    None => return Err(EINVAL),
                }
            } else {
                // Otherwise, this is from a different submission - look it up.
                match SyncObj::<TyrDriver>::find_fence(self.file, handle, point, 0)? {
                    Some(f) => f,
                    None => return Err(EINVAL), // A wait for which we can't find a fence is broken.
                }
            };

            deps.push(fence, GFP_KERNEL)?;
        }

        Ok(deps)
    }

    fn update_job_syncs(&mut self, job_idx: usize, done_fence: ARef<PublicDmaFence>) -> Result {
        // Get the sync operations for this job
        let syncops = self.jobs[job_idx].syncops.clone();

        for syncop in syncops.iter() {
            if !matches!(syncop.ty, SyncOpType::Signal) {
                continue;
            }

            let handle = syncop.handle.handle();
            let point = syncop.handle.timeline_value();

            // Find the signal in our internal registry
            if let Some(sig_sync) = self
                .signals
                .iter_mut()
                .find(|sig| sig.handle == handle && sig.point == point)
            {
                // Update the fence in the signal with the job's done fence
                match &mut sig_sync.fence_type {
                    SyncFence::Binary(fence) => {
                        *fence = Some(done_fence.clone());
                    }
                    SyncFence::Timeline { current_fence, .. } => {
                        *current_fence = Some(done_fence.clone());
                    }
                }
            } else {
                return Err(EINVAL);
            }
        }

        Ok(())
    }
}
