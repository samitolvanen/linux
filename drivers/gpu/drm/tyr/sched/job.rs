// SPDX-License-Identifier: GPL-2.0 or MIT

//! Queue submission helpers for scheduler groups.
//!
//! Group submission batches user queue streams and writes the corresponding
//! firmware sync objects. Keeping that queue-side submit flow here lets the
//! group object focus on group state and scheduler coordination.

use kernel::{
    alloc::KVec,
    dma_buf::dma_fence::PublicDmaFence,
    prelude::*,
    sync::{aref::ARef, Arc},
    transmute::FromBytes,
    uaccess::UserSlice,
    uapi,
};

use super::{
    deps::{self, SyncOp, SyncSignal},
    group::Group,
    queue::{PreparedQueueJob, QueueJob},
    syncs,
};

#[repr(transparent)]
struct RawQueueSubmit(uapi::drm_panthor_queue_submit);

// SAFETY: This wrapper is layout-identical to the UAPI queue-submit record
// read from userspace.
unsafe impl FromBytes for RawQueueSubmit {}

pub(crate) struct QueueSubmit {
    queue_index: usize,
    stream: KVec<u8>,
    syncs: KVec<SyncOp>,
}

impl QueueSubmit {
    pub(crate) fn from_uapi(uapi_submit: &uapi::drm_panthor_queue_submit) -> Result<Self> {
        let stream_size = uapi_submit.stream_size as usize;
        let mut stream = KVec::with_capacity(stream_size, GFP_KERNEL)?;
        let mut syncs = KVec::new();

        if stream_size != 0 {
            stream.resize(stream_size, 0, GFP_KERNEL)?;

            let mut reader = UserSlice::new(
                UserPtr::from_addr(uapi_submit.stream_addr as usize),
                stream_size,
            )
            .reader();
            reader.read_slice(&mut stream[..])?;
        }

        deps::append_syncops(
            &mut syncs,
            uapi_submit.syncs.array,
            uapi_submit.syncs.count,
            uapi_submit.syncs.stride,
        )?;

        Ok(Self {
            queue_index: uapi_submit.queue_index as usize,
            stream,
            syncs,
        })
    }

    pub(crate) fn queue_index(&self) -> usize {
        self.queue_index
    }

    pub(crate) fn into_parts(self) -> (KVec<u8>, KVec<SyncOp>) {
        (self.stream, self.syncs)
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
    stream: KVec<u8>,
    syncs: KVec<SyncOp>,
}

pub(crate) struct PreparedQueueSubmit {
    queue_index: usize,
    has_stream: bool,
    /// Per-queue submit seqno claimed at prepare time. Zero when
    /// `has_stream` is false (stream-less jobs never reach the GPU
    /// and so do not consume a seqno).
    seqno: u64,
    prepared: PreparedQueueJob,
    signals: KVec<SyncSignal>,
}

impl PreparedQueueSubmit {
    pub(crate) fn commit(self, group: &Group) -> Result<ARef<PublicDmaFence>> {
        let queue = group.queues.get(self.queue_index).ok_or(EINVAL)?;

        if self.has_stream {
            group.write_syncobj(
                self.queue_index,
                syncs::SyncObj64b {
                    seqno: self.seqno,
                    status: 0,
                    pad: 0,
                },
            )?;
        }

        let submit_fence = queue.commit_job(self.prepared);

        for signal in self.signals.into_iter() {
            signal.publish(&submit_fence);
        }

        Ok(submit_fence)
    }
}

impl Job {
    fn new(queue_index: usize, stream: KVec<u8>, syncs: KVec<SyncOp>) -> Self {
        Self {
            queue_index,
            stream,
            syncs,
        }
    }

    pub(crate) fn from_queue_submits(queue_submits: KVec<QueueSubmit>) -> Result<KVec<Self>> {
        let mut jobs = KVec::<Self>::new();

        for queue_submit in queue_submits.into_iter() {
            let queue_index = queue_submit.queue_index();
            let (stream, syncs) = queue_submit.into_parts();
            let mut syncs = Some(syncs);

            if stream.is_empty() && syncs.as_ref().is_some_and(KVec::is_empty) {
                continue;
            }

            let mut merged = false;
            for job in jobs.iter_mut() {
                if job.queue_index == queue_index {
                    job.stream.extend_from_slice(&stream, GFP_KERNEL)?;
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

            jobs.push(
                Self::new(queue_index, stream, syncs.take().ok_or(EINVAL)?),
                GFP_KERNEL,
            )?;
        }

        Ok(jobs)
    }

    pub(crate) fn prepare(
        self,
        group: &Arc<Group>,
        file: &crate::file::TyrDrmFile,
    ) -> Result<PreparedQueueSubmit> {
        let queue = group.queues.get(self.queue_index).ok_or(EINVAL)?;

        let deps = deps::wait_fences(file, &self.syncs)?;
        let signals = deps::signal_syncs(file, &self.syncs)?;
        let has_stream = !self.stream.is_empty();

        let prepared = queue.prepare_job(QueueJob::new(self.stream, group.clone()), &deps)?;

        // Claim the seqno after every fallible prepare step has
        // succeeded, so an Err return cannot leave a gap in
        // next_seqno that no GPU-visible syncobj seed fills.
        let seqno = if has_stream { queue.claim_seqno() } else { 0 };

        Ok(PreparedQueueSubmit {
            queue_index: self.queue_index,
            has_stream,
            seqno,
            prepared,
            signals,
        })
    }
}
