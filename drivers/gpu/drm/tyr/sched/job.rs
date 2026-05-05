// SPDX-License-Identifier: GPL-2.0 or MIT

//! Queue submission helpers for scheduler groups.
//!
//! Group submission batches user queue streams and writes the corresponding
//! firmware sync objects. Keeping that queue-side submit flow here lets the
//! group object focus on group state and scheduler coordination.

use kernel::{
    alloc::KVec,
    prelude::*,
    uaccess::UserSlice,
    uapi,
};

use super::{
    group::Group,
    syncs,
};

pub(crate) struct QueueSubmit {
    queue_index: usize,
    stream: KVec<u8>,
}

impl QueueSubmit {
    pub(crate) fn from_uapi(uapi_submit: &uapi::drm_panthor_queue_submit) -> Result<Self> {
        let stream_size = uapi_submit.stream_size as usize;
        let mut stream = KVec::with_capacity(stream_size, GFP_KERNEL)?;

        if stream_size != 0 {
            stream.resize(stream_size, 0, GFP_KERNEL)?;

            let mut reader =
                UserSlice::new(UserPtr::from_addr(uapi_submit.stream_addr as usize), stream_size)
                    .reader();
            reader.read_slice(&mut stream[..])?;
        }

        Ok(Self {
            queue_index: uapi_submit.queue_index as usize,
            stream,
        })
    }

    pub(crate) fn queue_index(&self) -> usize {
        self.queue_index
    }

    pub(crate) fn into_stream(self) -> KVec<u8> {
        self.stream
    }
}

pub(crate) struct Job {
    queue_index: usize,
    stream: KVec<u8>,
}

impl Job {
    fn new(queue_index: usize, stream: KVec<u8>) -> Self {
        Self { queue_index, stream }
    }

    pub(crate) fn from_queue_submits(queue_submits: KVec<QueueSubmit>) -> Result<KVec<Self>> {
        let mut jobs = KVec::<Self>::new();

        for queue_submit in queue_submits.into_iter() {
            let queue_index = queue_submit.queue_index();
            let stream = queue_submit.into_stream();

            if stream.is_empty() {
                continue;
            }

            let mut merged = false;
            for job in jobs.iter_mut() {
                if job.queue_index == queue_index {
                    job.stream.extend_from_slice(&stream, GFP_KERNEL)?;
                    merged = true;
                    break;
                }
            }

            if merged {
                continue;
            }

            jobs.push(Self::new(queue_index, stream), GFP_KERNEL)?;
        }

        Ok(jobs)
    }

    pub(crate) fn can_submit(&self, group: &Group) -> Result {
        let queue = group.queues.get(self.queue_index).ok_or(EINVAL)?;
        queue.can_append(self.stream.len())
    }

    pub(crate) fn submit(&self, group: &Group) -> Result {
        let queue = group.queues.get(self.queue_index).ok_or(EINVAL)?;

        queue.append_instrs(&self.stream)?;
        group.write_syncobj(
            self.queue_index,
            syncs::SyncObj64b {
                seqno: queue.claim_seqno(),
                status: 0,
                pad: 0,
            },
        )?;
        queue.kick()
    }
}