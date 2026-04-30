// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::{
    AtomicU32,
    Ordering,
};

use kernel::{
    alloc::KVec,
    prelude::*,
    sync::Arc,
    uapi,
};

use crate::{
    driver::TyrDrmDevice,
    file::{
        QueueCreate,
        TyrDrmFile,
    },
    gem,
    pool,
};

use super::queue::Queue;

pub(crate) struct Group {
    pub(crate) fatal_queues: AtomicU32,
    pub(crate) queues: KVec<Queue>,
    _suspend_buf: Arc<gem::MappedBo>,
    _protm_suspend_buf: Arc<gem::MappedBo>,
}

impl Group {
    fn create(
        ddev: &TyrDrmDevice,
        file: &TyrDrmFile,
        group_args: &uapi::drm_panthor_group_create,
        queue_args: KVec<QueueCreate>,
    ) -> Result<Arc<Self>> {
        if group_args.pad != 0 {
            return Err(EINVAL);
        }

        if group_args.priority
            > uapi::drm_panthor_group_priority_PANTHOR_GROUP_PRIORITY_MEDIUM as u8
        {
            return Err(EINVAL);
        }

        if (group_args.compute_core_mask & !ddev.gpu_info.shader_present) != 0
            || (group_args.fragment_core_mask & !ddev.gpu_info.shader_present) != 0
            || (group_args.tiler_core_mask & !ddev.gpu_info.tiler_present) != 0
        {
            return Err(EINVAL);
        }

        if group_args.compute_core_mask.count_ones() < u32::from(group_args.max_compute_cores)
            || group_args.fragment_core_mask.count_ones() < u32::from(group_args.max_fragment_cores)
            || group_args.tiler_core_mask.count_ones() < u32::from(group_args.max_tiler_cores)
        {
            return Err(EINVAL);
        }

        let vm = file
            .inner()
            .vm_pool()
            .get_vm(group_args.vm_id as usize)
            .ok_or(EINVAL)?;

        let (suspend_buf_size, protm_suspend_buf_size) = ddev.fw.group_suspend_buf_sizes()?;
        let suspend_buf = ddev.fw.alloc_suspend_buf(ddev, suspend_buf_size as usize)?;
        let protm_suspend_buf = ddev
            .fw
            .alloc_suspend_buf(ddev, protm_suspend_buf_size as usize)?;

        let mut queues = KVec::new();

        for queue_arg in queue_args.iter() {
            queues.push(Queue::new(ddev, queue_arg, vm.clone())?, GFP_KERNEL)?;
        }

        Ok(Arc::new(
            Self {
                fatal_queues: AtomicU32::new(0),
                queues,
                _suspend_buf: suspend_buf,
                _protm_suspend_buf: protm_suspend_buf,
            },
            GFP_KERNEL,
        )?)
    }

    pub(crate) fn fatal_queues(&self) -> u32 {
        self.fatal_queues.load(Ordering::Relaxed)
    }

    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }
}

pub(crate) struct Pool(pool::Pool<Group>);

impl Pool {
    pub(crate) fn create() -> Result<Self> {
        Ok(Self(pool::Pool::create()?))
    }

    pub(crate) fn create_group(
        &self,
        ddev: &TyrDrmDevice,
        groupcreate: &uapi::drm_panthor_group_create,
        file: &TyrDrmFile,
        queue_args: KVec<QueueCreate>,
    ) -> Result<usize> {
        let group = Group::create(ddev, file, groupcreate, queue_args)?;
        self.0.insert(group)
    }

    pub(crate) fn group(&self, index: usize) -> Option<Arc<Group>> {
        self.0.get(index)
    }

    pub(crate) fn destroy_group(&self, index: usize) -> Result {
        self.0.remove(index)?;
        Ok(())
    }

    pub(crate) fn destroy_all(&self) -> Result {
        for index in 1..self.0.index_upper_bound() {
            let _ = self.0.remove(index);
        }

        Ok(())
    }
}