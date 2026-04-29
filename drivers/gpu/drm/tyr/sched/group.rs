// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::{
    AtomicU32,
    Ordering,
};

use kernel::{
    prelude::*,
    sync::Arc,
    uapi,
};

use crate::{
    driver::TyrDrmDevice,
    file::TyrDrmFile,
    pool,
};

pub(crate) struct Group {
    fatal_queues: AtomicU32,
}

impl Group {
    fn create(
        ddev: &TyrDrmDevice,
        file: &TyrDrmFile,
        group_args: &uapi::drm_panthor_group_create,
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

        file.inner()
            .vm_pool()
            .get_vm(group_args.vm_id as usize)
            .ok_or(EINVAL)?;

        Ok(Arc::new(
            Self {
                fatal_queues: AtomicU32::new(0),
            },
            GFP_KERNEL,
        )?)
    }

    pub(crate) fn fatal_queues(&self) -> u32 {
        self.fatal_queues.load(Ordering::Relaxed)
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
    ) -> Result<usize> {
        let group = Group::create(ddev, file, groupcreate)?;
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