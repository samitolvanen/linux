// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    drm::gem::BaseObject,
    io::IoBase,
    prelude::*,
    sync::{
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc, //
    },
    uapi, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmRegistrationData, //
    },
    file::{
        QueueCreate,
        TyrDrmFile, //
    },
    gem,
    pool,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    }, //
};

use super::{
    queue::Queue,
    syncs, //
};

pub(crate) struct Group {
    pub(crate) fatal_queues: Atomic<u32>,
    pub(crate) queues: KVec<Queue>,
    #[expect(dead_code)]
    pub(super) vm: Arc<Vm>,
    #[expect(dead_code)]
    pub(super) priority: u8,
    #[expect(dead_code)]
    pub(super) compute_core_mask: u64,
    #[expect(dead_code)]
    pub(super) fragment_core_mask: u64,
    #[expect(dead_code)]
    pub(super) tiler_core_mask: u64,
    #[expect(dead_code)]
    pub(super) max_compute_cores: u8,
    #[expect(dead_code)]
    pub(super) max_fragment_cores: u8,
    #[expect(dead_code)]
    pub(super) max_tiler_cores: u8,
    #[expect(dead_code)]
    suspend_buf: Arc<gem::MappedBo>,
    #[expect(dead_code)]
    protm_suspend_buf: Arc<gem::MappedBo>,
    #[expect(dead_code)]
    syncobjs: Arc<gem::MappedBo>,
}

impl Group {
    fn create(
        ddev: &TyrDrmDevice,
        reg_data: &TyrDrmRegistrationData<'_>,
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

        if (group_args.compute_core_mask & !reg_data.gpu_info.shader_present) != 0
            || (group_args.fragment_core_mask & !reg_data.gpu_info.shader_present) != 0
            || (group_args.tiler_core_mask & !reg_data.gpu_info.tiler_present) != 0
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

        let (suspend_buf_size, protm_suspend_buf_size) = reg_data.fw.group_suspend_buf_sizes()?;
        let suspend_buf = reg_data
            .fw
            .alloc_suspend_buf(ddev, suspend_buf_size as usize)?;
        let protm_suspend_buf = reg_data
            .fw
            .alloc_suspend_buf(ddev, protm_suspend_buf_size as usize)?;

        let num_syncs =
            group_args.queues.count as usize * core::mem::size_of::<syncs::SyncObj64b>();
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let dev = reg_data.pdev.as_ref();
        let syncobjs = gem::new_kernel_object(dev, ddev, &vm, num_syncs, flags)?;

        let vmap = syncobjs.vmap();
        let size = vmap.owner().size();
        // SAFETY: `vmap` owns a valid writable mapping for `size` bytes.
        unsafe { core::ptr::write_bytes(vmap.as_view().as_ptr().cast::<u8>(), 0, size) };

        let mut queues = KVec::new();

        for queue_arg in queue_args.iter() {
            queues.push(
                Queue::new(ddev, reg_data, queue_arg, vm.clone())?,
                GFP_KERNEL,
            )?;
        }

        Ok(Arc::new(
            Self {
                fatal_queues: Atomic::new(0),
                queues,
                vm,
                priority: group_args.priority,
                compute_core_mask: group_args.compute_core_mask,
                fragment_core_mask: group_args.fragment_core_mask,
                tiler_core_mask: group_args.tiler_core_mask,
                max_compute_cores: group_args.max_compute_cores,
                max_fragment_cores: group_args.max_fragment_cores,
                max_tiler_cores: group_args.max_tiler_cores,
                suspend_buf,
                protm_suspend_buf,
                syncobjs,
            },
            GFP_KERNEL,
        )?)
    }

    pub(crate) fn fatal_queues(&self) -> u32 {
        self.fatal_queues.load(Relaxed)
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
        reg_data: &TyrDrmRegistrationData<'_>,
        groupcreate: &uapi::drm_panthor_group_create,
        file: &TyrDrmFile,
        queue_args: KVec<QueueCreate>,
    ) -> Result<usize> {
        let group = Group::create(ddev, reg_data, file, groupcreate, queue_args)?;
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
