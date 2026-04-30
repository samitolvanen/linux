// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::{
    AtomicU32,
    Ordering,
};

use kernel::{
    alloc::KVec,
    drm::gem::BaseObject,
    io::Io,
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
    vm::{
        Vm,
        VmFlag,
        VmMapFlags,
    },
};

use super::{
    queue::Queue,
    syncs,
};

pub(crate) struct Group {
    pub(crate) fatal_queues: AtomicU32,
    pub(crate) queues: KVec<Queue>,
    #[allow(dead_code)]
    pub(super) vm: Arc<Vm>,
    #[allow(dead_code)]
    pub(super) priority: u8,
    #[allow(dead_code)]
    pub(super) compute_core_mask: u64,
    #[allow(dead_code)]
    pub(super) fragment_core_mask: u64,
    #[allow(dead_code)]
    pub(super) tiler_core_mask: u64,
    #[allow(dead_code)]
    pub(super) max_compute_cores: u8,
    #[allow(dead_code)]
    pub(super) max_fragment_cores: u8,
    #[allow(dead_code)]
    pub(super) max_tiler_cores: u8,
    #[allow(dead_code)]
    pub(super) suspend_buf: Arc<gem::MappedBo>,
    #[allow(dead_code)]
    pub(super) protm_suspend_buf: Arc<gem::MappedBo>,
    _syncobjs: Arc<gem::MappedBo>,
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

        let num_syncs = group_args.queues.count as usize * core::mem::size_of::<syncs::SyncObj64b>();
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let syncobjs = gem::new_kernel_object(ddev, &vm, num_syncs, flags)?;

        let vmap = syncobjs.vmap();
        let size = vmap.owner().size();
        // SAFETY: `vmap` owns a valid writable mapping for `size` bytes.
        unsafe { core::ptr::write_bytes(vmap.addr() as *mut u8, 0, size) };

        let mut queues = KVec::new();

        for queue_arg in queue_args.iter() {
            queues.push(Queue::new(ddev, queue_arg, vm.clone())?, GFP_KERNEL)?;
        }

        Ok(Arc::new(
            Self {
                fatal_queues: AtomicU32::new(0),
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
                _syncobjs: syncobjs,
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

    pub(crate) fn destroy_group(&self, _ddev: &TyrDrmDevice, index: usize) -> Result {
        self.0.remove(index)?;
        Ok(())
    }

    pub(crate) fn destroy_all(&self, ddev: &TyrDrmDevice) -> Result {
        for index in 1..self.0.index_upper_bound() {
            let _ = self.destroy_group(ddev, index);
        }

        Ok(())
    }
}