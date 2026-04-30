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
        QueueSubmit,
        SyncOp,
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

const UNBOUND_CSG_ID: usize = usize::MAX;

pub(crate) struct Group {
    pub(crate) fatal_queues: Atomic<u32>,
    csg_id: Atomic<usize>,
    pub(crate) queues: KVec<Queue>,
    pub(super) vm: Arc<Vm>,
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
    pub(super) suspend_buf: Arc<gem::MappedBo>,
    #[expect(dead_code)]
    pub(super) protm_suspend_buf: Arc<gem::MappedBo>,
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
                csg_id: Atomic::new(UNBOUND_CSG_ID),
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

    pub(super) fn csg_id(&self) -> Option<usize> {
        let csg_id = self.csg_id.load(Relaxed);

        if csg_id == UNBOUND_CSG_ID {
            None
        } else {
            Some(csg_id)
        }
    }

    pub(super) fn set_csg_id(&self, csg_id: Option<usize>) {
        self.csg_id.store(csg_id.unwrap_or(UNBOUND_CSG_ID), Relaxed);
    }

    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }

    pub(super) fn submit(&self, syncs: KVec<SyncOp>, queue_submits: KVec<QueueSubmit>) -> Result {
        struct QueuedStream {
            queue_index: usize,
            stream: KVec<u8>,
        }

        if !syncs.is_empty() {
            return Err(ENOTSUPP);
        }

        let mut queued_streams: KVec<QueuedStream> = KVec::new();

        for queue_submit in queue_submits.iter() {
            let queue_index = queue_submit.queue_index();

            if !queue_submit.has_stream() {
                continue;
            }

            let stream = queue_submit.copy_stream()?;

            if let Some(queued_stream) = queued_streams
                .iter_mut()
                .find(|queued_stream| queued_stream.queue_index == queue_index)
            {
                queued_stream
                    .stream
                    .extend_from_slice(&stream, GFP_KERNEL)?;
                continue;
            }

            queued_streams.push(
                QueuedStream {
                    queue_index,
                    stream,
                },
                GFP_KERNEL,
            )?;
        }

        for queued_stream in queued_streams.iter() {
            let queue = self.queues.get(queued_stream.queue_index).ok_or(EINVAL)?;
            queue.append_instrs(&queued_stream.stream)?;
        }

        for queued_stream in queued_streams.iter() {
            let queue = self.queues.get(queued_stream.queue_index).ok_or(EINVAL)?;
            queue.kick()?;
        }

        Ok(())
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

        ddev.with_locked_scheduler(|sched| sched.add_group(group.clone()))?;

        self.0.insert(group)
    }

    pub(crate) fn group(&self, index: usize) -> Option<Arc<Group>> {
        self.0.get(index)
    }

    pub(crate) fn destroy_group(&self, ddev: &TyrDrmDevice, index: usize) -> Result {
        let group = self.0.get(index).ok_or(EINVAL)?;

        ddev.with_locked_scheduler(|sched| sched.remove_group(group))?;

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
