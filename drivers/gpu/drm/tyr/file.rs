// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    alloc::KVec,
    drm,
    drm::gem::BaseObject,
    io::Io,
    prelude::*,
    sizes::{
        SZ_4K,
        SZ_64K,
    },
    sync::{
        aref::ARef,
        Arc,
    },
    transmute::AsBytes,
    transmute::FromBytes,
    uaccess::UserSlice,
    uapi, //
    xarray,
    xarray::XArray,
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDriver, //
    },
    gem,
    heap,
    regs::{
        gpu_control,
        join_u64,
        read_u64_no_tearing,
    },
    sched::group,
    vm::{
        self,
        VmMapFlags,
    },
};

fn set_uobj<T: AsBytes>(usr_ptr: u64, usr_size: u32, obj: &T) -> Result {
    let kern_size = core::mem::size_of_val(obj);
    let usr_size = usr_size as usize;
    let copy_size = usr_size.min(kern_size);

    // SAFETY: `obj` implements AsBytes, so viewing it as a byte slice is safe.
    let bytes = unsafe { core::slice::from_raw_parts(core::ptr::from_ref(obj).cast::<u8>(), kern_size) };

    let mut writer = UserSlice::new(UserPtr::from_addr(usr_ptr as usize), usr_size).writer();
    writer.write_slice(&bytes[..copy_size])?;

    if usr_size > kern_size {
        let remaining = usr_size - kern_size;
        let zeros = [0u8; 64];
        let mut left = remaining;

        while left > 0 {
            let chunk = left.min(zeros.len());
            writer.write_slice(&zeros[..chunk])?;
            left -= chunk;
        }
    }

    Ok(())
}

#[pin_data(PinnedDrop)]
pub(crate) struct TyrDrmFileData {
    vm_pool: vm::Pool,
    group_pool: group::Pool,
    heap_pools: Pin<KBox<XArray<Arc<heap::Pool>>>>,
}

/// Convenience type alias for our DRM `File` type
pub(crate) type TyrDrmFile = drm::file::File<TyrDrmFileData>;

impl drm::file::DriverFile for TyrDrmFileData {
    type Driver = TyrDrmDriver;

    fn open(_dev: &drm::Device<Self::Driver>) -> Result<Pin<KBox<Self>>> {
        KBox::try_pin_init(
            try_pin_init!(Self {
                vm_pool: vm::Pool::create()?,
                group_pool: group::Pool::create()?,
                heap_pools <- KBox::pin_init(XArray::new(xarray::AllocKind::Alloc1), GFP_KERNEL)?,
            }),
            GFP_KERNEL,
        )
    }
}

#[pinned_drop]
impl PinnedDrop for TyrDrmFileData {
    fn drop(self: Pin<&mut Self>) {
        if let Err(e) = self.as_ref().group_pool().destroy_all() {
            pr_err!("Failed to destroy all groups: {:?}\n", e);
        }

        if let Err(e) = self.as_ref().vm_pool().destroy_all() {
            pr_err!("Failed to destroy all VMs: {:?}\n", e);
        }
    }
}

impl TyrDrmFileData {
    pub(crate) fn vm_pool(self: Pin<&Self>) -> &vm::Pool {
        &self.get_ref().vm_pool
    }

    pub(crate) fn group_pool(self: Pin<&Self>) -> &group::Pool {
        &self.get_ref().group_pool
    }

    pub(crate) fn dev_query(
        ddev: &TyrDrmDevice,
        devquery: &mut uapi::drm_panthor_dev_query,
        _file: &TyrDrmFile,
    ) -> Result<u32> {
        if devquery.pointer == 0 {
            match devquery.type_ {
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GPU_INFO => {
                    devquery.size = core::mem::size_of_val(&ddev.gpu_info) as u32;
                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_CSIF_INFO => {
                    devquery.size = core::mem::size_of::<crate::gpu::CsifInfo>() as u32;
                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_TIMESTAMP_INFO => {
                    devquery.size = core::mem::size_of::<uapi::drm_panthor_timestamp_info>() as u32;
                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GROUP_PRIORITIES_INFO => {
                    devquery.size = core::mem::size_of::<uapi::drm_panthor_group_priorities_info>() as u32;
                    Ok(0)
                }
                _ => Err(EINVAL),
            }
        } else {
            match devquery.type_ {
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GPU_INFO => {
                    set_uobj(devquery.pointer, devquery.size, &ddev.gpu_info)?;

                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_CSIF_INFO => {
                    let csif = ddev.csif_info.lock();
                    set_uobj(devquery.pointer, devquery.size, &*csif)?;

                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_TIMESTAMP_INFO => {
                    let timestamp_frequency = 0u64;

                    // SAFETY: `ddev` is a bound device in the ioctl path.
                    let dev = unsafe { ddev.as_ref().as_bound() };
                    let io = ddev.iomem.access(dev)?;

                    let current_timestamp = read_u64_no_tearing(
                        || io.read(gpu_control::TIMESTAMP_LO).into_raw(),
                        || io.read(gpu_control::TIMESTAMP_HI).into_raw(),
                    );

                    let timestamp_offset = join_u64(
                        io.read(gpu_control::TIMESTAMP_OFFSET_LO).into_raw(),
                        io.read(gpu_control::TIMESTAMP_OFFSET_HI).into_raw(),
                    );

                    let data = [timestamp_frequency, current_timestamp, timestamp_offset];
                    set_uobj(devquery.pointer, devquery.size, &data)?;

                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GROUP_PRIORITIES_INFO => {
                    let mask = (1 << uapi::drm_panthor_group_priority_PANTHOR_GROUP_PRIORITY_LOW)
                        | (1 << uapi::drm_panthor_group_priority_PANTHOR_GROUP_PRIORITY_MEDIUM);
                    let data: [u8; 4] = [mask as u8, 0, 0, 0];

                    set_uobj(devquery.pointer, devquery.size, &data)?;

                    Ok(0)
                }
                _ => Err(EINVAL),
            }
        }
    }

    pub(crate) fn vm_create(
        ddev: &TyrDrmDevice,
        vmcreate: &mut uapi::drm_panthor_vm_create,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if vmcreate.flags != 0 {
            return Err(EINVAL);
        }

        let (id, user_va_range) = file
            .inner()
            .vm_pool()
            .create_vm(&ARef::from(ddev), vmcreate.user_va_range)?;

        vmcreate.id = id as u32;
        vmcreate.user_va_range = user_va_range;
        Ok(0)
    }

    pub(crate) fn vm_destroy(
        _ddev: &TyrDrmDevice,
        vmdestroy: &mut uapi::drm_panthor_vm_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if vmdestroy.pad != 0 {
            return Err(EINVAL);
        }

        file.inner().vm_pool().destroy_vm(vmdestroy.id as usize)?;
        Ok(0)
    }

    pub(crate) fn vm_bind(
        _ddev: &TyrDrmDevice,
        vmbind: &mut uapi::drm_panthor_vm_bind,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        let async_flag = uapi::drm_panthor_vm_bind_flags_DRM_PANTHOR_VM_BIND_ASYNC;

        if vmbind.flags & !async_flag != 0 {
            return Err(EINVAL);
        }

        if vmbind.flags & async_flag != 0 {
            return Err(ENOTSUPP);
        }

        if vmbind.ops.stride as usize != core::mem::size_of::<uapi::drm_panthor_vm_bind_op>() {
            return Err(ENOTSUPP);
        }

        let count = vmbind.ops.count as usize;
        let stride = vmbind.ops.stride as usize;
        let vm = file
            .inner()
            .vm_pool()
            .get_vm(vmbind.vm_id as usize)
            .ok_or(EINVAL)?;

        let mut reader = UserSlice::new(
            UserPtr::from_addr(vmbind.ops.array as usize),
            stride * count,
        )
        .reader();

        for i in 0..count {
            let res = {
                let op: VmBindOp = reader.read()?;
                let type_mask =
                    uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MASK;
                let map_flags = (uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_READONLY
                    | uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_NOEXEC
                    | uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_UNCACHED)
                    as u32;

                if op.0.syncs.count != 0 || op.0.syncs.array != 0 {
                    Err(EINVAL)?;
                }

                match op.0.flags as i32 & type_mask {
                    uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MAP => {
                        let bo = gem::lookup_handle(file, op.0.bo_handle)?;

                        if op.0.flags & !((type_mask as u32) | map_flags) != 0 {
                            Err(EINVAL)?;
                        }

                        let flags = VmMapFlags::try_from(op.0.flags & map_flags)?;

                        vm.map_bo_range(&bo, op.0.bo_offset, op.0.size, op.0.va, flags)?;
                    }
                    uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_UNMAP => {
                        if op.0.bo_handle != 0 || op.0.bo_offset != 0 {
                            Err(EINVAL)?;
                        }

                        if op.0.flags & !(type_mask as u32) != 0 {
                            Err(EINVAL)?;
                        }

                        vm.unmap_range(op.0.va, op.0.size)?;
                    }
                    _ => Err(ENOTSUPP)?,
                }

                Ok(0)
            };

            if let Err(e) = res {
                vmbind.ops.count = i as u32;
                return Err(e);
            }
        }

        Ok(0)
    }

    pub(crate) fn vm_get_state(
        _ddev: &TyrDrmDevice,
        vmgetstate: &mut uapi::drm_panthor_vm_get_state,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        let vm = file
            .inner()
            .vm_pool()
            .get_vm(vmgetstate.vm_id as usize)
            .ok_or(EINVAL)?;

        vmgetstate.state = if vm.is_unusable() {
            uapi::drm_panthor_vm_state_DRM_PANTHOR_VM_STATE_UNUSABLE
        } else {
            uapi::drm_panthor_vm_state_DRM_PANTHOR_VM_STATE_USABLE
        };

        Ok(0)
    }

    pub(crate) fn bo_create(
        ddev: &TyrDrmDevice,
        bocreate: &mut uapi::drm_panthor_bo_create,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if bocreate.flags & !uapi::drm_panthor_bo_flags_DRM_PANTHOR_BO_NO_MMAP != 0 {
            dev_err!(
                ddev.as_ref(),
                "bo_create: invalid flags {}\n",
                bocreate.flags
            );

            return Err(EINVAL);
        }

        let bo = gem::new_bo(ddev, bocreate.size as usize, bocreate.flags)?;
        let handle = bo.create_handle(file)?;

        bocreate.handle = handle;
        bocreate.size = bo.size() as u64;

        Ok(0)
    }

    pub(crate) fn bo_mmap_offset(
        _ddev: &TyrDrmDevice,
        bommap: &mut uapi::drm_panthor_bo_mmap_offset,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        let bo = gem::lookup_handle(file, bommap.handle)?;

        bommap.offset = bo.create_mmap_offset()?;

        Ok(0)
    }

    pub(crate) fn group_create(
        ddev: &TyrDrmDevice,
        groupcreate: &mut uapi::drm_panthor_group_create,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if groupcreate.queues.count == 0 {
            return Err(EINVAL);
        }

        if groupcreate.queues.stride as usize
            != core::mem::size_of::<uapi::drm_panthor_queue_create>()
        {
            return Err(ENOTSUPP);
        }

        let mut reader = UserSlice::new(
            UserPtr::from_addr(groupcreate.queues.array as usize),
            groupcreate.queues.stride as usize * groupcreate.queues.count as usize,
        )
        .reader();

        let mut queue_args = KVec::new();

        for _ in 0..groupcreate.queues.count {
            let queue: QueueCreate = reader.read()?;
            queue.validate()?;
            queue_args.push(queue, GFP_KERNEL)?;
        }

        let handle = file
            .inner()
            .group_pool()
            .create_group(ddev, groupcreate, file, queue_args)?;

        groupcreate.group_handle = handle as u32;

        Ok(0)
    }

    pub(crate) fn group_destroy(
        _ddev: &TyrDrmDevice,
        groupdestroy: &mut uapi::drm_panthor_group_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if groupdestroy.pad != 0 {
            return Err(EINVAL);
        }

        file.inner()
            .group_pool()
            .destroy_group(groupdestroy.group_handle as usize)?;

        Ok(0)
    }

    pub(crate) fn group_submit(
        _ddev: &TyrDrmDevice,
        groupsubmit: &mut uapi::drm_panthor_group_submit,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if groupsubmit.pad != 0 {
            return Err(EINVAL);
        }

        if groupsubmit.queue_submits.count == 0 {
            return Err(EINVAL);
        }

        if groupsubmit.queue_submits.stride as usize
            != core::mem::size_of::<uapi::drm_panthor_queue_submit>()
        {
            return Err(ENOTSUPP);
        }

        let group = file
            .inner()
            .group_pool()
            .group(groupsubmit.group_handle as usize)
            .ok_or(EINVAL)?;

        let mut reader = UserSlice::new(
            UserPtr::from_addr(groupsubmit.queue_submits.array as usize),
            groupsubmit.queue_submits.stride as usize * groupsubmit.queue_submits.count as usize,
        )
        .reader();

        for _ in 0..groupsubmit.queue_submits.count {
            let queue: QueueSubmit = reader.read()?;
            queue.validate(group.queue_count())?;

            let mut sync_reader = UserSlice::new(
                UserPtr::from_addr(queue.0.syncs.array as usize),
                queue.0.syncs.stride as usize * queue.0.syncs.count as usize,
            )
            .reader();

            for _ in 0..queue.0.syncs.count {
                let sync: SyncOp = sync_reader.read()?;
                sync.validate()?;
            }
        }

        Err(ENOTSUPP)
    }

    pub(crate) fn group_get_state(
        _ddev: &TyrDrmDevice,
        groupgetstate: &mut uapi::drm_panthor_group_get_state,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if groupgetstate.pad != 0 {
            return Err(EINVAL);
        }

        let group = file
            .inner()
            .group_pool()
            .group(groupgetstate.group_handle as usize)
            .ok_or(EINVAL)?;

        groupgetstate.state = 0;
        groupgetstate.fatal_queues = group.fatal_queues();

        if groupgetstate.fatal_queues != 0 {
            groupgetstate.state |=
                uapi::drm_panthor_group_state_flags_DRM_PANTHOR_GROUP_STATE_FATAL_FAULT;
        }

        Ok(0)
    }

    pub(crate) fn heap_create(
        ddev: &TyrDrmDevice,
        heapcreate: &mut uapi::drm_panthor_tiler_heap_create,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        let vm_id = heapcreate.vm_id as usize;
        let vm = file.inner().vm_pool().get_vm(vm_id).ok_or(EINVAL)?;

        let args = heap::ContextCreateArgs {
            initial_chunk_count: heapcreate.initial_chunk_count,
            chunk_size: heapcreate.chunk_size,
            max_chunks: heapcreate.max_chunks,
            target_in_flight: heapcreate.target_in_flight,
        };

        let file_inner = file.inner();
        let xa = file_inner.heap_pools.as_ref();

        {
            let guard = xa.lock();
            if guard.get(vm_id).is_none() {
                drop(guard);
                let pool = Arc::new(heap::Pool::create(ddev, vm.clone())?, GFP_KERNEL)?;
                xa.lock().store(vm_id, pool, GFP_KERNEL)?;
            }
        }

        let created_context = {
            let guard = xa.lock();
            let pool = guard.get(vm_id).ok_or(EINVAL)?;
            pool.create_heap_context(ddev, args)?
        };

        heapcreate.handle = heapcreate.vm_id << 16 | created_context.context_id as u32;
        heapcreate.tiler_heap_ctx_gpu_va = created_context.context_gpu_va;
        heapcreate.first_heap_chunk_gpu_va = created_context.first_chunk_gpu_va;

        Ok(0)
    }

    pub(crate) fn heap_destroy(
        _ddev: &TyrDrmDevice,
        heapdestroy: &mut uapi::drm_panthor_tiler_heap_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if heapdestroy.pad != 0 {
            return Err(EINVAL);
        }

        let vm_id = (heapdestroy.handle >> 16) as usize;
        let heap_idx = (heapdestroy.handle & 0xffff) as usize;

        let file_inner = file.inner();
        let xa = file_inner.heap_pools.as_ref();
        let guard = xa.lock();
        let pool = guard.get(vm_id).ok_or(EINVAL)?;
        pool.destroy_heap_context(heap_idx)?;

        Ok(0)
    }

    pub(crate) fn bo_set_label(
        _ddev: &TyrDrmDevice,
        _args: &mut uapi::drm_panthor_bo_set_label,
        _file: &TyrDrmFile,
    ) -> Result<u32> {
        Ok(0)
    }

    pub(crate) fn set_user_mmio_offset(
        _ddev: &TyrDrmDevice,
        _args: &mut uapi::drm_panthor_set_user_mmio_offset,
        _file: &TyrDrmFile,
    ) -> Result<u32> {
        Err(ENOTSUPP)
    }

    pub(crate) fn bo_sync(
        _ddev: &TyrDrmDevice,
        _args: &mut uapi::drm_panthor_bo_sync,
        _file: &TyrDrmFile,
    ) -> Result<u32> {
        Ok(0)
    }

    pub(crate) fn bo_query_info(
        _ddev: &TyrDrmDevice,
        args: &mut uapi::drm_panthor_bo_query_info,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        let bo = gem::lookup_handle(file, args.handle)?;

        args.create_flags = bo.create_flags();
        args.extra_flags = 0;
        args.pad = 0;

        Ok(0)
    }
}

#[repr(transparent)]
struct VmBindOp(uapi::drm_panthor_vm_bind_op);

// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for VmBindOp {}

#[repr(transparent)]
pub(crate) struct QueueCreate(uapi::drm_panthor_queue_create);

// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for QueueCreate {}

impl QueueCreate {
    fn validate(&self) -> Result {
        if self.0.pad != [0; 3] {
            return Err(EINVAL);
        }

        if self.0.priority > 15 {
            return Err(EINVAL);
        }

        if self.0.ringbuf_size < SZ_4K as u32
            || self.0.ringbuf_size > SZ_64K as u32
            || !self.0.ringbuf_size.is_power_of_two()
        {
            return Err(EINVAL);
        }

        Ok(())
    }

    pub(crate) fn priority(&self) -> u8 {
        self.0.priority
    }

    pub(crate) fn ringbuf_size(&self) -> u32 {
        self.0.ringbuf_size
    }
}

#[repr(transparent)]
struct QueueSubmit(uapi::drm_panthor_queue_submit);

// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for QueueSubmit {}

impl QueueSubmit {
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

        if self.0.syncs.stride as usize != core::mem::size_of::<uapi::drm_panthor_sync_op>() {
            return Err(ENOTSUPP);
        }

        Ok(())
    }
}

#[repr(transparent)]
struct SyncOp(uapi::drm_panthor_sync_op);

// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for SyncOp {}

impl SyncOp {
    fn validate(&self) -> Result {
        let valid_flags = (uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_SIGNAL
            | uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_WAIT
            | uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK)
            as u32;

        if self.0.flags & !valid_flags != 0 {
            return Err(EINVAL);
        }

        let handle_type = self.0.flags
            & uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK as u32;

        if handle_type != uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ as u32
            && handle_type
                != uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ as u32
        {
            return Err(EINVAL);
        }

        Ok(())
    }
}
