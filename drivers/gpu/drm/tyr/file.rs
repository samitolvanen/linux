// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    alloc::KVec,
    drm,
    drm::gem::BaseObject,
    io::Io,
    prelude::*,
    sync::aref::ARef,
    transmute::{AsBytes, FromBytes},
    uaccess::UserSlice,
    uapi,
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDriver, //
    },
    gem, heap,
    regs::{gpu_control, join_u64, read_u64_no_tearing},
    sched::{deps, group},
    vm::{self, VmMapFlags},
};

fn set_uobj<T: AsBytes>(usr_ptr: u64, usr_size: u32, obj: &T) -> Result {
    let kern_size = core::mem::size_of_val(obj);
    let usr_size = usr_size as usize;
    let copy_size = usr_size.min(kern_size);

    // SAFETY: `obj` implements AsBytes, so viewing it as a byte slice is safe.
    let bytes =
        unsafe { core::slice::from_raw_parts(core::ptr::from_ref(obj).cast::<u8>(), kern_size) };

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
    heap_pools: heap::Pools,
    tdev: ARef<TyrDrmDevice>,
}

/// Convenience type alias for our DRM `File` type
pub(crate) type TyrDrmFile = drm::file::File<TyrDrmFileData>;

impl drm::file::DriverFile for TyrDrmFileData {
    type Driver = TyrDrmDriver;

    fn open(dev: &drm::Device<Self::Driver>) -> Result<Pin<KBox<Self>>> {
        let tdev = ARef::from(dev);

        KBox::try_pin_init(
            try_pin_init!(Self {
                vm_pool: vm::Pool::create()?,
                group_pool: group::Pool::create()?,
                heap_pools: heap::Pools::create()?,
                tdev,
            }),
            GFP_KERNEL,
        )
    }
}

#[pinned_drop]
impl PinnedDrop for TyrDrmFileData {
    fn drop(self: Pin<&mut Self>) {
        if let Err(e) = self.as_ref().group_pool().destroy_all(&self.tdev) {
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

    pub(crate) fn heap_pools(self: Pin<&Self>) -> &heap::Pools {
        &self.get_ref().heap_pools
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
                    devquery.size =
                        core::mem::size_of::<uapi::drm_panthor_group_priorities_info>() as u32;
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
                    let csif_data = {
                        let csif = ddev.csif_info.lock();
                        *csif
                    };
                    set_uobj(devquery.pointer, devquery.size, &csif_data)?;

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

        file.inner()
            .vm_pool()
            .create_vm(&ARef::from(ddev), vmcreate)?;
        Ok(0)
    }

    pub(crate) fn vm_destroy(
        _ddev: &TyrDrmDevice,
        vmdestroy: &mut uapi::drm_panthor_vm_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        file.inner().vm_pool().destroy_vm(vmdestroy)?;
        Ok(0)
    }

    pub(crate) fn vm_bind(
        ddev: &TyrDrmDevice,
        vmbind: &mut uapi::drm_panthor_vm_bind,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        let async_flag = uapi::drm_panthor_vm_bind_flags_DRM_PANTHOR_VM_BIND_ASYNC;

        if vmbind.flags & !async_flag != 0 {
            return Err(EINVAL);
        }

        if vmbind.flags & async_flag != 0 {
            return Self::vm_bind_async(ddev, vmbind, file);
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
                let type_mask = uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MASK;
                let map_flags =
                    (uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_READONLY
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

    fn vm_bind_async(
        _ddev: &TyrDrmDevice,
        vmbind: &mut uapi::drm_panthor_vm_bind,
        file: &TyrDrmFile,
    ) -> Result<u32> {
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

        if vm.is_unusable() {
            return Err(EINVAL);
        }

        let mut reader = UserSlice::new(
            UserPtr::from_addr(vmbind.ops.array as usize),
            stride * count,
        )
        .reader();

        for i in 0..count {
            let res = {
                let op: VmBindOp = reader.read()?;
                let (job, syncs) = op.capture(file, true)?;
                let deps = deps::wait_fences(file, &syncs)?;
                let signals = deps::signal_syncs(file, &syncs)?;
                let prepared = vm.prepare_bind_job(job, &deps)?;

                vm.with_prepared_vm(1, |mut prepared_vm| {
                    let fence = vm.commit_bind_job(prepared);
                    prepared_vm.resv_add_fence(
                        &fence,
                        kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                        kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                    );

                    for signal in signals {
                        signal.publish(&fence);
                    }

                    Ok(())
                })?;

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
        file.inner().vm_pool().get_vm_state(vmgetstate)?;

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
        file.inner()
            .group_pool()
            .create_group(ddev, groupcreate, file)?;

        Ok(0)
    }

    pub(crate) fn group_destroy(
        ddev: &TyrDrmDevice,
        groupdestroy: &mut uapi::drm_panthor_group_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        file.inner()
            .group_pool()
            .destroy_group(ddev, groupdestroy)?;

        Ok(0)
    }

    pub(crate) fn group_submit(
        _ddev: &TyrDrmDevice,
        groupsubmit: &mut uapi::drm_panthor_group_submit,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        file.inner().group_pool().submit_group(groupsubmit, file)?;

        Ok(0)
    }

    pub(crate) fn group_get_state(
        _ddev: &TyrDrmDevice,
        groupgetstate: &mut uapi::drm_panthor_group_get_state,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        file.inner().group_pool().get_group_state(groupgetstate)?;

        Ok(0)
    }

    pub(crate) fn heap_create(
        ddev: &TyrDrmDevice,
        heapcreate: &mut uapi::drm_panthor_tiler_heap_create,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        let vm_id = heapcreate.vm_id as usize;
        let vm = file.inner().vm_pool().get_vm(vm_id).ok_or(EINVAL)?;
        let pool = file
            .inner()
            .heap_pools()
            .create_context(ddev, vm_id, vm.clone(), heapcreate)?;

        file.inner().group_pool().set_heap_pool_for_vm(&vm, pool)?;

        Ok(0)
    }

    pub(crate) fn heap_destroy(
        _ddev: &TyrDrmDevice,
        heapdestroy: &mut uapi::drm_panthor_tiler_heap_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        file.inner().heap_pools().destroy_context(heapdestroy)?;

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

impl VmBindOp {
    fn capture(
        &self,
        file: &TyrDrmFile,
        is_async: bool,
    ) -> Result<(vm::VmBindJob, KVec<deps::SyncOp>)> {
        let type_mask = uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MASK;
        let map_flags = (uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_READONLY
            | uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_NOEXEC
            | uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_UNCACHED)
            as u32;
        let mut syncs = KVec::new();

        if is_async {
            deps::append_syncops(
                &mut syncs,
                self.0.syncs.array,
                self.0.syncs.count,
                self.0.syncs.stride,
            )?;
        } else if self.0.syncs.count != 0 || self.0.syncs.array != 0 {
            return Err(EINVAL);
        }

        let mut job = vm::VmBindJob::new();

        match self.0.flags as i32 & type_mask {
            uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MAP => {
                let bo = gem::lookup_handle(file, self.0.bo_handle)?;

                if self.0.flags & !((type_mask as u32) | map_flags) != 0 {
                    return Err(EINVAL);
                }

                job.push_map(
                    bo,
                    self.0.bo_offset,
                    self.0.size,
                    self.0.va,
                    VmMapFlags::try_from(self.0.flags & map_flags)?,
                )?;
            }
            uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_UNMAP => {
                if self.0.bo_handle != 0 || self.0.bo_offset != 0 {
                    return Err(EINVAL);
                }

                if self.0.flags & !(type_mask as u32) != 0 {
                    return Err(EINVAL);
                }

                job.push_unmap(self.0.va, self.0.size)?;
            }
            uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_SYNC_ONLY => {
                if !is_async
                    || self.0.bo_handle != 0
                    || self.0.bo_offset != 0
                    || self.0.va != 0
                    || self.0.size != 0
                {
                    return Err(EINVAL);
                }

                if self.0.flags & !(type_mask as u32) != 0 || syncs.is_empty() {
                    return Err(EINVAL);
                }
            }
            _ => return Err(ENOTSUPP),
        }

        Ok((job, syncs))
    }
}
