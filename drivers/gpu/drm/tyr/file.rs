// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::{
    Deref,
    DerefMut, //
};

use kernel::{
    alloc::flags::*,
    bits::genmask_u32,
    drm,
    drm::{
        device::Device as DrmDevice,
        gem::BaseObject,
        gpuvm::GpuVaAlloc, //
    },
    io::Io,
    kvec,
    prelude::*,
    sync::Arc,
    transmute::{
        AsBytes,
        FromBytes, //
    },
    types::ARef,
    uaccess::UserSlice,
    uapi,
    xarray,
    xarray::XArray, //
};
use pin_init::pinned_drop;

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDriver, //
    },
    gem,
    gpu,
    heap,
    sched::{
        deps,
        group, //
    },
    vm::{
        bind_job::{
            VmBindJob,
            VmOperation, //
        },
        pool::Pool,
        GpuVmData,
        VmLayout,
        VmMapFlags,
        VmOpResources,
        VmUserSize, //
    }, //
};

/// Copy a kernel object to a user object, handling size negotiation.
///
/// Mirrors Panthor's `panthor_set_uobj()`: copies `min(usr_size, kern_size)` bytes
/// from the kernel struct to userspace. If the user buffer is larger than the
/// kernel struct, the excess is zero-filled for forward compatibility.
fn set_uobj<T: AsBytes>(usr_ptr: u64, usr_size: u32, obj: &T) -> Result {
    let kern_size = core::mem::size_of_val(obj);
    let usr_size = usr_size as usize;
    let copy_size = usr_size.min(kern_size);

    // SAFETY: `obj` implements AsBytes, so viewing it as a byte slice is safe.
    let bytes = unsafe { core::slice::from_raw_parts(obj as *const T as *const u8, kern_size) };

    let mut writer = UserSlice::new(UserPtr::from_addr(usr_ptr as usize), usr_size).writer();

    writer.write_slice(&bytes[..copy_size])?;

    // Zero-fill if user buffer is larger than the kernel struct
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
    /// A pool storing our VMs for this particular context.
    #[pin]
    vm_pool: Pool,

    group_pool: group::Pool,

    /// Heap pools, indexed by VM ID.
    ///
    /// Stored as `Arc` so we can clone the reference and release the XArray
    /// spinlock before doing any sleeping work (e.g. pool creation or
    /// `create_heap_context` which takes the `gpu_contexts` mutex).
    heap_pools: Pin<KBox<XArray<Arc<heap::Pool>>>>,

    /// Reference to the device for cleanup
    tdev: ARef<TyrDrmDevice>,
}

/// Convenience type alias for our DRM `File` type
pub(crate) type TyrDrmFile = drm::file::File<TyrDrmFileData>;

impl drm::file::DriverFile for TyrDrmFileData {
    type Driver = TyrDrmDriver;

    fn open(dev: &DrmDevice<Self::Driver>) -> Result<Pin<KBox<Self>>> {
        dev_dbg!(dev.as_ref(), "drm::device::Device::open\n");

        let tdev = ARef::from(dev);

        KBox::try_pin_init(
            try_pin_init!(Self {
                vm_pool: Pool::create()?,
                group_pool: group::Pool::create()?,
                heap_pools <- KBox::pin_init(XArray::new(xarray::AllocKind::Alloc1), GFP_KERNEL)?,
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
                    devquery.size = core::mem::size_of::<gpu::CsifInfo>() as u32;
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
                    use crate::regs::gpu_control;
                    use crate::regs::join_u64;
                    use crate::regs::read_u64_no_tearing;

                    let timestamp_frequency = 0u64;

                    // SAFETY: ddev is a bound device. Reading from the TyrDrmDevice
                    // requires accessing the iomem, which needs a bound device ref.
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

                    let data: [u64; 3] = [timestamp_frequency, current_timestamp, timestamp_offset];

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
        let id = file.inner().vm_pool().create_vm(
            &ARef::from(ddev),
            VmLayout::from_user_sz(ddev, VmUserSize::Custom(vmcreate.user_va_range)),
        )?;

        vmcreate.id = id as u32;
        Ok(0)
    }

    pub(crate) fn vm_destroy(
        _tdev: &TyrDrmDevice,
        vmdestroy: &mut uapi::drm_panthor_vm_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        file.inner().vm_pool().destroy_vm(vmdestroy.id as usize)?;
        Ok(0)
    }

    pub(crate) fn vm_bind_async(
        ddev: &TyrDrmDevice,
        vmbind: &mut uapi::drm_panthor_vm_bind,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if vmbind.ops.stride as usize != core::mem::size_of::<uapi::drm_panthor_vm_bind_op>() {
            dev_info!(
                ddev.as_ref(),
                "We cannot graciously handle stride mismatches yet"
            );
            return Err(ENOTSUPP);
        }

        let vm = file
            .inner()
            .vm_pool()
            .get_vm(vmbind.vm_id as usize)
            .ok_or(EINVAL)?;

        if vm.is_unusable() {
            return Err(EINVAL);
        }

        let stride = vmbind.ops.stride as usize;
        let count = vmbind.ops.count as usize;

        let mut reader = UserSlice::new(
            UserPtr::from_addr(vmbind.ops.array as usize),
            stride * count,
        )
        .reader();

        let mut ctx = deps::Context::new(file);

        for i in 0..count {
            let op: VmBindOp = reader.read()?;
            let mask = uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MASK;

            let vm_operation = match op.0.flags as i32 & mask {
                uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MAP => {
                    let bo = gem::lookup_handle(file, op.0.bo_handle)?;
                    let va_range = op.0.va..op.0.va + op.0.size;
                    let flags = VmMapFlags::try_from(op.0.flags & 0b111)?;

                    VmOperation::Map {
                        va_range,
                        bo,
                        bo_offset: op.0.bo_offset,
                        flags,
                    }
                }

                uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_UNMAP => {
                    if op.0.bo_handle != 0 || op.0.bo_offset != 0 {
                        vmbind.ops.count = i as u32;
                        return Err(EINVAL);
                    }

                    let va_range = op.0.va..op.0.va + op.0.size;
                    VmOperation::Unmap { va_range }
                }

                _ => {
                    vmbind.ops.count = i as u32;
                    return Err(ENOTSUPP);
                }
            };

            if op.0.syncs.stride as usize != core::mem::size_of::<uapi::drm_panthor_sync_op>() {
                dev_info!(
                    ddev.as_ref(),
                    "We cannot graciously handle sync stride mismatches yet"
                );
                vmbind.ops.count = i as u32;
                return Err(ENOTSUPP);
            }

            let sync_count = op.0.syncs.count as usize;
            let sync_stride = op.0.syncs.stride as usize;

            let mut sync_reader = UserSlice::new(
                UserPtr::from_addr(op.0.syncs.array as usize),
                sync_stride * sync_count,
            )
            .reader();

            let mut sync_ops = kvec![];
            for _ in 0..sync_count {
                let sync_op_uapi: SyncOp = sync_reader.read()?;
                sync_ops.push(sync_op_uapi, GFP_KERNEL)?;
            }

            let internal_syncs = deps::SyncOp::from_uapi_slice(&sync_ops)?;
            let resources = match &vm_operation {
                VmOperation::Map { .. } => VmOpResources::for_map()?,
                VmOperation::Unmap { .. } => VmOpResources::for_unmap()?,
            };
            let job = VmBindJob::new(vm.clone(), vm_operation, resources);
            ctx.add_vm_bind_job(job, internal_syncs)?;
        }

        // Collect signal operations across all jobs (second pass).
        let mut reader = UserSlice::new(
            UserPtr::from_addr(vmbind.ops.array as usize),
            stride * count,
        )
        .reader();

        for _ in 0..count {
            let op: VmBindOp = reader.read()?;

            let sync_count = op.0.syncs.count as usize;
            let sync_stride = op.0.syncs.stride as usize;

            let mut sync_reader = UserSlice::new(
                UserPtr::from_addr(op.0.syncs.array as usize),
                sync_stride * sync_count,
            )
            .reader();

            let mut sync_ops = kvec![];
            for _ in 0..sync_count {
                let sync_op_uapi: SyncOp = sync_reader.read()?;
                sync_ops.push(sync_op_uapi, GFP_KERNEL)?;
            }

            let internal_syncs = deps::SyncOp::from_uapi_slice(&sync_ops)?;
            ctx.collect_signal_ops(&internal_syncs)?;
        }

        // Push all VM bind jobs with dependencies and update reservation objects.
        vm.with_prepared_vm_and_job_queue(count as u32, |mut prepared_vm, job_queue| {
            let finished_fences = ctx.add_deps_and_push_vm_bind_jobs(job_queue)?;

            for fence in &finished_fences {
                prepared_vm.resv_add_fence(
                    fence,
                    kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                    kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                );
            }

            Ok(())
        })?;

        // Push all signal fences to their syncobjs.
        ctx.push_fences();

        Ok(0)
    }

    pub(crate) fn vm_bind(
        ddev: &TyrDrmDevice,
        vmbind: &mut uapi::drm_panthor_vm_bind,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if vmbind.flags & uapi::drm_panthor_vm_bind_flags_DRM_PANTHOR_VM_BIND_ASYNC != 0 {
            return Self::vm_bind_async(ddev, vmbind, file);
        }

        if vmbind.ops.stride as usize != core::mem::size_of::<uapi::drm_panthor_vm_bind_op>() {
            dev_info!(
                ddev.as_ref(),
                "We cannot graciously handle stride mismatches yet"
            );
            return Err(ENOTSUPP);
        }

        let stride = vmbind.ops.stride as usize;
        let count = vmbind.ops.count as usize;

        let mut reader = UserSlice::new(
            UserPtr::from_addr(vmbind.ops.array as usize),
            stride * count,
        )
        .reader();

        for i in 0..count {
            let res = {
                let op: VmBindOp = reader.read()?;
                let mask = uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MASK;

                match op.0.flags as i32 & mask {
                    uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MAP => {
                        let bo = gem::lookup_handle(file, op.0.bo_handle)?;

                        let vm = file
                            .inner()
                            .vm_pool()
                            .get_vm(vmbind.vm_id as usize)
                            .ok_or(EINVAL)?;

                        let flags = VmMapFlags::try_from(op.0.flags & 0b111)?;

                        let mut resources = VmOpResources::for_map()?;
                        vm.map_bo_range(
                            &bo,
                            op.0.bo_offset,
                            op.0.size,
                            op.0.va,
                            flags,
                            &mut resources,
                            GFP_KERNEL,
                        )?;
                    }

                    uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_UNMAP => {
                        if op.0.bo_handle != 0 || op.0.bo_offset != 0 {
                            return Err(EINVAL);
                        }

                        let vm = file
                            .inner()
                            .vm_pool()
                            .get_vm(vmbind.vm_id as usize)
                            .ok_or(EINVAL)?;

                        let mut resources = VmOpResources::for_unmap()?;
                        vm.unmap_range(op.0.va, op.0.size, &mut resources, GFP_KERNEL)?;
                    }
                    _ => return Err(ENOTSUPP),
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
        _tdev: &TyrDrmDevice,
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
        _tdev: &TyrDrmDevice,
        bommap: &mut uapi::drm_panthor_bo_mmap_offset,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        let bo = gem::lookup_handle(file, bommap.handle)?;

        bommap.offset = bo.create_mmap_offset()?;

        Ok(0)
    }

    pub(crate) fn vm_pool(self: Pin<&Self>) -> Pin<&Pool> {
        // SAFETY: Field projection, we never move out of this field.
        unsafe { self.map_unchecked(|f| &f.vm_pool) }
    }

    pub(crate) fn group_pool(self: Pin<&Self>) -> Pin<&group::Pool> {
        // SAFETY: Field projection, we never move out of this field.
        unsafe { self.map_unchecked(|f| &f.group_pool) }
    }

    pub(crate) fn group_create(
        ddev: &TyrDrmDevice,
        groupcreate: &mut uapi::drm_panthor_group_create,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if groupcreate.queues.count == 0 {
            return Err(EINVAL);
        }

        let mut reader = UserSlice::new(
            UserPtr::from_addr(groupcreate.queues.array as usize),
            groupcreate.queues.stride as usize * groupcreate.queues.count as usize,
        )
        .reader();

        let mut queue_args = kvec![];
        for _ in 0..groupcreate.queues.count {
            let queue: QueueCreate = reader.read()?;
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
        ddev: &TyrDrmDevice,
        groupdestroy: &mut uapi::drm_panthor_group_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        file.inner()
            .group_pool()
            .destroy_group(ddev, groupdestroy.group_handle as usize)?;

        Ok(0)
    }

    pub(crate) fn group_submit(
        ddev: &TyrDrmDevice,
        groupsubmit: &mut uapi::drm_panthor_group_submit,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if groupsubmit.queue_submits.count == 0 {
            return Err(EINVAL);
        }

        let mut reader = UserSlice::new(
            UserPtr::from_addr(groupsubmit.queue_submits.array as usize),
            groupsubmit.queue_submits.stride as usize * groupsubmit.queue_submits.count as usize,
        )
        .reader();

        let mut queue_submits = kvec![];
        let mut syncs = kvec![];

        for _ in 0..groupsubmit.queue_submits.count {
            let queue: QueueSubmit = reader.read()?;

            let mut sync_reader = UserSlice::new(
                UserPtr::from_addr(queue.syncs.array as usize),
                queue.syncs.stride as usize * queue.syncs.count as usize,
            )
            .reader();

            for _ in 0..queue.syncs.count {
                let sync: SyncOp = sync_reader.read()?;

                let valid_flags = (uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_SIGNAL
                    | uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_WAIT
                    | uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK)
                    as u32;

                if sync.flags & !valid_flags != 0 {
                    pr_err!("group_submit: invalid sync op flags: 0x{:x}", sync.flags);
                    return Err(EINVAL);
                }

                let handle_type = sync.flags
                    & uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK as u32;
                if handle_type != uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ as u32
                    && handle_type != uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ as u32
                {
                    pr_err!("group_submit: invalid sync handle type: 0x{:x}", handle_type);
                    return Err(EINVAL);
                }

                syncs.push(sync, GFP_KERNEL)?;
            }

            queue_submits.push(queue, GFP_KERNEL)?;
        }

        let group = file
            .inner()
            .group_pool()
            .group(groupsubmit.group_handle as usize)
            .ok_or(EINVAL)?;

        ddev.with_locked_scheduler(|sched| {
            sched.bind(ddev, group.clone())?;
            sched.submit(syncs, group, queue_submits, file)
        })?;

        Ok(0)
    }

    pub(crate) fn group_get_state(
        _tdev: &TyrDrmDevice,
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
        groupgetstate.fatal_queues = 0;

        group.with_locked_inner(|inner| {
            if inner.fatal_queues != 0 {
                groupgetstate.state |=
                    uapi::drm_panthor_group_state_flags_DRM_PANTHOR_GROUP_STATE_FATAL_FAULT;
                groupgetstate.fatal_queues = inner.fatal_queues;
            }

            Ok(())
        })?;

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

        // Get or create the heap pool for this VM.  We must not hold the
        // XArray spinlock while doing any sleeping work, so we clone the Arc
        // under the lock and then drop it before calling into the pool.
        let file_inner = file.inner();
        let xa = file_inner.heap_pools.as_ref();

        let pool: Arc<heap::Pool> = {
            let guard = xa.lock();
            if let Some(existing) = guard.get(vm_id) {
                // Pool already exists — clone Arc and release spinlock.
                existing.into()
            } else {
                drop(guard);
                let new_pool = Arc::pin_init(heap::Pool::create(ddev, vm.clone())?, GFP_KERNEL)?;
                let mut guard = xa.lock();
                if let Some(existing) = guard.get(vm_id) {
                    existing.into()
                } else {
                    guard.store(vm_id, new_pool.clone(), GFP_ATOMIC)?;
                    new_pool
                }
            }
        };

        let created_context = pool.create_heap_context(ddev, args)?;

        heapcreate.handle = heapcreate.vm_id << 16 | created_context.context_id as u32;
        heapcreate.tiler_heap_ctx_gpu_va = created_context.context_gpu_va;
        heapcreate.first_heap_chunk_gpu_va = created_context.first_chunk_gpu_va;

        Ok(0)
    }

    pub(crate) fn heap_destroy(
        _tdev: &TyrDrmDevice,
        heapdestroy: &mut uapi::drm_panthor_tiler_heap_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        let vm_id = (heapdestroy.handle >> 16) as usize;
        let heap_idx = (heapdestroy.handle & genmask_u32(0..=15)) as usize;

        let file_inner = file.inner();
        let xa = file_inner.heap_pools.as_ref();

        // Clone the Arc under the spinlock, then release it before calling
        // destroy_heap_context (which takes the pool's inner XArray spinlock).
        let pool: Arc<heap::Pool> = xa.lock().get(vm_id).ok_or(EINVAL)?.into();
        pool.destroy_heap_context(heap_idx).ok_or(EINVAL)?;

        Ok(0)
    }

    /// Set a debug label on a buffer object.
    ///
    /// Stub: labeling is not yet implemented in Tyr.
    pub(crate) fn bo_set_label(
        _tdev: &TyrDrmDevice,
        _args: &mut uapi::drm_panthor_bo_set_label,
        _file: &TyrDrmFile,
    ) -> Result<u32> {
        // TODO: Implement BO labeling for debug purposes.
        Ok(0)
    }

    /// Set the user MMIO offset for this file context.
    ///
    /// Stub: user MMIO offset configuration is not yet implemented.
    pub(crate) fn set_user_mmio_offset(
        _tdev: &TyrDrmDevice,
        _args: &mut uapi::drm_panthor_set_user_mmio_offset,
        _file: &TyrDrmFile,
    ) -> Result<u32> {
        // TODO: Implement user MMIO offset for 32-bit compat (FEX).
        Err(ENOTSUPP)
    }

    /// Synchronize buffer object caches.
    ///
    /// Stub: cache sync is not yet implemented. This is needed for
    /// imported BOs (dma-buf) but not for native allocations.
    pub(crate) fn bo_sync(
        _tdev: &TyrDrmDevice,
        _args: &mut uapi::drm_panthor_bo_sync,
        _file: &TyrDrmFile,
    ) -> Result<u32> {
        // TODO: Implement cache sync for imported BOs.
        Ok(0)
    }

    /// Query information about a buffer object.
    pub(crate) fn bo_query_info(
        _tdev: &TyrDrmDevice,
        args: &mut uapi::drm_panthor_bo_query_info,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        let bo = gem::lookup_handle(file, args.handle)?;

        args.create_flags = bo.flags;
        args.extra_flags = 0;
        args.pad = 0;

        // TODO: Check if the BO is imported (dma-buf) once the Rust DRM GEM API
        // exposes drm_gem_is_imported(). For now, all BOs report as native.

        Ok(0)
    }
}

#[repr(transparent)]
struct VmBindOp(uapi::drm_panthor_vm_bind_op);

// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for VmBindOp {}

#[repr(transparent)]
pub(crate) struct QueueCreate(pub uapi::drm_panthor_queue_create);

// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for QueueCreate {}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub(crate) struct QueueSubmit(pub uapi::drm_panthor_queue_submit);

// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for QueueSubmit {}

impl Deref for QueueSubmit {
    type Target = uapi::drm_panthor_queue_submit;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for QueueSubmit {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(transparent)]
pub(crate) struct SyncOp(pub uapi::drm_panthor_sync_op);

// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for SyncOp {}

impl Deref for SyncOp {
    type Target = uapi::drm_panthor_sync_op;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SyncOp {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
