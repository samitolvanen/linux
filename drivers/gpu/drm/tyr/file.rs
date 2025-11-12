// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Deref;
use core::ops::DerefMut;

use kernel::alloc::flags::*;
use kernel::bits::genmask_u32;
use kernel::drm;
use kernel::drm::device::Device as DrmDevice;
use kernel::drm::gem::BaseObject;
use kernel::kvec;
use kernel::prelude::*;
use kernel::transmute::FromBytes;
use kernel::types::ARef;
use kernel::uaccess::UserSlice;
use kernel::uapi;
use kernel::xarray;
use kernel::xarray::XArray;
use pin_init::pinned_drop;

use crate::driver::TyrDevice;
use crate::driver::TyrDriver;
use crate::gem;
use crate::gpu;
use crate::heap;
use crate::mmu::vm;
use crate::mmu::vm::pool::Pool;
use crate::mmu::vm::VmLayout;
use crate::mmu::vm::VmUserSize;
use crate::mmu::vm::WithLockedVm;
use crate::mmu::vm::{VmBindJob, VmOperation};
use crate::sched::deps;
use crate::sched::group;

#[pin_data(PinnedDrop)]
pub(crate) struct File {
    /// A pool storing our VMs for this particular context.
    #[pin]
    vm_pool: Pool,

    group_pool: group::Pool,

    /// Heap pools, indexed by VM ID.
    ///
    /// Each VM can have its own heap pool for tiler heap management.
    /// The heap pool is created on-demand when the first heap context is created.
    heap_pools: Pin<KBox<XArray<KBox<heap::Pool>>>>,

    /// Reference to the device for cleanup
    tdev: ARef<TyrDevice>,
}

/// Convenience type alias for our DRM `File` type
pub(crate) type DrmFile = drm::file::File<File>;

impl drm::file::DriverFile for File {
    type Driver = TyrDriver;

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
impl PinnedDrop for File {
    fn drop(self: Pin<&mut Self>) {
        pr_info!("Cleaning up DRM file resources\n");

        // Destroy all groups (this unbinds them if necessary)
        if let Err(e) = self.as_ref().group_pool().destroy_all(&self.tdev) {
            pr_err!("Failed to destroy all groups: {:?}\n", e);
        }

        // Destroy all VMs
        if let Err(e) = self.as_ref().vm_pool().destroy_all(self.tdev.iomem.clone()) {
            pr_err!("Failed to destroy all VMs: {:?}\n", e);
        }
    }
}

impl File {
    pub(crate) fn dev_query(
        tdev: &TyrDevice,
        devquery: &mut uapi::drm_panthor_dev_query,
        _file: &DrmFile,
    ) -> Result<u32> {
        if devquery.pointer == 0 {
            match devquery.type_ {
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GPU_INFO => {
                    devquery.size = core::mem::size_of_val(&tdev.gpu_info) as u32;
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
                    let mut writer = UserSlice::new(
                        UserPtr::from_addr(devquery.pointer as usize),
                        devquery.size as usize,
                    )
                    .writer();

                    writer.write(&tdev.gpu_info)?;

                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_CSIF_INFO => {
                    let mut writer = UserSlice::new(
                        UserPtr::from_addr(devquery.pointer as usize),
                        devquery.size as usize,
                    )
                    .writer();

                    let csif = tdev.csif_info.lock();
                    writer.write(&*csif)?;

                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_TIMESTAMP_INFO => {
                    use crate::regs;

                    let timestamp_frequency = 0u64;
                    let current_timestamp = regs::GPU_TIMESTAMP.read64_counter(&tdev.iomem)?;
                    let timestamp_offset = regs::GPU_TIMESTAMP_OFFSET.read64(&tdev.iomem)?;

                    let data: [u64; 3] = [timestamp_frequency, current_timestamp, timestamp_offset];

                    let mut writer = UserSlice::new(
                        UserPtr::from_addr(devquery.pointer as usize),
                        devquery.size as usize,
                    )
                    .writer();

                    writer.write(&data)?;

                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GROUP_PRIORITIES_INFO => {
                    // Return group priorities info - allow LOW and MEDIUM
                    // PANTHOR_GROUP_PRIORITY_HIGH requires CAP_SYS_NICE or DRM_MASTER
                    // PANTHOR_GROUP_PRIORITY_REALTIME is EINVAL
                    let mask = (1 << uapi::drm_panthor_group_priority_PANTHOR_GROUP_PRIORITY_LOW)
                        | (1 << uapi::drm_panthor_group_priority_PANTHOR_GROUP_PRIORITY_MEDIUM);
                    let data: [u8; 4] = [mask as u8, 0, 0, 0];

                    let mut writer = UserSlice::new(
                        UserPtr::from_addr(devquery.pointer as usize),
                        devquery.size.min(core::mem::size_of::<[u8; 4]>() as u32) as usize,
                    )
                    .writer();

                    writer.write(&data)?;

                    Ok(0)
                }
                _ => Err(EINVAL),
            }
        }
    }

    pub(crate) fn vm_create(
        tdev: &TyrDevice,
        vmcreate: &mut uapi::drm_panthor_vm_create,
        file: &DrmFile,
    ) -> Result<u32> {
        let id = file.inner().vm_pool().create_vm(
            &ARef::from(tdev),
            VmLayout::from_user_sz(tdev, VmUserSize::Custom(vmcreate.user_va_range)),
        )?;

        vmcreate.id = id as u32;
        Ok(0)
    }

    pub(crate) fn vm_destroy(
        tdev: &TyrDevice,
        vmdestroy: &mut uapi::drm_panthor_vm_destroy,
        file: &DrmFile,
    ) -> Result<u32> {
        let iomem = tdev.iomem.clone();

        file.inner()
            .vm_pool()
            .destroy_vm(vmdestroy.id as usize, iomem)?;
        Ok(0)
    }

    pub(crate) fn vm_bind_async(
        tdev: &TyrDevice,
        vmbind: &mut uapi::drm_panthor_vm_bind,
        file: &DrmFile,
    ) -> Result<u32> {
        if vmbind.ops.stride as usize != core::mem::size_of::<uapi::drm_panthor_vm_bind_op>() {
            dev_info!(
                tdev.as_ref(),
                "We cannot graciously handle stride mismatches yet"
            );
            return Err(ENOTSUPP);
        }

        let vm = file
            .inner()
            .vm_pool()
            .get_vm(vmbind.vm_id as usize)
            .ok_or(EINVAL)?;

        if vm.lock().unusable {
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
                    let flags = vm::map_flags::Flags::try_from(op.0.flags & 0b111)?;

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
                    tdev.as_ref(),
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

            // Convert UAPI sync operations to internal representation
            let internal_syncs = deps::SyncOp::from_uapi_slice(&sync_ops)?;

            let job = VmBindJob::new(vm.clone(), vm_operation);

            ctx.add_vm_bind_job(job, internal_syncs)?;
        }

        // Collect all signal operations across all jobs
        // We need to iterate through all sync ops again to collect signals
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

        // Push all VM bind jobs with dependencies and update reservation objects
        vm.with_lock_taken(|vm| {
            vm.with_prepared_vm_and_entity(count as u32, |mut locked_vm, entity| {
                let finished_fences = ctx.add_deps_and_push_vm_bind_jobs(entity)?;

                // Add the finished fences to the reservation objects
                for fence in &finished_fences {
                    locked_vm.resv_add_fence(
                        fence,
                        kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                        kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                    );
                }

                Ok(())
            })
        })?;

        // Push all signal fences to their syncobjs
        ctx.push_fences();

        Ok(0)
    }

    pub(crate) fn vm_bind(
        tdev: &TyrDevice,
        vmbind: &mut uapi::drm_panthor_vm_bind,
        file: &DrmFile,
    ) -> Result<u32> {
        if vmbind.flags & uapi::drm_panthor_vm_bind_flags_DRM_PANTHOR_VM_BIND_ASYNC != 0 {
            return Self::vm_bind_async(tdev, vmbind, file);
        }

        if vmbind.ops.stride as usize != core::mem::size_of::<uapi::drm_panthor_vm_bind_op>() {
            dev_info!(
                tdev.as_ref(),
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
        let iomem = tdev.iomem.clone();

        for i in 0..count {
            let res = {
                let op: VmBindOp = reader.read()?;
                let mask = uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MASK;

                match op.0.flags as i32 & mask {
                    uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MAP => {
                        let bo = gem::lookup_handle(file, op.0.bo_handle)?;
                        let range = op.0.va..op.0.va + op.0.size;

                        let vm = file
                            .inner()
                            .vm_pool()
                            .get_vm(vmbind.vm_id as usize)
                            .ok_or(EINVAL)?;

                        pr_info!("binding BO handle {} at offset {:#x} to VA range {:#x}-{:#x} in VM id {} AS {}\n",
                            op.0.bo_handle,
                            op.0.bo_offset,
                            range.start,
                            range.end,
                            vmbind.vm_id,
                            vm.lock().address_space().map_or(-1, |as_nr| as_nr as i32)
                        );

                        vm.lock().bind_gem(
                            iomem.clone(),
                            &bo.gem,
                            op.0.bo_offset,
                            range,
                            vm::map_flags::Flags::try_from(op.0.flags & 0b111)?,
                        )?;
                    }

                    uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_UNMAP => {
                        if op.0.bo_handle != 0 || op.0.bo_offset != 0 {
                            return Err(EINVAL);
                        }

                        let range = op.0.va..op.0.va + op.0.size;

                        let vm = file
                            .inner()
                            .vm_pool()
                            .get_vm(vmbind.vm_id as usize)
                            .ok_or(EINVAL)?;

                        pr_info!(
                            "unbinding VA range {:#x}-{:#x} in VM {}\n",
                            range.start,
                            range.end,
                            vmbind.vm_id
                        );
                        vm.lock().unmap_range(iomem.clone(), range)?;
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
        _tdev: &TyrDevice,
        vmgetstate: &mut uapi::drm_panthor_vm_get_state,
        file: &DrmFile,
    ) -> Result<u32> {
        let vm = file
            .inner()
            .vm_pool()
            .get_vm(vmgetstate.vm_id as usize)
            .ok_or(EINVAL)?;

        let vm = vm.lock();
        vmgetstate.state = if vm.unusable {
            uapi::drm_panthor_vm_state_DRM_PANTHOR_VM_STATE_UNUSABLE
        } else {
            uapi::drm_panthor_vm_state_DRM_PANTHOR_VM_STATE_USABLE
        };

        Ok(0)
    }

    pub(crate) fn bo_create(
        tdev: &TyrDevice,
        bocreate: &mut uapi::drm_panthor_bo_create,
        file: &DrmFile,
    ) -> Result<u32> {
        if bocreate.flags & !uapi::drm_panthor_bo_flags_DRM_PANTHOR_BO_NO_MMAP != 0 {
            dev_err!(
                tdev.as_ref(),
                "bo_create: invalid flags {}\n",
                bocreate.flags
            );

            return Err(EINVAL);
        }

        let bo = gem::new_object(tdev, bocreate.size as usize, bocreate.flags)?;

        let handle = bo.gem.create_handle(file)?;
        bocreate.handle = handle;
        bocreate.size = bo.gem.size() as u64;

        Ok(0)
    }

    pub(crate) fn bo_mmap_offset(
        _tdev: &TyrDevice,
        bommap: &mut uapi::drm_panthor_bo_mmap_offset,
        file: &DrmFile,
    ) -> Result<u32> {
        let bo = gem::lookup_handle(file, bommap.handle)?;

        bommap.offset = bo.gem.create_mmap_offset()?;

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
        tdev: &TyrDevice,
        groupcreate: &mut uapi::drm_panthor_group_create,
        file: &DrmFile,
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
            .create_group(tdev, groupcreate, file, queue_args)?;

        groupcreate.group_handle = handle as u32;

        Ok(0)
    }

    pub(crate) fn group_destroy(
        tdev: &TyrDevice,
        groupdestroy: &mut uapi::drm_panthor_group_destroy,
        file: &DrmFile,
    ) -> Result<u32> {
        file.inner()
            .group_pool()
            .destroy_group(tdev, groupdestroy.group_handle as usize)?;

        Ok(0)
    }

    pub(crate) fn group_submit(
        tdev: &TyrDevice,
        groupsubmit: &mut uapi::drm_panthor_group_submit,
        file: &DrmFile,
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

                // Validate handle type
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

        tdev.with_locked_scheduler(|sched| {
            sched.bind(tdev, group.clone())?;
            sched.submit(syncs, group, queue_submits, file)
        })?;

        Ok(0)
    }

    pub(crate) fn group_get_state(
        _tdev: &TyrDevice,
        groupgetstate: &mut uapi::drm_panthor_group_get_state,
        file: &DrmFile,
    ) -> Result<u32> {
        if groupgetstate.pad != 0 {
            return Err(EINVAL);
        }

        let group = file
            .inner()
            .group_pool()
            .group(groupgetstate.group_handle as usize)
            .ok_or(EINVAL)?;

        // Clear the output fields first
        groupgetstate.state = 0;
        groupgetstate.fatal_queues = 0;

        group.with_locked_inner(|inner| {
            // Check for fatal queues
            if inner.fatal_queues != 0 {
                groupgetstate.state |=
                    uapi::drm_panthor_group_state_flags_DRM_PANTHOR_GROUP_STATE_FATAL_FAULT;
                groupgetstate.fatal_queues = inner.fatal_queues;
            }

            // TODO: Add support for timedout and innocent flags when tyr implements
            // timeout tracking and reset handling similar to Panthor

            Ok(())
        })?;

        Ok(0)
    }

    pub(crate) fn heap_create(
        tdev: &TyrDevice,
        heapcreate: &mut uapi::drm_panthor_tiler_heap_create,
        file: &DrmFile,
    ) -> Result<u32> {
        let vm_id = heapcreate.vm_id as usize;
        let vm = file.inner().vm_pool().get_vm(vm_id).ok_or(EINVAL)?;

        let args = heap::ContextCreateArgs {
            initial_chunk_count: heapcreate.initial_chunk_count,
            chunk_size: heapcreate.chunk_size,
            max_chunks: heapcreate.max_chunks,
            target_in_flight: heapcreate.target_in_flight,
        };

        // Create the heap pool for this VM if it doesn't exist yet
        let file_inner = file.inner();
        let xa = file_inner.heap_pools.as_ref();

        {
            let guard = xa.lock();
            if guard.get(vm_id).is_none() {
                drop(guard); // Release lock before creating pool
                let pool = KBox::new(
                    heap::Pool::create(tdev, tdev.iomem.clone(), vm.clone())?,
                    GFP_KERNEL,
                )?;
                xa.lock().store(vm_id, pool, GFP_KERNEL)?;
            }
        }

        let guard = xa.lock();
        let pool = guard.get(vm_id).ok_or(EINVAL)?;
        let created_context = pool.create_heap_context(tdev, args)?;

        heapcreate.handle = heapcreate.vm_id << 16 | created_context.context_id as u32;
        heapcreate.tiler_heap_ctx_gpu_va = created_context.context_gpu_va;
        heapcreate.first_heap_chunk_gpu_va = created_context.first_chunk_gpu_va;

        Ok(0)
    }

    pub(crate) fn heap_destroy(
        _tdev: &TyrDevice,
        heapdestroy: &mut uapi::drm_panthor_tiler_heap_destroy,
        file: &DrmFile,
    ) -> Result<u32> {
        let vm_id = (heapdestroy.handle >> 16) as usize;
        let heap_idx = (heapdestroy.handle & genmask_u32(0..=15)) as usize;

        let file_inner = file.inner();
        let xa = file_inner.heap_pools.as_ref();
        let guard = xa.lock();
        let pool = guard.get(vm_id).ok_or(EINVAL)?;
        pool.destroy_heap_context(heap_idx).ok_or(EINVAL)?;

        Ok(0)
    }
}

#[repr(transparent)]
struct VmBindOp(uapi::drm_panthor_vm_bind_op);

// XXX: we cannot implement this trait for the uapi type directly, hence the
// wrapper.
// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for VmBindOp {}

#[repr(transparent)]
pub(crate) struct QueueCreate(pub uapi::drm_panthor_queue_create);

// XXX: we cannot implement this trait for the uapi type directly, hence the
// wrapper.
// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for QueueCreate {}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub(crate) struct QueueSubmit(pub uapi::drm_panthor_queue_submit);

// XXX: we cannot implement this trait for the uapi type directly, hence the
// wrapper.
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

// XXX: we cannot implement this trait for the uapi type directly, hence the
// wrapper.
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
