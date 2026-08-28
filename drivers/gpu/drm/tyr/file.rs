// SPDX-License-Identifier: GPL-2.0 or MIT

use core::mem::offset_of;

use kernel::{
    alloc::KVec,
    dma_buf::DmaResvUsage,
    drm::{
        self,
        exec::{
            Exec,
            ExecFlag, //
        },
        gem::BaseObject, //
    },
    io::Io,
    new_spinlock,
    pm::PMProfile,
    preempt,
    prelude::*,
    str::CString,
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc,
        SpinLock, //
    },
    task,
    time::{
        self,
        Timespec64, //
    },
    transmute::{
        AsBytes,
        FromBytes, //
    },
    uaccess::{
        UserSlice,
        UserSliceReader, //
    },
    uapi, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDriver, //
    },
    gem,
    heap,
    mmap,
    regs::{
        gpu_control,
        join_u64,
        read_u64_no_tearing, //
    },
    sched::{
        deps,
        group, //
    },
    vm::{
        self,
        VmMapFlags, //
    }, //
};

/// GPU MMU page size is fixed at 4 KiB regardless of host page size.
const GPU_PAGE_MASK: u64 = (1 << 12) - 1;

fn set_uobj<T: AsBytes>(usr_ptr: u64, usr_size: u32, min_size: usize, obj: &T) -> Result {
    let kern_size = core::mem::size_of_val(obj);
    let usr_size = usr_size as usize;

    if usr_size < min_size {
        return Err(EINVAL);
    }

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

/// Verifies that the next `len` bytes of `reader` are all zero, advancing the
/// reader past them. Mirrors `copy_struct_from_user`: a larger user stride is
/// accepted only if its trailing bytes are zero, otherwise the call is
/// rejected with `E2BIG`.
pub(crate) fn read_padding_zero(reader: &mut UserSliceReader, len: usize) -> Result {
    let mut buf = [0u8; 64];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(buf.len());
        reader.read_slice(&mut buf[..chunk])?;
        if buf[..chunk].iter().any(|&b| b != 0) {
            return Err(E2BIG);
        }
        remaining -= chunk;
    }
    Ok(())
}

/// Validate a single `drm_panthor_vm_bind_op` at the ioctl entry, before any
/// state is mutated or any job is queued. Rejects `EINVAL` if `va`, `size`,
/// or `bo_offset` is not GPU-page-aligned, if `[va, va + size)` falls outside
/// the VM's user VA range, and for `MAP` ops if `bo_handle` is invalid, if
/// `bo_offset + size` is out of bounds for the target BO, or if the BO is
/// exclusive to a VM other than `vm`.
///
/// For `MAP` ops, returns the looked-up `Bo` so the caller can perform the
/// bind against the same BO that was validated, avoiding a TOCTOU window.
fn validate_bind_op(
    op: &VmBindOp,
    file: &TyrDrmFile,
    vm: &vm::Vm,
) -> Result<Option<ARef<gem::Bo>>> {
    if (op.0.va | op.0.size | op.0.bo_offset) & GPU_PAGE_MASK != 0 {
        return Err(EINVAL);
    }

    if !vm.in_user_va_range(op.0.va, op.0.size) {
        return Err(EINVAL);
    }

    let type_mask = uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MASK;
    if op.0.flags as i32 & type_mask
        == uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MAP
    {
        let bo = gem::lookup_handle(file, op.0.bo_handle).map_err(|_| EINVAL)?;
        let bo_size = bo.size() as u64;
        // Check size first to avoid underflow in the subtraction.
        if op.0.size > bo_size || op.0.bo_offset > bo_size - op.0.size {
            return Err(EINVAL);
        }
        if let Some(root) = bo.exclusive_vm_root_gem() {
            if !core::ptr::eq(root, vm.root_gem()) {
                return Err(EINVAL);
            }
        }
        return Ok(Some(bo));
    }

    Ok(None)
}

/// Accumulated GPU usage for a file, exposed through fdinfo.
///
/// Drained from the per-group accumulators at fdinfo show time.
#[derive(Clone, Copy, Default)]
pub(crate) struct Stats {
    pub(crate) cycles: u64,
    pub(crate) time: u64,
}

/// GPU memory footprint for a file, exposed through fdinfo.
#[derive(Default)]
pub(crate) struct MemoryStats {
    pub(crate) resident: u64,
    pub(crate) active: u64,
}

#[pin_data(PinnedDrop)]
pub(crate) struct TyrDrmFileData {
    vm_pool: vm::Pool,
    group_pool: group::Pool,
    heap_pools: heap::Pools,
    user_mmio_offset: Atomic<u64>,
    tdev: ARef<TyrDrmDevice>,
    /// Accumulated GPU usage, a spinlock to match the per-group
    /// accumulator it drains from.
    #[pin]
    stats: SpinLock<Stats>,
}

/// Convenience type alias for our DRM `File` type
pub(crate) type TyrDrmFile = drm::file::File<TyrDrmFileData>;

impl drm::file::DriverFile for TyrDrmFileData {
    type Driver = TyrDrmDriver;

    fn open(dev: &drm::Device<Self::Driver>) -> Result<Pin<KBox<Self>>> {
        let tdev = ARef::from(dev);

        let user_mmio_offset = if task::in_compat_syscall() {
            uapi::DRM_PANTHOR_USER_MMIO_OFFSET_32BIT
        } else {
            mmap::DRM_PANTHOR_USER_MMIO_OFFSET
        };

        KBox::try_pin_init(
            try_pin_init!(Self {
                vm_pool: vm::Pool::create()?,
                group_pool: group::Pool::create()?,
                heap_pools: heap::Pools::create()?,
                user_mmio_offset: Atomic::new(user_mmio_offset),
                tdev,
                stats <- new_spinlock!(Stats::default()),
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

        if let Err(e) = self.as_ref().vm_pool().destroy_all(&self.tdev) {
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

    pub(crate) fn user_mmio_offset(&self) -> u64 {
        self.user_mmio_offset.load(Relaxed)
    }

    /// Drains the per-group profiling samples into the file accumulator.
    ///
    /// The two spinlocks are never held at once, so no lock-order inversion
    /// is possible.
    pub(crate) fn gather_group_samples(self: Pin<&Self>) {
        let mut drained = Stats::default();
        self.group_pool().gather_stats(&mut drained);

        let mut stats = self.stats.lock();
        stats.cycles = stats.cycles.wrapping_add(drained.cycles);
        stats.time = stats.time.wrapping_add(drained.time);
    }

    /// Returns a snapshot of the file's accumulated GPU usage.
    pub(crate) fn stats_snapshot(&self) -> Stats {
        *self.stats.lock()
    }

    /// Collects the file's GPU memory footprint.
    ///
    /// Resident sums each group's kernel BOs and every VM's tiler-heap
    /// pool. Active counts the groups on a CSG slot and the heap pools
    /// whose VM holds an address-space slot.
    pub(crate) fn gather_mem_info(self: Pin<&Self>) -> MemoryStats {
        let mut stats = MemoryStats::default();
        self.group_pool().gather_mem_info(&mut stats);

        for vm_id in 1..self.vm_pool().index_upper_bound() {
            if let Some(pool) = self.heap_pools().get_pool(vm_id) {
                let size = pool.total_size() as u64;
                stats.resident += size;
                if self
                    .vm_pool()
                    .get_vm(vm_id)
                    .and_then(|vm| vm.as_slot())
                    .is_some()
                {
                    stats.active += size;
                }
            }
        }

        stats
    }

    pub(crate) fn dev_query(
        ddev: &TyrDrmDevice,
        devquery: &mut uapi::drm_panthor_dev_query,
        file: &TyrDrmFile,
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
                    let min_size =
                        offset_of!(uapi::drm_panthor_gpu_info, tiler_present) + size_of::<u64>();
                    set_uobj(devquery.pointer, devquery.size, min_size, &ddev.gpu_info)?;

                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_CSIF_INFO => {
                    let csif_data = {
                        let csif = ddev.csif_info.lock();
                        *csif
                    };
                    let min_size = size_of::<uapi::drm_panthor_csif_info>();
                    set_uobj(devquery.pointer, devquery.size, min_size, &csif_data)?;

                    Ok(0)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_TIMESTAMP_INFO => {
                    Self::query_timestamp_info(ddev, devquery)
                }
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GROUP_PRIORITIES_INFO => {
                    let mut allowed_mask: u8 = 0;
                    for prio in 0..=uapi::drm_panthor_group_priority_PANTHOR_GROUP_PRIORITY_REALTIME
                    {
                        if group::priority_permit(file, prio as u8).is_ok() {
                            allowed_mask |= 1 << prio;
                        }
                    }
                    let data: [u8; 4] = [allowed_mask, 0, 0, 0];

                    let min_size = size_of::<uapi::drm_panthor_group_priorities_info>();
                    set_uobj(devquery.pointer, devquery.size, min_size, &data)?;

                    Ok(0)
                }
                _ => Err(EINVAL),
            }
        }
    }

    fn query_timestamp_info(
        ddev: &TyrDrmDevice,
        devquery: &mut uapi::drm_panthor_dev_query,
    ) -> Result<u32> {
        use uapi::{
            drm_panthor_timestamp_info_flags_DRM_PANTHOR_TIMESTAMP_CPU_MONOTONIC as CPU_MONOTONIC,
            drm_panthor_timestamp_info_flags_DRM_PANTHOR_TIMESTAMP_CPU_MONOTONIC_RAW as CPU_MONOTONIC_RAW,
            drm_panthor_timestamp_info_flags_DRM_PANTHOR_TIMESTAMP_CPU_NONE as CPU_NONE,
            drm_panthor_timestamp_info_flags_DRM_PANTHOR_TIMESTAMP_CPU_TYPE_MASK as CPU_TYPE_MASK,
            drm_panthor_timestamp_info_flags_DRM_PANTHOR_TIMESTAMP_DURATION as DURATION,
            drm_panthor_timestamp_info_flags_DRM_PANTHOR_TIMESTAMP_FREQ as FREQ,
            drm_panthor_timestamp_info_flags_DRM_PANTHOR_TIMESTAMP_GPU as GPU,
            drm_panthor_timestamp_info_flags_DRM_PANTHOR_TIMESTAMP_GPU_CYCLE_COUNT as GPU_CYCLE_COUNT,
            drm_panthor_timestamp_info_flags_DRM_PANTHOR_TIMESTAMP_GPU_OFFSET as GPU_OFFSET,
        };

        const VALID: u32 = GPU | CPU_TYPE_MASK | GPU_OFFSET | GPU_CYCLE_COUNT | FREQ | DURATION;

        let min_size =
            offset_of!(uapi::drm_panthor_timestamp_info, current_timestamp) + size_of::<u64>();

        let mut info = TimestampInfo(uapi::drm_panthor_timestamp_info::default());
        let kern_size = size_of::<uapi::drm_panthor_timestamp_info>();
        let usr_size = devquery.size as usize;
        let copy_size = usr_size.min(kern_size);
        // SAFETY: `info` is `FromBytes`, so any byte pattern read into it is
        // valid, and `AsBytes`, so the mutable byte view is sound.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::from_mut(&mut info).cast::<u8>(), kern_size)
        };
        let mut reader =
            UserSlice::new(UserPtr::from_addr(devquery.pointer as usize), usr_size).reader();
        reader.read_slice(&mut bytes[..copy_size])?;
        read_padding_zero(&mut reader, usr_size - copy_size)?;

        let flags = if info.0.flags != 0 {
            info.0.flags
        } else {
            GPU | GPU_OFFSET | FREQ
        };

        let mut timestamp_types = 0u32;
        match flags & CPU_TYPE_MASK {
            CPU_NONE => {}
            CPU_MONOTONIC | CPU_MONOTONIC_RAW => timestamp_types += 1,
            _ => return Err(EINVAL),
        }

        if flags & !VALID != 0 {
            return Err(EINVAL);
        }

        if flags & GPU != 0 {
            timestamp_types += 1;
        }
        if flags & GPU_CYCLE_COUNT != 0 {
            timestamp_types += 1;
        }

        let minimize_interruption = flags & DURATION != 0 || timestamp_types >= 2;

        let _awake = match ddev.pm_context() {
            Some(ctx) => Some(ctx.get(PMProfile::new().auto())?),
            None => None,
        };

        // SAFETY: `ddev` is a bound device in the ioctl path.
        let dev = unsafe { ddev.as_ref().as_bound() };
        let io = ddev.iomem.access(dev)?;

        info.0.timestamp_frequency = if flags & FREQ != 0 {
            time::arch_timer_get_rate().map_or(0, u64::from)
        } else {
            0
        };

        info.0.timestamp_offset = if flags & GPU_OFFSET != 0 {
            join_u64(
                io.read(gpu_control::TIMESTAMP_OFFSET_LO).into_raw(),
                io.read(gpu_control::TIMESTAMP_OFFSET_HI).into_raw(),
            )
        } else {
            0
        };

        let mut cpu_ts = Timespec64::default();

        let mut sample = || {
            let query_start = if flags & DURATION != 0 {
                time::local_clock()
            } else {
                0
            };

            info.0.current_timestamp = if flags & GPU != 0 {
                read_u64_no_tearing(
                    || io.read(gpu_control::TIMESTAMP_LO).into_raw(),
                    || io.read(gpu_control::TIMESTAMP_HI).into_raw(),
                )
            } else {
                0
            };

            match flags & CPU_TYPE_MASK {
                CPU_MONOTONIC => cpu_ts = time::ktime_get_ts64(),
                CPU_MONOTONIC_RAW => cpu_ts = time::ktime_get_raw_ts64(),
                _ => {}
            }

            info.0.cycle_count = if flags & GPU_CYCLE_COUNT != 0 {
                read_u64_no_tearing(
                    || io.read(gpu_control::CYCLE_COUNT_LO).into_raw(),
                    || io.read(gpu_control::CYCLE_COUNT_HI).into_raw(),
                )
            } else {
                0
            };

            info.0.duration_nsec = if flags & DURATION != 0 {
                (time::local_clock() - query_start) as u32
            } else {
                0
            };
        };

        if minimize_interruption {
            preempt::with_preempt_irq_disabled(sample);
        } else {
            sample();
        }

        if flags & CPU_TYPE_MASK != 0 {
            // SAFETY: This runs in the ioctl's process context, so
            // `current->nsproxy` is live.
            unsafe { cpu_ts.add_monotonic() };
            info.0.cpu_timestamp_sec = cpu_ts.tv_sec as u64;
            info.0.cpu_timestamp_nsec = cpu_ts.tv_nsec as u64;
        } else {
            info.0.cpu_timestamp_sec = 0;
            info.0.cpu_timestamp_nsec = 0;
        }

        set_uobj(devquery.pointer, devquery.size, min_size, &info)?;

        Ok(0)
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
        ddev: &TyrDrmDevice,
        vmdestroy: &mut uapi::drm_panthor_vm_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        file.inner().vm_pool().destroy_vm(ddev, vmdestroy)?;
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

        static_assert!(
            size_of::<uapi::drm_panthor_vm_bind_op>()
                == offset_of!(uapi::drm_panthor_vm_bind_op, syncs)
                    + size_of::<uapi::drm_panthor_obj_array>()
        );
        let min_size = offset_of!(uapi::drm_panthor_vm_bind_op, syncs)
            + size_of::<uapi::drm_panthor_obj_array>();
        let stride = vmbind.ops.stride as usize;
        if stride < min_size {
            return Err(EINVAL);
        }

        let count = vmbind.ops.count as usize;
        let vm = file
            .inner()
            .vm_pool()
            .get_vm(vmbind.vm_id as usize)
            .ok_or(EINVAL)?;

        let mut reader = UserSlice::new(
            UserPtr::from_addr(vmbind.ops.array as usize),
            stride.checked_mul(count).ok_or(EINVAL)?,
        )
        .reader();

        for i in 0..count {
            let res: Result = (|| {
                let op: VmBindOp = reader.read()?;
                read_padding_zero(&mut reader, stride - min_size)?;
                let type_mask = uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MASK;
                let map_flags =
                    (uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_READONLY
                        | uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_NOEXEC
                        | uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_MAP_UNCACHED)
                        as u32;

                if op.0.syncs.count != 0 || op.0.syncs.array != 0 {
                    Err(EINVAL)?;
                }

                // A zero-size op carries no work, so treat it as a no-op.
                if op.0.size == 0 {
                    return Ok(());
                }

                let validated_bo = validate_bind_op(&op, file, &vm)?;

                match op.0.flags as i32 & type_mask {
                    uapi::drm_panthor_vm_bind_op_flags_DRM_PANTHOR_VM_BIND_OP_TYPE_MAP => {
                        let bo = validated_bo.ok_or(EINVAL)?;

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
                    _ => Err(EINVAL)?,
                }

                Ok(())
            })();

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
        let min_size = offset_of!(uapi::drm_panthor_vm_bind_op, syncs)
            + size_of::<uapi::drm_panthor_obj_array>();
        let stride = vmbind.ops.stride as usize;
        if stride < min_size {
            return Err(EINVAL);
        }

        let count = vmbind.ops.count as usize;
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
            stride.checked_mul(count).ok_or(EINVAL)?,
        )
        .reader();

        // `count` is unbounded, so the arrays come from kvmalloc.
        let mut ctx = deps::Context::new(file, vm::BindOps::new(vm.clone()));
        ctx.reserve_jobs(count)?;

        let mut op_bos = KVVec::with_capacity(count, GFP_KERNEL)?;

        for _ in 0..count {
            let op: VmBindOp = reader.read()?;
            read_padding_zero(&mut reader, stride - min_size)?;
            let validated_bo = validate_bind_op(&op, file, &vm)?;
            let (job, syncs) = op.capture(&vm, true, validated_bo.clone())?;

            ctx.add_job(job, Arc::new(syncs, GFP_KERNEL)?)?;
            op_bos.push(validated_bo, GFP_KERNEL)?;
        }

        if op_bos.is_empty() {
            return Ok(0);
        }

        ctx.collect_signal_ops()?;

        let _bind_lock = vm.lock_binds();

        for idx in 0..op_bos.len() {
            ctx.prepare(idx)?;
        }

        // One slot per object covers the whole array, because its fences share
        // the bind queue's fence context and their sequence numbers increase,
        // so the first add on a reservation takes the slot and the rest
        // replace it.
        let (mut exec, (vm_resv, obj_resvs)) = Exec::lock(
            ExecFlag::InterruptibleWait | ExecFlag::IgnoreDuplicates,
            0,
            |exec_ctx| {
                let vm_resv = vm.prepare_resv(exec_ctx)?;
                let mut obj_resvs = KVVec::with_capacity(op_bos.len(), GFP_KERNEL)?;

                for bo in op_bos.iter() {
                    let obj_resv = match bo.as_deref() {
                        Some(bo) => Some(exec_ctx.prepare_obj(bo, 1)?),
                        None => None,
                    };

                    obj_resvs.push(obj_resv, GFP_KERNEL)?;
                }

                Ok((vm_resv, obj_resvs))
            },
        )?;

        // The context, `op_bos`, and `obj_resvs` were all filled in op
        // order, so `idx` names the same op in all three.
        for (idx, obj_resv) in obj_resvs.into_iter().enumerate() {
            let fence = ctx.commit(idx)?;

            exec.resv_add_fence(vm_resv, &fence, DmaResvUsage::Bookkeep);
            if let Some(obj_resv) = obj_resv {
                exec.resv_add_fence(obj_resv, &fence, DmaResvUsage::Bookkeep);
            }
        }

        ctx.push_fences();

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
        if bocreate.pad != 0 {
            return Err(EINVAL);
        }

        let valid_flags = uapi::drm_panthor_bo_flags_DRM_PANTHOR_BO_NO_MMAP
            | uapi::drm_panthor_bo_flags_DRM_PANTHOR_BO_WB_MMAP;

        if bocreate.flags & !valid_flags != 0 {
            dev_err!(
                ddev.as_ref(),
                "bo_create: invalid flags {}\n",
                bocreate.flags
            );

            return Err(EINVAL);
        }

        let no_mmap = uapi::drm_panthor_bo_flags_DRM_PANTHOR_BO_NO_MMAP;
        let wb_mmap = uapi::drm_panthor_bo_flags_DRM_PANTHOR_BO_WB_MMAP;
        if bocreate.flags & no_mmap != 0 && bocreate.flags & wb_mmap != 0 {
            return Err(EINVAL);
        }

        let exclusive_vm = if bocreate.exclusive_vm_id != 0 {
            Some(
                file.inner()
                    .vm_pool()
                    .get_vm(bocreate.exclusive_vm_id as usize)
                    .ok_or(EINVAL)?,
            )
        } else {
            None
        };

        let bo = gem::new_bo(
            ddev,
            bocreate.size as usize,
            bocreate.flags,
            ddev.coherent,
            exclusive_vm.as_deref(),
        )?;
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
        if bommap.pad != 0 {
            return Err(EINVAL);
        }

        let bo = gem::lookup_handle(file, bommap.handle)?;

        if bo.create_flags() & uapi::drm_panthor_bo_flags_DRM_PANTHOR_BO_NO_MMAP != 0 {
            return Err(EPERM);
        }

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
        args: &mut uapi::drm_panthor_bo_set_label,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if args.pad != 0 {
            return Err(EINVAL);
        }

        let bo = gem::lookup_handle(file, args.handle)?;

        let label = if args.label != 0 {
            let mut buf = KVec::new();
            buf.resize(gem::BO_LABEL_MAXLEN + 1, 0u8, GFP_KERNEL)?;

            let reader =
                UserSlice::new(UserPtr::from_addr(args.label as usize), buf.len()).reader();
            let label = reader.strcpy_into_buf(&mut buf)?;
            if label.to_bytes_with_nul().len() > gem::BO_LABEL_MAXLEN {
                return Err(E2BIG);
            }

            Some(CString::try_from(label)?)
        } else {
            None
        };

        bo.set_label(label);

        Ok(0)
    }

    pub(crate) fn set_user_mmio_offset(
        _ddev: &TyrDrmDevice,
        args: &mut uapi::drm_panthor_set_user_mmio_offset,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if args.offset != uapi::DRM_PANTHOR_USER_MMIO_OFFSET_32BIT
            && args.offset != uapi::DRM_PANTHOR_USER_MMIO_OFFSET_64BIT
        {
            return Err(EINVAL);
        }

        file.inner().user_mmio_offset.store(args.offset, Relaxed);

        Ok(0)
    }

    pub(crate) fn bo_sync(
        ddev: &TyrDrmDevice,
        args: &mut uapi::drm_panthor_bo_sync,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if args.ops.count == 0 {
            return Ok(0);
        }

        let op_size = size_of::<uapi::drm_panthor_bo_sync_op>();
        let stride = args.ops.stride as usize;
        if stride < op_size {
            return Err(EINVAL);
        }

        let count = args.ops.count as usize;

        let mut reader = UserSlice::new(
            UserPtr::from_addr(args.ops.array as usize),
            stride.checked_mul(count).ok_or(EINVAL)?,
        )
        .reader();

        // SAFETY: `ddev` is a bound device in the ioctl path.
        let dev = unsafe { ddev.as_ref().as_bound() };

        for _ in 0..count {
            let op: BoSyncOp = reader.read()?;
            read_padding_zero(&mut reader, stride - op_size)?;
            let bo = gem::lookup_handle(file, op.0.handle)?;
            gem::sync(&bo, dev, op.0.type_, op.0.offset, op.0.size)?;
        }

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

        if bo.is_imported() {
            args.extra_flags |= uapi::drm_panthor_bo_extra_flags_DRM_PANTHOR_BO_IS_IMPORTED;
        }

        Ok(0)
    }
}

#[repr(transparent)]
struct VmBindOp(uapi::drm_panthor_vm_bind_op);

// SAFETY: this struct is safe to be transmuted from a byte slice.
unsafe impl FromBytes for VmBindOp {}

#[repr(transparent)]
struct BoSyncOp(uapi::drm_panthor_bo_sync_op);

// SAFETY: `drm_panthor_bo_sync_op` is a C-repr POD with no padding holes
// and no validity invariants on any field, so every bit pattern is valid.
unsafe impl FromBytes for BoSyncOp {}

#[repr(transparent)]
struct TimestampInfo(uapi::drm_panthor_timestamp_info);

// SAFETY: `drm_panthor_timestamp_info` is a C-repr POD with no validity
// invariants on any field, so every bit pattern is valid.
unsafe impl FromBytes for TimestampInfo {}

// SAFETY: `drm_panthor_timestamp_info` is a C-repr POD, so it is sound to
// view as a byte slice.
unsafe impl AsBytes for TimestampInfo {}

impl VmBindOp {
    fn capture(
        &self,
        vm: &vm::Vm,
        is_async: bool,
        validated_bo: Option<ARef<gem::Bo>>,
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
                let bo = validated_bo.ok_or(EINVAL)?;

                if self.0.flags & !((type_mask as u32) | map_flags) != 0 {
                    return Err(EINVAL);
                }

                job.push_map(
                    vm,
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
            _ => return Err(EINVAL),
        }

        Ok((job, syncs))
    }
}
