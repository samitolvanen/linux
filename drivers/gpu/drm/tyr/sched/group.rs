// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::AtomicUsize;

use kernel::bits::genmask_checked_u32;
use kernel::dma_fence::PublicDmaFence;
use kernel::drm::gem::BaseObject;
use kernel::kvec;
use kernel::new_mutex;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::types::ARef;
use kernel::xarray;
use kernel::xarray::XArray;

use crate::driver::TyrDevice;
use crate::file::DrmFile;
use crate::file::QueueSubmit;
use crate::file::SyncOp;
use crate::fw::global::csg;
use crate::fw::global::csg::Priority;
use crate::fw::SharedSectionEntry;
use crate::gem;
use crate::mmu::vm::map_flags;
use crate::mmu::vm::Vm;
use crate::sched::deps;
use crate::sched::syncs::SyncObj64b;

use super::job;
use super::queue::Queue;
use super::syncs;
use super::Scheduler;

/// The part of the state protected under the group lock.
#[pin_data]
pub(crate) struct GroupInner {
    /// The group state.
    pub(crate) state: State,

    /// The group's queues.
    pub(crate) queues: KVec<Queue>,

    /// The ID of the FW group slot if the group is active.
    pub(crate) csg_id: Option<usize>,

    /// Bitmask reflecting the blocked queues.
    pub(crate) blocked_queues: u32,

    /// Bitmask reflecting the idle queues.
    pub(crate) idle_queues: u32,

    /// Bitmask reflecting the fatal queues.
    pub(crate) fatal_queues: u32,

    /// True when the group has been destroyed.
    ///
    /// If a group is destroyed it becomes useless: no further jobs can be
    /// submitted to its queues. We simply wait for all references to be
    /// dropped.
    pub(crate) destroyed: bool,

    /// The buffer with all the KMD synchronization objects for the group.
    ///
    /// There is one syncobj per queue.
    pub(super) syncobjs: gem::ObjectRef,
}

/// A scheduling group object, usually backing an execution context, e.g.: a
/// VkQueue or similar.
///
/// Commands are submitted to groups via the `GROUP_SUBMIT` ioctl.
///
/// Groups are eventually scheduled into hardware CSG slots, and the group's
/// queues are then scheduled into hardware CS slots for execution.
#[pin_data]
pub(crate) struct Group {
    #[pin]
    inner: Mutex<GroupInner>,

    /// VM bound to the group.
    pub(super) vm: Arc<Mutex<Vm>>,

    /// Mask of shader cores that can be used for compute jobs.
    pub(super) compute_core_mask: u64,

    /// Mask of shader cores that can be used for fragment jobs.
    pub(super) fragment_core_mask: u64,

    /// Mask of tiler cores that can be used for tiler jobs.
    pub(super) tiler_core_mask: u64,

    /// Maximum number of shader cores used for compute jobs.
    pub(super) max_compute_cores: u8,

    /// Maximum number of shader cores used for fragment jobs.
    pub(super) max_fragment_cores: u8,

    /// Maximum number of tiler cores used for tiler jobs.
    pub(super) max_tiler_cores: u8,

    /// Suspend buffer.
    ///
    /// Stores the state of the group and its queues when a group is suspended.
    ///
    /// Used at resume time to restore the group to its previous state.
    ///
    /// The size of the suspend buffer is exposed through the FW interface.
    pub(super) suspend_buf: gem::ObjectRef,

    /// Protected-mode suspend buffer.
    ///
    /// Stores the state of the group and its queues when a group is suspended.
    ///
    /// Used at resume time to restore the group to its previous state.
    ///
    /// The size of the suspend buffer is exposed through the FW interface.
    pub(super) protm_suspend_buf: gem::ObjectRef,

    /// The group's priority.
    pub(super) priority: Priority,
}

impl Group {
    pub(super) fn create(
        tdev: &TyrDevice,
        file: &DrmFile,
        group_args: &kernel::uapi::drm_panthor_group_create,
        queue_args: KVec<crate::file::QueueCreate>,
    ) -> Result<Arc<Self>> {
        let gpu_info = &tdev.gpu_info;
        let fw = &tdev.fw;

        if group_args.pad != 0 {
            pr_err!("group_create: invalid padding {}", group_args.pad);
            return Err(EINVAL);
        }

        if group_args.priority > csg::Priority::num_priorities() as u8 {
            pr_err!("group_create: invalid priority {}", group_args.priority);
            return Err(EINVAL);
        }

        if (group_args.compute_core_mask & !gpu_info.shader_present) != 0
            || (group_args.fragment_core_mask & !gpu_info.shader_present) != 0
            || (group_args.tiler_core_mask & !gpu_info.tiler_present) != 0
        {
            pr_err!("group_create: invalid core mask");
            return Err(EINVAL);
        }

        if group_args.compute_core_mask.count_ones() < group_args.max_compute_cores as u32
            || group_args.fragment_core_mask.count_ones() < group_args.max_fragment_cores as u32
            || group_args.tiler_core_mask.count_ones() < group_args.max_tiler_cores as u32
        {
            pr_err!("group_create: core mask must have at least max_cores bits set");
            return Err(EINVAL);
        }

        let vm = file
            .inner()
            .vm_pool()
            .get_vm(group_args.vm_id as usize)
            .ok_or(EINVAL)?;

        let (suspend_buf_size, protm_suspend_buf_size) =
            fw.with_locked_global_iface(|glb_iface| {
                let csg = glb_iface.csg(0).ok_or(EINVAL)?;
                let control = csg.read_control()?;

                Ok((control.suspend_size, control.protm_suspend_size))
            })?;

        let suspend_buf = fw.alloc_suspend_buf(tdev, suspend_buf_size as usize)?;
        let protm_suspend_buf = fw.alloc_suspend_buf(tdev, protm_suspend_buf_size as usize)?;

        let num_syncs = group_args.queues.count as usize * core::mem::size_of::<SyncObj64b>();
        let mut syncobjs = {
            let mut vm_guard = vm.lock();
            gem::new_kernel_object(
                tdev,
                tdev.iomem.clone(),
                &mut vm_guard,
                gem::KernelVaPlacement::Auto { size: num_syncs },
                map_flags::Flags::from(map_flags::NOEXEC)
                    | map_flags::Flags::from(map_flags::UNCACHED),
            )?
        };

        let vmap = syncobjs.vmap()?;
        let size = vmap.owner().size();
        unsafe { vmap.get().as_mut_slice(0, size)?.fill(0) };

        let mut queues = kvec![];
        for i in 0..group_args.queues.count {
            let queue = Queue::new(tdev, &queue_args[i as usize], vm.clone(), tdev.wq.clone())?;
            queues.push(queue, GFP_KERNEL)?;
        }

        let idle_queues = genmask_checked_u32(0..=queues.len() as u32 - 1).ok_or(EINVAL)?;
        let priority = group_args.priority.try_into()?;

        Arc::pin_init(
            pin_init!(Group {
                inner <- new_mutex!(GroupInner {
                    state: State::Created,
                    queues,
                    csg_id: None,
                    blocked_queues: 0,
                    idle_queues,
                    fatal_queues:0,
                    destroyed: false,
                    syncobjs,
                }),
                vm,
                compute_core_mask: group_args.compute_core_mask,
                fragment_core_mask: group_args.fragment_core_mask,
                tiler_core_mask: group_args.tiler_core_mask,
                max_compute_cores: group_args.max_compute_cores,
                max_fragment_cores: group_args.max_fragment_cores,
                max_tiler_cores: group_args.max_tiler_cores,
                suspend_buf,
                protm_suspend_buf,
                priority,
            }),
            GFP_KERNEL,
        )
    }

    #[expect(dead_code)]
    pub(super) fn idle(&self, sched: &Scheduler) -> bool {
        let inner = self.inner.lock();
        if let Some(csg_id) = inner.csg_id {
            match &sched.csg_slots[csg_id] {
                Some(csg) => csg.idle,
                None => true,
            }
        } else {
            let inactive_queues = inner.blocked_queues | inner.idle_queues;
            inactive_queues.count_ones() == inner.queues.len() as u32
        }
    }

    /// Provide access to the part of the group we may want to mutate.
    ///
    /// This uses a closure in order to reduce the scope of the lock.
    pub(crate) fn with_locked_inner<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut GroupInner) -> Result<R>,
    {
        let mut inner = self.inner.lock();
        f(&mut inner)
    }

    pub(super) fn submit(
        self: Arc<Self>,
        syncs: KVec<SyncOp>,
        queue_submits: KVec<QueueSubmit>,
        file: &DrmFile,
    ) -> Result<KVec<ARef<PublicDmaFence>>> {
        let as_nr = self.vm.lock().address_space();
        if as_nr.is_none() {
            let csg_id = self.with_locked_inner(|inner| Ok(inner.csg_id));
            pr_err!(
                "group_submit: invalid address space (AS={:?}, csg_id={:?})\n",
                as_nr,
                csg_id
            );
            return Err(EINVAL);
        }

        let destroyed = self.with_locked_inner(|inner| Ok(inner.destroyed))?;

        if destroyed {
            pr_err!("group_submit: invalid group: group is destroyed");
            return Err(EINVAL);
        }

        // Convert UAPI sync operations to internal representation
        let internal_syncs = deps::SyncOp::from_uapi_slice(&syncs)?;

        let mut ctx = deps::Context::new(file);

        let mut fences = KVec::with_capacity(queue_submits.len(), GFP_KERNEL)?;

        let vm = self.vm.lock();

        // Prepare the VM with enough slots for all submissions
        vm.with_prepared_vm(queue_submits.len() as u32, |mut locked_vm| {
            // Create all jobs and add them to the context
            self.with_locked_inner(|inner| {
                for queue_submit in queue_submits.iter() {
                    // Validate the queue index up-front; submit_to_hw() will
                    // also check this but bailing early gives a cleaner error.
                    if inner
                        .queues
                        .get(queue_submit.queue_index as usize)
                        .is_none()
                    {
                        return Err(EINVAL);
                    }

                    let sync_addr = inner.syncobjs.kernel_va().ok_or(EINVAL)?;
                    let sync_addr = sync_addr.start
                        + u64::from(queue_submit.queue_index)
                            * core::mem::size_of::<syncs::SyncObj64b>() as u64;

                    let job = job::Job::create(*queue_submit, self.clone(), sync_addr)?;

                    ctx.add_job(job, internal_syncs.clone())?;
                }
                Ok(())
            })?;

            ctx.collect_signal_ops(&internal_syncs)?;

            // Collect unique queue indices from all queue submits
            let mut queue_indices = kvec![];
            for queue_submit in queue_submits.iter() {
                let idx = queue_submit.queue_index as usize;
                if !queue_indices.iter().any(|&qi| qi == idx) {
                    queue_indices.push(idx, GFP_KERNEL)?;
                }
            }

            // Process jobs for each queue
            for &queue_idx in queue_indices.iter() {
                let finished_fences = self.with_locked_inner(|inner| {
                    let queue = inner.queues.get_mut(queue_idx).ok_or(EINVAL)?;
                    ctx.add_deps_and_push_jobs(&queue.job_queue, queue_idx)
                })?;

                // Add the finished fences to the reservation objects and
                // collect them to return to the caller (for syncobj signalling).
                for fence in &finished_fences {
                    locked_vm.resv_add_fence(
                        &**fence,
                        kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                        kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                    );
                    fences.push(fence.clone(), GFP_KERNEL)?;
                }
            }

            Ok(())
        })?;

        // Push all signal fences to their syncobjs
        ctx.push_fences();

        Ok(fences)
    }
}

/// Represents the scheduling group state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum State {
    /// Group was created, but not scheduled yet.
    Created,

    /// Group is currently scheduled.
    Active,

    /// Group was scheduled at least once, but is inactive/suspended right now.
    Suspended,

    /// Group was terminated.
    ///
    /// Can no longer be scheduled. The only allowed action is destruction.
    Terminated,

    /// Group is in an unknown state.
    ///
    /// The firmware returned an inconsistent state. The group is flagged as
    /// unusable and can no longer be scheduled. The only allowed action is
    /// destruction.
    ///
    /// When this happens, a firmware reset is also scheduled to start from a
    /// fresh state.
    Unknown,
}

/// The group pool.
///
/// Each context (i.e. DrmFile) has its own group pool.
// TODO: this is essentially the same as vm/pool.rs. It can be trivially
// refactored into a single type later.
pub(crate) struct Pool {
    xa: Pin<KBox<XArray<Arc<Group>>>>,
    free_index: AtomicUsize,
}

impl Pool {
    pub(crate) fn create() -> Result<Self> {
        let xa = KBox::pin_init(XArray::new(xarray::AllocKind::Alloc1), GFP_KERNEL)?;

        Ok(Self {
            xa,
            free_index: AtomicUsize::new(1),
        })
    }

    pub(crate) fn create_group(
        self: Pin<&Self>,
        tdev: &TyrDevice,
        groupcreate: &mut kernel::uapi::drm_panthor_group_create,
        file: &DrmFile,
        queue_args: KVec<crate::file::QueueCreate>,
    ) -> Result<usize> {
        let group = Group::create(tdev, file, groupcreate, queue_args)?;

        tdev.with_locked_scheduler(|sched| {
            sched.idle_groups[group.priority as usize]
                .push(group.clone(), GFP_KERNEL)
                .map_err(|_| ENOMEM)
        })?;

        let index = self
            .free_index
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        let xa = self.xa.as_ref();
        let mut guard = xa.lock();
        guard.store(index, group, GFP_KERNEL).map_err(|_| EINVAL)?;

        Ok(index)
    }

    pub(crate) fn group(self: Pin<&Self>, index: usize) -> Option<Arc<Group>> {
        let xa = self.xa.as_ref();
        let guard = xa.lock();
        let group = guard.get(index)?;
        Some(group.into())
    }

    pub(crate) fn destroy_group(self: Pin<&Self>, tdev: &TyrDevice, index: usize) -> Result {
        let xa = self.xa.as_ref();

        let group = xa.lock().remove(index).ok_or(EINVAL)?;

        tdev.with_locked_scheduler(|sched| {
            let csg_id = group.with_locked_inner(|inner| Ok(inner.csg_id))?;

            if let Some(csg_id) = csg_id {
                pr_info!("Unbinding group from CSG slot {}\n", csg_id);
                sched.set_csg_state(tdev, csg_id, csg::GroupState::Terminate)?;
                sched.unbind_group(tdev, csg_id)?;
            }
            Ok(())
        })?;

        group.with_locked_inner(|inner| {
            inner.destroyed = true;
            Ok(())
        })
    }

    /// Destroy all groups in the pool.
    ///
    /// This is called when the file is being closed to ensure all groups
    /// are properly cleaned up (unbound if necessary) before being dropped.
    pub(crate) fn destroy_all(self: Pin<&Self>, tdev: &TyrDevice) -> Result {
        let max_index = self.free_index.load(core::sync::atomic::Ordering::Relaxed);

        // Try to destroy all possible groups from 0 to free_index as there's no
        // iterator implementation in xarray.rs.
        for index in 0..max_index {
            let _ = self.destroy_group(tdev, index);
        }

        Ok(())
    }
}
