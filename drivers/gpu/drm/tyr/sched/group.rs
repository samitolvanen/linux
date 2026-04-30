// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::{
    AtomicUsize,
    Ordering, //
};

use kernel::{
    bindings::{
        dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
        ECANCELED, //
    },
    bits::genmask_checked_u32,
    dma_fence::{
        impl_has_dma_fence_work,
        new_dma_fence_work,
        DmaFenceWork,
        DmaFenceWorkItem,
        Fence, //
    },
    drm::{
        gem::BaseObject,
        job_queue::JobQueue, //
    },
    io::Io,
    kvec,
    list::{
        impl_list_arc_safe,
        impl_list_item,
        AtomicTracker,
        ListArc,
        ListLinks,
        TryNewListArc, //
    },
    new_mutex,
    prelude::*,
    sync::{
        Arc,
        Mutex, //
    },
    types::ARef,
    xarray::{
        self,
        XArray, //
    },
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    file::{
        QueueSubmit,
        SyncOp,
        TyrDrmFile, //
    },
    fw::{
        global::csg::{
            self,
            Priority, //
        },
        SharedSectionEntry, //
    },
    gem,
    sched::{
        deps,
        syncs::SyncObj64b, //
    },
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    }, //
};

use super::{
    job,
    queue::Queue,
    syncs, //
};

/// Upper bound on queues per group, set by the width of the per-queue
/// bitmasks (`blocked_queues`, `idle_queues`, `fatal_queues`).
pub(crate) const MAX_CS_PER_GROUP: usize = 32;

/// The group list state.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) enum GroupListState {
    /// Not in any list.
    None,
    /// In the idle list.
    Idle,
    /// In the runnable list.
    Runnable,
}

/// The part of the state protected under the group lock.
#[pin_data]
pub(crate) struct GroupInner {
    /// The group state.
    pub(crate) state: State,

    /// Which scheduler list (idle / runnable / none) this group is on.
    pub(crate) list_state: GroupListState,

    /// The group's queues.
    pub(crate) queues: KVec<Queue>,

    /// The ID of the FW group slot if the group is active.
    pub(crate) csg_id: Option<usize>,

    /// Bitmask reflecting the blocked queues.
    blocked_queues: u32,

    /// Bitmask reflecting the idle queues.
    idle_queues: u32,

    /// Bitmask reflecting the fatal queues.
    fatal_queues: u32,

    /// The error that caused this group to terminate, if any.
    pub(crate) fatal_error: Option<Error>,

    /// Whether the group is idle.
    pub(crate) idle: bool,

    /// The buffer with all the KMD synchronization objects for the group.
    ///
    /// There is one syncobj per queue.
    pub(super) syncobjs: Arc<gem::MappedBo>,
}

impl GroupInner {
    /// Returns true if the group can run.
    ///
    /// A group cannot run if it is terminated, in an unknown state, destroyed,
    /// or has encountered a fatal error.
    pub(crate) fn can_run(&self) -> bool {
        self.state != State::Terminated
            && self.state != State::Unknown
            && self.fatal_error.is_none()
    }

    /// Returns the bitmap of queues that are currently blocked.
    pub(crate) fn blocked_queues(&self) -> u32 {
        self.blocked_queues
    }

    /// Returns true if any queue in the group is currently blocked.
    pub(crate) fn has_blocked_queues(&self) -> bool {
        self.blocked_queues != 0
    }

    /// Returns true if the queue at `queue_idx` is currently blocked.
    pub(crate) fn is_queue_blocked(&self, queue_idx: usize) -> bool {
        (self.blocked_queues & (1 << queue_idx)) != 0
    }

    /// Returns true if any queue in the group has hit a fatal error.
    pub(crate) fn has_fatal_queues(&self) -> bool {
        self.fatal_queues != 0
    }

    /// Returns the bitmap of queues that have hit a fatal error.
    pub(crate) fn fatal_queues(&self) -> u32 {
        self.fatal_queues
    }

    /// Sets a queue as blocked or unblocked.
    pub(crate) fn set_queue_blocked(&mut self, queue_idx: usize, blocked: bool) {
        let mask = 1 << queue_idx;

        if blocked {
            self.blocked_queues |= mask;
        } else {
            self.blocked_queues &= !mask;
        }
    }

    /// Sets a queue as idle or active.
    ///
    /// Returns true if the queue was previously idle.
    pub(crate) fn set_queue_idle(&mut self, group_id: u64, queue_idx: usize, idle: bool) -> bool {
        let mask = 1 << queue_idx;
        let was_idle = (self.idle_queues & mask) != 0;

        if idle {
            self.idle_queues |= mask;
        } else {
            self.idle_queues &= !mask;
        }

        if idle != was_idle {
            crate::trace::queue_idle_state(group_id, queue_idx as u32, idle);
        }

        was_idle
    }

    /// Marks a queue as having encountered a fatal error.
    pub(crate) fn set_queue_fatal(&mut self, group_id: u64, queue_idx: usize) {
        if (self.fatal_queues & (1 << queue_idx)) == 0 {
            self.fatal_queues |= 1 << queue_idx;
            self.fatal_error = Some(EFAULT);
            crate::trace::queue_fatal_state(group_id, queue_idx as u32, true);
        }
    }

    /// Returns true if the group is idle.
    ///
    /// For groups currently bound to a CSG slot the cached `idle` flag
    /// (refreshed from the firmware CSG output area) is used; otherwise
    /// a group is idle when every queue is either blocked or idle.
    pub(crate) fn is_idle(&self) -> bool {
        if self.csg_id.is_some() {
            self.idle
        } else {
            let inactive_queues = self.blocked_queues | self.idle_queues;
            inactive_queues.count_ones() == self.queues.len() as u32
        }
    }

    /// Update the queue's parked/timeout state to match the group state.
    ///
    /// Park/unpark cannot run inline: it would close the lock cycle
    /// `Group::inner` -> per-queue pipeline state -> `Group::inner`.
    /// Returns the deferred action to apply after the inner lock is dropped.
    pub(crate) fn sync_queue_state(
        &mut self,
        group_id: u64,
        queue_idx: usize,
    ) -> Option<QueueParkAction> {
        let is_blocked = (self.blocked_queues & (1 << queue_idx)) != 0;

        let should_park = matches!(self.state, State::Terminated | State::Unknown);

        let should_suspend = if self.csg_id.is_some() {
            should_park
        } else {
            match self.state {
                State::Suspended => !is_blocked,
                _ => true,
            }
        };

        let queue = &mut self.queues[queue_idx];
        let currently_suspended = queue.timeout_suspended.load(Ordering::Relaxed);

        if should_suspend != currently_suspended {
            if should_suspend {
                queue.suspend_timeout();
            } else {
                queue.resume_timeout();
            }
            crate::trace::queue_timeout_state(group_id, queue_idx as u32, should_suspend);
        }

        if should_park != queue.parked {
            queue.parked = should_park;
            crate::trace::queue_state(group_id, queue_idx as u32, should_park);
            Some(QueueParkAction {
                job_queue: queue.job_queue.clone(),
                park: should_park,
            })
        } else {
            None
        }
    }
}

/// Deferred park/unpark, applied after `Group::inner` is released.
#[must_use = "QueueParkAction must be applied after the Group::inner lock is dropped"]
pub(crate) struct QueueParkAction {
    job_queue: JobQueue<job::TyrJobHandler>,
    park: bool,
}

impl QueueParkAction {
    pub(crate) fn apply(self) {
        if self.park {
            self.job_queue.park();
        } else {
            self.job_queue.unpark();
        }
    }
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
    pub(super) vm: Arc<Vm>,

    /// The Tyr DRM device.
    pub(crate) tdev: ARef<crate::driver::TyrDrmDevice>,

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

    /// The group's priority.
    pub(super) priority: Priority,

    /// Suspend buffer.
    ///
    /// Stores the state of the group and its queues when a group is suspended.
    ///
    /// Used at resume time to restore the group to its previous state.
    ///
    /// The size of the suspend buffer is exposed through the FW interface.
    pub(super) suspend_buf: Arc<gem::MappedBo>,

    /// Protected-mode suspend buffer.
    ///
    /// Stores the state of the group and its queues when a group is suspended.
    ///
    /// Used at resume time to restore the group to its previous state.
    ///
    /// The size of the suspend buffer is exposed through the FW interface.
    pub(super) protm_suspend_buf: Arc<gem::MappedBo>,

    // Scheduling state. Kept at the top level (not in a substruct)
    // because `impl_list_item!` and `impl_has_dma_fence_work!`
    // reference them by bare field path.
    /// Tracks this group's binding to a hardware CSG slot.
    pub(crate) csg_seat: kernel::sync::LockedBy<crate::slot::Seat, super::CsgSlotManager>,

    /// Work for updating synchronization objects.
    #[pin]
    pub(crate) sync_upd_work: DmaFenceWork<Group, 0>,

    /// Work for terminating the group.
    #[pin]
    pub(crate) term_work: DmaFenceWork<Group, 1>,

    /// Work for deferred drop.
    #[pin]
    pub(crate) deferred_drop: kernel::workqueue::Work<Group, 2>,

    /// Links into the runnable/idle scheduler lists.
    #[pin]
    pub(crate) links: ListLinks,

    /// `ListArc` ownership tracker for [`Self::links`].
    #[pin]
    pub(crate) tracker: AtomicTracker<0>,

    /// Links into the syncobj-wait list.
    #[pin]
    pub(crate) wait_links: ListLinks<1>,

    /// `ListArc` ownership tracker for [`Self::wait_links`].
    #[pin]
    pub(crate) wait_tracker: AtomicTracker<1>,
}

impl_list_arc_safe! {
    impl ListArcSafe<0> for Group {
        tracked_by tracker: AtomicTracker<0>;
    }
}

impl_list_item! {
    impl ListItem<0> for Group {
        using ListLinks { self.links };
    }
}

impl_list_arc_safe! {
    impl ListArcSafe<1> for Group {
        tracked_by wait_tracker: AtomicTracker<1>;
    }
}

impl_list_item! {
    impl ListItem<1> for Group {
        using ListLinks { self.wait_links };
    }
}

impl Group {
    /// Creates a new group.
    pub(super) fn create(
        tdev: &TyrDrmDevice,
        file: &TyrDrmFile,
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

        if group_args.compute_core_mask.count_ones() < u32::from(group_args.max_compute_cores)
            || group_args.fragment_core_mask.count_ones() < u32::from(group_args.max_fragment_cores)
            || group_args.tiler_core_mask.count_ones() < u32::from(group_args.max_tiler_cores)
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
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let syncobjs = gem::new_kernel_object(tdev, &vm, num_syncs, flags)?;

        let vmap = syncobjs.vmap();
        let size = vmap.owner().size();
        // SAFETY: VMap guarantees the mapped region is valid for `size` bytes.
        unsafe { core::slice::from_raw_parts_mut(vmap.addr() as *mut u8, size).fill(0) };

        let mut queues = kvec![];
        for i in 0..group_args.queues.count {
            let queue = Queue::new(tdev, &queue_args[i as usize], vm.clone())?;
            queues.push(queue, GFP_KERNEL)?;
        }

        let idle_queues = genmask_checked_u32(0..=queues.len() as u32 - 1).ok_or(EINVAL)?;
        let priority = group_args.priority.try_into()?;

        Arc::pin_init(
            pin_init!(Group {
                inner <- new_mutex!(GroupInner {
                    state: State::Created,
                    list_state: GroupListState::Idle,
                    queues,
                    csg_id: None,
                    blocked_queues: 0,
                    idle_queues,
                    fatal_queues: 0,
                    fatal_error: None,
                    idle: false,
                    syncobjs,
                }),
                vm,
                tdev: ARef::from(tdev),
                csg_seat: kernel::sync::LockedBy::new(&tdev.csg_slot_manager, crate::slot::Seat::NoSeat),
                sync_upd_work <- new_dma_fence_work!("tyr-group-sync"),
                term_work <- new_dma_fence_work!("tyr-group-term"),
                deferred_drop <- kernel::workqueue::new_work!("tyr-group-defer-drop"),
                compute_core_mask: group_args.compute_core_mask,
                fragment_core_mask: group_args.fragment_core_mask,
                tiler_core_mask: group_args.tiler_core_mask,
                max_compute_cores: group_args.max_compute_cores,
                max_fragment_cores: group_args.max_fragment_cores,
                max_tiler_cores: group_args.max_tiler_cores,
                suspend_buf,
                protm_suspend_buf,
                priority,
                links <- ListLinks::new(),
                tracker <- AtomicTracker::new(),
                wait_links <- ListLinks::new(),
                wait_tracker <- AtomicTracker::new(),
            }),
            GFP_KERNEL,
        )
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

    /// Sets the state of the group.
    pub(crate) fn set_state(&self, new_state: State) {
        let group_id = self as *const _ as usize as u64;
        let _ = self.with_locked_inner(|inner| {
            inner.state = new_state;
            crate::trace::group_update(group_id, new_state as u32);
            Ok(())
        });
    }

    /// Submits jobs to the group.
    pub(crate) fn submit(
        self: Arc<Self>,
        all_syncs: KVec<KVec<SyncOp>>,
        queue_submits: KVec<QueueSubmit>,
        file: &TyrDrmFile,
    ) -> Result<KVec<Fence>> {
        if !self.can_run() {
            pr_err!("group_submit: invalid group: group cannot run");
            return Err(EINVAL);
        }

        let mut ctx = deps::Context::new(file);
        let mut fences = KVec::with_capacity(queue_submits.len(), GFP_KERNEL)?;

        // Prepare the VM with enough slots for all submissions
        self.vm
            .with_prepared_vm(queue_submits.len() as u32, |mut locked_vm| {
                // Create all jobs and add them to the context
                for (queue_submit, syncs) in core::iter::zip(queue_submits.iter(), all_syncs.iter())
                {
                    let sync_addr = self.with_locked_inner(|inner| {
                        inner
                            .queues
                            .get(queue_submit.queue_index as usize)
                            .ok_or(EINVAL)?;

                        let sync_addr = inner.syncobjs.kernel_va().ok_or(EINVAL)?;
                        Ok(sync_addr.start
                            + u64::from(queue_submit.queue_index)
                                * core::mem::size_of::<syncs::SyncObj64b>() as u64)
                    })?;

                    let job = job::Job::create(*queue_submit, self.clone(), sync_addr)?;
                    let internal_syncs = deps::SyncOp::from_uapi_slice(syncs)?;

                    ctx.add_job(job, internal_syncs)?;
                }

                ctx.collect_signal_ops()?;

                // Prepare all jobs and resolve dependencies (Pass 1)
                for (job_idx, queue_submit) in queue_submits.iter().enumerate() {
                    let queue_idx = queue_submit.queue_index as usize;

                    let job_queue = self.with_locked_inner(|inner| {
                        let queue = inner.queues.get_mut(queue_idx).ok_or(EINVAL)?;
                        Ok(queue.job_queue.clone())
                    })?;

                    ctx.prepare(job_idx, &job_queue)?;
                }

                // Process jobs in the order they were submitted (Pass 2)
                for (job_idx, queue_submit) in queue_submits.iter().enumerate() {
                    let queue_idx = queue_submit.queue_index as usize;

                    let job_queue = self.with_locked_inner(|inner| {
                        let queue = inner.queues.get_mut(queue_idx).ok_or(EINVAL)?;
                        Ok(queue.job_queue.clone())
                    })?;

                    let fence = ctx.commit(job_idx, &job_queue)?;

                    // Add the finished fence to the reservation objects and
                    // collect them to return to the caller (for syncobj signalling).
                    locked_vm.resv_add_fence(
                        &fence,
                        dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                        dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                    );
                    fences.push(fence, GFP_KERNEL)?;
                }

                Ok(())
            })?;

        // Push all signal fences to their syncobjs
        ctx.push_fences();

        Ok(fences)
    }

    /// Checks if the group is idle.
    pub(crate) fn is_idle(&self) -> bool {
        self.inner.lock().is_idle()
    }

    /// Gets the current status of the group.
    pub(crate) fn status(&self) -> GroupStatus {
        GroupStatus {
            can_run: self.can_run(),
            is_idle: self.is_idle(),
            csg_id: self.inner.lock().csg_id,
        }
    }

    /// Checks if the group can run.
    pub(crate) fn can_run(&self) -> bool {
        self.inner.lock().can_run()
    }

    /// Returns the group's current scheduler [`State`].
    pub(crate) fn state(&self) -> State {
        self.inner.lock().state
    }

    /// Evaluates if a queue's sync wait condition is met.
    pub(crate) fn eval_syncwait(&self, queue_idx: usize) -> Result<bool> {
        let (syncwait, syncobjs_va, syncobjs) = self.with_locked_inner(|inner| {
            let syncobjs_va = inner.syncobjs.kernel_va().ok_or(EINVAL)?;
            let queue = inner.queues.get_mut(queue_idx).ok_or(EINVAL)?;
            Ok((queue.syncwait.clone(), syncobjs_va, inner.syncobjs.clone()))
        })?;

        if syncwait.gpu_va == 0 {
            return Ok(false);
        }

        let value = if syncwait.gpu_va >= syncobjs_va.start && syncwait.gpu_va < syncobjs_va.end {
            let offset = (syncwait.gpu_va - syncobjs_va.start) as usize;
            if syncwait.sync64 {
                let sync_obj = syncs::SyncObj64b::read(&syncobjs, offset)?;
                sync_obj.seqno
            } else {
                let sync_obj = syncs::SyncObj32b::read(&syncobjs, offset)?;
                u64::from(sync_obj.seqno)
            }
        } else if let Some(cached_bo) = &syncwait.bo {
            let bo_offset = syncwait.bo_offset;
            if syncwait.sync64 {
                let sync_obj = syncs::SyncObj64b::read(cached_bo, bo_offset)?;
                sync_obj.seqno
            } else {
                let sync_obj = syncs::SyncObj32b::read(cached_bo, bo_offset)?;
                u64::from(sync_obj.seqno)
            }
        } else {
            let (bo, bo_offset) = self.vm.get_bo_for_va(syncwait.gpu_va).ok_or(EINVAL)?;

            let mapped_bo = gem::MappedBo::new(&bo)?;

            // Re-acquire the group lock and cache the MappedBo and offset if gpu_va hasn't changed.
            self.with_locked_inner(|inner| {
                let queue = inner.queues.get_mut(queue_idx).ok_or(EINVAL)?;
                if queue.syncwait.gpu_va == syncwait.gpu_va {
                    queue.syncwait.bo = Some(Arc::clone(&mapped_bo));
                    queue.syncwait.bo_offset = bo_offset as usize;
                }
                Ok(())
            })?;

            if syncwait.sync64 {
                let sync_obj = syncs::SyncObj64b::read(&mapped_bo, bo_offset as usize)?;
                sync_obj.seqno
            } else {
                let sync_obj = syncs::SyncObj32b::read(&mapped_bo, bo_offset as usize)?;
                u64::from(sync_obj.seqno)
            }
        };

        let result = if syncwait.gt {
            value > syncwait.ref_val
        } else {
            value <= syncwait.ref_val
        };

        Ok(result)
    }

    /// Cancels all pending queues in the group.
    pub(crate) fn cancel_queues(self: &Arc<Self>, err: Error) {
        let num_queues = self
            .with_locked_inner(|inner| Ok(inner.queues.len()))
            .unwrap_or(0);
        for i in 0..num_queues {
            if let Ok(job_queue) =
                self.with_locked_inner(|inner| Ok(inner.queues[i].job_queue.clone()))
            {
                job_queue.cancel_all();
                let fences_to_signal = self
                    .with_locked_inner(|inner| {
                        let queue = &mut inner.queues[i];
                        let seqno = queue.next_seqno.load(Ordering::Relaxed);
                        let sync_offset = i * core::mem::size_of::<syncs::SyncObj64b>();

                        let sync_obj = syncs::SyncObj64b {
                            seqno,
                            status: !0,
                            pad: 0,
                        };
                        let _ = syncs::SyncObj64b::write(&inner.syncobjs, sync_offset, sync_obj);

                        Ok(queue.take_all_fences())
                    })
                    .unwrap_or_else(|_| KVec::new());

                for pending in fences_to_signal {
                    if let Some(fence) = pending.fence {
                        fence.set_error(err.to_errno());
                        let _ = fence.signal();
                    }
                }
            }
        }
        self.schedule_sync_upd();
    }

    /// Schedules a sync update for the group.
    pub(crate) fn schedule_sync_upd(self: &Arc<Self>) {
        let _ = self.tdev.sched_wq.enqueue::<_, 0>(self.clone());
    }

    /// Schedules the group for termination.
    pub(crate) fn schedule_term(self: &Arc<Self>) {
        let _ = self.tdev.sched_wq.enqueue::<_, 1>(self.clone());
    }
}

/// The status of a group.
pub(crate) struct GroupStatus {
    /// Whether the group can be run.
    pub(crate) can_run: bool,
    /// Whether the group is idle.
    pub(crate) is_idle: bool,
    /// The CSG ID of the group if it is scheduled.
    pub(crate) csg_id: Option<usize>,
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
/// Each context (i.e. TyrDrmFile) has its own group pool.
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
        tdev: &TyrDrmDevice,
        groupcreate: &mut kernel::uapi::drm_panthor_group_create,
        file: &TyrDrmFile,
        queue_args: KVec<crate::file::QueueCreate>,
    ) -> Result<usize> {
        let group = Group::create(tdev, file, groupcreate, queue_args)?;

        tdev.with_locked_scheduler(|sched| {
            let list_arc = ListArc::try_from_arc(group.clone()).map_err(|_| ENOMEM)?;
            sched.requeue_group(list_arc);
            Ok(())
        })?;

        let index = self.free_index.fetch_add(1, Ordering::Relaxed);

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

    /// Destroys a group in the pool.
    ///
    /// The group is marked as destroyed. If it is currently active on a CSG slot,
    /// a tick is scheduled to handle the destruction. Otherwise, it is terminated
    /// immediately.
    pub(crate) fn destroy_group(self: Pin<&Self>, tdev: &TyrDrmDevice, index: usize) -> Result {
        let xa = self.xa.as_ref();

        let group = xa.lock().remove(index).ok_or(EINVAL)?;

        let csg_id = group.with_locked_inner(|inner| {
            inner.fatal_error = Some(Error::from_errno(-(ECANCELED as i32)));
            Ok(inner.csg_id)
        })?;

        if csg_id.is_some() {
            TyrDrmDeviceData::schedule_tick(&ARef::from(tdev));
        } else {
            group.schedule_term();
        }

        Ok(())
    }

    /// Destroy all groups in the pool.
    ///
    /// This is called when the file is being closed to ensure all groups
    /// are properly cleaned up (unbound if necessary) before being dropped.
    pub(crate) fn destroy_all(self: Pin<&Self>, tdev: &TyrDrmDevice) -> Result {
        let max_index = self.free_index.load(Ordering::Relaxed);

        // Try to destroy all possible groups from 0 to free_index as there's no
        // iterator implementation in xarray.rs.
        for index in 0..max_index {
            let _ = self.destroy_group(tdev, index);
        }

        Ok(())
    }
}

impl_has_dma_fence_work! {
    impl HasDmaFenceWork<Self, 0> for Group {
        self.sync_upd_work
    }
}

impl DmaFenceWorkItem<0> for Group {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        let num_queues = this
            .with_locked_inner(|inner| Ok(inner.queues.len()))
            .unwrap_or(0);

        for queue_idx in 0..num_queues {
            loop {
                let fence_to_signal = this
                    .with_locked_inner(|inner| {
                        let sync_offset = queue_idx * core::mem::size_of::<syncs::SyncObj64b>();
                        let sync_obj = syncs::SyncObj64b::read(&inner.syncobjs, sync_offset)?;
                        let queue = &mut inner.queues[queue_idx];

                        Ok(queue.pop_pending_fence_up_to(sync_obj.seqno))
                    })
                    .unwrap_or(None);

                match fence_to_signal {
                    Some(fence) => {
                        let _ = fence.signal();
                    }
                    None => break,
                }
            }
        }

        let _ = this.tdev.reset_wq.enqueue::<Arc<Self>, 2>(this.clone());
    }
}

impl_has_dma_fence_work! {
    impl HasDmaFenceWork<Self, 1> for Group {
        self.term_work
    }
}

impl DmaFenceWorkItem<1> for Group {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        let err = this
            .with_locked_inner(|inner| Ok(inner.fatal_error))
            .unwrap_or(Some(Error::from_errno(-(ECANCELED as i32))));

        if let Some(e) = err {
            this.cancel_queues(e);
        }
    }
}

kernel::workqueue::impl_has_work! {
    impl HasWork<Self, 2> for Group { self.deferred_drop }
}

impl kernel::workqueue::WorkItem<2> for Group {
    type Pointer = Arc<Self>;

    fn run(_this: Arc<Self>) {
        // Do nothing, letting the Arc drop.
    }
}
