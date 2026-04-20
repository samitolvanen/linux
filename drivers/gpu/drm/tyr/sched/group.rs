// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::{AtomicUsize, Ordering};

use kernel::bits::genmask_checked_u32;
use kernel::dma_fence::DmaFenceSignallingAnnotation;
use kernel::dma_fence::DmaFenceWork;
use kernel::dma_fence::DmaFenceWorkItem;
use kernel::dma_fence::PublicDmaFence;
use kernel::drm::gem::BaseObject;
use kernel::impl_has_dma_fence_work;
use kernel::kvec;
use kernel::list::{
    impl_list_arc_safe, impl_list_item, AtomicTracker, ListArc, ListLinks, TryNewListArc,
};
use kernel::new_dma_fence_work;
use kernel::new_mutex;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::types::ARef;
use kernel::xarray;
use kernel::xarray::XArray;

use crate::driver::TyrDevice;
use crate::file::DrmFile;
use crate::file::QueueCreate;
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

/// The part of the state protected under the group lock.
#[pin_data]
pub(crate) struct GroupInner {
    /// The group state.
    pub(crate) state: State,

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

    /// Whether the group is idle.
    pub(crate) idle: bool,

    /// The error that caused this group to terminate, if any.
    pub(crate) fatal_error: Option<kernel::error::Error>,

    /// The buffer with all the KMD synchronization objects for the group.
    ///
    /// There is one syncobj per queue.
    pub(super) syncobjs: gem::ObjectRef,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) enum GroupListState {
    None,
    Idle,
    Runnable,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct GroupStatus {
    pub(crate) can_run: bool,
    pub(crate) is_idle: bool,
    pub(crate) csg_id: Option<usize>,
}

// SAFETY: Group instances can be safely sent and shared across threads. The
// inner state is protected by a Mutex, and all fields are thread-safe or
// safely shared through Arc.
unsafe impl Send for Group {}
unsafe impl Sync for Group {}

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

    pub(crate) tdev: Arc<crate::driver::TyrData>,

    #[pin]
    pub(crate) links: ListLinks,

    #[pin]
    pub(crate) tracker: AtomicTracker<0>,

    #[pin]
    pub(crate) wait_links: ListLinks<1>,

    #[pin]
    pub(crate) wait_tracker: AtomicTracker<1>,

    /// Work to update group sync status.
    #[pin]
    pub(crate) sync_upd_work: DmaFenceWork<Self, 0>,

    /// Work to finish the group termination procedure asynchronously.
    #[pin]
    pub(crate) term_work: DmaFenceWork<Self, 1>,
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
    pub(crate) fn schedule_sync_upd(self: &Arc<Self>) {
        let _ = self.tdev.wq.enqueue::<_, 0>(self.clone());
    }

    pub(crate) fn schedule_term(self: &Arc<Self>) {
        let _ = self.tdev.wq.enqueue::<_, 1>(self.clone());
    }

    pub(super) fn create(
        tdev: &TyrDevice,
        file: &DrmFile,
        group_args: &kernel::uapi::drm_panthor_group_create,
        queue_args: KVec<QueueCreate>,
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
                    idle: false,
                    fatal_error: None,
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
                tdev: (*tdev).clone(),
                links <- ListLinks::new(),
                tracker <- AtomicTracker::new(),
                wait_links <- ListLinks::new(),
                wait_tracker <- AtomicTracker::new(),
                sync_upd_work <- new_dma_fence_work!("tyr-group-sync"),
                term_work <- new_dma_fence_work!("tyr-group-term"),
            }),
            GFP_KERNEL,
        )
    }
}

impl GroupInner {
    /// Returns the bitmask of currently blocked queues.
    pub(crate) fn blocked_queues(&self) -> u32 {
        self.blocked_queues
    }

    /// Returns true if there are any blocked queues in the group.
    pub(crate) fn has_blocked_queues(&self) -> bool {
        self.blocked_queues != 0
    }

    /// Returns true if the specific queue is blocked.
    pub(crate) fn is_queue_blocked(&self, queue_idx: usize) -> bool {
        (self.blocked_queues & (1 << queue_idx)) != 0
    }

    /// Returns true if there are any fatal queues in the group.
    pub(crate) fn has_fatal_queues(&self) -> bool {
        self.fatal_queues != 0
    }

    /// Returns the bitmask of currently fatal queues.
    pub(crate) fn fatal_queues(&self) -> u32 {
        self.fatal_queues
    }

    pub(crate) fn can_run(&self) -> bool {
        self.state != State::Terminated
            && self.state != State::Unknown
            && self.fatal_error.is_none()
    }

    pub(crate) fn is_idle(&self) -> bool {
        if self.csg_id.is_some() {
            self.idle
        } else {
            let inactive_queues = self.blocked_queues | self.idle_queues;
            inactive_queues.count_ones() == self.queues.len() as u32
        }
    }

    /// Evaluates the current state of a queue and applies the correct
    /// park and timeout suspend states to the underlying `JobQueue`.
    pub(crate) fn sync_queue_state(&mut self, queue_idx: usize) {
        let is_blocked = (self.blocked_queues & (1 << queue_idx)) != 0;

        // A queue should have its timeout suspended if the group is
        // unbound/evicted and not blocked on a syncobj.
        // A queue should be parked if it has encountered a terminal error.
        let should_park = match self.state {
            State::Terminated | State::Unknown => true,
            _ => false,
        };

        let should_suspend = if self.csg_id.is_some() {
            should_park
        } else {
            match self.state {
                State::Suspended => !is_blocked,
                _ => true,
            }
        };

        let queue = &mut self.queues[queue_idx];
        let currently_suspended = queue
            .timeout_suspended
            .load(core::sync::atomic::Ordering::Relaxed);

        if should_suspend != currently_suspended {
            if should_suspend {
                queue.suspend_timeout();
            } else {
                queue.resume_timeout();
            }
        }

        // We track park state to avoid redundant calls to JobQueue::park()
        // and avoid spamming the trace log.
        if should_park != queue.parked {
            queue.parked = should_park;
            if should_park {
                queue.job_queue.park();
            } else {
                queue.job_queue.unpark();
            }
        }
    }

    /// Helper to update the blocked state of a queue.
    pub(crate) fn set_queue_blocked(&mut self, queue_idx: usize, blocked: bool) {
        let mask = 1 << queue_idx;

        if blocked {
            self.blocked_queues |= mask;
        } else {
            self.blocked_queues &= !mask;
        }
    }

    /// Helper to update the idle state of a queue.
    pub(crate) fn set_queue_idle(&mut self, queue_idx: usize, idle: bool) -> bool {
        let mask = 1 << queue_idx;
        let was_idle = (self.idle_queues & mask) != 0;

        if idle {
            self.idle_queues |= mask;
        } else {
            self.idle_queues &= !mask;
        }

        was_idle
    }

    /// Helper to update the fatal state of a queue.
    pub(crate) fn set_queue_fatal(&mut self, queue_idx: usize) {
        if (self.fatal_queues & (1 << queue_idx)) == 0 {
            self.fatal_queues |= 1 << queue_idx;
            self.fatal_error = Some(kernel::error::code::EFAULT);
        }
    }
}

impl Group {
    /// Return the group's current status, evaluating whether it can be run and if it's idle.
    pub(crate) fn status(&self) -> GroupStatus {
        let inner = self.inner.lock();

        GroupStatus {
            can_run: inner.can_run(),
            is_idle: inner.is_idle(),
            csg_id: inner.csg_id,
        }
    }

    /// Return true if the group can be run.
    pub(crate) fn can_run(&self) -> bool {
        self.inner.lock().can_run()
    }

    /// Return true if the group is idle.
    pub(crate) fn is_idle(&self) -> bool {
        self.inner.lock().is_idle()
    }

    /// Return the group's current state.
    pub(crate) fn state(&self) -> State {
        self.inner.lock().state
    }

    pub(crate) fn set_state(&self, new_state: State) {
        let _ = self.with_locked_inner(|inner| {
            inner.state = new_state;
            Ok(())
        });
    }

    /// Cancel all queues in the group, signaling pending fences with the provided error.
    ///
    /// This also updates the hardware sync objects to indicate failure, ensuring that
    /// userspace or other software waiters polling the sync object memory are unblocked.
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
                        let _ =
                            syncs::SyncObj64b::write(&mut inner.syncobjs, sync_offset, sync_obj);

                        Ok(queue.take_all_fences())
                    })
                    .unwrap_or_else(|_| KVec::new());

                let _ann = DmaFenceSignallingAnnotation::new();
                for pending in fences_to_signal {
                    if let Some(fence) = pending.fence {
                        fence.signal(Err(err));
                    }
                }
            }
        }
        self.tdev.schedule_sync_upd();
    }
}

impl Group {
    pub(crate) fn eval_syncwait(&self, queue_idx: usize) -> Result<bool> {
        let (syncwait, syncobjs_va) = self.with_locked_inner(|inner| {
            let syncobjs_va = inner.syncobjs.kernel_va().ok_or(EINVAL)?;
            let queue = inner.queues.get_mut(queue_idx).ok_or(EINVAL)?;
            Ok((queue.syncwait.clone(), syncobjs_va))
        })?;

        if syncwait.gpu_va == 0 {
            return Ok(false);
        }

        let value = if syncwait.gpu_va >= syncobjs_va.start && syncwait.gpu_va < syncobjs_va.end {
            let offset = (syncwait.gpu_va - syncobjs_va.start) as usize;
            self.with_locked_inner(|inner| {
                if syncwait.sync64 {
                    let sync_obj = syncs::SyncObj64b::read(&mut inner.syncobjs, offset)?;
                    Ok(sync_obj.seqno)
                } else {
                    let sync_obj = syncs::SyncObj32b::read(&mut inner.syncobjs, offset)?;
                    Ok(sync_obj.seqno as u64)
                }
            })?
        } else {
            let vm_guard = self.vm.lock();
            let mut bo_offset = 0;
            let mut bo = vm_guard
                .get_bo_for_va(syncwait.gpu_va, &mut bo_offset)
                .ok_or(EINVAL)?;

            if syncwait.sync64 {
                let sync_obj = syncs::SyncObj64b::read(&mut bo, bo_offset as usize)?;
                sync_obj.seqno
            } else {
                let sync_obj = syncs::SyncObj32b::read(&mut bo, bo_offset as usize)?;
                sync_obj.seqno as u64
            }
        };

        let result = if syncwait.gt {
            value > syncwait.ref_val
        } else {
            value <= syncwait.ref_val
        };

        if result {
            self.with_locked_inner(|inner| {
                if let Some(queue) = inner.queues.get_mut(queue_idx) {
                    queue.syncwait.gpu_va = 0;
                }
                Ok(())
            })?;
        }

        Ok(result)
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

    pub(crate) fn submit(
        self: Arc<Self>,
        all_syncs: KVec<KVec<SyncOp>>,
        queue_submits: KVec<QueueSubmit>,
        file: &DrmFile,
    ) -> Result<KVec<ARef<PublicDmaFence>>> {
        if !self.can_run() {
            pr_err!("group_submit: invalid group: group is terminated");
            return Err(EINVAL);
        }

        let mut ctx = deps::Context::new(file);

        let mut fences = KVec::with_capacity(queue_submits.len(), GFP_KERNEL)?;

        let vm = self.vm.lock();

        // Prepare the VM with enough slots for all submissions
        vm.with_prepared_vm(queue_submits.len() as u32, |mut locked_vm| {
            // Create all jobs and add them to the context
            for (queue_submit, syncs) in core::iter::zip(queue_submits.iter(), all_syncs.iter()) {
                let sync_addr = self.with_locked_inner(|inner| {
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
                    &*fence,
                    kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                    kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                );
                fences.push(fence, GFP_KERNEL)?;
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
        queue_args: KVec<QueueCreate>,
    ) -> Result<usize> {
        let group = Group::create(tdev, file, groupcreate, queue_args)?;

        tdev.with_locked_scheduler(|sched| {
            let list_arc = ListArc::try_from_arc(group.clone()).map_err(|_| EINVAL)?;
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

    pub(crate) fn destroy_group(self: Pin<&Self>, tdev: &TyrDevice, index: usize) -> Result {
        let xa = self.xa.as_ref();

        let group = xa.lock().remove(index).ok_or(EINVAL)?;

        let is_bound = group.with_locked_inner(|inner| {
            inner.fatal_error = Some(ECANCELED);
            Ok(inner.csg_id.is_some())
        })?;

        if is_bound {
            tdev.schedule_tick();
        } else {
            group.schedule_term();
        }

        Ok(())
    }

    /// Destroy all groups in the pool.
    ///
    /// This is called when the file is being closed to ensure all groups
    /// are properly cleaned up (unbound if necessary) before being dropped.
    pub(crate) fn destroy_all(self: Pin<&Self>, tdev: &TyrDevice) -> Result {
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
                        let sync_obj = syncs::SyncObj64b::read(&mut inner.syncobjs, sync_offset)?;
                        let queue = &mut inner.queues[queue_idx];

                        Ok(queue.pop_pending_fence_up_to(sync_obj.seqno))
                    })
                    .unwrap_or(None);

                match fence_to_signal {
                    Some(fence) => {
                        fence.signal(Ok(()));
                    }
                    None => break,
                }
            }
        }
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
            .unwrap_or(Some(kernel::error::code::ECANCELED));

        if let Some(e) = err {
            this.cancel_queues(e);
        }
    }
}
