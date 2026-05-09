// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::AtomicU32;

use kernel::{
    alloc::KVec,
    drm::gem::BaseObject,
    io::Io,
    list::{
        impl_list_arc_safe,
        impl_list_item,
        AtomicTracker,
        ListLinks,
        TryNewListArc, //
    },
    new_mutex,
    prelude::*,
    sync::{
        aref::ARef,
        Arc,
        LockedBy,
        Mutex, //
    },
    uaccess::UserSlice,
    uapi,
};

use crate::{
    driver::TyrDrmDevice,
    file::TyrDrmFile,
    fw::global::csg::Priority,
    gem, heap, pool,
    sched::CsgSlotManager,
    slot::Seat,
    vm::{Vm, VmFlag, VmMapFlags},
};

use super::{
    job::{Job, PreparedQueueSubmit, QueueSubmit},
    queue::{Queue, QueueCreate},
    syncs,
};

/// Upper bound on queues per group, set by the width of the per-queue
/// bitmasks (`blocked_queues`, `idle_queues`, `fatal_queues`).
#[expect(dead_code)]
pub(crate) const MAX_CS_PER_GROUP: usize = 32;

/// The group's lifecycle state.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) enum State {
    Created,
    Active,
    /// Suspended from a CSG slot; may resume.
    Suspended,
    Terminated,
    /// Unknown state, typically after a firmware error.
    Unknown,
}

/// Which scheduler list (idle / runnable / none) a group is currently on.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) enum GroupListState {
    None,
    Idle,
    Runnable,
}

/// A snapshot of the scheduler-visible state of a [`Group`].
///
/// Lets the rule engine and Tick lifecycle read `can_run`, `is_idle`,
/// and `csg_id` together under a single `inner` lock acquisition.
pub(crate) struct GroupStatus {
    pub(crate) can_run: bool,
    pub(crate) is_idle: bool,
    /// CSG slot id when the group is bound, otherwise `None`.
    pub(crate) csg_id: Option<usize>,
}

/// The mutable scheduler-visible state for a [`Group`].
///
/// Protected by the `inner` mutex on [`Group`]; access via
/// [`Group::with_locked_inner`].
pub(crate) struct GroupInner {
    pub(crate) state: State,
    pub(crate) list_state: GroupListState,
    /// CSG slot id when the group is bound, otherwise `None`.
    pub(crate) csg_id: Option<usize>,
    blocked_queues: u32,
    idle_queues: u32,
    fatal_queues: u32,
    pub(crate) fatal_error: Option<Error>,
    // Cached from Group::queues.len(); GroupInner has no borrow of Group.
    queue_count: usize,
}

impl GroupInner {
    /// Returns false if the group is terminated, in an unknown state, or
    /// has a fatal error recorded.
    pub(crate) fn can_run(&self) -> bool {
        self.state != State::Terminated
            && self.state != State::Unknown
            && self.fatal_error.is_none()
    }

    #[expect(dead_code)]
    pub(crate) fn blocked_queues(&self) -> u32 {
        self.blocked_queues
    }

    #[expect(dead_code)]
    pub(crate) fn has_blocked_queues(&self) -> bool {
        self.blocked_queues != 0
    }

    #[expect(dead_code)]
    pub(crate) fn has_fatal_queues(&self) -> bool {
        self.fatal_queues != 0
    }

    pub(crate) fn fatal_queues(&self) -> u32 {
        self.fatal_queues
    }

    /// Sets a queue as blocked or unblocked.
    #[expect(dead_code)]
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
    #[expect(dead_code)]
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

    pub(crate) fn set_queue_fatal(&mut self, queue_idx: usize) {
        if (self.fatal_queues & (1 << queue_idx)) == 0 {
            self.fatal_queues |= 1 << queue_idx;
            self.fatal_error = Some(EFAULT);
        }
    }

    /// Returns true when every queue is either blocked or idle.
    pub(crate) fn is_idle(&self) -> bool {
        let inactive_queues = self.blocked_queues | self.idle_queues;
        inactive_queues.count_ones() == self.queue_count as u32
    }
}

#[pin_data]
pub(crate) struct Group {
    /// The mutable, lock-protected portion of the group state.
    #[pin]
    inner: Mutex<GroupInner>,
    pub(crate) tiler_oom: AtomicU32,
    /// Tyr DRM device that owns this group.
    ///
    /// # Invariants
    ///
    /// This field forms a strong refcount cycle: the device owns the
    /// per-priority scheduler lists and the [`CsgSlotManager`], both
    /// of which hold `Arc<Group>`, while every `Group` holds an
    /// [`ARef<TyrDrmDevice>`](kernel::sync::aref::ARef) here. The cycle
    /// is broken structurally at teardown:
    ///
    /// * On file close, [`TyrDrmFileData`]'s `PinnedDrop` empties the
    ///   per-file [`group::Pool`](pool::Pool), releasing the pool's
    ///   `Arc<Group>` references.
    /// * The tick and `term_work` paths drain any in-flight
    ///   `Arc<Group>` references they still hold to completion before
    ///   the file's last reference is released.
    ///
    /// By the time the device's final [`ARef`](kernel::sync::aref::ARef)
    /// drops on driver detach or last file close, every `Arc<Group>`
    /// reference has already reached zero, so the cycle does not pin
    /// the device.
    ///
    /// [`TyrDrmFileData`]: crate::file::TyrDrmFileData
    pub(crate) tdev: ARef<TyrDrmDevice>,
    /// CSG slot manager seat for this group.
    ///
    /// The owner is the per-device [`CsgSlotManager`] mutex. Callers
    /// must hold that lock to look the seat up, e.g.
    /// `group.csg_seat.access(&slot_manager).slot()` to retrieve the
    /// slot index when the seat is currently
    /// [`Seat::Active`](crate::slot::Seat::Active), or `None` when the
    /// group is idle or has never been bound.
    pub(crate) csg_seat: LockedBy<Seat, CsgSlotManager>,
    /// The group's queues.
    ///
    /// The container is immutable for the lifetime of the group; the
    /// per-queue state inside each [`Queue`] uses interior mutability so
    /// callers do not need the group's `inner` lock to operate on it.
    pub(crate) queues: KVec<Queue>,
    #[pin]
    pub(crate) links: ListLinks,
    #[pin]
    pub(crate) tracker: AtomicTracker<0>,
    #[pin]
    pub(crate) wait_links: ListLinks<1>,
    #[pin]
    pub(crate) wait_tracker: AtomicTracker<1>,
    #[allow(dead_code)]
    pub(super) vm: Arc<Vm>,
    /// Software-visible scheduling priority.
    pub(crate) priority: Priority,
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
    #[pin]
    heap_pool: Mutex<Option<Arc<heap::Pool>>>,
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

        let priority = Priority::try_from(group_args.priority)?;

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

        let num_syncs =
            group_args.queues.count as usize * core::mem::size_of::<syncs::SyncObj64b>();
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

        let queue_count = queues.len();

        Arc::pin_init(
            pin_init!(Self {
                inner <- new_mutex!(GroupInner {
                    state: State::Created,
                    list_state: GroupListState::None,
                    csg_id: None,
                    blocked_queues: 0,
                    idle_queues: 0,
                    fatal_queues: 0,
                    fatal_error: None,
                    queue_count,
                }),
                tiler_oom: AtomicU32::new(0),
                tdev: ddev.into(),
                csg_seat: LockedBy::new(&ddev.csg_slot_manager, Seat::default()),
                queues,
                links <- ListLinks::new(),
                tracker <- AtomicTracker::new(),
                wait_links <- ListLinks::new(),
                wait_tracker <- AtomicTracker::new(),
                vm,
                priority,
                compute_core_mask: group_args.compute_core_mask,
                fragment_core_mask: group_args.fragment_core_mask,
                tiler_core_mask: group_args.tiler_core_mask,
                max_compute_cores: group_args.max_compute_cores,
                max_fragment_cores: group_args.max_fragment_cores,
                max_tiler_cores: group_args.max_tiler_cores,
                suspend_buf,
                protm_suspend_buf,
                _syncobjs: syncobjs,
                heap_pool <- new_mutex!(file.inner().heap_pools().get_pool(group_args.vm_id as usize)),
            }),
            GFP_KERNEL,
        )
    }

    /// Caller must not already hold `inner`.
    pub(crate) fn with_locked_inner<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut GroupInner) -> R,
    {
        let mut inner = self.inner.lock();
        f(&mut inner)
    }

    pub(crate) fn fatal_queues(&self) -> u32 {
        self.inner.lock().fatal_queues()
    }

    pub(crate) fn state(&self) -> State {
        self.inner.lock().state
    }

    pub(crate) fn set_state(&self, new_state: State) {
        self.with_locked_inner(|inner| {
            inner.state = new_state;
        });
    }

    pub(crate) fn can_run(&self) -> bool {
        self.inner.lock().can_run()
    }

    pub(crate) fn is_idle(&self) -> bool {
        self.inner.lock().is_idle()
    }

    pub(crate) fn status(&self) -> GroupStatus {
        let inner = self.inner.lock();
        GroupStatus {
            can_run: inner.can_run(),
            is_idle: inner.is_idle(),
            csg_id: inner.csg_id,
        }
    }

    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }

    fn syncobj_offset(&self, queue_index: usize) -> Result<usize> {
        if queue_index >= self.queues.len() {
            return Err(EINVAL);
        }

        Ok(queue_index * core::mem::size_of::<syncs::SyncObj64b>())
    }

    #[expect(dead_code)]
    pub(super) fn read_syncobj(&self, queue_index: usize) -> Result<syncs::SyncObj64b> {
        syncs::SyncObj64b::read(&self._syncobjs, self.syncobj_offset(queue_index)?)
    }

    pub(super) fn write_syncobj(&self, queue_index: usize, value: syncs::SyncObj64b) -> Result {
        syncs::SyncObj64b::write(&self._syncobjs, self.syncobj_offset(queue_index)?, value)
    }

    pub(crate) fn set_heap_pool(&self, pool: Arc<heap::Pool>) {
        *self.heap_pool.lock() = Some(pool);
    }

    #[allow(dead_code)]
    pub(super) fn get_heap_pool(&self) -> Option<Arc<heap::Pool>> {
        self.heap_pool.lock().clone()
    }

    pub(super) fn submit(
        self: &Arc<Self>,
        queue_submits: KVec<QueueSubmit>,
        file: &TyrDrmFile,
    ) -> Result {
        let jobs = Job::from_queue_submits(queue_submits)?;
        let mut prepared_jobs = KVec::<PreparedQueueSubmit>::new();

        for job in jobs.into_iter() {
            prepared_jobs.push(job.prepare(self, file)?, GFP_KERNEL)?;
        }

        self.vm
            .with_prepared_vm(prepared_jobs.len() as u32, |mut prepared_vm| {
                for prepared_job in prepared_jobs.into_iter() {
                    let submit_fence = prepared_job.commit(self)?;
                    prepared_vm.resv_add_fence(
                        &submit_fence,
                        kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                        kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                    );
                }

                Ok(())
            })?;

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
        groupcreate: &mut uapi::drm_panthor_group_create,
        file: &TyrDrmFile,
    ) -> Result {
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

        let group = Group::create(ddev, file, groupcreate, queue_args)?;

        ddev.with_locked_scheduler(|sched| sched.add_group(group.clone()))?;

        groupcreate.group_handle = self.0.insert(group)? as u32;
        Ok(())
    }

    pub(crate) fn group(&self, index: usize) -> Option<Arc<Group>> {
        self.0.get(index)
    }

    pub(crate) fn set_heap_pool_for_vm(&self, vm: &Arc<Vm>, pool: Arc<heap::Pool>) -> Result {
        self.0.for_each(|_, group| {
            if Arc::ptr_eq(&group.vm, vm) {
                group.set_heap_pool(pool.clone());
            }

            Ok(())
        })
    }

    pub(crate) fn submit_group(
        &self,
        groupsubmit: &uapi::drm_panthor_group_submit,
        file: &TyrDrmFile,
    ) -> Result {
        if groupsubmit.pad != 0 {
            return Err(EINVAL);
        }

        if groupsubmit.queue_submits.count == 0 {
            return Err(EINVAL);
        }

        let group = self
            .group(groupsubmit.group_handle as usize)
            .ok_or(EINVAL)?;

        let mut queue_submits = KVec::new();

        super::job::append_queue_submits(
            &mut queue_submits,
            groupsubmit.queue_submits.array,
            groupsubmit.queue_submits.count,
            groupsubmit.queue_submits.stride,
            group.queue_count(),
        )?;

        group.submit(queue_submits, file)
    }

    pub(crate) fn get_group_state(
        &self,
        groupgetstate: &mut uapi::drm_panthor_group_get_state,
    ) -> Result {
        if groupgetstate.pad != 0 {
            return Err(EINVAL);
        }

        let group = self
            .group(groupgetstate.group_handle as usize)
            .ok_or(EINVAL)?;

        groupgetstate.state = 0;
        groupgetstate.fatal_queues = group.fatal_queues();

        if groupgetstate.fatal_queues != 0 {
            groupgetstate.state |=
                uapi::drm_panthor_group_state_flags_DRM_PANTHOR_GROUP_STATE_FATAL_FAULT;
        }

        Ok(())
    }

    fn destroy_group_index(&self, ddev: &TyrDrmDevice, index: usize) -> Result {
        let group = self.0.get(index).ok_or(EINVAL)?;

        ddev.with_locked_scheduler(|sched| sched.remove_group(ddev, group))?;

        self.0.remove(index)?;
        Ok(())
    }

    pub(crate) fn destroy_group(
        &self,
        ddev: &TyrDrmDevice,
        groupdestroy: &uapi::drm_panthor_group_destroy,
    ) -> Result {
        if groupdestroy.pad != 0 {
            return Err(EINVAL);
        }

        self.destroy_group_index(ddev, groupdestroy.group_handle as usize)
    }

    pub(crate) fn destroy_all(&self, ddev: &TyrDrmDevice) -> Result {
        for index in 1..self.0.index_upper_bound() {
            let _ = self.destroy_group_index(ddev, index);
        }

        Ok(())
    }
}
