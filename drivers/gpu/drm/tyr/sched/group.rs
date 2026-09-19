// SPDX-License-Identifier: GPL-2.0 or MIT

use core::mem::offset_of;

use kernel::{
    capability::{
        capable,
        Capability, //
    },
    dma_buf::dma_fence::{
        impl_has_dma_fence_work,
        new_dma_fence_work,
        DmaFenceWork,
        DmaFenceWorkItem,
        PublicDmaFence, //
    },
    drm::gem::BaseObject,
    io::IoBase,
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
        atomic::Atomic,
        Arc,
        LockedBy,
        Mutex, //
    },
    uaccess::UserSlice,
    uapi,
    workqueue::{
        impl_has_work,
        new_work,
        Work,
        WorkItem, //
    }, //
};

use crate::{
    cleanup,
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData,
        TyrDrmRegistrationData, //
    },
    file::{
        read_padding_zero,
        TyrDrmFile, //
    },
    fw::{
        global::csg::Priority,
        CsBlockedReason,
        Firmware, //
    },
    gem,
    gpu::CsifInfo,
    pool,
    sched::CsgSlotManager,
    slot::Seat,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    }, //
};

use super::{
    deps,
    job::{
        Job,
        QueueSubmit, //
    },
    queue::{
        PreparedQueueJob,
        Queue,
        QueueCreate,
        QueueJob, //
    },
    syncs, //
};

/// Per-group work-slot identifiers used as the `WORK_ID` const generic
/// on this group's work-item fields and their `HasWork` /
/// `HasDmaFenceWork` impls.
pub(crate) mod work_id {
    /// Terminal cancellation worker.
    pub(crate) const TERM: u64 = 1;
    /// Final release worker on the cleanup workqueue.
    pub(crate) const RELEASE: u64 = 2;
    /// Tiler heap out-of-memory growth worker.
    pub(crate) const TILER_OOM: u64 = 3;
}

/// Upper bound on queues per group, set by the width of the per-queue
/// bitmasks (`blocked_queues`, `idle_queues`, `fatal_queues`).
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

/// A snapshot of the scheduler-visible state of a `Group`.
///
/// Lets the rule engine and Tick lifecycle read `can_run`, `is_idle`,
/// `has_blocked_queues`, and `csg_id` together under a single `inner`
/// lock acquisition.
pub(crate) struct GroupStatus {
    pub(crate) can_run: bool,
    pub(crate) is_idle: bool,
    /// At least one CS in the group is classified as blocked on a sync
    /// object by `sync_csg_slot_queues_state`, so the group reports idle
    /// but cannot make progress until the wait resolves.
    pub(crate) has_blocked_queues: bool,
    /// CSG slot id when the group is bound, otherwise `None`.
    pub(crate) csg_id: Option<usize>,
}

/// The mutable scheduler-visible state for a `Group`.
///
/// Protected by the `inner` mutex on `Group`. Access via
/// `Group::with_locked_inner`.
pub(crate) struct GroupInner {
    pub(crate) state: State,
    pub(crate) list_state: GroupListState,
    /// Coarse bound-vs-unbound marker. Holds the slot id when the
    /// group is bound, otherwise `None`. `Group::csg_seat` is the
    /// authoritative slot binding and is only readable under the
    /// slot-manager mutex. This mirror is maintained alongside it and
    /// read under the group inner mutex so the submit path can tell
    /// bound from unbound without acquiring the slot-manager mutex.
    pub(crate) csg_id: Option<usize>,
    blocked_queues: u32,
    idle_queues: u32,
    fatal_queues: u32,
    pub(crate) fatal_error: Option<Error>,
    /// Set when a timeout occurred on any of the queues owned by this
    /// group, or when a CSG request targeting the group timed out.
    pub(crate) timedout: bool,
    /// Set when a CSG update failure forced a still-runnable group off its slot.
    pub(crate) innocent: bool,
    // Cached from Group::queues.len(). GroupInner has no borrow of Group.
    queue_count: usize,
    /// Set once `Group::schedule_term` has enqueued `term_work`. Latches
    /// for the rest of the group's life, so a second teardown path finds
    /// the enqueue done.
    term_scheduled: bool,
}

impl GroupInner {
    /// Returns false if the group is terminated, in an unknown state, timed
    /// out, or has a fatal error recorded.
    pub(crate) fn can_run(&self) -> bool {
        self.state != State::Terminated
            && self.state != State::Unknown
            && self.fatal_error.is_none()
            && !self.timedout
    }

    /// Records that a timeout forced the group off the GPU.
    pub(crate) fn mark_timedout(&mut self) {
        self.timedout = true;
        if self.fatal_error.is_none() {
            self.fatal_error = Some(ETIMEDOUT);
        }
    }

    /// Records a timeout eviction, marking the group innocent if it could still run.
    pub(crate) fn mark_evicted_by_timeout(&mut self) {
        if self.can_run() {
            self.innocent = true;
        }
        self.mark_timedout();
    }

    pub(crate) fn blocked_queues(&self) -> u32 {
        self.blocked_queues
    }

    pub(crate) fn has_blocked_queues(&self) -> bool {
        self.blocked_queues != 0
    }

    pub(crate) fn has_fatal_queues(&self) -> bool {
        self.fatal_queues != 0
    }

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
    /// Serializes a submit's prepare-to-commit window on this group, so
    /// every queue claims its pipeline slots and fence seqnos in the
    /// same order.
    ///
    /// Lock order `submit_lock > {drm_exec, job queue}`, with nothing
    /// else held when it is taken. The window allocates and holds the VM
    /// reservation lock, so the lock is off limits to dma-fence
    /// signalling sections and must not cover a userspace copy.
    #[pin]
    submit_lock: Mutex<()>,
    /// Pending TILER_OOM events, one bit per command stream.
    pub(crate) tiler_oom: Atomic<u32>,
    /// Tyr DRM device that owns this group.
    ///
    /// # Invariants
    ///
    /// The device reaches groups through the scheduler lists and the
    /// `CsgSlotManager`, and every group holds an `ARef` back, so the
    /// refcounts form a cycle. Three paths break it without waiting on
    /// the device:
    ///
    /// * File close empties the per-file `group::Pool`.
    /// * `Group::schedule_term` routes the tick's and destroy's
    ///   references to `release_work`, which drops them on the cleanup
    ///   workqueue.
    /// * Unbind flushes `heap_alloc_wq` after quiescing its producers,
    ///   so no `tiler_oom_work` outlives it.
    pub(crate) tdev: ARef<TyrDrmDevice>,
    /// CSG slot manager seat for this group.
    ///
    /// The owner is the per-device `CsgSlotManager` mutex. Callers
    /// must hold that lock to look the seat up, e.g.
    /// `group.csg_seat.access(&slot_manager).slot()` to retrieve the
    /// slot index when the seat is currently
    /// `Seat::Active`, or `None` when the
    /// group is idle or has never been bound.
    pub(crate) csg_seat: LockedBy<Seat, CsgSlotManager>,
    /// The group's queues.
    ///
    /// The container is immutable for the lifetime of the group. The
    /// per-queue state inside each `Queue` uses interior mutability so
    /// callers do not need the group's `inner` lock to operate on it.
    pub(crate) queues: KVec<Queue>,
    /// Worker that drives `Group::cancel_queues` on the device's
    /// `term_wq`.
    ///
    /// Enqueued by `Group::schedule_term` when the tick lifecycle
    /// evicts a group whose `can_run()` is false (fatal error, user
    /// destroy, timeout). The body runs inside the dma-fence
    /// signalling annotation and ends by handing its `Arc<Group>`
    /// to `release_work`.
    #[pin]
    term_work: DmaFenceWork<Group, { work_id::TERM }>,
    /// Worker that drops the reference `term_work` ran with, on the
    /// cleanup workqueue.
    ///
    /// The drop may be the group's last. Unmapping its buffers takes
    /// `dma_resv_lock` and allocates with `GFP_KERNEL`. Neither is
    /// allowed inside the signalling annotation. Every queue was
    /// drained by `term_work`, so the `cancel_all()` in
    /// `JobQueue::drop` signals nothing here.
    ///
    /// The item is embedded in the group, so the enqueue allocates
    /// nothing and has no `NoMemory` case to handle, unlike
    /// `cleanup::try_spawn_owned`.
    #[pin]
    release_work: Work<Group, { work_id::RELEASE }>,
    /// Worker that services this group's pending tiler OOMs on the
    /// device's `heap_alloc_wq`.
    #[pin]
    tiler_oom_work: Work<Group, { work_id::TILER_OOM }>,
    #[pin]
    pub(crate) links: ListLinks,
    #[pin]
    pub(crate) tracker: AtomicTracker<0>,
    #[pin]
    pub(crate) wait_links: ListLinks<1>,
    #[pin]
    pub(crate) wait_tracker: AtomicTracker<1>,
    pub(super) vm: Arc<Vm>,
    /// Software-visible scheduling priority.
    pub(crate) priority: Priority,
    pub(super) compute_core_mask: u64,
    pub(super) fragment_core_mask: u64,
    pub(super) tiler_core_mask: u64,
    pub(super) max_compute_cores: u8,
    pub(super) max_fragment_cores: u8,
    pub(super) max_tiler_cores: u8,
    pub(super) suspend_buf: gem::KernelBo,
    pub(super) protm_suspend_buf: gem::KernelBo,
    syncobjs: Arc<gem::MappedBo>,
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

/// Returns whether `file` is allowed to request `priority`.
///
/// Medium and below are always allowed. High and realtime require
/// `CAP_SYS_NICE` or DRM master. Anything beyond realtime is rejected
/// as `EINVAL`.
pub(crate) fn priority_permit(file: &TyrDrmFile, priority: u8) -> Result {
    if priority > uapi::drm_panthor_group_priority_PANTHOR_GROUP_PRIORITY_REALTIME as u8 {
        return Err(EINVAL);
    }

    if priority <= uapi::drm_panthor_group_priority_PANTHOR_GROUP_PRIORITY_MEDIUM as u8 {
        return Ok(());
    }

    if capable(Capability::SYS_NICE) || file.is_current_master() {
        return Ok(());
    }

    Err(EACCES)
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

        priority_permit(file, group_args.priority)?;

        let priority = Priority::try_from(group_args.priority)?;

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
        let syncobjs = gem::new_kernel_object(dev, ddev, &vm, num_syncs, flags, ddev.coherent)?;

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
                    timedout: false,
                    innocent: false,
                    queue_count,
                    term_scheduled: false,
                }),
                submit_lock <- new_mutex!(()),
                tiler_oom: Atomic::new(0),
                tdev: ddev.into(),
                csg_seat: LockedBy::new(&ddev.csg_slot_manager, Seat::default()),
                queues,
                term_work <- new_dma_fence_work!("tyr-group-term"),
                release_work <- new_work!("tyr-group-release"),
                tiler_oom_work <- new_work!("tyr-group-tiler-oom"),
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
                syncobjs,
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

    pub(crate) fn state(&self) -> State {
        self.inner.lock().state
    }

    pub(crate) fn set_state(&self, new_state: State) {
        self.with_locked_inner(|inner| {
            inner.state = new_state;
        });
    }

    pub(crate) fn can_run(&self) -> bool {
        !self.vm.is_unusable() && self.inner.lock().can_run()
    }

    /// Unlike the snapshot-only `GroupInner::is_idle`, each idle-classified
    /// queue's live ring is re-read to catch a job published after the
    /// snapshot. Only meaningful once the group has left `State::Active`.
    pub(crate) fn is_idle_live(&self) -> bool {
        let inner = self.inner.lock();
        if !inner.is_idle() {
            return false;
        }
        for (cs_id, queue) in self.queues.iter().enumerate() {
            if inner.blocked_queues() & (1u32 << cs_id) != 0 {
                continue;
            }
            if !queue.is_ringbuf_empty().unwrap_or(false) {
                return false;
            }
        }
        true
    }

    /// Mask of the blocked queues. Zero when any queue in the group is
    /// still active.
    ///
    /// No other queue in an idle group can signal the sync object a
    /// blocked queue waits on. The signal has to come from outside the
    /// group, and the job deadline bounds that wait.
    pub(crate) fn blocked_idle_queues(&self) -> u32 {
        let inner = self.inner.lock();
        if inner.is_idle() {
            inner.blocked_queues()
        } else {
            0
        }
    }

    pub(crate) fn status(&self) -> GroupStatus {
        let inner = self.inner.lock();
        GroupStatus {
            can_run: !self.vm.is_unusable() && inner.can_run(),
            is_idle: inner.is_idle(),
            has_blocked_queues: inner.has_blocked_queues(),
            csg_id: inner.csg_id,
        }
    }

    /// Schedules terminal cleanup for the group.
    ///
    /// Called by the tick lifecycle for groups whose `can_run()` is
    /// false at eviction time. Enqueues `term_work` on the device's
    /// `term_wq`. The workqueue holds the `Arc<Group>` for the duration
    /// of the worker's run, so the suspend buffers and syncobj pages
    /// stay live until cancellation has completed.
    ///
    /// The call is idempotent, since more than one teardown path can
    /// reach a group. A destroy of an unbound group calls
    /// `schedule_term` directly, and a later tick can pick the same
    /// group up after `can_run()` returns false. The `term_scheduled`
    /// latch in `GroupInner` drops repeat calls.
    pub(crate) fn schedule_term(self: &Arc<Self>) {
        let already_scheduled = self.with_locked_inner(|inner| {
            let was = inner.term_scheduled;
            inner.term_scheduled = true;
            was
        });
        if already_scheduled {
            return;
        }
        // The latch makes this the only enqueue of `term_work`, so it
        // cannot find the item pending. `self` keeps the group alive, so
        // dropping the clone returned in the error is not the group's
        // last drop.
        if self
            .tdev
            .term_wq
            .enqueue::<Arc<Self>, { work_id::TERM }>(self.clone())
            .is_err()
        {
            dev_err!(self.tdev.as_ref(), "Failed to enqueue group term_work\n");
        }
    }

    /// Leaks `group` after a failed enqueue of `release_work`.
    ///
    /// The failure is not expected. The enqueue runs inside the
    /// signalling annotation. A drop there may be the group's last, and
    /// that drop unmaps its buffers under `dma_resv_lock`.
    fn leak_on_release_enqueue_failure(group: Arc<Self>) {
        dev_err!(
            group.tdev.as_ref(),
            "Failed to enqueue group release_work, leaking the group\n"
        );
        core::mem::forget(group);
    }

    /// Schedules the group's tiler OOM worker. Safe from any context.
    ///
    /// The queued work holds an `Arc<Group>` reference until the worker
    /// runs.
    pub(crate) fn schedule_tiler_oom(self: &Arc<Self>) {
        let _ = self
            .tdev
            .heap_alloc_wq
            .enqueue::<Arc<Self>, { work_id::TILER_OOM }>(self.clone());
    }

    /// Parks every queue in the group.
    ///
    /// Must not be called with the scheduler mutex held. Submit takes
    /// the per-queue pipeline lock before that mutex.
    pub(crate) fn park_queues(&self) {
        for queue in self.queues.iter() {
            queue.park();
        }
    }

    /// Releases the park taken by `park_queues`. Same locking rule.
    pub(crate) fn unpark_queues(&self) {
        for queue in self.queues.iter() {
            queue.unpark();
        }
    }

    /// Cancels every queue in the group with `err`.
    ///
    /// Writes the per-queue terminator syncobj with `status = !0` and
    /// the highest seqno so GPU-side consumers observe the queue as
    /// done.
    pub(crate) fn cancel_queues(self: &Arc<Self>, err: Error) {
        for (queue_idx, queue) in self.queues.iter().enumerate() {
            queue.cancel(err);

            let seqno = queue.next_seqno();
            let _ = self.write_syncobj(
                queue_idx,
                syncs::SyncObj64b {
                    seqno,
                    status: !0,
                    pad: 0,
                },
            );
        }
    }

    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }

    /// Evaluates whether the queue at `queue_idx`'s captured sync-wait
    /// is satisfied.
    ///
    /// Reads the queue's `SyncWait` snapshot and applies the captured
    /// comparison. The awaited object sits either in the group's own
    /// `syncobjs` or in a foreign BO reached through `Vm::get_bo_for_va`.
    ///
    /// On a malformed snapshot the caller should treat the queue as
    /// still blocked and surface the error.
    ///
    /// A foreign-BO resolution is memoized on the `SyncWait` snapshot,
    /// keyed by its own `(gpu_va, sync64)`, so a later evaluation skips
    /// the gpuvm walk and rebuilds only when the key stops matching.
    ///
    /// Must not be called from a dma-fence signalling section. The
    /// foreign-BO path takes `dma_resv_lock` and `GFP_KERNEL`-vmaps.
    pub(crate) fn eval_syncwait(&self, fw: &Firmware<'_>, queue_idx: usize) -> Result<bool> {
        let queue = self.queues.get(queue_idx).ok_or(EINVAL)?;
        let syncwait = queue.syncwait_snapshot();

        if syncwait.gpu_va == 0 {
            return Ok(false);
        }

        // The firmware preserves CS_STATUS_WAIT_SYNC_POINTER across
        // CS state transitions, so the snapshot captured by an
        // earlier sync_csg_slot_queues_state pass can outlive the
        // wait itself. Re-read the firmware's current
        // CS_STATUS_BLOCKED_REASON to confirm the wait is still live
        // before resolving the awaited address.
        let csg_id = self.with_locked_inner(|inner| inner.csg_id);
        if let Some(csg_id) = csg_id {
            let still_waiting = fw.with_csg_mut(csg_id, |csg| match csg.cs_mut(queue_idx) {
                Some(cs) => Ok(cs.read_status_blocked_reason()? == CsBlockedReason::SyncWait),
                None => Ok(true),
            });
            if matches!(still_waiting, Ok(false)) {
                return Ok(true);
            }
        }

        let syncobjs_va = self.syncobjs.kernel_va().ok_or(EINVAL)?;

        // Resolve the awaited sync object's CPU mapping.
        let value = if syncwait.gpu_va >= syncobjs_va.start && syncwait.gpu_va < syncobjs_va.end {
            let offset = (syncwait.gpu_va - syncobjs_va.start) as usize;
            if syncwait.sync64 {
                syncs::SyncObj64b::read_seqno(&self.syncobjs, offset)?
            } else {
                u64::from(syncs::SyncObj32b::read_seqno(&self.syncobjs, offset)?)
            }
        } else if let Some(cached) = syncwait
            .cached
            .as_ref()
            .filter(|c| c.gpu_va == syncwait.gpu_va && c.sync64 == syncwait.sync64)
        {
            if syncwait.sync64 {
                syncs::SyncObj64b::read_seqno(&cached.bo, cached.offset)?
            } else {
                u64::from(syncs::SyncObj32b::read_seqno(&cached.bo, cached.offset)?)
            }
        } else {
            let (bo, bo_offset) = self.vm.get_bo_for_va(syncwait.gpu_va).ok_or(EINVAL)?;
            let mapped_bo = Arc::new(gem::BoVmap::new(&bo)?, GFP_KERNEL)?;
            let bo_offset = bo_offset as usize;

            // Memoize the resolved BO so subsequent re-evaluations
            // of the same wait take the cached-BO path.
            // `cache_syncwait_bo` re-checks that the snapshot still
            // names the same `(gpu_va, sync64)` before installing
            // the cache. If it returns false, `set_syncwait` ran
            // concurrently and changed either the address or the
            // sync-object width, so abandon this evaluation and let
            // the next cycle handle the new wait rather than reading
            // from a stale BO or with the wrong type.
            if !queue.cache_syncwait_bo(
                syncwait.gpu_va,
                syncwait.sync64,
                mapped_bo.clone(),
                bo_offset,
            ) {
                return Ok(false);
            }

            if syncwait.sync64 {
                syncs::SyncObj64b::read_seqno(&mapped_bo, bo_offset)?
            } else {
                u64::from(syncs::SyncObj32b::read_seqno(&mapped_bo, bo_offset)?)
            }
        };

        let satisfied = if syncwait.gt {
            value > syncwait.ref_val
        } else {
            value <= syncwait.ref_val
        };
        if satisfied {
            // Drop the cached BO resolution so the next wait does a
            // fresh gpuvm walk.
            drop(queue.take_syncwait_bo());
        }
        Ok(satisfied)
    }

    fn syncobj_offset(&self, queue_index: usize) -> Result<usize> {
        if queue_index >= self.queues.len() {
            return Err(EINVAL);
        }

        Ok(queue_index * core::mem::size_of::<syncs::SyncObj64b>())
    }

    /// GPU virtual address of the per-queue syncobj for `queue_index`.
    ///
    /// Errors with `EINVAL` if `queue_index` is out of range or the
    /// syncobjs BO has no kernel-side VA bound.
    pub(super) fn syncobj_va(&self, queue_index: usize) -> Result<u64> {
        let offset = self.syncobj_offset(queue_index)?;
        let syncobjs_va = self.syncobjs.kernel_va().ok_or(EINVAL)?;
        Ok(syncobjs_va.start + offset as u64)
    }

    pub(super) fn read_syncobj(&self, queue_index: usize) -> Result<u64> {
        syncs::SyncObj64b::read_seqno(&self.syncobjs, self.syncobj_offset(queue_index)?)
    }

    pub(super) fn write_syncobj(&self, queue_index: usize, value: syncs::SyncObj64b) -> Result {
        syncs::SyncObj64b::write(&self.syncobjs, self.syncobj_offset(queue_index)?, value)
    }

    pub(super) fn submit(
        self: &Arc<Self>,
        csif: &CsifInfo,
        queue_submits: KVec<QueueSubmit>,
        file: &TyrDrmFile,
    ) -> Result {
        if !self.can_run() {
            return Err(EINVAL);
        }

        let jobs = Job::from_queue_submits(queue_submits)?;
        let job_count = jobs.len();
        let mut ctx = deps::Context::new(file, SubmitOps::new(self.clone(), *csif));

        for (job, syncs) in jobs.into_iter() {
            ctx.add_job(job, Arc::new(syncs, GFP_KERNEL)?)?;
        }

        ctx.collect_signal_ops()?;

        let _submit_lock = self.submit_lock.lock();

        for idx in 0..job_count {
            ctx.prepare(idx)?;
        }

        self.vm
            .with_prepared_vm(job_count as u32, |mut prepared_vm| {
                for idx in 0..job_count {
                    let signal_fence = ctx.commit(idx)?;
                    prepared_vm.resv_add_fence(
                        &signal_fence,
                        kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                        kernel::bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
                    );
                }

                Ok(())
            })?;

        ctx.push_fences();

        Ok(())
    }
}

/// A submit job that has claimed its slot on a queue.
struct PreparedSubmit {
    queue_index: usize,
    queue_job: PreparedQueueJob,
    /// Number of command-stream pieces the job carries, and the number
    /// of seqnos the commit claims for it. Zero for a sync-only job.
    piece_count: usize,
}

/// Runs the jobs of a group submit through `deps::Context`.
struct SubmitOps {
    group: Arc<Group>,
    /// CSIF information snapshotted at submit time and used to size the
    /// wrapper's working registers.
    csif: CsifInfo,
}

impl SubmitOps {
    fn new(group: Arc<Group>, csif: CsifInfo) -> Self {
        Self { group, csif }
    }
}

impl deps::BatchOps for SubmitOps {
    type Job = Job;
    type Prepared = PreparedSubmit;

    /// Allocates the wrapped command stream, reserves the pending submit
    /// fence slot, and hands the job to its queue.
    fn prepare(
        &self,
        job: Job,
        deps: &[ARef<PublicDmaFence>],
        extra_dep_capacity: usize,
    ) -> Result<PreparedSubmit> {
        let queue_index = job.queue_index();
        let queue = self.group.queues.get(queue_index).ok_or(EINVAL)?;
        let has_stream = job.has_stream();

        let reservation = if has_stream {
            Some(queue.reserve_pending_submit_fence()?)
        } else {
            None
        };

        let wrapped = if has_stream {
            let sync_va = self.group.syncobj_va(queue_index)?;
            job.build_wrapped_stream(&self.csif, sync_va)?
        } else {
            KVec::new()
        };

        // The extra slot holds the prior-work dependency that
        // `SubmitOps::commit` adds.
        let prepared = queue.prepare_job(
            QueueJob::new(wrapped, self.group.clone(), queue_index, reservation),
            deps,
            extra_dep_capacity + usize::from(!has_stream),
        )?;

        Ok(PreparedSubmit {
            queue_index,
            queue_job: prepared,
            piece_count: job.piece_count(),
        })
    }

    fn add_dep(&self, prepared: &mut PreparedSubmit, fence: ARef<PublicDmaFence>) -> Result {
        prepared.queue_job.add_dep(fence)
    }

    fn commit(&self, prepared: PreparedSubmit) -> Result<ARef<PublicDmaFence>> {
        let PreparedSubmit {
            queue_index,
            mut queue_job,
            piece_count,
        } = prepared;
        let has_stream = piece_count != 0;

        let queue = self.group.queues.get(queue_index).ok_or(EINVAL)?;

        // The wrapped stream emits exactly one `SYNC_ADD64(+1)` per piece,
        // so the syncobj reaches the highest claimed seqno precisely when
        // every piece has retired. A stream-less job emits no GPU work, so
        // it waits on the queue's last command stream instead of signalling
        // as soon as its dependencies resolve.
        if has_stream {
            let job = queue_job.job().ok_or(EINVAL)?;
            job.set_done_seqno(queue.claim_seqnos(piece_count));
        } else if let Some(fence) = queue.last_submit_fence() {
            queue_job.add_dep(fence)?;
        }

        let submit_fence = queue.commit_job(queue_job);

        if has_stream {
            queue.set_last_submit_fence(submit_fence.clone());
        }

        Ok(submit_fence)
    }
}

impl_has_dma_fence_work! {
    impl HasDmaFenceWork<Group, { work_id::TERM }> for Group {
        self.term_work
    }
}

impl_has_work! {
    impl HasWork<Group, { work_id::RELEASE }> for Group {
        self.release_work
    }
    impl HasWork<Group, { work_id::TILER_OOM }> for Group {
        self.tiler_oom_work
    }
}

impl DmaFenceWorkItem<{ work_id::TERM }> for Group {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        // Use the error captured at eviction time (fatal fault, user
        // destroy, or tick timeout). Fall back to ECANCELED if none
        // was recorded.
        let err = this
            .with_locked_inner(|inner| inner.fatal_error)
            .unwrap_or(ECANCELED);
        this.cancel_queues(err);

        // The `term_scheduled` latch makes this the only enqueue of
        // `release_work`, so it cannot find the item pending.
        if let Err(group) = cleanup::enqueue::<Arc<Self>, { work_id::RELEASE }>(this) {
            Self::leak_on_release_enqueue_failure(group);
        }
    }
}

impl WorkItem<{ work_id::RELEASE }> for Group {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        drop(this);
    }
}

/// Maximum number of live groups per file.
const MAX_GROUPS_PER_POOL: u32 = 128;

pub(crate) struct Pool(pool::Pool<Group>);

impl Pool {
    pub(crate) fn create() -> Result<Self> {
        Ok(Self(pool::Pool::create(MAX_GROUPS_PER_POOL)?))
    }

    pub(crate) fn create_group(
        &self,
        ddev: &TyrDrmDevice,
        reg_data: &TyrDrmRegistrationData<'_>,
        groupcreate: &mut uapi::drm_panthor_group_create,
        file: &TyrDrmFile,
    ) -> Result {
        if groupcreate.queues.count == 0 || groupcreate.queues.count as usize > MAX_CS_PER_GROUP {
            return Err(EINVAL);
        }

        static_assert!(
            size_of::<uapi::drm_panthor_queue_create>()
                == offset_of!(uapi::drm_panthor_queue_create, ringbuf_size) + size_of::<u32>()
        );
        let min_size = offset_of!(uapi::drm_panthor_queue_create, ringbuf_size) + size_of::<u32>();
        let stride = groupcreate.queues.stride as usize;
        if stride < min_size {
            return Err(EINVAL);
        }

        let mut reader = UserSlice::new(
            UserPtr::from_addr(groupcreate.queues.array as usize),
            stride
                .checked_mul(groupcreate.queues.count as usize)
                .ok_or(EINVAL)?,
        )
        .reader();

        let mut queue_args = KVec::new();

        for _ in 0..groupcreate.queues.count {
            let queue: QueueCreate = reader.read()?;
            read_padding_zero(&mut reader, stride - min_size)?;
            queue.validate()?;
            queue_args.push(queue, GFP_KERNEL)?;
        }

        let group = Group::create(ddev, reg_data, file, groupcreate, queue_args)?;

        ddev.with_locked_scheduler(|sched| sched.add_group(group.clone()))?;

        let handle = match self.0.insert(group.clone()) {
            Ok(handle) => handle,
            Err(e) => {
                // The group is unreachable without a handle, and a
                // tick may already have bound it.
                group.with_locked_inner(|inner| {
                    inner.fatal_error = Some(ECANCELED);
                });

                let csg_id = ddev.with_locked_scheduler(|sched| {
                    sched.detach_destroyed_group(&group);
                    Ok(group.with_locked_inner(|inner| inner.csg_id))
                });

                if matches!(csg_id, Ok(Some(_))) {
                    TyrDrmDeviceData::schedule_tick(&ARef::from(ddev));
                }

                return Err(e);
            }
        };

        groupcreate.group_handle = handle as u32;
        Ok(())
    }

    pub(crate) fn group(&self, index: usize) -> Option<Arc<Group>> {
        self.0.get(index)
    }

    pub(crate) fn submit_group(
        &self,
        csif: &CsifInfo,
        groupsubmit: &uapi::drm_panthor_group_submit,
        file: &TyrDrmFile,
    ) -> Result {
        if groupsubmit.pad != 0 {
            return Err(EINVAL);
        }

        if groupsubmit.queue_submits.count == 0 {
            return Ok(());
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

        group.submit(csif, queue_submits, file)
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

        let (timedout, innocent, fatal_queues) =
            group.with_locked_inner(|inner| (inner.timedout, inner.innocent, inner.fatal_queues()));

        *groupgetstate = Default::default();

        if timedout {
            groupgetstate.state |=
                uapi::drm_panthor_group_state_flags_DRM_PANTHOR_GROUP_STATE_TIMEDOUT;
        }

        if fatal_queues != 0 {
            groupgetstate.state |=
                uapi::drm_panthor_group_state_flags_DRM_PANTHOR_GROUP_STATE_FATAL_FAULT;
            groupgetstate.fatal_queues = fatal_queues;
        }

        if innocent {
            groupgetstate.state |=
                uapi::drm_panthor_group_state_flags_DRM_PANTHOR_GROUP_STATE_INNOCENT;
        }

        Ok(())
    }

    fn destroy_group_index(&self, ddev: &TyrDrmDevice, index: usize) -> Result {
        let group = self.0.remove(index)?;

        group.with_locked_inner(|inner| {
            inner.fatal_error = Some(ECANCELED);
        });

        let csg_id = ddev.with_locked_scheduler(|sched| {
            sched.detach_destroyed_group(&group);
            Ok(group.with_locked_inner(|inner| inner.csg_id))
        });

        if matches!(csg_id, Ok(Some(_))) {
            // The group is bound. The tick observes `can_run() == false`,
            // stages terminate, evicts, and routes the group through
            // `schedule_term`.
            TyrDrmDeviceData::schedule_tick(&ARef::from(ddev));
        } else {
            group.schedule_term();
        }

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
        self.0.for_each(|index, _| {
            let _ = self.destroy_group_index(ddev, index);

            Ok(())
        })
    }
}
