// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    device::{
        Bound,
        Device, //
    },
    list::{
        List,
        ListArc,
        ListItem, //
    },
    pm::AwakeScope,
    pr_warn_once,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::Relaxed,
        Arc, //
    },
    time::{
        jiffies64,
        msecs_to_jiffies,
        Delta,
        Instant,
        Jiffies,
        Monotonic, //
    }, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    fw::{
        global::{
            csg::Priority,
            CsStatusWait,
            CsgActivateInputs, //
        },
        CsBlockedReason,
        CsDbMask,
        CsWaitCondition,
        CsgExecutionState,
        CsgSlotMask,
        Firmware,
        CSG_CONFIG,
        CSG_EP_REQ,
        CSG_REQ, //
    },
    gpu::{
        self,
        CsifInfo, //
    },
    heap,
    mask::MaskIdx,
    mmu::Mmu,
    sched::group::GroupListState,
    slot::{
        LockedSeat,
        SlotManager,
        SlotOperations, //
    },
    trace, //
};

use group::{
    Group,
    QueueIdx, //
};

const GROUP_PRIORITY_COUNT: usize = Priority::num_priorities();

/// Maximum number of CSG slots the scheduler can address.
///
/// One entry per CSG priority. `Scheduler::init` caps the slot count the
/// firmware reports at this many. Bounds the fixed-capacity per-tick
/// accumulator so tick callbacks never allocate.
pub(crate) const MAX_CSGS: usize = MAX_CSG_PRIO as usize + 1;

/// Highest firmware priority value assignable to a CSG (`CSG_EP_REQ.priority` field).
pub(crate) const MAX_CSG_PRIO: u32 = 0xf;

/// Index of a scheduler CSG slot.
///
/// The four bits cover `0..MAX_CSGS`, so the index is in range for the
/// per-slot arrays and masks.
pub(crate) type CsgSlotIdx = MaskIdx<4>;

static_assert!(MAX_CSGS == 1 << 4);

pub(crate) mod deps;
pub(crate) mod events;
pub(crate) mod group;
pub(crate) mod job;
pub(crate) mod queue;
pub(crate) mod syncs;
pub(crate) mod tick;

/// The scheduler object.
pub(crate) enum SchedulerState {
    /// The scheduler has not been initialized yet.
    Disabled,
    /// The scheduler is ready to accept work.
    Enabled(Scheduler),
}

impl SchedulerState {
    pub(crate) fn enable(&mut self, scheduler: Scheduler) {
        *self = Self::Enabled(scheduler);
    }

    pub(crate) fn enabled_mut(&mut self) -> Result<&mut Scheduler> {
        match self {
            Self::Enabled(scheduler) => Ok(scheduler),
            Self::Disabled => Err(EINVAL),
        }
    }
}

/// Per-slot driver data attached to a `CsgSlotManager` slot.
pub(crate) struct CsgSlotData {
    /// The group that currently owns the slot.
    pub(in crate::sched) group: Arc<Group>,
    /// CSG firmware priority programmed into `CSG_EP_REQ.priority`.
    pub(in crate::sched) fw_priority: u32,
}

impl CsgSlotData {
    /// Returns a reference to the group bound to this CSG slot.
    pub(crate) fn group(&self) -> &Arc<Group> {
        &self.group
    }
}

/// Per-tick accumulator for CSG slot programming.
///
/// CSG slot operations need to coalesce multiple per-slot writes into a
/// single CSG_REQ word, ring the per-CSG doorbell once, then wait for
/// the firmware to acknowledge the resulting state transitions.
/// `Scheduler::program_csg_activate` stages into this accumulator while
/// the slot-manager mutex is held. `Scheduler::apply_csg_updates` then
/// drives the firmware-visible side of the transaction. The
/// slot-manager mutex is dropped around the firmware ack wait so other
/// slot accessors can run. The scheduler mutex stays held.
pub(crate) struct CsgUpdateContext {
    pub(crate) req_value: [CSG_REQ; MAX_CSGS],
    pub(crate) req_mask: [CSG_REQ; MAX_CSGS],
    /// Per-slot bits acknowledged by the firmware in response to this
    /// tick's `req_value` writes. Bits in `req_mask` missing from here
    /// mark the slot as timed out (see `timedout_mask`).
    pub(crate) acked_reqs: [CSG_REQ; MAX_CSGS],
    /// CSG_DB_REQ bits to toggle per slot (per-CS doorbell ring requests).
    ///
    /// One bit per CS in the group; flipped against `CSG_DB_ACK` by
    /// `apply_csg_updates` before the global doorbell ring so the
    /// firmware kicks the matching streams when it processes the
    /// per-CSG doorbell event.
    pub(crate) db_toggle: [CsDbMask; MAX_CSGS],
    pub(crate) update_mask: CsgSlotMask,
    /// Bitmask of CSG slot indices whose request timed out during the
    /// most recent apply cycle.
    pub(crate) timedout_mask: CsgSlotMask,
}

/// CSG_REQ::state field mask (bits 2:0). The firmware transitions all
/// three bits as a unit.
const CSG_REQ_STATE_MASK: CSG_REQ = CSG_REQ::from_raw(CSG_REQ::STATE_MASK);
/// CSG_REQ::ep_cfg bit (4:4). Endpoint-configuration toggle.
const CSG_REQ_EP_CFG: CSG_REQ = CSG_REQ::from_raw(CSG_REQ::EP_CFG_MASK);
/// CSG_REQ::status_update bit (5:5). Status-update toggle.
const CSG_REQ_STATUS_UPDATE: CSG_REQ = CSG_REQ::from_raw(CSG_REQ::STATUS_UPDATE_MASK);

/// A `CSG_REQ` bit that the firmware expects to be toggled.
#[derive(Copy, Clone)]
pub(crate) enum CsgReqToggle {
    /// The endpoint-configuration toggle, `CSG_REQ::ep_cfg`.
    EpCfg,
    /// The status-update toggle, `CSG_REQ::status_update`.
    StatusUpdate,
}

impl CsgReqToggle {
    const fn bit(self) -> CSG_REQ {
        match self {
            Self::EpCfg => CSG_REQ_EP_CFG,
            Self::StatusUpdate => CSG_REQ_STATUS_UPDATE,
        }
    }
}

impl CsgUpdateContext {
    /// Bits that the firmware expects to be toggled instead of set.
    ///
    /// Both `ep_cfg` and `status_update` are notification-style bits.
    /// The driver flips the request bit, the firmware mirrors the
    /// flip in `CSG_ACK`, and the request and ack bits stay matched
    /// across cycles. Pure-set bits would race with the firmware's
    /// own writes.
    pub(crate) const TOGGLE_BITS: CSG_REQ =
        CSG_REQ::from_raw(CSG_REQ::EP_CFG_MASK | CSG_REQ::STATUS_UPDATE_MASK);

    /// Creates an empty accumulator.
    pub(crate) fn new() -> Self {
        const ZERO: CSG_REQ = CSG_REQ::from_raw(0);
        Self {
            req_value: [ZERO; MAX_CSGS],
            req_mask: [ZERO; MAX_CSGS],
            acked_reqs: [ZERO; MAX_CSGS],
            db_toggle: [CsDbMask::empty(); MAX_CSGS],
            update_mask: CsgSlotMask::empty(),
            timedout_mask: CsgSlotMask::empty(),
        }
    }

    /// Stages an update of `mask` bits in `CSG_REQ` for `csg_idx` to
    /// the corresponding bits in `value`.
    ///
    /// Subsequent stages on the same slot replace the bits in `mask`,
    /// and the union of all `mask`s passed for a slot is what
    /// `Scheduler::apply_csg_updates` will toggle in `CSG_REQ` and
    /// wait for.
    fn queue_reqs(&mut self, csg_idx: CsgSlotIdx, value: CSG_REQ, mask: CSG_REQ) {
        let idx = csg_idx.get();

        self.req_value[idx] = (self.req_value[idx] & !mask) | (value & mask);
        self.req_mask[idx] |= mask;
        self.update_mask.insert(csg_idx);
    }

    /// Stages a toggle of `toggle` in `CSG_REQ` for `csg_idx`.
    pub(crate) fn toggle_reqs(&mut self, csg_idx: CsgSlotIdx, toggle: CsgReqToggle) {
        self.queue_reqs(csg_idx, toggle.bit(), toggle.bit());
    }

    /// Stages a `CSG_REQ.state` transition to `state` for `csg_idx`.
    pub(crate) fn set_state(&mut self, csg_idx: CsgSlotIdx, state: CsgExecutionState) {
        self.queue_reqs(
            csg_idx,
            CSG_REQ::zeroed().with_state(state),
            CSG_REQ_STATE_MASK,
        );
    }

    /// Adds `mask` to the per-CS doorbell-ring set for `csg_idx`.
    ///
    /// Each bit in `mask` corresponds to a CS within the CSG. The
    /// `apply_csg_updates` step flips the matching `CSG_DB_REQ` bits
    /// against `CSG_DB_ACK` before ringing the per-CSG doorbell.
    /// Calling this also marks the slot as having pending updates so
    /// the apply loop visits it even if no `CSG_REQ` bits were staged.
    pub(crate) fn add_db_toggle(&mut self, csg_idx: CsgSlotIdx, mask: CsDbMask) {
        if mask.is_empty() {
            return;
        }
        let idx = csg_idx.get();
        let raw = self.db_toggle[idx].into_raw() | mask.into_raw();
        self.db_toggle[idx] = CsDbMask::from_raw(raw);
        self.update_mask.insert(csg_idx);
    }
}

/// CSG slot operations.
///
/// `activate` makes the group's VM resident in a hardware AS slot.
/// `evict` releases that binding. The CSG_INPUT programming, the
/// firmware-visible `CSG_REQ` write, the doorbell ring and the ack
/// wait are driven by the scheduler.
pub(crate) struct CsgSlotOps;

impl SlotOperations<MAX_CSGS> for CsgSlotOps {
    type SlotData = CsgSlotData;

    fn seat(slot_data: &Self::SlotData) -> &LockedSeat<Self, MAX_CSGS> {
        &slot_data.group.csg_seat
    }

    fn activate(&mut self, _slot_idx: usize, slot_data: &Self::SlotData) -> Result {
        slot_data.group.vm.activate()?;
        Ok(())
    }

    fn evict(&mut self, slot_idx: usize, slot_data: &Self::SlotData) -> Result {
        // Tear the binding down. Clear `csg_id` and the per-queue
        // `doorbell_id`, then flag the VM's AS slot idle so it stays
        // resident and reusable on the next bind. This makes no
        // assumption about firmware state. Only
        // `Tick::halt_and_unbind_evicted_groups` stages a halt and waits
        // for the ack before evicting. The bind rollback evicts without
        // staging one.
        let was_bound = slot_data.group.with_locked_inner(|inner| {
            for queue in slot_data.group.queues.iter() {
                queue.set_doorbell_id(None);
            }
            inner.csg_id.take().is_some()
        });
        // The bind rollback evicts before `csg_id` is published, so the
        // slot was never announced as bound and the VM's bound-group
        // record was never set.
        if was_bound {
            trace::group_unbind(
                slot_data.group.handle(),
                slot_data.group.uid(),
                slot_idx as u32,
            );
            trace::csg_slot_assign(
                slot_idx as u32,
                slot_data.group.handle(),
                slot_data.group.uid(),
                false,
            );
            for (cs_idx, queue) in slot_data.group.queues.iter().enumerate() {
                if let Ok((seqno, status)) = slot_data.group.read_syncobj_raw(cs_idx) {
                    trace::csg_syncobj(
                        slot_data.group.handle(),
                        slot_data.group.uid(),
                        cs_idx as u32,
                        trace::CsgSyncobjPhase::Suspend,
                        seqno,
                        status,
                        queue.next_seqno(),
                    );
                }
            }
            slot_data.group.vm.as_data.clear_bound_group();
        }
        slot_data.group.tiler_oom.store(0, Relaxed);

        slot_data.group.vm.idle()?;
        Ok(())
    }
}

/// Type alias for the SlotManager parameterized for CSG slots.
pub(crate) type CsgSlotManager = SlotManager<CsgSlotOps, MAX_CSGS>;

/// One wait-list entry captured by `Scheduler::collect_syncwait_candidates`.
pub(crate) struct SyncwaitCandidate {
    group: Arc<Group>,
    prio: usize,
    blocked: u32,
}

/// Per-group result of `Scheduler::evaluate_syncwait_candidates`.
pub(crate) struct SyncwaitResult {
    group: Arc<Group>,
    prio: usize,
    unblocked: u32,
}

/// Minimal scheduler shell.
///
/// # Lock order
///
/// scheduler > csg_slot_manager > {group.inner, fw.inner}. fw.inner is
/// also taken standalone, so never before csg_slot_manager.
///
/// The scheduler mutex must not be held across gpuvm_unique,
/// dma_resv_lock, or GFP_KERNEL. eval_syncwait reaches BoVmap::new,
/// so the sync_upd path snapshots the wait list, evaluates without the
/// mutex, then re-acquires it to apply.
///
/// The firmware ack wait holds the scheduler mutex but drops the
/// slot-manager mutex around the wait.
pub(crate) struct Scheduler {
    /// Groups that have at least one queue that can be currently scheduled.
    pub(in crate::sched) runnable_groups: [List<Group, 0>; GROUP_PRIORITY_COUNT],
    /// Groups whose queues are all idle (nothing to execute or blocked).
    pub(in crate::sched) idle_groups: [List<Group, 0>; GROUP_PRIORITY_COUNT],
    /// Groups whose queues are blocked on a sync object.
    pub(in crate::sched) waiting_groups: [List<Group, 1>; GROUP_PRIORITY_COUNT],
    /// Number of CSG slots the firmware exposes, capped to `MAX_CSG_PRIO + 1`.
    pub(in crate::sched) csg_slot_count: u32,
    /// Per-tick address-space budget, boxed to keep `Scheduler` small
    /// while probe moves it by value.
    pub(in crate::sched) as_budget: KBox<tick::AsBudget>,
    /// Number of CSG slots used by the most recent tick.
    pub(in crate::sched) used_csg_slot_count: u32,
    /// Set when a resident group may have become idle. The submit path
    /// then ticks immediately to re-evaluate residency. Recomputed from
    /// each tick's idle-group count.
    pub(in crate::sched) might_have_idle_groups: bool,
    /// When the next tick should occur, if any.
    pub(in crate::sched) resched_target: Option<Instant<Monotonic>>,
    /// When the last tick occurred.
    pub(in crate::sched) last_tick: Instant<Monotonic>,
    /// When the last full tick occurred, measured in the same jiffies
    /// clock the periodic tick is armed in. Only a full tick writes
    /// it, so event ticks cannot push the next one out.
    pub(in crate::sched) last_full_tick_jiffies: u64,

    /// Runtime-PM usage reference held while any resident group has work.
    pub(in crate::sched) pm_ref: Option<AwakeScope>,
    /// Latched by a failed runtime resume and cleared by a successful one.
    /// While set, the tick releases the usage reference before asking the
    /// PM core again, since the failed attempt's reference arms nothing.
    pub(in crate::sched) resume_failed: bool,
}

/// The tick to schedule after marking a group runnable.
///
/// Dispatched by the caller once the scheduler mutex is dropped.
pub(crate) enum SubmitTick {
    Immediate,
    /// Re-arm the periodic tick `delay` from now.
    Periodic(Jiffies),
    /// No tick is needed.
    None,
}

impl SubmitTick {
    pub(crate) fn dispatch(self, tdev: &ARef<TyrDrmDevice>) {
        match self {
            Self::Immediate => TyrDrmDeviceData::schedule_tick(tdev),
            Self::Periodic(delay) => TyrDrmDeviceData::schedule_periodic_tick(tdev, delay),
            Self::None => {}
        }
    }
}

impl Scheduler {
    pub(crate) fn init(
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        mmu: &Mmu,
    ) -> Result<(Self, CsifInfo)> {
        let (csg_slot_count, cs_slot_count, cs_reg_count, scoreboard_slot_count) =
            fw.csif_info_counts()?;

        let user_as_slot_count = mmu.as_slot_count().saturating_sub(1);
        if user_as_slot_count == 0 {
            dev_err!(
                tdev.as_ref(),
                "Not enough AS slots ({}, expected at least 2)\n",
                mmu.as_slot_count()
            );
            return Err(EINVAL);
        }

        let as_budget = KBox::new(tick::AsBudget::new(user_as_slot_count), GFP_KERNEL)?;

        // A distinct CSG priority per slot avoids a FW scheduler deadlock,
        // capping the usable slots to the priority count.
        let csg_slot_count = core::cmp::min(MAX_CSG_PRIO + 1, csg_slot_count);

        let csif = CsifInfo::new(
            csg_slot_count,
            cs_slot_count,
            cs_reg_count,
            scoreboard_slot_count,
        );

        // Narrow the manager's iteration bound now that the firmware
        // has reported the real slot count.
        tdev.csg_slot_manager
            .lock()
            .set_slot_count(csg_slot_count as usize)?;

        Ok((
            Self {
                runnable_groups: [const { List::new() }; GROUP_PRIORITY_COUNT],
                idle_groups: [const { List::new() }; GROUP_PRIORITY_COUNT],
                waiting_groups: [const { List::new() }; GROUP_PRIORITY_COUNT],
                csg_slot_count,
                as_budget,
                used_csg_slot_count: 0,
                might_have_idle_groups: false,
                resched_target: None,
                last_tick: Instant::<Monotonic>::now(),
                last_full_tick_jiffies: jiffies64(),
                pm_ref: None,
                resume_failed: false,
            },
            csif,
        ))
    }

    /// Returns whether any priority band has runnable groups queued.
    pub(crate) fn has_runnable_groups(&self) -> bool {
        self.runnable_groups.iter().any(|list| !list.is_empty())
    }

    /// Removes `group` from the list named by `list_state`.
    pub(crate) fn remove_group_from_list(
        &mut self,
        group: &Group,
        priority: usize,
        list_state: GroupListState,
    ) -> Option<ListArc<Group, 0>> {
        let list = match list_state {
            GroupListState::Idle => Some(&mut self.idle_groups[priority]),
            GroupListState::Runnable => Some(&mut self.runnable_groups[priority]),
            GroupListState::None => None,
        };

        if let Some(list) = list {
            // SAFETY: `idle_groups` and `runnable_groups` are both
            // `List<Group, 0>`. Passing `group` to the wrong head would be
            // UB. The match above selects the head named by `list_state`,
            // and every writer of `list_state` holds the scheduler mutex
            // and pairs the `list_state` update with the matching list
            // operation. We hold the scheduler mutex here, so `list_state`
            // agrees with actual list membership and `group` is on `list`.
            let list_arc = unsafe { list.remove(group) };
            if list_arc.is_none() {
                dev_err!(
                    group.tdev.as_ref(),
                    "group was marked {:?} but not found\n",
                    list_state
                );
            }
            list_arc
        } else {
            None
        }
    }

    /// Removes `group` from the wait list at its priority, if it is on
    /// that list.
    fn remove_group_from_wait_list(&mut self, group: &Group) {
        let priority = group.priority as usize;
        let target: *const Group = core::ptr::from_ref(group);
        let mut cursor = self.waiting_groups[priority].cursor_front();
        while let Some(peek) = cursor.peek_next() {
            let here: *const Group = &*peek.arc();
            if core::ptr::eq(here, target) {
                let _ = peek.remove();
                trace::group_wait(group.handle(), false);
                return;
            }
            cursor.move_next();
        }
    }

    /// Detaches `group` from every scheduler list it is currently on.
    ///
    /// The id-0 (idle/runnable) and id-1 (waiting) memberships are
    /// independent, and both are handled.
    pub(crate) fn detach_group(&mut self, group: &Arc<Group>) {
        let priority = group.priority as usize;
        let list_state = group.with_locked_inner(|inner| inner.list_state);

        if !matches!(list_state, GroupListState::None) {
            let _ = self.remove_group_from_list(group, priority, list_state);
            group.with_locked_inner(|inner| {
                inner.list_state = GroupListState::None;
            });
        }

        self.remove_group_from_wait_list(group);
    }

    /// Moves every unbound group that can no longer run from `list` to
    /// `dead`.
    fn take_unrunnable_groups<const ID: u64>(list: &mut List<Group, ID>, dead: &mut List<Group, ID>)
    where
        Group: ListItem<ID>,
    {
        let mut cursor = list.cursor_front();

        while let Some(peek) = cursor.peek_next() {
            let status = peek.arc().status();
            if status.can_run || status.csg_id.is_some() {
                cursor.move_next();
                continue;
            }

            dead.push_back(peek.remove());
        }
    }

    /// Detaches every unbound group that can no longer run, moving its
    /// idle or runnable link to `dead` and its wait-list link to
    /// `dead_waiting`.
    ///
    /// Both lists must be empty on entry. They hold the detached links
    /// until the caller drains them outside the scheduler mutex, so no
    /// path can take a fresh `ListArc` and relist the group.
    pub(crate) fn detach_unrunnable_groups(
        &mut self,
        dead: &mut List<Group, 0>,
        dead_waiting: &mut List<Group, 1>,
    ) {
        for prio in 0..GROUP_PRIORITY_COUNT {
            Self::take_unrunnable_groups(&mut self.idle_groups[prio], dead);
            Self::take_unrunnable_groups(&mut self.runnable_groups[prio], dead);
            Self::take_unrunnable_groups(&mut self.waiting_groups[prio], dead_waiting);
        }

        let mut cursor = dead.cursor_front();
        while let Some(peek) = cursor.peek_next() {
            peek.arc().with_locked_inner(|inner| {
                inner.list_state = GroupListState::None;
            });
            cursor.move_next();
        }
    }

    pub(crate) fn add_group(&mut self, group: Arc<Group>) -> Result {
        let priority = group.priority as usize;
        let list_arc = ListArc::try_from_arc(group.clone()).map_err(|_| EINVAL)?;

        group.with_locked_inner(|inner| {
            inner.list_state = GroupListState::Idle;
        });
        trace::group_list(group.handle(), GroupListState::Idle as u32);

        self.idle_groups[priority].push_back(list_arc);
        Ok(())
    }

    /// Schedules the next scheduler tick `TICK_PERIOD_MS` from now.
    ///
    /// Wraps `TyrDrmDeviceData::schedule_periodic_tick` with the
    /// scheduler-policy-defined period so callers don't have to know
    /// the right delay value. Coalescing semantics are inherited from
    /// the underlying `enqueue_delayed` call. Requesting a tick while
    /// one is already pending does not shorten the existing delay.
    pub(crate) fn request_tick(tdev: &ARef<TyrDrmDevice>) {
        TyrDrmDeviceData::schedule_periodic_tick(tdev, msecs_to_jiffies(tick::TICK_PERIOD_MS));
    }

    /// Schedules the retry of a failed runtime resume, `RESUME_RETRY_MS`
    /// from now. Coalescing matches `Self::request_tick`.
    pub(in crate::sched) fn request_resume_retry(tdev: &ARef<TyrDrmDevice>) {
        TyrDrmDeviceData::schedule_periodic_tick(tdev, msecs_to_jiffies(tick::RESUME_RETRY_MS));
    }

    /// Programs the static CSG_INPUT and per-CS CS_INPUT registers for
    /// a slot the manager has just bound, publishes the binding, and
    /// stages the matching CSG_REQ transition and per-CS doorbell
    /// rings.
    ///
    /// Every fallible step runs before anything is published or staged,
    /// so a failure leaves both the group and the accumulator untouched.
    /// Partially written firmware registers and shared memory stay
    /// inert until a doorbell ring, which only a staged slot receives.
    ///
    /// The caller must hold the slot-manager mutex. The manager has
    /// already recorded the binding by this point, so a caller that
    /// sees an error must evict the seat.
    pub(in crate::sched) fn program_csg_activate(
        fw: &Firmware<'_>,
        group: &Group,
        slot_idx: usize,
        fw_priority: u32,
        context: &mut CsgUpdateContext,
    ) -> Result {
        let csg_idx = CsgSlotIdx::new(slot_idx).ok_or(EINVAL)?;
        let as_slot = group.vm.as_slot().ok_or(EINVAL)?;
        let suspend_va = group.suspend_buf.kernel_va().ok_or(EINVAL)?.start;
        let protm_suspend_va = group.protm_suspend_buf.kernel_va().ok_or(EINVAL)?.start;

        let ep_req = CSG_EP_REQ::zeroed()
            .with_compute_ep(group.max_compute_cores)
            .with_fragment_ep(group.max_fragment_cores)
            .try_with_tiler_ep(group.max_tiler_cores)?
            .try_with_priority(fw_priority)?;
        let config = CSG_CONFIG::zeroed().try_with_jasid(u32::from(as_slot))?;

        let inputs = CsgActivateInputs {
            allow_compute: group.compute_core_mask,
            allow_fragment: group.fragment_core_mask,
            // `tiler_core_mask` is u64 in the UAPI. The firmware only
            // exposes a 32-bit allow mask for "other" endpoints, so
            // the upper bits are silently dropped.
            allow_other: group.tiler_core_mask as u32,
            ep_req,
            suspend_buf: suspend_va,
            protm_suspend_buf: protm_suspend_va,
            config,
        };

        // Per-CS doorbells follow the slot index (`slot_idx + 1`) and
        // remain stable for as long as the slot is active.
        let cs_doorbell = csg_idx.get() as u32 + 1;

        // Fail before any firmware write if a queue's inputs are invalid.
        for queue in group.queues.iter() {
            queue.cs_activate_inputs(cs_doorbell)?;
        }

        for (cs_idx, queue) in group.queues.iter().enumerate() {
            queue.sync_extract_init()?;
            let (insert, extract, extract_init) = queue.ringbuf_state_for_trace()?;
            trace::cs_activate_ringbuf_state(
                group.handle(),
                cs_idx as u32,
                insert,
                extract,
                extract_init,
            );
            if let Ok((seqno, status)) = group.read_syncobj_raw(cs_idx) {
                trace::csg_syncobj(
                    group.handle(),
                    group.uid(),
                    cs_idx as u32,
                    trace::CsgSyncobjPhase::Resume,
                    seqno,
                    status,
                    queue.next_seqno(),
                );
            }
        }

        let mut db_mask = CsDbMask::empty();
        let group_id = group.handle();
        let mut cs_req_writes: [Option<(u32, u32)>; group::MAX_CS_PER_GROUP] =
            [const { None }; group::MAX_CS_PER_GROUP];
        fw.with_csg_mut(slot_idx, |csg| {
            csg.program_activate_inputs(&inputs)?;
            for (cs_idx, queue) in group.indexed_queues() {
                let cs = csg.cs_mut(cs_idx.get()).ok_or(EINVAL)?;
                let cs_input = queue.cs_activate_inputs(cs_doorbell)?;
                let config_raw =
                    (u32::from(cs_input.priority) & 0xf) | ((cs_input.doorbell_id & 0xff) << 8);
                trace::fw_cs_activate_inputs(
                    slot_idx as u32,
                    cs_idx.get() as u32,
                    cs_input.ringbuf_base,
                    cs_input.ringbuf_size,
                    cs_input.ringbuf_input_va,
                    cs_input.ringbuf_output_va,
                    config_raw,
                );
                cs_req_writes[cs_idx.get()] = Some(cs.program_activate_inputs(&cs_input)?);
                db_mask.insert(cs_idx);
            }
            Ok(())
        })?;
        for (cs_idx, write) in cs_req_writes.iter().enumerate() {
            let Some((new_req, update_mask)) = write else {
                break;
            };
            trace::fw_cs_req(
                slot_idx as u32,
                cs_idx as u32,
                group_id,
                *new_req,
                *update_mask,
                0,
            );
        }

        // Publish the per-queue doorbell ids and the bound CSG slot
        // index in one `inner` critical section. `TyrQueueOps::submit`
        // reads `csg_id` and rings the matching `doorbell_id` under the
        // same lock, so it can never see a bound `csg_id` next to an
        // `UNASSIGNED` doorbell. `CsgSlotOps::evict` clears both the
        // same way. The caller holds the slot-manager mutex, matching
        // the `csg_slot_manager > inner` order.
        group.with_locked_inner(|inner| {
            for queue in group.queues.iter() {
                queue.set_doorbell_id(Some(csg_idx.get() + 1));
            }
            inner.csg_id = Some(slot_idx);
        });
        group
            .vm
            .as_data
            .set_bound_group(group.handle(), group.uid(), slot_idx as u32);
        trace::group_bind(group.handle(), group.uid(), slot_idx as u32);
        trace::csg_slot_assign(slot_idx as u32, group.handle(), group.uid(), true);

        let state = match group.state() {
            group::State::Suspended => CsgExecutionState::Resume,
            _ => CsgExecutionState::Start,
        };
        context.set_state(csg_idx, state);
        context.toggle_reqs(csg_idx, CsgReqToggle::EpCfg);
        context.add_db_toggle(csg_idx, db_mask);
        Ok(())
    }

    /// Apply accumulated CSG updates.
    ///
    /// Writes the per-slot CSG_REQ delta, rings the per-CSG
    /// doorbells, waits for firmware acks, then runs the post-ack
    /// sync pass. Returns `ETIMEDOUT` if any slot's request was
    /// not fully acked.
    ///
    /// # Locking
    ///
    /// `Firmware::wait_csg_acks` takes the firmware inner mutex
    /// briefly. Callers must not pre-hold it. The scheduler mutex
    /// may be held throughout.
    ///
    /// The post-ack sync pass takes the `csg_slot_manager` mutex.
    /// Callers must not pre-hold it.
    pub(crate) fn apply_csg_updates(
        &mut self,
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        context: &mut CsgUpdateContext,
    ) -> Result {
        if context.update_mask.is_empty() {
            return Ok(());
        }

        if let Ok(io) = fw.iomem() {
            gpu::trace_shader_power_state(io);
        }

        const CSG_REQ_ACK_TIMEOUT_MS: u32 = 100;

        for csg_id in CsgSlotIdx::all() {
            if !context.update_mask.contains(csg_id) {
                continue;
            }
            let req_mask = context.req_mask[csg_id.get()];
            if req_mask.is_empty() {
                continue;
            }
            let set_mask = req_mask & !CsgUpdateContext::TOGGLE_BITS;
            let toggle_mask = req_mask & CsgUpdateContext::TOGGLE_BITS;
            let req_value = context.req_value[csg_id.get()] & !CsgUpdateContext::TOGGLE_BITS;
            let group_id = tdev
                .csg_slot_manager
                .lock()
                .slot_data(csg_id.get())
                .map(|s| s.group.handle())
                .unwrap_or(0);
            let new_req = fw.with_csg_mut(csg_id.get(), |csg| {
                csg.update_and_toggle_input_req(req_value, set_mask, toggle_mask)
            })?;
            trace::fw_csg_req(
                csg_id.get() as u32,
                group_id,
                new_req.into_raw(),
                set_mask.into_raw(),
                toggle_mask.into_raw(),
            );
        }

        for csg_id in CsgSlotIdx::all() {
            if !context.update_mask.contains(csg_id) {
                continue;
            }
            let db_mask = context.db_toggle[csg_id.get()];
            if db_mask.is_empty() {
                continue;
            }
            fw.with_csg_mut(csg_id.get(), |csg| csg.toggle_input_db_req(db_mask))?;
        }

        fw.ring_csg_doorbells(context.update_mask)?;

        for csg_id in CsgSlotIdx::all() {
            if !context.update_mask.contains(csg_id) {
                continue;
            }
            let req_mask = context.req_mask[csg_id.get()];
            match fw.wait_csg_acks(csg_id.get(), req_mask, CSG_REQ_ACK_TIMEOUT_MS) {
                Ok(acked) => {
                    context.acked_reqs[csg_id.get()] = acked;
                    if acked != req_mask {
                        dev_err!(
                            tdev.as_ref(),
                            "CSG {}: firmware ack timeout: req_mask=0x{:x} acked=0x{:x}\n",
                            csg_id.get(),
                            req_mask,
                            acked
                        );
                        if let Some(re_acked) =
                            self.probe_csg_ack_timeout(tdev, fw, csg_id, req_mask, acked)
                        {
                            context.acked_reqs[csg_id.get()] = re_acked;
                        } else {
                            context.timedout_mask.insert(csg_id);
                        }
                    }
                }
                Err(e) => {
                    dev_err!(
                        tdev.as_ref(),
                        "wait_csg_acks {} failed: {}\n",
                        csg_id.get(),
                        e.to_errno()
                    );
                    context.timedout_mask.insert(csg_id);
                }
            }
        }

        // Take the slot manager and dispatch by which acked bits
        // the firmware reported. The guard is held mutably so
        // `sync_csg_slot_priority` can write back the acknowledged
        // firmware priority into the per-slot `CsgSlotData`.
        let mut csg_slot_manager = tdev.csg_slot_manager.lock();
        for csg_id in CsgSlotIdx::all() {
            if !context.update_mask.contains(csg_id) {
                continue;
            }
            let acked_reqs = context.acked_reqs[csg_id.get()];

            if !(acked_reqs & CSG_REQ_EP_CFG).is_empty() {
                self.sync_csg_slot_priority(fw, &mut csg_slot_manager, csg_id.get())?;
            }
            if !(acked_reqs & CSG_REQ_STATE_MASK).is_empty() {
                self.sync_csg_slot_state(tdev, fw, &csg_slot_manager, csg_id.get())?;
            }
            if !(acked_reqs & CSG_REQ_STATUS_UPDATE).is_empty() {
                self.sync_csg_slot_queues_state(fw, &csg_slot_manager, csg_id.get())?;
            }
        }

        if !context.timedout_mask.is_empty() {
            // `sync_csg_slot_queues_state` is unreachable when STATUS_UPDATE
            // times out, so snapshot the per-CS status registers directly
            // here.
            if let Ok(io) = fw.iomem() {
                gpu::trace_shader_power_state(io);
            }
            for csg_id in CsgSlotIdx::all() {
                if !context.timedout_mask.contains(csg_id) {
                    continue;
                }
                if let Ok((ack, state, ep_cur, ep_req, rdep)) =
                    fw.with_csg_mut(csg_id.get(), |csg| csg.read_output_dump_raw())
                {
                    trace::fw_csg_dump_output(
                        csg_id.get() as u32,
                        ack,
                        state,
                        ep_cur,
                        ep_req,
                        rdep,
                    );
                }

                let (vm, group_uid, queue_count) = csg_slot_manager
                    .slot_data(csg_id.get())
                    .map(|s| {
                        (
                            Some(s.group.vm.clone()),
                            s.group.uid(),
                            core::cmp::min(s.group.queue_count(), group::MAX_CS_PER_GROUP),
                        )
                    })
                    .unwrap_or((None, 0, 0));
                let _ = fw.with_csg_mut(csg_id.get(), |csg| {
                    for cs_id in 0..queue_count {
                        let Some(cs) = csg.cs_mut(cs_id) else {
                            continue;
                        };
                        let req = cs.read_input_req_raw()?;
                        let ack = cs.read_output_ack_raw()?;
                        let status_wait = cs.read_status_wait_raw()?;
                        let reason = cs.read_status_blocked_reason()? as u32;
                        let scoreboards = cs.read_status_scoreboards()?;
                        let sync_ptr = cs.read_status_wait_sync_pointer_raw()?;
                        let (cur_val, cur_val_valid) = match &vm {
                            Some(vm) if trace::cs_status_snapshot_enabled() => {
                                let sync64 = status_wait & (1 << 30) != 0;
                                events::read_syncwait_cur_val(vm, sync_ptr, sync64)
                            }
                            _ => (0, false),
                        };
                        trace::cs_status_snapshot(
                            csg_id.get() as u32,
                            group_uid,
                            cs_id as u32,
                            req,
                            ack,
                            status_wait,
                            reason,
                            scoreboards,
                            sync_ptr,
                            cur_val,
                            cur_val_valid,
                        );
                    }
                    Ok::<_, Error>(())
                });
            }
            return Err(ETIMEDOUT);
        }

        Ok(())
    }

    /// Diagnostic probe for a CSG slot whose ack timed out.
    ///
    /// Reads back the firmware-visible ringbuf state for the bound
    /// group's queues, then re-rings the doorbell for this slot and
    /// waits once more. Returns `Some(acked)` if the re-kick recovered
    /// the slot, in which case the caller proceeds normally; `None` if
    /// it stayed wedged, in which case the caller records the timeout
    /// unchanged.
    ///
    /// Downstream-only debug aid; not for upstream. Distinguishes a
    /// transient CPU->MCU visibility race (re-kick recovers) from
    /// firmware state corruption (re-kick does not).
    fn probe_csg_ack_timeout(
        &mut self,
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        csg_id: CsgSlotIdx,
        req_mask: CSG_REQ,
        acked: CSG_REQ,
    ) -> Option<CSG_REQ> {
        // Snapshot the per-CS ringbuf state under a short-lived slot
        // manager lock; the lock must be dropped before `wait_csg_acks`.
        let mut ringbuf: [Option<(u64, u64)>; group::MAX_CS_PER_GROUP] =
            [const { None }; group::MAX_CS_PER_GROUP];
        {
            let csg_slot_manager = tdev.csg_slot_manager.lock();
            if let Some(slot_data) = csg_slot_manager.slot_data(csg_id.get()) {
                let queue_count =
                    core::cmp::min(slot_data.group.queue_count(), group::MAX_CS_PER_GROUP);
                for (cs_id, slot) in ringbuf.iter_mut().enumerate().take(queue_count) {
                    if let Ok((insert, extract, _)) =
                        slot_data.group.queues[cs_id].ringbuf_state_for_trace()
                    {
                        *slot = Some((insert, extract));
                    }
                }
            }
        }
        for (cs_id, state) in ringbuf.iter().enumerate() {
            if let Some((insert, extract)) = state {
                trace::csg_ack_timeout_state(
                    csg_id.get() as u32,
                    cs_id as u32,
                    req_mask.into_raw(),
                    acked.into_raw(),
                    *insert,
                    *extract,
                );
            }
        }

        // Re-ring the global doorbell for just this slot, then wait once more
        // for the still-pending request.
        const CSG_REQ_ACK_TIMEOUT_MS: u32 = 100;
        let mut rekick_mask = CsgSlotMask::empty();
        rekick_mask.insert(csg_id);
        if let Err(e) = fw.ring_csg_doorbells(rekick_mask) {
            pr_info!(
                "CSG {}: re-kick doorbell failed: {}\n",
                csg_id.get(),
                e.to_errno()
            );
            return None;
        }
        match fw.wait_csg_acks(csg_id.get(), req_mask, CSG_REQ_ACK_TIMEOUT_MS) {
            Ok(re_acked) if re_acked == req_mask => {
                pr_info!(
                    "CSG {}: re-kick recovered ack: req_mask=0x{:x} acked=0x{:x}\n",
                    csg_id.get(),
                    req_mask,
                    re_acked
                );
                Some(re_acked)
            }
            Ok(re_acked) => {
                pr_info!(
                    "CSG {}: re-kick did not recover: req_mask=0x{:x} acked=0x{:x}\n",
                    csg_id.get(),
                    req_mask,
                    re_acked
                );
                None
            }
            Err(e) => {
                pr_info!(
                    "CSG {}: re-kick wait failed: {}\n",
                    csg_id.get(),
                    e.to_errno()
                );
                None
            }
        }
    }

    /// Stages a firmware-priority update for CSG slot `csg_idx`.
    pub(crate) fn update_csg_slot_priority(
        &mut self,
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        csg_slot_manager: &CsgSlotManager,
        csg_idx: usize,
        fw_prio: u32,
        context: &mut CsgUpdateContext,
    ) -> Result {
        if fw_prio > MAX_CSG_PRIO {
            dev_err!(
                tdev.as_ref(),
                "update_csg_slot_priority: invalid fw priority {}\n",
                fw_prio
            );
            return Err(EINVAL);
        }

        let Some(csg_slot) = CsgSlotIdx::new(csg_idx) else {
            dev_err!(
                tdev.as_ref(),
                "update_csg_slot_priority: invalid csg {}\n",
                csg_idx
            );
            return Err(EINVAL);
        };

        let slot_data = csg_slot_manager.slot_data(csg_idx).ok_or(EINVAL)?;
        let group = slot_data.group.clone();

        fw.with_csg_mut(csg_idx, |csg| {
            let ep_req = CSG_EP_REQ::zeroed()
                .with_compute_ep(group.max_compute_cores)
                .with_fragment_ep(group.max_fragment_cores)
                .try_with_tiler_ep(group.max_tiler_cores)?
                .try_with_priority(fw_prio)?;
            csg.write_input_ep_req(ep_req)
        })?;

        context.toggle_reqs(csg_slot, CsgReqToggle::EpCfg);
        Ok(())
    }

    /// Refreshes `CsgSlotData::fw_priority` from the
    /// firmware-acknowledged `CSG_EP_REQ.priority` value.
    fn sync_csg_slot_priority(
        &mut self,
        fw: &Firmware<'_>,
        csg_slot_manager: &mut CsgSlotManager,
        csg_idx: usize,
    ) -> Result {
        let Some(slot_data) = csg_slot_manager.slot_data_mut(csg_idx) else {
            return Ok(());
        };
        let ep_req = fw.with_csg_mut(csg_idx, |csg| csg.read_input_ep_req())?;
        slot_data.fw_priority = ep_req.priority().get();
        Ok(())
    }

    /// Refreshes the resident group's recorded `group::State` from the
    /// firmware-acknowledged `CSG_ACK.state`.
    ///
    /// A transition into `Suspend` also opens the off-slot deadline
    /// credit, except for the queues in `Group::blocked_idle_queues`.
    fn sync_csg_slot_state(
        &mut self,
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        csg_slot_manager: &CsgSlotManager,
        csg_idx: usize,
    ) -> Result {
        let Some(slot_data) = csg_slot_manager.slot_data(csg_idx) else {
            return Ok(());
        };
        let group = slot_data.group.clone();

        let old_state = group.state();

        let ack = fw.with_csg_mut(csg_idx, |csg| csg.read_output_ack())?;
        trace::fw_csg_status_update(csg_idx as u32, group.handle(), ack.into_raw());

        let new_state = match ack.state() {
            Ok(CsgExecutionState::Start) | Ok(CsgExecutionState::Resume) => group::State::Active,
            Ok(CsgExecutionState::Terminate) => group::State::Terminated,
            Ok(CsgExecutionState::Suspend) => group::State::Suspended,
            Err(_) => group::State::Unknown,
        };

        if old_state == new_state {
            return Ok(());
        }

        if new_state == group::State::Unknown {
            group.with_locked_inner(|inner| {
                inner.fatal = true;
            });
            trace::reset_request(trace::ResetReason::CsgStateUnknown);
            tdev.reset.schedule();
        }

        if new_state == group::State::Suspended {
            self.sync_csg_slot_queues_state(fw, csg_slot_manager, csg_idx)?;

            let blocked_idle = group.blocked_idle_queues();
            for (queue_idx, queue) in group.indexed_queues() {
                if (blocked_idle & queue_idx.bit()) != 0 {
                    continue;
                }
                queue.suspend_timeout();
            }
        }

        if old_state == group::State::Active {
            // Reset the per-CS request state so a future `Start`/
            // `Resume` on this slot does not pick up the previous
            // group's CS_REQ bits. No doorbell is needed, because the
            // firmware re-evaluates CS_REQ when the next CSG state
            // transition completes.
            fw.with_csg_mut(csg_idx, |csg| {
                let mut i = 0;
                while let Some(cs) = csg.cs_mut(i) {
                    let _ = cs.clear_input_req_state();
                    i += 1;
                }
                Ok(())
            })?;
        }

        // Publish `Active` before the kick loop below. A submit either
        // sees `Active` and kicks itself, or has already committed its
        // ring bytes, and the loop kicks that queue instead.
        group.set_state(new_state, trace::StateChangeReason::FwAck);

        // On the bind-side `Start`/`Resume` ack, ring the per-CS user
        // doorbell on every queue whose ringbuf already has commands.
        // `Scheduler::program_csg_activate` publishes `doorbell_id`
        // before this point.
        if new_state == group::State::Active {
            for queue in slot_data.group.queues.iter() {
                queue.resume_timeout();
                if queue.is_ringbuf_empty().unwrap_or(true) {
                    continue;
                }
                if let Err(e) = queue.kick() {
                    dev_err!(
                        tdev.as_ref(),
                        "CSG {}: user-doorbell kick on bind failed: {}\n",
                        csg_idx,
                        e.to_errno()
                    );
                }
            }
        }

        Ok(())
    }

    /// Synchronizes the per-CS in-memory state from the CSG output area
    /// after a `CSG_REQ.status_update` ack is observed.
    ///
    /// Walks every CS in the group to classify each queue's state from
    /// `CS_STATUS_BLOCKED_REASON`, `CS_STATUS_WAIT`,
    /// `CS_STATUS_SCOREBOARDS` and (for sync-wait blocked queues) the
    /// `CS_STATUS_WAIT_SYNC_*` words:
    ///
    /// * `Unblocked` with empty ringbuffer (`INSERT == EXTRACT`) and
    ///   no in-flight scoreboard entries -> mark queue idle.
    /// * `SyncWait`: capture the active wait into `QueueData::syncwait`
    ///   and, when no scoreboards are still in flight, mark the queue
    ///   blocked. The group is then pushed onto
    ///   `Scheduler::waiting_groups`.
    /// * Other reasons are not blocking and leave the queue in its
    ///   current classification.
    fn sync_csg_slot_queues_state(
        &mut self,
        fw: &Firmware<'_>,
        csg_slot_manager: &CsgSlotManager,
        csg_idx: usize,
    ) -> Result {
        let Some(slot_data) = csg_slot_manager.slot_data(csg_idx) else {
            return Ok(());
        };
        let group = slot_data.group.clone();
        let priority = group.priority as usize;

        // Snapshot the per-CS firmware state under one
        // `with_csg_mut`. The arrays are sized to
        // `MAX_CS_PER_GROUP` (the width of the per-queue bitmasks
        // in `GroupInner`) so this stays allocation-free.
        let mut blocked_reasons: [Option<CsBlockedReason>; group::MAX_CS_PER_GROUP] =
            [const { None }; group::MAX_CS_PER_GROUP];
        let mut scoreboards: [u32; group::MAX_CS_PER_GROUP] = [0; group::MAX_CS_PER_GROUP];
        let mut sync_waits: [Option<CsStatusWait>; group::MAX_CS_PER_GROUP] =
            [const { None }; group::MAX_CS_PER_GROUP];

        let group_handle = group.handle();
        let group_uid = group.uid();
        if let Ok((ack, state, ep_cur, ep_req, rdep)) =
            fw.with_csg_mut(csg_idx, |csg| csg.read_output_dump_raw())
        {
            trace::fw_csg_dump_output(csg_idx as u32, ack, state, ep_cur, ep_req, rdep);
        }
        fw.with_csg_mut(csg_idx, |csg| {
            for (cs_id, _) in group.indexed_queues() {
                let Some(cs) = csg.cs_mut(cs_id.get()) else {
                    continue;
                };
                let reason = cs.read_status_blocked_reason()?;
                trace::fw_cs_status_update(
                    csg_idx as u32,
                    cs_id.get() as u32,
                    group_handle,
                    reason as u32,
                );
                blocked_reasons[cs_id.get()] = Some(reason);
                scoreboards[cs_id.get()] = cs.read_status_scoreboards()?;

                let cs_req_raw = cs.read_input_req_raw()?;
                let cs_ack_raw = cs.read_output_ack_raw()?;
                let status_wait_raw = cs.read_status_wait_raw()?;
                let sync_pointer = cs.read_status_wait_sync_pointer_raw()?;
                let (cur_val, cur_val_valid) = if trace::cs_status_snapshot_enabled() {
                    let sync64 = status_wait_raw & (1 << 30) != 0;
                    events::read_syncwait_cur_val(&group.vm, sync_pointer, sync64)
                } else {
                    (0, false)
                };
                trace::cs_status_snapshot(
                    csg_idx as u32,
                    group_uid,
                    cs_id.get() as u32,
                    cs_req_raw,
                    cs_ack_raw,
                    status_wait_raw,
                    reason as u32,
                    scoreboards[cs_id.get()],
                    sync_pointer,
                    cur_val,
                    cur_val_valid,
                );

                if reason == CsBlockedReason::SyncWait {
                    let wait = cs.read_status_wait_sync()?;
                    let sync_size = if wait.sync64 { 8u32 } else { 4u32 };
                    trace::cs_sync_wait_operand(
                        group_handle,
                        cs_id.get() as u32,
                        wait.sync_ptr,
                        wait.ref_val,
                        sync_size,
                    );
                    sync_waits[cs_id.get()] = Some(wait);
                }
            }

            Ok::<_, Error>(())
        })?;

        for ((cs_id, queue), sync_wait) in group.indexed_queues().zip(sync_waits.iter_mut()) {
            if let Some(wait) = sync_wait.take() {
                let (cur_val, cur_val_valid) = if trace::syncwait_capture_enabled() {
                    events::read_syncwait_cur_val(&group.vm, wait.sync_ptr, wait.sync64)
                } else {
                    (0, false)
                };
                trace::syncwait_capture(
                    group.vm.handle(),
                    group_handle,
                    group_uid,
                    cs_id.get() as u32,
                    wait.sync_ptr,
                    wait.ref_val,
                    wait.sync64,
                    wait.condition == Some(CsWaitCondition::Gt),
                    cur_val,
                    cur_val_valid,
                );
                queue.set_syncwait(wait.sync_ptr, wait.ref_val, wait.sync64, wait.condition);
            }
        }

        // Apply the per-queue classification under the inner lock.
        // Returns whether any queue ended up blocked on a sync object,
        // which decides if the group needs to land on the wait list.
        let has_sync_wait = group.with_locked_inner(|inner| {
            let mut has_sync_wait = false;

            for (cs_id, queue) in group.indexed_queues() {
                let mut idle = false;
                let mut blocked = false;

                match blocked_reasons[cs_id.get()] {
                    // `is_ringbuf_empty` reads firmware-shared memory directly, not
                    // through the firmware lock, so probing it here under `inner` is safe.
                    Some(CsBlockedReason::Unblocked)
                        if scoreboards[cs_id.get()] == 0
                            && queue.is_ringbuf_empty().unwrap_or(false) =>
                    {
                        idle = true;
                    }
                    Some(CsBlockedReason::Unblocked) => {}
                    Some(CsBlockedReason::SyncWait) => {
                        has_sync_wait = true;
                        // Only blocked if there is no deferred work
                        // still resolving on the scoreboards.
                        if scoreboards[cs_id.get()] == 0 {
                            blocked = true;
                        }
                    }
                    _ => {
                        // Other reasons (`SbWait`, `ProgressWait`,
                        // `Deferred`, `Resource`, `Flush`, `Unknown`)
                        // do not count as scheduler-visible blocks.
                        // The queue is still considered runnable.
                    }
                }

                inner.set_queue_idle(cs_id, idle);
                inner.set_queue_blocked(cs_id, blocked);
                trace::queue_blocked_state_change(
                    group_handle,
                    cs_id.get() as u32,
                    blocked,
                    trace::QueueBlockedCaller::SyncSlotApply,
                );
                trace::queue_idle_state(group_handle, cs_id.get() as u32, idle);
                trace::queue_state(group_handle, cs_id.get() as u32, blocked);
            }

            has_sync_wait
        });

        // Push the group onto the per-priority wait list once any
        // queue is blocked on a sync object. `try_from_arc` fails if
        // a `ListArc<Group, 1>` is already outstanding for this
        // group, which both prevents duplicate inserts and keeps the
        // wait-list link single-owner so a list walker can iterate
        // without racing concurrent inserts.
        if has_sync_wait {
            let group_handle = group.handle();
            if let Ok(wait_arc) = ListArc::<Group, 1>::try_from_arc(group) {
                self.waiting_groups[priority].push_back(wait_arc);
                trace::group_wait(group_handle, true);
            }
        }

        Ok(())
    }

    /// Appends every group on `list` to `out`, returning `false` if
    /// `out` could not grow.
    fn collect_list(list: &mut List<Group, 0>, out: &mut KVec<Arc<Group>>) -> bool {
        let mut cursor = list.cursor_front();
        while let Some(peek) = cursor.peek_next() {
            let group: Arc<Group> = peek.arc().into();
            if out.push(group, GFP_NOWAIT).is_err() {
                return false;
            }
            cursor.move_next();
        }
        true
    }

    /// Snapshots every group on the runnable and idle lists.
    ///
    /// Allocates with `GFP_NOWAIT` so the caller can hold the scheduler
    /// mutex without recording an `fs_reclaim` edge against it.
    /// Allocation failure ends the walk and returns what was collected.
    pub(crate) fn collect_listed_groups(&mut self, tdev: &TyrDrmDevice) -> KVec<Arc<Group>> {
        let mut groups = KVec::new();

        for prio in 0..GROUP_PRIORITY_COUNT {
            if !Self::collect_list(&mut self.runnable_groups[prio], &mut groups)
                || !Self::collect_list(&mut self.idle_groups[prio], &mut groups)
            {
                dev_err!(
                    tdev.as_ref(),
                    "reset: out of memory snapshotting the group lists\n"
                );
                break;
            }
        }

        groups
    }

    /// Detaches and terminates every group on `list`, canceling its fences.
    fn terminate_list(list: &mut List<Group, 0>) {
        while let Some(list_arc) = list.pop_front() {
            let group: Arc<Group> = list_arc.into_arc();
            group.with_locked_inner(|inner| {
                inner.list_state = GroupListState::None;
                inner.state = group::State::Terminated;
                inner.fatal = true;
            });
            group.schedule_term();
        }
    }

    /// Terminates every group on the scheduler lists.
    ///
    /// Called after a failed GPU reset or at unbind, when the hardware is
    /// unusable. Each group is detached, marked terminated, and routed
    /// through `Group::schedule_term` so its queued and in-flight fences
    /// are canceled. Nothing is bound at this point. The pre-reset or
    /// suspend pass evicted every CSG slot.
    pub(crate) fn fail_all_groups(&mut self) {
        for prio in 0..GROUP_PRIORITY_COUNT {
            Self::terminate_list(&mut self.runnable_groups[prio]);
            Self::terminate_list(&mut self.idle_groups[prio]);

            // Groups on the wait list may also have been on an id-0
            // list above. The `term_scheduled` flag stops the terminal
            // cleanup running twice.
            while let Some(wait_arc) = self.waiting_groups[prio].pop_front() {
                let group: Arc<Group> = wait_arc.into_arc();
                trace::group_wait(group.handle(), false);
                group.with_locked_inner(|inner| {
                    inner.state = group::State::Terminated;
                    inner.fatal = true;
                });
                group.schedule_term();
            }
        }

        // No runnable work remains. Release the usage reference so the
        // unusable device is not pinned active.
        if self.pm_ref.is_some() {
            trace::pm_usage(trace::PmUsageEvent::Release, false);
        }
        self.pm_ref = None;

        // No tick is armed once every group fails, so clear the coalescing
        // state. Stale full-residency values would make a later submit skip
        // its own tick, and no other tick source survives a dead device.
        self.resched_target = None;
        self.used_csg_slot_count = 0;
        self.might_have_idle_groups = false;
    }

    /// Requeues a group onto the idle or runnable list.
    pub(crate) fn requeue_group(&mut self, list_arc: ListArc<Group, 0>, is_idle: bool) {
        let group_arc: Arc<Group> = list_arc.clone_arc();
        let priority = group_arc.priority as usize;

        let new_state = if is_idle {
            group::GroupListState::Idle
        } else {
            group::GroupListState::Runnable
        };
        group_arc.with_locked_inner(|inner| {
            inner.list_state = new_state;
        });
        trace::group_list(group_arc.handle(), new_state as u32);

        if is_idle {
            self.idle_groups[priority].push_back(list_arc);
        } else {
            self.runnable_groups[priority].push_back(list_arc);
        }
    }

    /// Marks `group` as runnable, moving it onto the runnable list at
    /// its priority if it is not already there.
    ///
    /// This is idempotent. A group already on the runnable list, or
    /// is currently bound to a CSG slot, is left in place. An idle
    /// group is moved off `Scheduler::idle_groups` onto
    /// `Scheduler::runnable_groups`. Only the id-0 lists are
    /// manipulated. The wait-list (id-1) is owned elsewhere.
    pub(crate) fn mark_group_runnable(&mut self, group: &Arc<Group>) {
        let priority = group.priority as usize;

        group.with_locked_inner(|inner| {
            if inner.fatal || group.vm.is_unusable() {
                return;
            }

            match inner.list_state {
                group::GroupListState::Runnable => {}
                group::GroupListState::None => {
                    // Not on any id-0 list. Promote to runnable only
                    // if the group is not currently bound. Bound
                    // groups already get scheduled via the per-tick
                    // `Keep` rules and don't need a runnable-list
                    // entry.
                    if inner.csg_id.is_none() {
                        if let Ok(list_arc) = ListArc::try_from_arc(group.clone()) {
                            self.runnable_groups[priority].push_back(list_arc);
                            inner.list_state = group::GroupListState::Runnable;
                            trace::group_list(
                                group.handle(),
                                group::GroupListState::Runnable as u32,
                            );
                        }
                    }
                }
                group::GroupListState::Idle => {
                    if let Some(list_arc) =
                        self.remove_group_from_list(group, priority, group::GroupListState::Idle)
                    {
                        self.runnable_groups[priority].push_back(list_arc);
                        inner.list_state = group::GroupListState::Runnable;
                        trace::group_list(group.handle(), group::GroupListState::Runnable as u32);
                    }
                }
            }
        });
    }

    /// Decides which tick a submit should schedule after marking its group
    /// runnable. A real-time group, a possibly-idle resident group, or a free
    /// slot ticks now. With every slot busy the submit rides the periodic tick.
    pub(crate) fn submit_tick(&mut self, priority: Priority) -> SubmitTick {
        if priority == Priority::RealTime {
            return SubmitTick::Immediate;
        }

        if self.might_have_idle_groups {
            return SubmitTick::Immediate;
        }

        if self.resched_target.is_some() {
            if self.used_csg_slot_count < self.csg_slot_count {
                return SubmitTick::Immediate;
            }
            return SubmitTick::None;
        }

        self.resume_tick()
    }

    /// Decides which tick a submit to a resident group schedules after it
    /// feeds a queue that was idle. An armed tick already re-evaluates
    /// residency, so only a stopped one restarts.
    pub(crate) fn resident_submit_tick(&mut self) -> SubmitTick {
        if self.resched_target.is_some() {
            return SubmitTick::None;
        }

        self.resume_tick()
    }

    /// Restarts a stopped tick at the rotation deadline, or now once that
    /// deadline has passed or a slot is free.
    fn resume_tick(&mut self) -> SubmitTick {
        let period_ms = i64::from(tick::TICK_PERIOD_MS);
        self.resched_target = Some(self.last_tick + Delta::from_millis(period_ms));

        let elapsed_ms = self.last_tick.elapsed().as_millis();
        if self.used_csg_slot_count == self.csg_slot_count && elapsed_ms < period_ms {
            SubmitTick::Periodic(msecs_to_jiffies((period_ms - elapsed_ms) as u32))
        } else {
            SubmitTick::Immediate
        }
    }

    /// Drains every resident queue's pending submit fences whose
    /// `done_seqno` is at or below the per-queue syncobj value.
    ///
    /// Must be called outside `TyrDrmDeviceData::with_locked_scheduler`.
    /// The per-queue `complete_submit_fences` opens a
    /// `DmaFenceSignallingAnnotation` and signals user-visible
    /// dma-fences, and signalling-section code may not nest inside a
    /// wide driver lock like the scheduler mutex.
    ///
    /// Snapshots the bound groups under the slot-manager lock and
    /// drops it before touching firmware-shared memory. The snapshot
    /// is a fixed-capacity `[Option<Arc<Group>>; MAX_CSGS]` so this
    /// stays allocation-free. Per-queue read errors are logged and
    /// skipped.
    pub(crate) fn drain_resident_queue_completions(tdev: &TyrDrmDevice) {
        let mut snapshot: [Option<Arc<Group>>; MAX_CSGS] = [const { None }; MAX_CSGS];
        {
            let csg_slot_manager = tdev.csg_slot_manager.lock();
            for (csg_idx, slot) in snapshot.iter_mut().enumerate() {
                if let Some(slot_data) = csg_slot_manager.slot_data(csg_idx) {
                    *slot = Some(slot_data.group.clone());
                }
            }
        }

        Self::drain_queue_completions(tdev, &snapshot);
    }

    /// Drains the queues of `groups` like `drain_resident_queue_completions`.
    /// Must be called outside `TyrDrmDeviceData::with_locked_scheduler`.
    fn drain_queue_completions(tdev: &TyrDrmDevice, groups: &[Option<Arc<Group>>]) {
        for entry in groups.iter() {
            let Some(group) = entry else {
                continue;
            };
            for (queue_idx, queue) in group.queues.iter().enumerate() {
                match group.read_syncobj_raw(queue_idx) {
                    Ok((seqno, status)) => queue.complete_submit_fences(group, seqno, status),
                    Err(err) => dev_err!(
                        tdev.as_ref(),
                        "queue completion drain failed: {}\n",
                        err.to_errno()
                    ),
                }
            }
        }
    }

    /// Snapshots the wait list under the scheduler mutex.
    ///
    /// Walks `waiting_groups` and records `(Arc<Group>, prio,
    /// blocked_bitmap)` for every group with at least one blocked
    /// queue. Allocates with `GFP_NOWAIT` so the caller can hold the
    /// scheduler mutex without recording an `fs_reclaim` edge against
    /// it. Allocation failure aborts the walk and the next sync_upd
    /// or periodic tick will revisit.
    ///
    /// Pair with `evaluate_syncwait_candidates` and
    /// `apply_syncwait_results`.
    pub(crate) fn collect_syncwait_candidates(
        &mut self,
        tdev: &TyrDrmDevice,
    ) -> KVec<SyncwaitCandidate> {
        let mut snapshot = KVec::new();

        for prio in 0..GROUP_PRIORITY_COUNT {
            let mut cursor = self.waiting_groups[prio].cursor_front();
            while let Some(peek) = cursor.peek_next() {
                let group: Arc<Group> = peek.arc().into();
                let blocked = group.with_locked_inner(|inner| inner.blocked_queues());
                if snapshot
                    .push(
                        SyncwaitCandidate {
                            group,
                            prio,
                            blocked,
                        },
                        GFP_NOWAIT,
                    )
                    .is_err()
                {
                    dev_err!(
                        tdev.as_ref(),
                        "sync_upd: out of memory snapshotting wait list\n"
                    );
                    return snapshot;
                }
                cursor.move_next();
            }
        }

        snapshot
    }

    /// Evaluates each candidate's blocked queues without holding the
    /// scheduler mutex.
    ///
    /// `Group::eval_syncwait` takes the per-VM gpuvm mutex and may
    /// `GFP_KERNEL`-vmap a foreign BO, both of which would close a
    /// lockdep cycle through `dma_fence_map` if the scheduler mutex
    /// were held. Evaluation errors unblock the queue, and only the first
    /// one is logged. Allocation failure on the results vector drops the
    /// remaining candidates. The periodic tick will revisit.
    pub(crate) fn evaluate_syncwait_candidates(
        dev: &Device<Bound>,
        fw: &Firmware<'_>,
        snapshot: KVec<SyncwaitCandidate>,
    ) -> KVec<SyncwaitResult> {
        let mut results = KVec::new();

        for candidate in snapshot {
            let mut unblocked: u32 = 0;
            let mut tested = candidate.blocked;
            while tested != 0 {
                let cs_id = tested.trailing_zeros();
                tested &= !(1u32 << cs_id);
                match candidate.group.eval_syncwait(dev, fw, cs_id as usize) {
                    Ok(true) => unblocked |= 1u32 << cs_id,
                    Ok(false) => {}
                    Err(e) => {
                        let gpu_va = candidate
                            .group
                            .queues
                            .get(cs_id as usize)
                            .map(|q| q.syncwait_snapshot().gpu_va)
                            .unwrap_or(0);
                        pr_warn_once!(
                            "eval_syncwait failed: group={} cs={} gpu_va={:#x}: {:?}\n",
                            candidate.group.handle(),
                            cs_id,
                            gpu_va,
                            e,
                        );
                        unblocked |= 1u32 << cs_id;
                    }
                }
            }

            if results
                .push(
                    SyncwaitResult {
                        group: candidate.group,
                        prio: candidate.prio,
                        unblocked,
                    },
                    GFP_KERNEL,
                )
                .is_err()
            {
                return results;
            }
        }

        results
    }

    /// Applies the results from `evaluate_syncwait_candidates`
    /// under the scheduler mutex.
    ///
    /// An unbound group becomes runnable once any of its queues is
    /// unblocked, and a group leaves the wait list once none is blocked.
    /// Unblocking a queue of a resident group marks devfreq busy and takes
    /// the scheduler runtime-PM reference.
    /// Results are re-validated against the live wait list, so a group
    /// that another path removed between the snapshot and the apply is
    /// skipped.
    ///
    /// Caller must not drop `results` before releasing the scheduler
    /// mutex.
    ///
    /// Returns an immediate tick for a promoted real-time group and a
    /// periodic one for any other promotion. Without a promotion, an
    /// unblocked queue on an idle resident group restarts a stopped tick.
    pub(crate) fn apply_syncwait_results(
        &mut self,
        tdev: &TyrDrmDevice,
        results: &KVec<SyncwaitResult>,
    ) -> SubmitTick {
        let mut immediate_tick = false;
        let mut promoted = false;
        let mut resident_unblocked = false;
        let mut resident_woken = false;

        for prio in 0..GROUP_PRIORITY_COUNT {
            // Stage the wait-list links of groups that should move to
            // the runnable list. A `List<Group, 1>` does not allocate
            // and lets us release the wait-list cursor before
            // re-borrowing `self` mutably for `mark_group_runnable`.
            let mut make_runnable = List::<Group, 1>::new();

            {
                let mut cursor = self.waiting_groups[prio].cursor_front();
                while let Some(peek) = cursor.peek_next() {
                    let group_ptr: *const Group = &*peek.arc();
                    let result = results
                        .iter()
                        .find(|r| r.prio == prio && core::ptr::eq(&*r.group, group_ptr));

                    let Some(result) = result else {
                        cursor.move_next();
                        continue;
                    };

                    let group_handle = result.group.handle();
                    let (unblocked, move_to_runnable) = result.group.with_locked_inner(|inner| {
                        let was_idle = inner.is_idle();
                        let cleared = result.unblocked & inner.blocked_queues();
                        for cs_id in QueueIdx::iter_mask(result.unblocked) {
                            inner.set_queue_blocked(cs_id, false);
                            trace::queue_blocked_state_change(
                                group_handle,
                                cs_id.get() as u32,
                                false,
                                trace::QueueBlockedCaller::ApplyResults,
                            );
                        }

                        let unblocked = !inner.has_blocked_queues();
                        let move_to_runnable = result.unblocked != 0 && inner.csg_id.is_none();
                        if cleared != 0 && inner.csg_id.is_some() {
                            resident_unblocked = true;
                            resident_woken |= was_idle && !inner.is_idle();
                        }
                        (unblocked, move_to_runnable)
                    });

                    if unblocked || move_to_runnable {
                        let list_arc = peek.remove();
                        if unblocked {
                            trace::group_wait(result.group.handle(), false);
                        }
                        if move_to_runnable {
                            if prio == Priority::RealTime as usize {
                                immediate_tick = true;
                            }
                            promoted = true;
                            make_runnable.push_back(list_arc);
                        }
                    } else {
                        cursor.move_next();
                    }
                }
            }

            // The wait-list cursor borrow is dropped, so we can now
            // re-borrow `self` mutably for `mark_group_runnable`.
            while let Some(list_arc) = make_runnable.pop_front() {
                let group: Arc<Group> = list_arc.clone_arc();
                self.mark_group_runnable(&group);
                if group.with_locked_inner(|inner| inner.has_blocked_queues()) {
                    self.waiting_groups[prio].push_back(list_arc);
                }
            }
        }

        if resident_unblocked {
            tdev.devfreq_data.devfreq_state.lock().mark_busy();
            if self.pm_ref.is_none() {
                self.pm_ref = tdev.sched_pm_get();
            }
        }

        if immediate_tick {
            SubmitTick::Immediate
        } else if promoted {
            SubmitTick::Periodic(msecs_to_jiffies(tick::TICK_PERIOD_MS))
        } else if resident_woken {
            self.resident_submit_tick()
        } else {
            SubmitTick::None
        }
    }

    /// Returns whether an unbound idle group that can still run waits on a
    /// sync object.
    pub(crate) fn needs_syncwait_poll(&self) -> bool {
        self.waiting_groups.iter().flatten().any(|group| {
            !group.vm.is_unusable()
                && group.with_locked_inner(|inner| {
                    inner.can_run()
                        && inner.csg_id.is_none()
                        && inner.is_idle()
                        && inner.has_blocked_queues()
                })
        })
    }

    /// Stages `CSG_REQ.STATUS_UPDATE` on every resident CSG slot and
    /// applies the batch. The post-ack sync pass refreshes per-queue
    /// firmware-status state.
    pub(crate) fn sync_group_states(&mut self, tdev: &TyrDrmDevice, fw: &Firmware<'_>) -> Result {
        let mut context = CsgUpdateContext::new();
        let mut faulted_groups: [Option<(usize, Arc<Group>)>; MAX_CSGS] =
            [const { None }; MAX_CSGS];

        {
            let csg_slot_manager = tdev.csg_slot_manager.lock();
            for (csg_idx, slot) in CsgSlotIdx::all()
                .zip(faulted_groups.iter_mut())
                .take(csg_slot_manager.slot_count())
            {
                let Some(slot_data) = csg_slot_manager.slot_data(csg_idx.get()) else {
                    continue;
                };
                if slot_data.group.vm.as_data.unhandled_fault.load(Relaxed) {
                    *slot = Some((csg_idx.get(), slot_data.group.clone()));
                }
                context.toggle_reqs(csg_idx, CsgReqToggle::StatusUpdate);
            }
        }

        for slot in faulted_groups.iter() {
            let Some((csg_idx, group)) = slot else {
                continue;
            };
            if let Err(e) = self.process_csg_irq(tdev, fw, *csg_idx) {
                dev_err!(
                    tdev.as_ref(),
                    "process_csg_irq {} failed: {}\n",
                    csg_idx,
                    e.to_errno()
                );
            }
            let queue_count = group.queue_count();
            group.with_locked_inner(|inner| {
                if inner.has_fatal_queues() {
                    return;
                }
                for cs_id in QueueIdx::all().take(queue_count) {
                    inner.set_queue_fatal(cs_id);
                    trace::queue_fatal_state(group.handle(), cs_id.get() as u32, true);
                }
            });
        }

        self.apply_csg_updates(tdev, fw, &mut context)
    }

    /// Snapshots live groups into the caller-provided `out` buffer for
    /// the periodic heap-state dump. Only `Arc<Group>` clones (refcount
    /// bumps) happen under the locks; `out` is preallocated by the
    /// caller with `push_within_capacity` used for the fill, so no
    /// allocation occurs while the scheduler or slot-manager mutex is
    /// held. This matters because the scheduler mutex is also taken
    /// inside a dma-fence signalling section (the tick worker), so an
    /// `fs_reclaim` edge against it would close a circular lock
    /// dependency.
    ///
    /// The caller resolves each group's `heap_pool` and runs the dump
    /// after dropping the locks, so the per-pool `try_lock` and the
    /// kernel-vmap reads stay lock-free with respect to the scheduler.
    /// Groups beyond `out`'s capacity are dropped; this is a debug aid,
    /// so a best-effort snapshot is acceptable.
    ///
    /// Covers groups parked on the runnable/idle/waiting priority
    /// lists *and* groups currently bound to a CSG slot. The latter
    /// are tracked in `tdev.csg_slot_manager` only, so without the
    /// slot-manager walk a steady-state workload (one group resident
    /// on a slot) would emit no dump events at all.
    ///
    /// Downstream-only debug aid; not for upstream.
    pub(crate) fn collect_heap_pools_for_trace(
        &self,
        tdev: &TyrDrmDevice,
        out: &mut KVec<Arc<Group>>,
    ) {
        for list in self.runnable_groups.iter() {
            for group in list.iter() {
                let _ = out.push_within_capacity(group.into());
            }
        }
        for list in self.idle_groups.iter() {
            for group in list.iter() {
                let _ = out.push_within_capacity(group.into());
            }
        }
        for list in self.waiting_groups.iter() {
            for group in list.iter() {
                let _ = out.push_within_capacity(group.into());
            }
        }

        let slot_manager = tdev.csg_slot_manager.lock();
        for csg_id in 0..MAX_CSGS {
            if let Some(data) = slot_manager.slot_data(csg_id) {
                let _ = out.push_within_capacity(data.group.clone());
            }
        }
    }

    /// Resolves the heap pool of each snapshotted group and emits the
    /// dump tracepoints. Runs outside the scheduler and slot-manager
    /// mutexes (so the resolution and the dump can take per-pool locks
    /// and allocate), consuming the group buffer produced by
    /// `collect_heap_pools_for_trace`. Groups whose `heap_pool` mutex is
    /// contended are silently skipped via `Group::try_get_heap_pool`;
    /// duplicates that arise from a group appearing on both a priority
    /// list and a CSG slot are filtered by `Arc::ptr_eq` on the pool.
    ///
    /// Downstream-only debug aid; not for upstream.
    pub(crate) fn dump_heap_pools_for_trace(groups: &KVec<Arc<Group>>) {
        let mut seen: KVec<Arc<heap::Pool>> = KVec::new();
        for group in groups.iter() {
            let Some(pool) = group.try_get_heap_pool() else {
                continue;
            };
            if seen.iter().any(|p| Arc::ptr_eq(p, &pool)) {
                continue;
            }
            pool.dump_for_trace(group.handle(), 0);
            let _ = seen.push(pool, GFP_KERNEL);
        }
    }
}
