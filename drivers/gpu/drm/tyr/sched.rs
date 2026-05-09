// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::Ordering;

use kernel::{
    list::{
        List,
        ListArc, //
    },
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    },
    time::{
        msecs_to_jiffies,
        Instant,
        Monotonic, //
    },
    types::ScopeGuard,
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    fw,
    fw::{
        global::{
            csg::Priority,
            CsActivateInputs,
            CsgActivateInputs,
            //
        },
        CsBlockedReason,
        CsWaitCondition,
        CsgExecutionState,
        CSG_CONFIG,
        CSG_EP_REQ,
        CSG_REQ, //
    },
    sched::group::GroupListState,
    slot::SlotManager, //
};

use group::Group;

const GROUP_PRIORITY_COUNT: usize = Priority::num_priorities();

/// Maximum number of CSG slots the scheduler can address.
///
/// Matches [`fw::MAX_CSG`], the firmware-imposed hardware ceiling. It is
/// the `MAX_SLOTS` parameter of [`CsgSlotManager`] and bounds the
/// fixed-capacity per-tick accumulator [`CsgUpdateContext`], so callbacks
/// never have to allocate from the dma-fence-signalling-critical tick
/// path.
pub(crate) const MAX_CSGS: usize = fw::MAX_CSG;

/// Highest firmware priority value assignable to a CSG (`CSG_EP_REQ.priority` field).
pub(crate) const MAX_CSG_PRIO: u32 = 0xf;

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

/// Per-slot driver data attached to a [`CsgSlotManager`] slot.
///
/// The [`SlotManager`] hands a borrow of this back to
/// [`CsgSlotOps::activate`] and [`CsgSlotOps::evict`] alongside the slot
/// index and the per-tick [`CsgUpdateContext`].
pub(crate) struct CsgSlotData {
    /// The group that currently owns the slot.
    pub(in crate::sched) group: Arc<Group>,
    /// CSG firmware priority programmed into `CSG_EP_REQ.priority`.
    pub(in crate::sched) fw_priority: u32,
}

/// Per-tick accumulator for CSG slot programming.
///
/// CSG slot operations need to coalesce multiple per-slot writes into a
/// single CSG_REQ word, ring the per-CSG doorbell once, then wait for
/// the firmware to acknowledge the resulting state transitions. The
/// activate / evict callbacks of [`CsgSlotOps`] update this accumulator
/// while the slot-manager mutex is held; [`Scheduler::apply_csg_updates`]
/// then drives the firmware-visible side of the transaction with both
/// the scheduler and slot-manager mutexes dropped.
///
/// The arrays are sized to [`MAX_CSGS`] so the accumulator can be
/// stack-allocated by the tick worker. This keeps the per-tick path
/// free of `GFP_KERNEL` allocations and therefore safe inside a
/// `dma_fence_begin_signalling()` section once the rest of the tick
/// path is brought up to that contract.
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
    pub(crate) db_toggle: [u32; MAX_CSGS],
    pub(crate) update_mask: u32,
    /// Bitmask of CSG slot indices whose request timed out during the
    /// most recent apply cycle.
    pub(crate) timedout_mask: u32,
}

/// CSG_REQ::state field mask (bits 2:0). The firmware transitions all
/// three bits as a unit.
const CSG_REQ_STATE_MASK: CSG_REQ = CSG_REQ::from_raw(CSG_REQ::STATE_MASK);
/// CSG_REQ::ep_cfg bit (4:4). Endpoint-configuration toggle.
const CSG_REQ_EP_CFG: CSG_REQ = CSG_REQ::from_raw(CSG_REQ::EP_CFG_MASK);
/// CSG_REQ::status_update bit (5:5). Status-update toggle.
#[allow(dead_code)]
const CSG_REQ_STATUS_UPDATE: CSG_REQ = CSG_REQ::from_raw(CSG_REQ::STATUS_UPDATE_MASK);

impl CsgUpdateContext {
    /// Bits that the firmware expects to be toggled instead of set.
    ///
    /// Both `ep_cfg` and `status_update` are notification-style bits:
    /// the driver flips the request bit, the firmware mirrors the
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
            db_toggle: [0; MAX_CSGS],
            update_mask: 0,
            timedout_mask: 0,
        }
    }

    /// Stages an update of `mask` bits in `CSG_REQ` for `csg_idx` to
    /// the corresponding bits in `value`.
    ///
    /// Subsequent stages on the same slot replace the bits in `mask`,
    /// and the union of all `mask`s passed for a slot is what
    /// [`Scheduler::apply_csg_updates`] will toggle in `CSG_REQ` and
    /// wait for.
    pub(crate) fn queue_reqs(&mut self, csg_idx: usize, value: CSG_REQ, mask: CSG_REQ) {
        debug_assert!(csg_idx < MAX_CSGS);
        debug_assert!(!mask.is_empty());

        self.req_value[csg_idx] = (self.req_value[csg_idx] & !mask) | (value & mask);
        self.req_mask[csg_idx] |= mask;
        self.update_mask |= 1u32 << csg_idx;
    }

    /// Stages a toggle of `toggle_bit` in `CSG_REQ` for `csg_idx`.
    ///
    /// `toggle_bit` must be a subset of [`Self::TOGGLE_BITS`]; the
    /// `apply_csg_updates` partition assumes set and toggle bits never
    /// overlap.
    pub(crate) fn toggle_reqs(&mut self, csg_idx: usize, toggle_bit: CSG_REQ) {
        debug_assert!((toggle_bit & !Self::TOGGLE_BITS).is_empty());
        self.queue_reqs(csg_idx, toggle_bit, toggle_bit);
    }

    /// Stages a `CSG_REQ.state` transition to `state` for `csg_idx`.
    pub(crate) fn set_state(&mut self, csg_idx: usize, state: CsgExecutionState) {
        self.queue_reqs(
            csg_idx,
            CSG_REQ::zeroed().with_state(state),
            CSG_REQ_STATE_MASK,
        );
    }

    /// Adds `mask` to the per-CS doorbell-ring set for `csg_idx`.
    ///
    /// Each bit in `mask` corresponds to a CS within the CSG; the
    /// `apply_csg_updates` step flips the matching `CSG_DB_REQ` bits
    /// against `CSG_DB_ACK` before ringing the per-CSG doorbell.
    /// Calling this also marks the slot as having pending updates so
    /// the apply loop visits it even if no `CSG_REQ` bits were staged.
    pub(crate) fn add_db_toggle(&mut self, csg_idx: usize, mask: u32) {
        debug_assert!(csg_idx < MAX_CSGS);
        if mask == 0 {
            return;
        }
        self.db_toggle[csg_idx] |= mask;
        self.update_mask |= 1u32 << csg_idx;
    }
}

/// CSG slot operations.
///
/// `activate` programs the static CSG_INPUT registers and stages a
/// `CSG_REQ.state = Start`. The firmware-visible `CSG_REQ` write,
/// doorbell ring and ack wait are driven by
/// [`Scheduler::apply_csg_updates`].
///
/// Eviction releases the AS slot; the firmware-visible
/// `CSG_REQ.state = Terminate` is staged by the tick worker (see
/// `Tick::halt_and_unbind_evicted_groups`) and applied with the
/// scheduler mutex dropped before this callback runs, so the
/// callback itself just tears the binding down.
pub(crate) struct CsgSlotOps {
    fw: Arc<fw::Firmware>,
}

impl CsgSlotOps {
    pub(crate) fn new(fw: Arc<fw::Firmware>) -> Self {
        Self { fw }
    }
}

impl crate::slot::SlotOperations for CsgSlotOps {
    type SlotData = CsgSlotData;
    type Context = CsgUpdateContext;

    fn activate(
        &mut self,
        slot_idx: usize,
        slot_data: &Self::SlotData,
        ctx: &mut Self::Context,
    ) -> Result {
        slot_data.group.vm.activate()?;

        // Release the AS-slot binding on any failure of the per-CS
        // programming below.
        let rollback = ScopeGuard::new(|| {
            if let Err(e) = slot_data.group.vm.deactivate() {
                pr_err!(
                    "CSG slot {} activate rollback: vm.deactivate() failed: {}\n",
                    slot_idx,
                    e.to_errno()
                );
            }
        });

        let group = &slot_data.group;
        let as_slot = group.vm.as_slot().ok_or(EINVAL)?;
        let suspend_va = group.suspend_buf.kernel_va().ok_or(EINVAL)?.start;
        let protm_suspend_va = group.protm_suspend_buf.kernel_va().ok_or(EINVAL)?.start;

        let ep_req = CSG_EP_REQ::zeroed()
            .with_compute_ep(group.max_compute_cores)
            .with_fragment_ep(group.max_fragment_cores)
            .try_with_tiler_ep(group.max_tiler_cores)?
            .try_with_priority(slot_data.fw_priority)?;
        let config = CSG_CONFIG::zeroed().try_with_jasid(u32::from(as_slot))?;

        let inputs = CsgActivateInputs {
            allow_compute: group.compute_core_mask,
            allow_fragment: group.fragment_core_mask,
            // `tiler_core_mask` is u64 in the UAPI; the firmware only
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
        let cs_doorbell = (slot_idx as u32) + 1;

        // Stage per-CS inputs on the stack so a per-queue EINVAL bails
        // before any firmware write, and to keep the activate path
        // allocation-free.
        let mut cs_inputs: [Option<CsActivateInputs>; group::MAX_CS_PER_GROUP] =
            [const { None }; group::MAX_CS_PER_GROUP];
        for (cs_idx, queue) in group.queues.iter().enumerate() {
            cs_inputs[cs_idx] = Some(queue.cs_activate_inputs(cs_doorbell)?);
        }

        let mut db_mask: u32 = 0;
        self.fw.with_csg_mut(slot_idx, |csg| {
            csg.program_activate_inputs(&inputs)?;
            for (cs_idx, cs_input) in cs_inputs.iter().enumerate() {
                let Some(cs_input) = cs_input else { break };
                let cs = csg.cs_mut(cs_idx).ok_or(EINVAL)?;
                cs.program_activate_inputs(cs_input)?;
                db_mask |= 1u32 << cs_idx;
            }
            Ok(())
        })?;

        // Publish the per-queue doorbell ids and the bound CSG slot
        // index together under the group's `inner` mutex. The two
        // publishes share a single critical section because
        // `TyrQueueOps::submit` decides bound-vs-unbound by observing
        // `csg_id` under the same lock and rings the doorbell on the
        // matching `doorbell_id`; pairing them here keeps a stale
        // `UNASSIGNED` doorbell from being observed alongside an
        // already-bound `csg_id` on weakly-ordered architectures. The
        // per-CS doorbells wired here remain stable for as long as
        // the slot is active; the matching clear lives in `evict`
        // below. The `csg_slot_manager > inner` lock ordering matches
        // the rest of the scheduler: callers already hold the
        // slot-manager mutex when they reach the activate callback.
        group.with_locked_inner(|inner| {
            for queue in group.queues.iter() {
                queue.set_doorbell_id(Some(slot_idx + 1));
            }
            inner.csg_id = Some(slot_idx);
        });

        ctx.set_state(slot_idx, CsgExecutionState::Start);
        // Stage the per-CS doorbell ring so `apply_csg_updates` flips
        // CSG_DB_REQ for these CSes before the global doorbell write.
        ctx.add_db_toggle(slot_idx, db_mask);
        rollback.dismiss();
        Ok(())
    }

    fn evict(
        &mut self,
        _slot_idx: usize,
        slot_data: &Self::SlotData,
        _ctx: &mut Self::Context,
    ) -> Result {
        // The firmware-side Terminate is staged by
        // `halt_and_unbind_evicted_groups` and acked via
        // `apply_csg_updates` (which drops the scheduler mutex around
        // the wait) before this callback runs. This callback only
        // tears the binding down: clear `csg_id` / per-queue
        // `doorbell_id`, release the AS slot.
        slot_data.group.with_locked_inner(|inner| {
            for queue in slot_data.group.queues.iter() {
                queue.set_doorbell_id(None);
            }
            inner.csg_id = None;
        });
        slot_data.group.vm.deactivate()?;
        Ok(())
    }
}

/// Type alias for the SlotManager parameterised for CSG slots.
pub(crate) type CsgSlotManager = SlotManager<CsgSlotOps, MAX_CSGS>;

/// Minimal scheduler shell.
///
/// # Lock order
///
/// The scheduler mutex sits above `gpuvm_unique` and `dma_resv_lock`.
/// [`Self::sync_upd_step`] reaches [`gem::MappedUserBo::new`] (via
/// [`Group::eval_syncwait`]), which takes `gpuvm_unique` and
/// `dma_resv_lock` while the scheduler mutex is held. Any new path
/// that takes the scheduler mutex from inside a `gpuvm_unique` or
/// `dma_resv_lock` critical section would deadlock.
///
/// [`Group::eval_syncwait`]: crate::sched::group::Group::eval_syncwait
/// [`gem::MappedUserBo::new`]: crate::gem::MappedUserBo::new
pub(crate) struct Scheduler {
    /// Groups that have at least one queue that can be currently scheduled.
    pub(in crate::sched) runnable_groups: [List<Group, 0>; GROUP_PRIORITY_COUNT],
    /// Groups whose queues are all idle (nothing to execute or blocked).
    pub(in crate::sched) idle_groups: [List<Group, 0>; GROUP_PRIORITY_COUNT],
    /// Groups whose queues are blocked on a sync object.
    pub(in crate::sched) waiting_groups: [List<Group, 1>; GROUP_PRIORITY_COUNT],
    /// Number of CSG slots used by the most recent tick.
    pub(in crate::sched) used_csg_slot_count: u32,
    /// True if an active group might have become idle.
    pub(in crate::sched) might_have_idle_groups: bool,
    /// When the next tick should occur, if any.
    pub(in crate::sched) resched_target: Option<Instant<Monotonic>>,
    /// When the last tick occurred.
    pub(in crate::sched) last_tick: Instant<Monotonic>,
}

impl Scheduler {
    pub(crate) fn init(tdev: &TyrDrmDevice) -> Result<Self> {
        let (csg_slot_count, cs_slot_count, cs_reg_count, scoreboard_slot_count) =
            tdev.fw.csif_info_counts()?;

        {
            let mut csif = tdev.csif_info.lock();
            csif.csg_slot_count = csg_slot_count;
            csif.cs_slot_count = cs_slot_count;
            csif.cs_reg_count = cs_reg_count;
            csif.scoreboard_slot_count = scoreboard_slot_count;
        }

        // The CSG slot manager is preallocated at TyrDrmDeviceData
        // pin-init time with a `MAX_CSGS` upper bound because it must
        // sit at a stable address (the seats embedded in groups are
        // `LockedBy<Seat, CsgSlotManager>` and reference it). Now
        // that the firmware has reported the actual slot count, narrow
        // the manager's iteration bound to that.
        tdev.csg_slot_manager
            .lock()
            .set_slot_count(csg_slot_count as usize)?;

        Ok(Self {
            runnable_groups: [const { List::new() }; GROUP_PRIORITY_COUNT],
            idle_groups: [const { List::new() }; GROUP_PRIORITY_COUNT],
            waiting_groups: [const { List::new() }; GROUP_PRIORITY_COUNT],
            used_csg_slot_count: 0,
            might_have_idle_groups: false,
            resched_target: None,
            last_tick: Instant::<Monotonic>::now(),
        })
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
            // SAFETY: list_state was read under the group's inner mutex,
            // and the scheduler mutex serialises every code path that
            // changes a group's list membership, so `group` is on `list`.
            let list_arc = unsafe { list.remove(group) };
            if list_arc.is_none() {
                pr_err!("group was marked {:?} but not found\n", list_state);
            }
            list_arc
        } else {
            None
        }
    }

    /// Detaches `group` from every scheduler list it is currently on.
    ///
    /// The id-0 (idle/runnable) and id-1 (waiting) memberships are
    /// independent; both are handled.
    pub(crate) fn detach_destroyed_group(&mut self, group: &Arc<Group>) {
        let priority = group.priority as usize;
        let list_state = group.with_locked_inner(|inner| inner.list_state);

        if !matches!(list_state, GroupListState::None) {
            let _ = self.remove_group_from_list(group, priority, list_state);
            group.with_locked_inner(|inner| {
                inner.list_state = GroupListState::None;
            });
        }

        let target = Arc::as_ptr(group);
        let mut cursor = self.waiting_groups[priority].cursor_front();
        while let Some(peek) = cursor.peek_next() {
            let here: *const Group = &*peek.arc();
            if core::ptr::eq(here, target) {
                let _ = peek.remove();
                return;
            }
            cursor.move_next();
        }
    }

    pub(crate) fn add_group(&mut self, group: Arc<Group>) -> Result {
        let priority = group.priority as usize;
        let list_arc = ListArc::try_from_arc(group.clone()).map_err(|_| EINVAL)?;

        group.with_locked_inner(|inner| {
            inner.list_state = GroupListState::Idle;
        });

        self.idle_groups[priority].push_back(list_arc);
        Ok(())
    }

    /// Schedules the next scheduler tick `TICK_PERIOD_MS` from now.
    ///
    /// Wraps [`TyrDrmDeviceData::schedule_periodic_tick`] with the
    /// scheduler-policy-defined period so callers don't have to know
    /// the right delay value. Coalescing semantics are inherited from
    /// the underlying `enqueue_delayed` call: requesting a tick while
    /// one is already pending does not shorten the existing delay.
    pub(crate) fn request_tick(tdev: &ARef<TyrDrmDevice>) {
        TyrDrmDeviceData::schedule_periodic_tick(tdev, msecs_to_jiffies(tick::TICK_PERIOD_MS));
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
        data: ARef<TyrDrmDevice>,
        context: &mut CsgUpdateContext,
    ) -> Result {
        if context.update_mask == 0 {
            return Ok(());
        }

        const CSG_REQ_ACK_TIMEOUT_MS: u32 = 100;

        for csg_id in 0..MAX_CSGS {
            if context.update_mask & (1u32 << csg_id) == 0 {
                continue;
            }
            let req_mask = context.req_mask[csg_id];
            if req_mask.is_empty() {
                continue;
            }
            let set_mask = req_mask & !CsgUpdateContext::TOGGLE_BITS;
            let toggle_mask = req_mask & CsgUpdateContext::TOGGLE_BITS;
            let req_value = context.req_value[csg_id] & !CsgUpdateContext::TOGGLE_BITS;
            data.fw.with_csg_mut(csg_id, |csg| {
                csg.update_and_toggle_input_req(
                    req_value.into_raw(),
                    set_mask.into_raw(),
                    toggle_mask.into_raw(),
                )
            })?;
        }

        // Flip CSG_DB_REQ for every slot with pending per-CS doorbell
        // requests so the firmware kicks the streams on the global
        // doorbell ring below.
        for csg_id in 0..MAX_CSGS {
            if context.update_mask & (1u32 << csg_id) == 0 {
                continue;
            }
            let db_mask = context.db_toggle[csg_id];
            if db_mask == 0 {
                continue;
            }
            data.fw
                .with_csg_mut(csg_id, |csg| csg.toggle_input_db_req(db_mask))?;
        }

        data.fw.ring_csg_doorbells(context.update_mask)?;

        for csg_id in 0..MAX_CSGS {
            if context.update_mask & (1u32 << csg_id) == 0 {
                continue;
            }
            let req_mask = context.req_mask[csg_id];
            match data
                .fw
                .wait_csg_acks(csg_id, req_mask, CSG_REQ_ACK_TIMEOUT_MS)
            {
                Ok(acked) => {
                    context.acked_reqs[csg_id] = acked;
                    if acked != req_mask {
                        pr_err!(
                            "CSG {}: firmware ack timeout: req_mask=0x{:x} acked=0x{:x}\n",
                            csg_id,
                            req_mask,
                            acked
                        );
                        context.timedout_mask |= 1u32 << csg_id;
                    }
                }
                Err(e) => {
                    pr_err!("wait_csg_acks {} failed: {}\n", csg_id, e.to_errno());
                    context.timedout_mask |= 1u32 << csg_id;
                }
            }
        }

        // Take the slot manager and dispatch by which acked bits
        // the firmware reported. The guard is held mutably so
        // `sync_csg_slot_priority` can write back the acknowledged
        // firmware priority into the per-slot `CsgSlotData`.
        let mut csg_slot_manager = data.csg_slot_manager.lock();
        for csg_id in 0..MAX_CSGS {
            if context.update_mask & (1u32 << csg_id) == 0 {
                continue;
            }
            let acked_reqs = context.acked_reqs[csg_id];

            if !(acked_reqs & CSG_REQ_EP_CFG).is_empty() {
                self.sync_csg_slot_priority(&data, &mut csg_slot_manager, csg_id)?;
            }
            if !(acked_reqs & CSG_REQ_STATE_MASK).is_empty() {
                self.sync_csg_slot_state(&data, &csg_slot_manager, csg_id)?;
            }
            if !(acked_reqs & CSG_REQ_STATUS_UPDATE).is_empty() {
                self.sync_csg_slot_queues_state(&data, &csg_slot_manager, csg_id)?;
            }
        }

        if context.timedout_mask != 0 {
            return Err(ETIMEDOUT);
        }

        Ok(())
    }

    /// Stages a firmware-priority update for CSG slot `csg_idx`.
    ///
    /// Caller must hold the slot-manager lock.
    pub(crate) fn update_csg_slot_priority(
        &mut self,
        data: &TyrDrmDeviceData,
        csg_slot_manager: &CsgSlotManager,
        csg_idx: usize,
        fw_prio: u32,
        context: &mut CsgUpdateContext,
    ) -> Result {
        if fw_prio > MAX_CSG_PRIO {
            pr_err!(
                "update_csg_slot_priority: invalid fw priority {}\n",
                fw_prio
            );
            return Err(EINVAL);
        }

        if csg_idx >= MAX_CSGS {
            pr_err!("update_csg_slot_priority: invalid csg {}\n", csg_idx);
            return Err(EINVAL);
        }

        let slot_data = csg_slot_manager.slot_data(csg_idx).ok_or(EINVAL)?;
        let group = slot_data.group.clone();

        data.fw.with_csg_mut(csg_idx, |csg| {
            let ep_req = CSG_EP_REQ::zeroed()
                .with_compute_ep(group.max_compute_cores)
                .with_fragment_ep(group.max_fragment_cores)
                .try_with_tiler_ep(group.max_tiler_cores)?
                .try_with_priority(fw_prio)?;
            csg.write_input_ep_req(ep_req)
        })?;

        context.toggle_reqs(csg_idx, CSG_REQ_EP_CFG);
        Ok(())
    }

    /// Refreshes [`CsgSlotData::fw_priority`] from the
    /// firmware-acknowledged `CSG_EP_REQ.priority` value.
    fn sync_csg_slot_priority(
        &mut self,
        data: &TyrDrmDeviceData,
        csg_slot_manager: &mut CsgSlotManager,
        csg_idx: usize,
    ) -> Result {
        let Some(slot_data) = csg_slot_manager.slot_data_mut(csg_idx) else {
            return Ok(());
        };
        let ep_req = data
            .fw
            .with_csg_mut(csg_idx, |csg| csg.read_input_ep_req())?;
        slot_data.fw_priority = ep_req.priority().get();
        Ok(())
    }

    /// Refreshes the resident group's recorded [`group::State`] from
    /// `CSG_ACK.state`. Transitions into `Suspend` also refresh the
    /// per-CS queue state; transitions out of `Active` clear per-CS
    /// `CS_REQ.state` so a subsequent re-bind starts clean.
    fn sync_csg_slot_state(
        &mut self,
        data: &TyrDrmDeviceData,
        csg_slot_manager: &CsgSlotManager,
        csg_idx: usize,
    ) -> Result {
        let Some(slot_data) = csg_slot_manager.slot_data(csg_idx) else {
            return Ok(());
        };
        let group = slot_data.group.clone();

        let old_state = group.state();

        let ack = data.fw.with_csg_mut(csg_idx, |csg| csg.read_output_ack())?;

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
                if inner.fatal_error.is_none() {
                    inner.fatal_error = Some(EINVAL);
                }
            });
        }
        if new_state == group::State::Suspended {
            self.sync_csg_slot_queues_state(data, csg_slot_manager, csg_idx)?;
        }

        if old_state == group::State::Active {
            // Reset the per-CS request state so a future `Start`/
            // `Resume` on this slot does not pick up the previous
            // group's CS_REQ bits. No doorbell is needed: the
            // firmware re-evaluates CS_REQ when the next CSG state
            // transition completes.
            data.fw.with_csg_mut(csg_idx, |csg| {
                let mut i = 0;
                while let Some(cs) = csg.cs_mut(i) {
                    let _ = cs.clear_input_req_state();
                    i += 1;
                }
                Ok(())
            })?;
        }

        group.set_state(new_state);
        Ok(())
    }

    /// Synchronises the per-CS in-memory state from the CSG output area
    /// after a `CSG_REQ.status_update` ack is observed.
    ///
    /// Walks every CS in the group to classify each queue's state from
    /// `CS_STATUS_BLOCKED_REASON`, `CS_STATUS_WAIT`,
    /// `CS_STATUS_SCOREBOARDS` and (for sync-wait blocked queues) the
    /// `CS_STATUS_WAIT_SYNC_*` words:
    ///
    /// * `Unblocked` with empty ringbuffer (`INSERT == EXTRACT`) and
    ///   no in-flight scoreboard entries -> mark queue idle.
    /// * `SyncWait`: capture the active wait into [`QueueData::syncwait`]
    ///   and, when no scoreboards are still in flight, mark the queue
    ///   blocked. The group is then pushed onto
    ///   [`Scheduler::waiting_groups`].
    /// * Other reasons are not blocking and leave the queue in its
    ///   current classification.
    fn sync_csg_slot_queues_state(
        &mut self,
        data: &TyrDrmDeviceData,
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
        // [`MAX_CS_PER_GROUP`] (the width of the per-queue bitmasks
        // in `GroupInner`) so this stays allocation-free; the loop
        // bound is min(queue_count, MAX_CS_PER_GROUP) to avoid
        // out-of-bounds access if a future caller created a larger
        // group.
        let queue_count = core::cmp::min(group.queue_count(), group::MAX_CS_PER_GROUP);
        let mut blocked_reasons: [Option<CsBlockedReason>; group::MAX_CS_PER_GROUP] =
            [const { None }; group::MAX_CS_PER_GROUP];
        let mut scoreboards: [u32; group::MAX_CS_PER_GROUP] = [0; group::MAX_CS_PER_GROUP];
        let mut sync_waits: [Option<(u64, u64, bool, bool)>; group::MAX_CS_PER_GROUP] =
            [const { None }; group::MAX_CS_PER_GROUP];

        data.fw.with_csg_mut(csg_idx, |csg| {
            for cs_id in 0..queue_count {
                let Some(cs) = csg.cs_mut(cs_id) else {
                    continue;
                };
                let reason = cs.read_status_blocked_reason()?;
                blocked_reasons[cs_id] = Some(reason);
                scoreboards[cs_id] = cs.read_status_scoreboards()?;

                if reason == CsBlockedReason::SyncWait {
                    let wait = cs.read_status_wait_sync()?;
                    let gt = matches!(wait.condition, CsWaitCondition::Gt);
                    sync_waits[cs_id] = Some((wait.sync_ptr, wait.ref_val, wait.sync64, gt));
                }
            }

            Ok::<_, Error>(())
        })?;

        // Publish each captured sync-wait onto its queue. Empty
        // ringbuffer probes hit firmware-shared memory and don't take
        // the firmware lock, so they go in this pre-pass too.
        let mut empty_queues: u32 = 0;
        for cs_id in 0..queue_count {
            let queue = &group.queues[cs_id];
            if let Some((gpu_va, ref_val, sync64, gt)) = sync_waits[cs_id].take() {
                queue.set_syncwait(gpu_va, ref_val, sync64, gt);
            }
            if blocked_reasons[cs_id] == Some(CsBlockedReason::Unblocked)
                && queue.is_ringbuf_empty().unwrap_or(false)
            {
                empty_queues |= 1u32 << cs_id;
            }
        }

        // Apply the per-queue classification under the inner lock.
        // Returns whether any queue ended up blocked on a sync object,
        // which decides if the group needs to land on the wait list.
        let has_sync_wait = group.with_locked_inner(|inner| {
            let mut has_sync_wait = false;

            for cs_id in 0..queue_count {
                let mut idle = false;
                let mut blocked = false;

                match blocked_reasons[cs_id] {
                    Some(CsBlockedReason::Unblocked)
                        if (empty_queues & (1u32 << cs_id)) != 0 && scoreboards[cs_id] == 0 =>
                    {
                        idle = true;
                    }
                    Some(CsBlockedReason::Unblocked) => {}
                    Some(CsBlockedReason::SyncWait) => {
                        has_sync_wait = true;
                        // Only blocked if there is no deferred work
                        // still resolving on the scoreboards.
                        if scoreboards[cs_id] == 0 {
                            blocked = true;
                        }
                    }
                    _ => {
                        // Other reasons (`SbWait`, `ProgressWait`,
                        // `Deferred`, `Resource`, `Flush`) do not
                        // count as scheduler-visible blocks: the
                        // queue is still considered runnable.
                    }
                }

                inner.set_queue_idle(cs_id, idle);
                inner.set_queue_blocked(cs_id, blocked);
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
            if let Ok(wait_arc) = ListArc::<Group, 1>::try_from_arc(group) {
                self.waiting_groups[priority].push_back(wait_arc);
            }
        }

        Ok(())
    }

    /// Requeues a group onto the idle or runnable list.
    pub(crate) fn requeue_group(&mut self, list_arc: ListArc<Group, 0>, is_idle: bool) {
        let group_arc: Arc<Group> = list_arc.clone_arc();
        let priority = group_arc.priority as usize;

        group_arc.with_locked_inner(|inner| {
            inner.list_state = if is_idle {
                group::GroupListState::Idle
            } else {
                group::GroupListState::Runnable
            };
        });

        if is_idle {
            self.idle_groups[priority].push_back(list_arc);
        } else {
            self.runnable_groups[priority].push_back(list_arc);
        }
    }

    /// Marks `group` as runnable, moving it onto the runnable list at
    /// its priority if it is not already there.
    ///
    /// Idempotent: a group that is already on the runnable list, or
    /// is currently bound to a CSG slot, is left in place. An idle
    /// group is moved off [`Scheduler::idle_groups`] onto
    /// [`Scheduler::runnable_groups`]. Only the id-0 lists are
    /// manipulated; the wait-list (id-1) is owned elsewhere.
    pub(crate) fn mark_group_runnable(&mut self, group: &Arc<Group>) {
        let priority = group.priority as usize;

        group.with_locked_inner(|inner| {
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
                        }
                    }
                }
                group::GroupListState::Idle => {
                    if let Some(list_arc) =
                        self.remove_group_from_list(group, priority, group::GroupListState::Idle)
                    {
                        self.runnable_groups[priority].push_back(list_arc);
                        inner.list_state = group::GroupListState::Runnable;
                    }
                }
            }
        });
    }

    /// Walks `waiting_groups` once, re-evaluating each blocked queue's
    /// captured `SyncWait` and moving newly unblocked groups onto
    /// `runnable_groups`.
    ///
    /// Returns `true` if an unbound RealTime-priority group was
    /// promoted to `runnable_groups`, in which case the caller fires
    /// an immediate tick so the rule engine binds it without waiting
    /// for the periodic tick.
    ///
    /// May allocate inside `eval_syncwait`'s foreign-BO fast-miss
    /// path, but that runs on `system_unbound()` (the `sync_upd`
    /// worker) and is therefore permitted.
    pub(crate) fn sync_upd_step(&mut self) -> bool {
        let mut immediate_tick = false;

        for prio in 0..GROUP_PRIORITY_COUNT {
            // Stage the wait-list links of groups that should move to
            // the runnable list. A `List<Group, 1>` does not allocate
            // and lets us release the wait-list cursor before
            // re-borrowing `self` mutably for `mark_group_runnable`.
            let mut make_runnable = List::<Group, 1>::new();

            {
                let mut cursor = self.waiting_groups[prio].cursor_front();
                while let Some(peek) = cursor.peek_next() {
                    let group: Arc<Group> = peek.arc().into();

                    let blocked = group.with_locked_inner(|inner| inner.blocked_queues());

                    let mut unblocked: u32 = 0;
                    let mut tested = blocked;
                    while tested != 0 {
                        let cs_id = tested.trailing_zeros();
                        tested &= !(1u32 << cs_id);
                        match group.eval_syncwait(cs_id as usize) {
                            Ok(true) => unblocked |= 1u32 << cs_id,
                            Ok(false) => {}
                            // Treat read errors as "unblock and let
                            // the next tick surface any further
                            // failure".
                            Err(e) => {
                                pr_err!("eval_syncwait failed: {}\n", e.to_errno());
                                unblocked |= 1u32 << cs_id;
                            }
                        }
                    }

                    let (unblocked, move_to_runnable) = group.with_locked_inner(|inner| {
                        if unblocked != 0 {
                            let mut bits = unblocked;
                            while bits != 0 {
                                let cs_id = bits.trailing_zeros() as usize;
                                bits &= !(1u32 << cs_id);
                                inner.set_queue_blocked(cs_id, false);
                            }
                        }

                        let unblocked = !inner.has_blocked_queues();
                        let move_to_runnable = unblocked && inner.csg_id.is_none();
                        (unblocked, move_to_runnable)
                    });

                    if unblocked {
                        let list_arc = peek.remove();
                        if move_to_runnable {
                            if prio == Priority::RealTime as usize {
                                immediate_tick = true;
                            }
                            make_runnable.push_back(list_arc);
                        }
                    } else {
                        cursor.move_next();
                    }
                }
            }

            // The wait-list cursor borrow is dropped: now safe to
            // re-borrow `self` mutably for `mark_group_runnable`.
            while let Some(list_arc) = make_runnable.pop_front() {
                let group: Arc<Group> = list_arc.into_arc();
                self.mark_group_runnable(&group);
            }
        }

        immediate_tick
    }

    /// Stages a `CSG_REQ.status_update` for every bound CSG slot and
    /// applies the batch, refreshing `GroupInner::idle` from the
    /// firmware view via the post-ack sync pass.
    pub(crate) fn sync_group_states(&mut self, data: ARef<TyrDrmDevice>) -> Result {
        let mut context = CsgUpdateContext::new();
        let mut faulted_groups: [Option<(usize, Arc<Group>)>; MAX_CSGS] =
            [const { None }; MAX_CSGS];

        {
            let csg_slot_manager = data.csg_slot_manager.lock();
            for csg_idx in 0..csg_slot_manager.slot_count() {
                let Some(slot_data) = csg_slot_manager.slot_data(csg_idx) else {
                    continue;
                };
                if slot_data
                    .group
                    .vm
                    .as_data
                    .unhandled_fault
                    .load(Ordering::Relaxed)
                {
                    faulted_groups[csg_idx] = Some((csg_idx, slot_data.group.clone()));
                }
                context.toggle_reqs(csg_idx, CSG_REQ_STATUS_UPDATE);
            }
        }

        for slot in faulted_groups.iter() {
            let Some((csg_idx, group)) = slot else {
                continue;
            };
            self.process_csg_irq(&data, *csg_idx)?;
            let queue_count = group.queue_count();
            group.with_locked_inner(|inner| {
                if inner.has_fatal_queues() {
                    return;
                }
                for cs_id in 0..queue_count {
                    inner.set_queue_fatal(cs_id);
                }
            });
        }

        self.apply_csg_updates(data, &mut context)
    }
}
