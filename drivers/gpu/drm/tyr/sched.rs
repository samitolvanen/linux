// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::Ordering;

use kernel::{
    list::{
        List,
        ListArc,
        ListItem, //
    },
    pm::AwakeScope,
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    },
    time::{
        jiffies64,
        msecs_to_jiffies,
        Delta,
        Instant,
        Jiffies,
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
        CsDbMask,
        CsWaitCondition,
        CsgExecutionState,
        CsgSlotMask,
        CSG_CONFIG,
        CSG_EP_REQ,
        CSG_REQ, //
    },
    gpu,
    gpu::UNPRESERVED_CS_REG_COUNT,
    heap,
    sched::group::GroupListState,
    slot::SlotManager,
    trace, //
};

use group::Group;

const GROUP_PRIORITY_COUNT: usize = Priority::num_priorities();

/// Maximum number of CSG slots the scheduler can address.
///
/// Matches `fw::MAX_CSG`, the firmware-imposed hardware ceiling.
/// Bounds the fixed-capacity per-tick accumulator so tick callbacks
/// never allocate.
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
/// the firmware to acknowledge the resulting state transitions. The
/// activate / evict callbacks of `CsgSlotOps` update this accumulator
/// while the slot-manager mutex is held; `Scheduler::apply_csg_updates`
/// then drives the firmware-visible side of the transaction. The
/// slot-manager mutex is dropped around the firmware ack wait so other
/// slot accessors can run; the scheduler mutex stays held.
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
    /// True when this batch frees slots for other work.
    pub(crate) reclaim: bool,
}

/// CSG_REQ::state field mask (bits 2:0). The firmware transitions all
/// three bits as a unit.
const CSG_REQ_STATE_MASK: CSG_REQ = CSG_REQ::from_raw(CSG_REQ::STATE_MASK);
/// CSG_REQ::ep_cfg bit (4:4). Endpoint-configuration toggle.
const CSG_REQ_EP_CFG: CSG_REQ = CSG_REQ::from_raw(CSG_REQ::EP_CFG_MASK);
/// CSG_REQ::status_update bit (5:5). Status-update toggle.
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
            db_toggle: [CsDbMask::empty(); MAX_CSGS],
            update_mask: CsgSlotMask::empty(),
            timedout_mask: CsgSlotMask::empty(),
            reclaim: false,
        }
    }

    /// Stages an update of `mask` bits in `CSG_REQ` for `csg_idx` to
    /// the corresponding bits in `value`.
    ///
    /// Subsequent stages on the same slot replace the bits in `mask`,
    /// and the union of all `mask`s passed for a slot is what
    /// `Scheduler::apply_csg_updates` will toggle in `CSG_REQ` and
    /// wait for.
    pub(crate) fn queue_reqs(&mut self, csg_idx: usize, value: CSG_REQ, mask: CSG_REQ) {
        debug_assert!(csg_idx < MAX_CSGS);
        debug_assert!(!mask.is_empty());

        self.req_value[csg_idx] = (self.req_value[csg_idx] & !mask) | (value & mask);
        self.req_mask[csg_idx] |= mask;
        self.update_mask.insert(csg_idx);
    }

    /// Stages a toggle of `toggle_bit` in `CSG_REQ` for `csg_idx`.
    ///
    /// `toggle_bit` must be a subset of `Self::TOGGLE_BITS`; the
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
    pub(crate) fn add_db_toggle(&mut self, csg_idx: usize, mask: CsDbMask) {
        debug_assert!(csg_idx < MAX_CSGS);
        if mask.is_empty() {
            return;
        }
        let raw = self.db_toggle[csg_idx].into_raw() | mask.into_raw();
        self.db_toggle[csg_idx] = CsDbMask::from_raw(raw);
        self.update_mask.insert(csg_idx);
    }
}

/// CSG slot operations.
///
/// `activate` programs the static CSG_INPUT registers and stages a
/// `CSG_REQ.state = Start`. The firmware-visible `CSG_REQ` write,
/// doorbell ring and ack wait are driven by
/// `Scheduler::apply_csg_updates`.
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

        // Undo the AS-slot user reference taken above on any failure of
        // the per-CS programming below. A sibling group of the same VM
        // may still be bound, so this drops a user rather than evicting
        // the shared slot.
        let rollback = ScopeGuard::new(|| {
            if let Err(e) = slot_data.group.vm.idle() {
                pr_err!(
                    "CSG slot {} activate rollback: vm.idle() failed: {}\n",
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
            if let Ok(syncobj) = group.read_syncobj(cs_idx) {
                trace::csg_syncobj(
                    group.handle(),
                    group.uid(),
                    cs_idx as u32,
                    trace::CsgSyncobjPhase::Resume,
                    syncobj.seqno,
                    syncobj.status,
                    queue.next_seqno(),
                );
            }
        }

        let mut db_mask = CsDbMask::empty();
        let group_id = group.handle();
        let mut cs_req_writes: [Option<(u32, u32)>; group::MAX_CS_PER_GROUP] =
            [const { None }; group::MAX_CS_PER_GROUP];
        self.fw.with_csg_mut(slot_idx, |csg| {
            csg.program_activate_inputs(&inputs)?;
            for (cs_idx, cs_input) in cs_inputs.iter().enumerate() {
                let Some(cs_input) = cs_input else { break };
                let cs = csg.cs_mut(cs_idx).ok_or(EINVAL)?;
                let config_raw =
                    (u32::from(cs_input.priority) & 0xf) | ((cs_input.doorbell_id & 0xff) << 8);
                trace::fw_cs_activate_inputs(
                    slot_idx as u32,
                    cs_idx as u32,
                    cs_input.ringbuf_base,
                    cs_input.ringbuf_size,
                    cs_input.ringbuf_input_va,
                    cs_input.ringbuf_output_va,
                    config_raw,
                );
                cs_req_writes[cs_idx] = Some(cs.program_activate_inputs(cs_input)?);
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
        // index together under the group's `inner` mutex. The two
        // publishes share a single critical section because
        // `TyrQueueOps::submit` decides bound-vs-unbound by observing
        // `csg_id` under the same lock and rings the doorbell on the
        // matching `doorbell_id`; pairing them here keeps a stale
        // `UNASSIGNED` doorbell from being observed alongside an
        // already-bound `csg_id` on weakly-ordered architectures. The
        // per-CS doorbells wired here remain stable for as long as
        // the slot is active. The `csg_slot_manager > inner` lock
        // ordering matches the rest of the scheduler: callers already
        // hold the slot-manager mutex when they reach the activate
        // callback.
        group.with_locked_inner(|inner| {
            for queue in group.queues.iter() {
                queue.set_doorbell_id(Some(slot_idx + 1));
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
        ctx.set_state(slot_idx, state);
        ctx.toggle_reqs(slot_idx, CSG_REQ_EP_CFG);
        ctx.add_db_toggle(slot_idx, db_mask);
        rollback.dismiss();
        Ok(())
    }

    fn evict(
        &mut self,
        slot_idx: usize,
        slot_data: &Self::SlotData,
        _ctx: &mut Self::Context,
    ) -> Result {
        // The firmware ack for this slot's state transition landed before
        // this callback runs, so it only tears the binding down. The VM
        // keeps its AS slot, flagged idle for reuse on the next bind.
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
            if let Ok(syncobj) = slot_data.group.read_syncobj(cs_idx) {
                trace::csg_syncobj(
                    slot_data.group.handle(),
                    slot_data.group.uid(),
                    cs_idx as u32,
                    trace::CsgSyncobjPhase::Suspend,
                    syncobj.seqno,
                    syncobj.status,
                    queue.next_seqno(),
                );
            }
        }
        slot_data.group.with_locked_inner(|inner| {
            for queue in slot_data.group.queues.iter() {
                queue.set_doorbell_id(None);
            }
            inner.csg_id = None;
        });
        slot_data.group.tiler_oom.store(0, Ordering::Relaxed);
        slot_data.group.vm.as_data.clear_bound_group();
        slot_data.group.vm.idle()?;
        Ok(())
    }
}

/// Type alias for the SlotManager parameterised for CSG slots.
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
/// dma_resv_lock, or GFP_KERNEL. eval_syncwait reaches MappedUserBo::new,
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
    /// Set by a failed runtime suspend. The next granted tick rings the
    /// user doorbell of every non-empty resident ring buffer.
    pub(in crate::sched) pending_resident_kick: bool,
}

/// The tick a submit schedules after marking its group runnable.
///
/// Dispatched by the caller once the scheduler mutex is dropped.
pub(crate) enum SubmitTick {
    Immediate,
    /// Re-arm the periodic tick `delay` from now.
    Periodic(Jiffies),
    /// A tick is already due by the rotation deadline, so do nothing.
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
    pub(crate) fn init(tdev: &TyrDrmDevice) -> Result<Self> {
        let (csg_slot_count, cs_slot_count, cs_reg_count, scoreboard_slot_count) =
            tdev.fw.csif_info_counts()?;

        // A distinct CSG priority per slot avoids a FW scheduler deadlock,
        // capping the usable slots to the priority count.
        let csg_slot_count = core::cmp::min(MAX_CSG_PRIO + 1, csg_slot_count);

        {
            let mut csif = tdev.csif_info.lock();
            csif.csg_slot_count = csg_slot_count;
            csif.cs_slot_count = cs_slot_count;
            csif.cs_reg_count = cs_reg_count;
            csif.scoreboard_slot_count = scoreboard_slot_count;
            csif.unpreserved_cs_reg_count = UNPRESERVED_CS_REG_COUNT;
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
            csg_slot_count,
            used_csg_slot_count: 0,
            might_have_idle_groups: false,
            resched_target: None,
            last_tick: Instant::<Monotonic>::now(),
            last_full_tick_jiffies: jiffies64(),
            pm_ref: None,
            pending_resident_kick: false,
        })
    }

    /// Requests a resident-queue doorbell kick from the next granted
    /// tick. Called from the failed-runtime-suspend path.
    pub(crate) fn request_resident_kick(&mut self) {
        self.pending_resident_kick = true;
        trace::pm_usage(trace::PmUsageEvent::ResidentKick, self.pm_ref.is_some());
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
            // `List<Group, 0>`; passing `group` to the wrong head would be
            // UB. The match above selects the head named by `list_state`,
            // and every writer of `list_state` holds the scheduler mutex
            // and pairs the `list_state` update with the matching list
            // operation. We hold the scheduler mutex here, so `list_state`
            // agrees with actual list membership and `group` is on `list`.
            let list_arc = unsafe { list.remove(group) };
            if list_arc.is_none() {
                pr_err!("group was marked {:?} but not found\n", list_state);
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
                return;
            }
            cursor.move_next();
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
        data: &TyrDrmDevice,
        context: &mut CsgUpdateContext,
    ) -> Result {
        if context.update_mask.is_empty() {
            return Ok(());
        }

        gpu::trace_shader_power_state(&data.iomem);

        const CSG_REQ_ACK_TIMEOUT_MS: u32 = 100;

        for csg_id in 0..MAX_CSGS {
            if !context.update_mask.contains(csg_id) {
                continue;
            }
            let req_mask = context.req_mask[csg_id];
            if req_mask.is_empty() {
                continue;
            }
            let set_mask = req_mask & !CsgUpdateContext::TOGGLE_BITS;
            let toggle_mask = req_mask & CsgUpdateContext::TOGGLE_BITS;
            let req_value = context.req_value[csg_id] & !CsgUpdateContext::TOGGLE_BITS;
            let group_id = data
                .csg_slot_manager
                .lock()
                .slot_data(csg_id)
                .map(|s| s.group.handle())
                .unwrap_or(0);
            let new_req = data.fw.with_csg_mut(csg_id, |csg| {
                csg.update_and_toggle_input_req(req_value, set_mask, toggle_mask)
            })?;
            trace::fw_csg_req(
                csg_id as u32,
                group_id,
                new_req.into_raw(),
                set_mask.into_raw(),
                toggle_mask.into_raw(),
            );
        }

        for csg_id in 0..MAX_CSGS {
            if !context.update_mask.contains(csg_id) {
                continue;
            }
            let db_mask = context.db_toggle[csg_id];
            if db_mask.is_empty() {
                continue;
            }
            data.fw
                .with_csg_mut(csg_id, |csg| csg.toggle_input_db_req(db_mask))?;
        }

        data.fw.ring_csg_doorbells(context.update_mask)?;

        let mut glb_probed = false;
        for csg_id in 0..MAX_CSGS {
            if !context.update_mask.contains(csg_id) {
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
                        if let Some(re_acked) = self.probe_csg_ack_timeout(
                            data,
                            csg_id,
                            req_mask,
                            acked,
                            &mut glb_probed,
                        ) {
                            context.acked_reqs[csg_id] = re_acked;
                        } else {
                            context.timedout_mask.insert(csg_id);
                        }
                    }
                }
                Err(e) => {
                    pr_err!("wait_csg_acks {} failed: {}\n", csg_id, e.to_errno());
                    context.timedout_mask.insert(csg_id);
                }
            }
        }

        // Take the slot manager and dispatch by which acked bits
        // the firmware reported. The guard is held mutably so
        // `sync_csg_slot_priority` can write back the acknowledged
        // firmware priority into the per-slot `CsgSlotData`.
        let mut csg_slot_manager = data.csg_slot_manager.lock();
        for csg_id in 0..MAX_CSGS {
            if !context.update_mask.contains(csg_id) {
                continue;
            }
            let acked_reqs = context.acked_reqs[csg_id];

            if !(acked_reqs & CSG_REQ_EP_CFG).is_empty() {
                self.sync_csg_slot_priority(data, &mut csg_slot_manager, csg_id)?;
            }
            if !(acked_reqs & CSG_REQ_STATE_MASK).is_empty() {
                self.sync_csg_slot_state(data, &csg_slot_manager, csg_id, context.reclaim)?;
            }
            if !(acked_reqs & CSG_REQ_STATUS_UPDATE).is_empty() {
                self.sync_csg_slot_queues_state(data, &csg_slot_manager, csg_id)?;
            }
        }

        if !context.timedout_mask.is_empty() {
            // `sync_csg_slot_queues_state` is unreachable when STATUS_UPDATE
            // times out, so snapshot the per-CS status registers directly
            // here. Firmware that stops acking one slot may have stopped
            // acking all of them, so dump every slot and every CS
            // interface on it, bound or not. A CS whose blocked reason
            // does not decode still gets dumped, with the reason reported
            // as `u32::MAX`.
            gpu::trace_shader_power_state(&data.iomem);
            for csg_id in 0..MAX_CSGS {
                if let Ok((ack, state, ep_cur, ep_req, rdep)) = data
                    .fw
                    .with_csg_mut(csg_id, |csg| csg.read_output_dump_raw())
                {
                    trace::fw_csg_dump_output(csg_id as u32, ack, state, ep_cur, ep_req, rdep);
                }

                let (vm, group_uid) = csg_slot_manager
                    .slot_data(csg_id)
                    .map(|s| (Some(s.group.vm.clone()), s.group.uid()))
                    .unwrap_or((None, 0));
                let _ = data.fw.with_csg_mut(csg_id, |csg| {
                    for cs_id in 0..group::MAX_CS_PER_GROUP {
                        let Some(cs) = csg.cs_mut(cs_id) else {
                            continue;
                        };
                        let req = cs.read_input_req_raw()?;
                        let ack = cs.read_output_ack_raw()?;
                        let status_wait = cs.read_status_wait_raw()?;
                        let reason = cs
                            .read_status_blocked_reason()
                            .map_or(u32::MAX, |reason| reason as u32);
                        let scoreboards = cs.read_status_scoreboards()?;
                        let sync_ptr = cs.read_status_wait_sync_pointer_raw()?;
                        let req_resource = cs.read_status_req_resource_raw()?;
                        let heap = cs.read_heap_output_state()?;
                        let (cur_val, cur_val_valid) = match &vm {
                            Some(vm) if trace::cs_status_snapshot_enabled() => {
                                let sync64 = status_wait & (1 << 30) != 0;
                                events::read_syncwait_cur_val(vm, sync_ptr, sync64)
                            }
                            _ => (0, false),
                        };
                        trace::cs_status_snapshot(
                            csg_id as u32,
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
                        trace::wedge_cs_state(
                            csg_id as u32,
                            group_uid,
                            cs_id as u32,
                            status_wait,
                            reason,
                            req_resource,
                            heap.heap_address,
                            heap.vt_start,
                            heap.vt_end,
                            heap.frag_end,
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
    /// A slot that stays wedged also gets a global-interface liveness
    /// probe, unless `glb_probed` says an earlier slot in this pass
    /// already ran one.
    ///
    /// Downstream-only debug aid; not for upstream. Distinguishes a
    /// transient CPU->MCU visibility race (re-kick recovers) from
    /// firmware state corruption (re-kick does not).
    fn probe_csg_ack_timeout(
        &mut self,
        data: &TyrDrmDevice,
        csg_id: usize,
        req_mask: CSG_REQ,
        acked: CSG_REQ,
        glb_probed: &mut bool,
    ) -> Option<CSG_REQ> {
        // Snapshot the per-CS ringbuf state under a short-lived slot
        // manager lock; the lock must be dropped before `wait_csg_acks`.
        let mut ringbuf: [Option<(u64, u64)>; group::MAX_CS_PER_GROUP] =
            [const { None }; group::MAX_CS_PER_GROUP];
        {
            let csg_slot_manager = data.csg_slot_manager.lock();
            if let Some(slot_data) = csg_slot_manager.slot_data(csg_id) {
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
                    csg_id as u32,
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
        let recovered = match data.fw.ring_csg_doorbells(rekick_mask) {
            Err(e) => {
                pr_info!(
                    "CSG {}: re-kick doorbell failed: {}\n",
                    csg_id,
                    e.to_errno()
                );
                None
            }
            Ok(()) => match data
                .fw
                .wait_csg_acks(csg_id, req_mask, CSG_REQ_ACK_TIMEOUT_MS)
            {
                Ok(re_acked) if re_acked == req_mask => {
                    pr_info!(
                        "CSG {}: re-kick recovered ack: req_mask=0x{:x} acked=0x{:x}\n",
                        csg_id,
                        req_mask,
                        re_acked
                    );
                    Some(re_acked)
                }
                Ok(re_acked) => {
                    pr_info!(
                        "CSG {}: re-kick did not recover: req_mask=0x{:x} acked=0x{:x}\n",
                        csg_id,
                        req_mask,
                        re_acked
                    );
                    None
                }
                Err(e) => {
                    pr_info!("CSG {}: re-kick wait failed: {}\n", csg_id, e.to_errno());
                    None
                }
            },
        };

        if recovered.is_none() && !*glb_probed {
            *glb_probed = true;
            Self::probe_glb_liveness(data, csg_id, req_mask);
        }

        recovered
    }

    /// Probes the global interface once for a slot that stayed unacked
    /// through a re-kick.
    ///
    /// A ping ack means the firmware still runs the global protocol and
    /// only the CSG state machine is stuck. A missing ack points at the
    /// MCU itself, and `MCU_STATUS` says which state it stopped in.
    ///
    /// Downstream-only debug aid. Not for upstream.
    fn probe_glb_liveness(data: &TyrDrmDevice, csg_id: usize, req_mask: CSG_REQ) {
        const GLB_PROBE_TIMEOUT_MS: u32 = 100;

        match data.fw.probe_liveness(GLB_PROBE_TIMEOUT_MS) {
            Ok((probe, mcu_status)) => {
                pr_err!(
                    "CSG {}: GLB liveness probe: {} req_mask=0x{:x} glb_req=0x{:x}->0x{:x} glb_ack=0x{:x}->0x{:x} mcu_status=0x{:x}\n",
                    csg_id,
                    if probe.acked {
                        "glb alive"
                    } else {
                        "glb unresponsive"
                    },
                    req_mask.into_raw(),
                    probe.req_before,
                    probe.req_after,
                    probe.ack_before,
                    probe.ack_after,
                    mcu_status
                );
                trace::wedge_glb_probe(
                    csg_id as u32,
                    req_mask.into_raw(),
                    probe.req_before,
                    probe.ack_before,
                    probe.req_after,
                    probe.ack_after,
                    probe.acked,
                    mcu_status,
                );
            }
            Err(e) => {
                pr_err!(
                    "CSG {}: GLB liveness probe failed: {}\n",
                    csg_id,
                    e.to_errno()
                );
            }
        }
    }

    /// Stages a firmware-priority update for CSG slot `csg_idx`.
    pub(crate) fn update_csg_slot_priority(
        &mut self,
        data: &TyrDrmDevice,
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

    /// Refreshes `CsgSlotData::fw_priority` from the
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

    /// Refreshes the resident group's recorded `group::State` from the
    /// firmware-acknowledged `CSG_ACK.state`.
    ///
    /// A transition into `Suspend` also opens the off-slot deadline
    /// credit. `Group::blocked_idle_queues` documents the reclaim
    /// exception.
    fn sync_csg_slot_state(
        &mut self,
        data: &TyrDrmDeviceData,
        csg_slot_manager: &CsgSlotManager,
        csg_idx: usize,
        reclaim: bool,
    ) -> Result {
        let Some(slot_data) = csg_slot_manager.slot_data(csg_idx) else {
            return Ok(());
        };
        let group = slot_data.group.clone();

        let old_state = group.state();

        let ack = data.fw.with_csg_mut(csg_idx, |csg| csg.read_output_ack())?;
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
                if inner.fatal_error.is_none() {
                    inner.fatal_error = Some(EINVAL);
                }
            });
            trace::reset_request(trace::ResetReason::CsgStateUnknown);
            data.reset.schedule();
        }
        if new_state == group::State::Suspended {
            self.sync_csg_slot_queues_state(data, csg_slot_manager, csg_idx)?;

            let blocked_idle = if reclaim {
                group.blocked_idle_queues()
            } else {
                0
            };
            for (queue_idx, queue) in group.queues.iter().enumerate() {
                if (blocked_idle & (1u32 << queue_idx)) != 0 {
                    continue;
                }
                queue.suspend_timeout();
            }
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

        // Publish `Active` before the kick loop below. A submit either
        // sees `Active` and kicks itself, or has already committed its
        // ring bytes, and the loop kicks that queue instead.
        group.set_state(new_state, trace::StateChangeReason::FwAck);

        // On the bind-side `Start`/`Resume` ack, ring the per-CS user
        // doorbell on every queue whose ringbuf already has commands.
        // `CsgSlotOps::activate` publishes `doorbell_id` before this point.
        if new_state == group::State::Active {
            for queue in slot_data.group.queues.iter() {
                queue.resume_timeout();
                if queue.is_ringbuf_empty().unwrap_or(true) {
                    continue;
                }
                if let Err(e) = queue.kick() {
                    pr_err!(
                        "CSG {}: user-doorbell kick on bind failed: {}\n",
                        csg_idx,
                        e.to_errno()
                    );
                }
            }
        }

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
    /// * `SyncWait`: capture the active wait into `QueueData::syncwait`
    ///   and, when no scoreboards are still in flight, mark the queue
    ///   blocked. The group is then pushed onto
    ///   `Scheduler::waiting_groups`.
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
        // `MAX_CS_PER_GROUP` (the width of the per-queue bitmasks
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

        let group_handle = group.handle();
        let group_uid = group.uid();
        if let Ok((ack, state, ep_cur, ep_req, rdep)) = data
            .fw
            .with_csg_mut(csg_idx, |csg| csg.read_output_dump_raw())
        {
            trace::fw_csg_dump_output(csg_idx as u32, ack, state, ep_cur, ep_req, rdep);
        }
        data.fw.with_csg_mut(csg_idx, |csg| {
            for cs_id in 0..queue_count {
                let Some(cs) = csg.cs_mut(cs_id) else {
                    continue;
                };
                let reason = cs.read_status_blocked_reason()?;
                trace::fw_cs_status_update(
                    csg_idx as u32,
                    cs_id as u32,
                    group_handle,
                    reason as u32,
                );
                blocked_reasons[cs_id] = Some(reason);
                scoreboards[cs_id] = cs.read_status_scoreboards()?;

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
                    cs_id as u32,
                    cs_req_raw,
                    cs_ack_raw,
                    status_wait_raw,
                    reason as u32,
                    scoreboards[cs_id],
                    sync_pointer,
                    cur_val,
                    cur_val_valid,
                );

                if reason == CsBlockedReason::SyncWait {
                    let wait = cs.read_status_wait_sync()?;
                    let gt = matches!(wait.condition, CsWaitCondition::Gt);
                    let sync_size = if wait.sync64 { 8u32 } else { 4u32 };
                    trace::cs_sync_wait_operand(
                        group_handle,
                        cs_id as u32,
                        wait.sync_ptr,
                        wait.ref_val,
                        sync_size,
                    );
                    sync_waits[cs_id] = Some((wait.sync_ptr, wait.ref_val, wait.sync64, gt));
                }
            }

            Ok::<_, Error>(())
        })?;

        for (cs_id, sync_wait) in sync_waits.iter_mut().enumerate().take(queue_count) {
            if let Some((gpu_va, ref_val, sync64, gt)) = sync_wait.take() {
                let (cur_val, cur_val_valid) = if trace::syncwait_capture_enabled() {
                    events::read_syncwait_cur_val(&group.vm, gpu_va, sync64)
                } else {
                    (0, false)
                };
                trace::syncwait_capture(
                    group.vm.handle(),
                    group_handle,
                    group_uid,
                    cs_id as u32,
                    gpu_va,
                    ref_val,
                    sync64,
                    gt,
                    cur_val,
                    cur_val_valid,
                );
                group.queues[cs_id].set_syncwait(gpu_va, ref_val, sync64, gt);
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
                    // `is_ringbuf_empty` reads firmware-shared memory directly, not
                    // through the firmware lock, so probing it here under `inner` is safe.
                    Some(CsBlockedReason::Unblocked)
                        if scoreboards[cs_id] == 0
                            && group.queues[cs_id].is_ringbuf_empty().unwrap_or(false) =>
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
                trace::queue_blocked_state_change(
                    group_handle,
                    cs_id as u32,
                    blocked,
                    trace::QueueBlockedCaller::SyncSlotApply,
                );
                trace::queue_idle_state(group_handle, cs_id as u32, idle);
                trace::queue_state(group_handle, cs_id as u32, blocked);
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
    pub(crate) fn collect_listed_groups(&mut self) -> KVec<Arc<Group>> {
        let mut groups = KVec::new();

        for prio in 0..GROUP_PRIORITY_COUNT {
            if !Self::collect_list(&mut self.runnable_groups[prio], &mut groups)
                || !Self::collect_list(&mut self.idle_groups[prio], &mut groups)
            {
                pr_err!("reset: out of memory snapshotting the group lists\n");
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
                if inner.fatal_error.is_none() {
                    inner.fatal_error = Some(ENODEV);
                }
            });
            group.schedule_term();
        }
    }

    /// Terminates every group on the scheduler lists.
    ///
    /// Called after a failed GPU reset, when the hardware is unusable.
    /// Each group is detached, marked terminated, and routed through
    /// `Group::schedule_term` so its queued and in-flight fences are
    /// canceled. Nothing is bound at this point. The pre-reset pass
    /// evicted every CSG slot.
    pub(crate) fn fail_all_groups(&mut self) {
        for prio in 0..GROUP_PRIORITY_COUNT {
            Self::terminate_list(&mut self.runnable_groups[prio]);
            Self::terminate_list(&mut self.idle_groups[prio]);

            // Groups on the wait list may also have been on an id-0
            // list above. The `term_scheduled` flag stops the terminal
            // cleanup running twice.
            while let Some(wait_arc) = self.waiting_groups[prio].pop_front() {
                let group: Arc<Group> = wait_arc.into_arc();
                group.with_locked_inner(|inner| {
                    inner.state = group::State::Terminated;
                    if inner.fatal_error.is_none() {
                        inner.fatal_error = Some(ENODEV);
                    }
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
    /// Idempotent: a group that is already on the runnable list, or
    /// is currently bound to a CSG slot, is left in place. An idle
    /// group is moved off `Scheduler::idle_groups` onto
    /// `Scheduler::runnable_groups`. Only the id-0 lists are
    /// manipulated; the wait-list (id-1) is owned elsewhere.
    pub(crate) fn mark_group_runnable(&mut self, group: &Arc<Group>) {
        let priority = group.priority as usize;

        group.with_locked_inner(|inner| {
            if inner.fatal_error.is_some() || group.vm.is_unusable() {
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
    /// Must be called *outside* `TyrDrmDeviceData::with_locked_scheduler`:
    /// the per-queue `complete_submit_fences` opens a
    /// `DmaFenceSignallingAnnotation` and signals user-visible
    /// dma-fences, and signalling-section code may not nest inside a
    /// wide driver lock like the scheduler mutex.
    ///
    /// Snapshots the bound groups under the slot-manager lock and
    /// drops it before touching firmware-shared memory; the snapshot
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

        for entry in snapshot.iter() {
            let Some(group) = entry else {
                continue;
            };
            for (queue_idx, queue) in group.queues.iter().enumerate() {
                match group.read_syncobj(queue_idx) {
                    Ok(syncobj) => queue.complete_submit_fences(syncobj.seqno, syncobj.status),
                    Err(err) => pr_err!(
                        "sync_upd: queue completion drain failed: {}\n",
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
    /// it; allocation failure aborts the walk and the next sync_upd
    /// or periodic tick will revisit.
    ///
    /// Pair with `evaluate_syncwait_candidates` and
    /// `apply_syncwait_results`.
    pub(crate) fn collect_syncwait_candidates(&mut self) -> KVec<SyncwaitCandidate> {
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
                    pr_err!("sync_upd: out of memory snapshotting wait list\n");
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
    /// were held. Read errors are logged and treated as "unblock and
    /// let the next tick surface any further failure". Allocation
    /// failure on the results vector drops the remaining candidates;
    /// the periodic tick will revisit.
    pub(crate) fn evaluate_syncwait_candidates(
        snapshot: KVec<SyncwaitCandidate>,
    ) -> KVec<SyncwaitResult> {
        let mut results = KVec::new();

        for candidate in snapshot {
            let mut unblocked: u32 = 0;
            let mut tested = candidate.blocked;
            while tested != 0 {
                let cs_id = tested.trailing_zeros();
                tested &= !(1u32 << cs_id);
                match candidate.group.eval_syncwait(cs_id as usize) {
                    Ok(true) => unblocked |= 1u32 << cs_id,
                    Ok(false) => {}
                    Err(e) => {
                        let gpu_va = candidate
                            .group
                            .queues
                            .get(cs_id as usize)
                            .map(|q| q.syncwait_snapshot().gpu_va)
                            .unwrap_or(0);
                        pr_err!(
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
                pr_err!("sync_upd: out of memory recording results\n");
                return results;
            }
        }

        results
    }

    /// Applies the results from `evaluate_syncwait_candidates`
    /// under the scheduler mutex.
    ///
    /// Walks `waiting_groups` per priority once and, for each peeked
    /// group that has a matching result, clears the newly unblocked
    /// queue bits, then removes the group from the wait list and
    /// marks it runnable if it has no other blocked queues and is
    /// not currently bound to a CSG slot. Re-validation against the
    /// live wait list handles groups that another path (e.g.
    /// destroy) removed between the snapshot and apply phases.
    ///
    /// Caller must not drop `results` before releasing the scheduler
    /// mutex.
    ///
    /// Returns `true` if an unbound RealTime-priority group was
    /// promoted to `runnable_groups`, in which case the caller fires
    /// an immediate tick so the rule engine binds it without waiting
    /// for the periodic tick.
    pub(crate) fn apply_syncwait_results(&mut self, results: &KVec<SyncwaitResult>) -> bool {
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
                        let mut bits = result.unblocked;
                        while bits != 0 {
                            let cs_id = bits.trailing_zeros() as usize;
                            bits &= !(1u32 << cs_id);
                            inner.set_queue_blocked(cs_id, false);
                            trace::queue_blocked_state_change(
                                group_handle,
                                cs_id as u32,
                                false,
                                trace::QueueBlockedCaller::ApplyResults,
                            );
                        }

                        let unblocked = !inner.has_blocked_queues();
                        let move_to_runnable = unblocked && inner.csg_id.is_none();
                        (unblocked, move_to_runnable)
                    });

                    if unblocked {
                        let list_arc = peek.remove();
                        trace::group_wait(result.group.handle(), false);
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

    /// Stages `CSG_REQ.STATUS_UPDATE` on every resident CSG slot and
    /// applies the batch. The post-ack sync pass refreshes per-queue
    /// firmware-status state.
    pub(crate) fn sync_group_states(&mut self, data: ARef<TyrDrmDevice>) -> Result {
        let mut context = CsgUpdateContext::new();
        let mut faulted_groups: [Option<(usize, Arc<Group>)>; MAX_CSGS] =
            [const { None }; MAX_CSGS];

        {
            let csg_slot_manager = data.csg_slot_manager.lock();
            for (csg_idx, slot) in faulted_groups
                .iter_mut()
                .enumerate()
                .take(csg_slot_manager.slot_count())
            {
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
                    *slot = Some((csg_idx, slot_data.group.clone()));
                }
                context.toggle_reqs(csg_idx, CSG_REQ_STATUS_UPDATE);
            }
        }

        for slot in faulted_groups.iter() {
            let Some((csg_idx, group)) = slot else {
                continue;
            };
            if let Err(e) = self.process_csg_irq(&data, *csg_idx) {
                pr_err!("process_csg_irq {} failed: {}\n", csg_idx, e.to_errno());
            }
            let queue_count = group.queue_count();
            group.with_locked_inner(|inner| {
                if inner.has_fatal_queues() {
                    return;
                }
                for cs_id in 0..queue_count {
                    inner.set_queue_fatal(cs_id);
                    trace::queue_fatal_state(group.handle(), cs_id as u32, true);
                }
            });
        }

        self.apply_csg_updates(&data, &mut context)
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
    pub(crate) fn dump_heap_pools_for_trace(tdev: &TyrDrmDevice, groups: &KVec<Arc<Group>>) {
        let mut seen: KVec<Arc<heap::Pool>> = KVec::new();
        for group in groups.iter() {
            let Some(pool) = group.try_get_heap_pool() else {
                continue;
            };
            if seen.iter().any(|p| Arc::ptr_eq(p, &pool)) {
                continue;
            }
            pool.dump_for_trace(tdev, group.handle(), 0);
            let _ = seen.push(pool, GFP_KERNEL);
        }
    }
}
