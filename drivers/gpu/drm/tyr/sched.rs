// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    list::{
        List,
        ListArc, //
    },
    prelude::*,
    sync::Arc,
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
            CsgActivateInputs,
            //
        },
        CsgExecutionState,
        CsgSlotMask,
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
/// Matches [`fw::MAX_CSG`], the firmware-imposed hardware ceiling.
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
pub(crate) struct CsgUpdateContext {
    pub(crate) req_value: [CSG_REQ; MAX_CSGS],
    pub(crate) req_mask: [CSG_REQ; MAX_CSGS],
    /// Per-slot bits acknowledged by the firmware in response to this
    /// tick's `req_value` writes. Bits in `req_mask` missing from here
    /// mark the slot as timed out (see `timedout_mask`).
    pub(crate) acked_reqs: [CSG_REQ; MAX_CSGS],
    #[expect(dead_code)]
    db_toggle: [u32; MAX_CSGS],
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
            update_mask: CsgSlotMask::empty(),
            timedout_mask: CsgSlotMask::empty(),
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
        self.update_mask.insert(csg_idx);
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
}

/// CSG slot operations.
///
/// `activate` programs the static CSG_INPUT registers and stages a
/// `CSG_REQ.state = Start`; `evict` releases the AS slot. The
/// firmware-visible `CSG_REQ` write, doorbell ring and ack wait are
/// driven by [`Scheduler::apply_csg_updates`].
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

        // Release the AS-slot binding on any failure of the CSG_INPUT
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

        self.fw
            .with_csg_mut(slot_idx, |csg| csg.program_activate_inputs(&inputs))?;

        let state = match group.state() {
            group::State::Suspended => CsgExecutionState::Resume,
            _ => CsgExecutionState::Start,
        };
        ctx.set_state(slot_idx, state);
        ctx.toggle_reqs(slot_idx, CSG_REQ_EP_CFG);
        rollback.dismiss();
        Ok(())
    }

    fn evict(
        &mut self,
        _slot_idx: usize,
        slot_data: &Self::SlotData,
        _ctx: &mut Self::Context,
    ) -> Result {
        slot_data.group.vm.deactivate()?;
        Ok(())
    }
}

/// Type alias for the SlotManager parameterised for CSG slots.
pub(crate) type CsgSlotManager = SlotManager<CsgSlotOps, MAX_CSGS>;

/// Minimal scheduler shell.
pub(crate) struct Scheduler {
    /// Groups that have at least one queue that can be currently scheduled.
    pub(in crate::sched) runnable_groups: [List<Group, 0>; GROUP_PRIORITY_COUNT],
    /// Groups whose queues are all idle (nothing to execute or blocked).
    pub(in crate::sched) idle_groups: [List<Group, 0>; GROUP_PRIORITY_COUNT],
    /// Groups whose queues are blocked on a sync object.
    #[expect(dead_code)]
    pub(in crate::sched) waiting_groups: [List<Group, 1>; GROUP_PRIORITY_COUNT],
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

    pub(crate) fn bind(
        &mut self,
        tdev: &TyrDrmDevice,
        group: Arc<Group>,
        ctx: &mut CsgUpdateContext,
    ) -> Result {
        let mut slot_manager = tdev.csg_slot_manager.lock();

        // Already resident; nothing to do.
        if group.csg_seat.access(&slot_manager).slot().is_some() {
            return Ok(());
        }

        // Pull `group` off its current list. Clear list_state while
        // in flight; the ScopeGuard below restores it on failure.
        let priority = group.priority as usize;
        let prior_list_state = group.with_locked_inner(|inner| {
            let prior = inner.list_state;
            inner.list_state = GroupListState::None;
            prior
        });

        let list_arc = self
            .remove_group_from_list(&group, priority, prior_list_state)
            .ok_or(EINVAL)?;

        let restore_list = match prior_list_state {
            GroupListState::Runnable => &mut self.runnable_groups[priority],
            GroupListState::Idle => &mut self.idle_groups[priority],
            // Unreachable: ok_or(EINVAL)? above takes the error path.
            GroupListState::None => unreachable!(),
        };
        let list_arc = ScopeGuard::new_with_data(list_arc, |list_arc| {
            restore_list.push_back(list_arc);
            group.with_locked_inner(|inner| {
                inner.list_state = prior_list_state;
            });
        });

        let slot_data = CsgSlotData {
            group: Arc::clone(&group),
            fw_priority: 0,
        };

        slot_manager.activate(&group.csg_seat, slot_data, ctx)?;

        // Cache the CSG doorbell id on each queue so submit-side kicks
        // can find it without reaching back into the slot manager. The
        // doorbells wired here remain stable for as long as the slot
        // is active.
        let slot_idx = group.csg_seat.access(&slot_manager).slot().ok_or(EINVAL)? as usize;
        for queue in group.queues.iter() {
            queue.set_doorbell_id(Some(slot_idx + 1));
        }

        // Bind succeeded; drop the list_arc rather than restoring.
        let _ = list_arc.dismiss();
        Ok(())
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

    pub(crate) fn remove_group(&mut self, tdev: &TyrDrmDevice, group: Arc<Group>) -> Result {
        let mut slot_manager = tdev.csg_slot_manager.lock();

        if group.csg_seat.access(&slot_manager).slot().is_some() {
            for queue in group.queues.iter() {
                queue.set_doorbell_id(None);
            }

            let mut ctx = CsgUpdateContext::new();
            slot_manager.evict(&group.csg_seat, &mut ctx)?;
            return Ok(());
        }

        // Drop the slot-manager lock before we touch the scheduler's
        // own idle queues. We don't take any other lock from the slot
        // manager callbacks, but releasing it here keeps the lock
        // ordering (sched > csg_slot_manager) one-directional.
        drop(slot_manager);

        let priority = group.priority as usize;
        let list_state = group.with_locked_inner(|inner| {
            let state = inner.list_state;
            inner.list_state = GroupListState::None;
            state
        });

        let _ = self.remove_group_from_list(&group, priority, list_state);

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
        data: &TyrDrmDevice,
        context: &mut CsgUpdateContext,
    ) -> Result {
        if context.update_mask.is_empty() {
            return Ok(());
        }

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
            data.fw.with_csg_mut(csg_id, |csg| {
                csg.update_and_toggle_input_req(req_value, set_mask, toggle_mask)
            })?;
        }

        data.fw.ring_csg_doorbells(context.update_mask)?;

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
                        context.timedout_mask.insert(csg_id);
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
                self.sync_csg_slot_state(data, &csg_slot_manager, csg_id)?;
            }
            if !(acked_reqs & CSG_REQ_STATUS_UPDATE).is_empty() {
                self.sync_csg_slot_queues_state(data, &csg_slot_manager, csg_id)?;
            }
        }

        if !context.timedout_mask.is_empty() {
            return Err(ETIMEDOUT);
        }

        Ok(())
    }

    /// Stages a firmware-priority update for CSG slot `csg_idx`.
    ///
    /// Caller must hold the slot-manager lock.
    #[expect(dead_code)]
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
    fn sync_csg_slot_queues_state(
        &mut self,
        _data: &TyrDrmDeviceData,
        _csg_slot_manager: &CsgSlotManager,
        _csg_idx: usize,
    ) -> Result {
        Ok(())
    }
}
