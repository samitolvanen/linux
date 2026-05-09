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
    driver::TyrDrmDevice,
    fw,
    fw::global::csg::Priority,
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
    #[expect(dead_code)]
    pub(in crate::sched) fw_priority: u32,
}

/// Per-tick accumulator for CSG slot programming.
///
/// CSG slot operations need to coalesce multiple per-slot writes into a
/// single CSG_REQ word, ring the per-CSG doorbell once, then wait for
/// the firmware to acknowledge the resulting state transitions. The
/// activate / evict callbacks of [`CsgSlotOps`] update this accumulator
/// while the slot-manager mutex is held.
pub(crate) struct CsgUpdateContext {}

impl CsgUpdateContext {
    /// Creates an empty accumulator.
    pub(crate) fn new() -> Self {
        Self {}
    }
}

/// CSG slot operations.
///
/// `activate` makes the group's VM resident in a hardware AS slot;
/// `evict` releases that binding. Programming CSG_REQ and waiting for
/// firmware acknowledgements happens elsewhere.
pub(crate) struct CsgSlotOps {
    #[expect(dead_code)]
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
        _slot_idx: usize,
        slot_data: &Self::SlotData,
        _ctx: &mut Self::Context,
    ) -> Result {
        slot_data.group.vm.activate()?;
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

    pub(crate) fn bind(&mut self, tdev: &TyrDrmDevice, group: Arc<Group>) -> Result {
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

        let mut ctx = CsgUpdateContext::new();
        let slot_data = CsgSlotData {
            group: Arc::clone(&group),
            fw_priority: 0,
        };

        slot_manager.activate(&group.csg_seat, slot_data, &mut ctx)?;

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
}
