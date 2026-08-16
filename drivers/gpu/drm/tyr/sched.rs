// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    list::{
        List,
        ListArc, //
    },
    prelude::*,
    sync::Arc,
    types::ScopeGuard,
    uapi, //
};

use crate::{
    driver::TyrDrmDevice,
    fw::{
        self,
        global::csg::Priority,
        Firmware, //
    },
    gpu::CsifInfo,
    sched::group::GroupListState,
    slot::{
        LockedSeat,
        SlotManager,
        SlotOperations, //
    }, //
};

use group::Group;

const GROUP_PRIORITY_COUNT: usize = Priority::num_priorities();

/// Maximum number of CSG slots the scheduler can address.
///
/// Matches `fw::MAX_CSG`, the firmware-imposed hardware ceiling.
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

/// Per-slot driver data attached to a `CsgSlotManager` slot.
pub(crate) struct CsgSlotData {
    /// The group that currently owns the slot.
    pub(in crate::sched) group: Arc<Group>,
    /// CSG firmware priority programmed into `CSG_EP_REQ.priority`.
    #[expect(dead_code)]
    pub(in crate::sched) fw_priority: u32,
}

/// CSG slot operations.
///
/// `activate` makes the group's VM resident in a hardware AS slot.
/// `evict` releases that binding. Programming CSG_REQ and waiting for
/// firmware acknowledgements happens elsewhere.
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

    fn evict(&mut self, _slot_idx: usize, slot_data: &Self::SlotData) -> Result {
        slot_data.group.vm.deactivate()?;
        Ok(())
    }
}

/// Type alias for the SlotManager parameterized for CSG slots.
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
    pub(crate) fn init(tdev: &TyrDrmDevice, fw: &Firmware<'_>) -> Result<(Self, CsifInfo)> {
        let (csg_slot_count, cs_slot_count, cs_reg_count, scoreboard_slot_count) =
            fw.csif_info_counts()?;

        let csif = CsifInfo(uapi::drm_panthor_csif_info {
            csg_slot_count,
            cs_slot_count,
            cs_reg_count,
            scoreboard_slot_count,
            ..Default::default()
        });

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
            },
            csif,
        ))
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
        // in flight. The ScopeGuard below restores it on failure.
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

        slot_manager.activate(slot_data)?;

        // Cache the CSG doorbell id on each queue so submit-side kicks
        // can find it without reaching back into the slot manager. The
        // doorbells wired here remain stable for as long as the slot
        // is active.
        let slot_idx = group.csg_seat.access(&slot_manager).slot().ok_or(EINVAL)? as usize;
        for queue in group.queues.iter() {
            queue.set_doorbell_id(Some(slot_idx + 1));
        }

        // Bind succeeded, so drop the list_arc rather than restoring.
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

            slot_manager.evict(&group.csg_seat)?;
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
