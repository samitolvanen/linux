// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    alloc::KVec,
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
    fw::global::csg::Priority,
    sched::group::GroupListState, //
};

use group::Group;

const GROUP_PRIORITY_COUNT: usize = Priority::num_priorities();

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

struct CommandStreamGroupSlot {
    group: Arc<Group>,
}

/// Minimal scheduler shell.
pub(crate) struct Scheduler {
    /// Groups that have at least one queue that can be currently scheduled.
    pub(in crate::sched) runnable_groups: [List<Group, 0>; GROUP_PRIORITY_COUNT],
    /// Groups whose queues are all idle (nothing to execute or blocked).
    pub(in crate::sched) idle_groups: [List<Group, 0>; GROUP_PRIORITY_COUNT],
    /// Groups whose queues are blocked on a sync object.
    #[expect(dead_code)]
    pub(in crate::sched) waiting_groups: [List<Group, 1>; GROUP_PRIORITY_COUNT],
    csg_slots: KVec<Option<CommandStreamGroupSlot>>,
}

impl Scheduler {
    pub(crate) fn init(tdev: &TyrDrmDevice) -> Result<Self> {
        let (csg_slot_count, cs_slot_count, cs_reg_count, scoreboard_slot_count) =
            tdev.fw.csif_info_counts()?;
        let mut csg_slots = KVec::with_capacity(csg_slot_count as usize, GFP_KERNEL)?;

        for _ in 0..csg_slot_count {
            csg_slots.push(None, GFP_KERNEL)?;
        }

        {
            let mut csif = tdev.csif_info.lock();
            csif.csg_slot_count = csg_slot_count;
            csif.cs_slot_count = cs_slot_count;
            csif.cs_reg_count = cs_reg_count;
            csif.scoreboard_slot_count = scoreboard_slot_count;
        }

        Ok(Self {
            runnable_groups: [const { List::new() }; GROUP_PRIORITY_COUNT],
            idle_groups: [const { List::new() }; GROUP_PRIORITY_COUNT],
            waiting_groups: [const { List::new() }; GROUP_PRIORITY_COUNT],
            csg_slots,
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

    pub(crate) fn bind(&mut self, _tdev: &TyrDrmDevice, group: Arc<Group>) -> Result {
        if group.csg_id().is_some() {
            return Ok(());
        }

        let csg_slot = self
            .csg_slots
            .iter_mut()
            .position(|slot| slot.is_none())
            .ok_or(ENOSPC)?;

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

        group.vm.activate()?;
        let slot = self.csg_slots.get_mut(csg_slot).ok_or(EINVAL)?;
        group.set_csg_id(Some(csg_slot));
        for queue in group.queues.iter() {
            queue.set_doorbell_id(Some(csg_slot + 1));
        }
        *slot = Some(CommandStreamGroupSlot {
            group: Arc::clone(&group),
        });

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

    pub(crate) fn remove_group(&mut self, group: Arc<Group>) -> Result {
        if let Some(csg_id) = group.csg_id() {
            let csg_slot = self.csg_slots.get_mut(csg_id).ok_or(EINVAL)?;
            let slot = csg_slot.as_mut().ok_or(EINVAL)?;
            slot.group.vm.deactivate()?;
            for queue in slot.group.queues.iter() {
                queue.set_doorbell_id(None);
            }
            slot.group.set_csg_id(None);
            *csg_slot = None;
            return Ok(());
        }

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
