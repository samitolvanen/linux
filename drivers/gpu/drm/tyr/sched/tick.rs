// SPDX-License-Identifier: GPL-2.0 or MIT

use super::Scheduler;
use crate::{
    driver::{
        work_id,
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    fw::global::csg::{
        GroupState,
        Priority,
        MAX_CSGS, //
    },
    sched::{
        group::Group,
        CsgSlotData,
        CsgSlotManager,
        CsgUpdateContext, //
    },
};
use kernel::{
    dma_fence::{
        impl_has_dma_fence_work,
        DmaFenceWorkItem, //
    },
    list::{
        List,
        ListArc, //
    },
    prelude::*,
    sync::Arc,
    time::{
        msecs_to_jiffies,
        Delta,
        Instant,
        Monotonic, //
    },
    types::ARef,
    workqueue::WorkItem, //
};

const MAX_PRUNED_PER_TICK: usize = 16;
const TEARDOWN_ARRAY_SIZE: usize = MAX_CSGS as usize + MAX_PRUNED_PER_TICK;

/// A policy action taken during scheduler rule evaluation.
#[derive(Copy, Clone)]
enum Action {
    /// Retain currently bound groups that match the rule criteria.
    Keep,
    /// Bind new, unbound groups from the software queues that match the rule criteria.
    Take,
}

/// A scheduling policy rule that determines how groups are selected for hardware slots.
#[derive(Copy, Clone)]
struct Rule {
    /// The action (`Keep` or `Take`) to perform for groups matching this rule.
    action: Action,
    /// The software scheduling priority this rule applies to.
    priority: Priority,
    /// Whether this rule applies to idle groups (`true`) or runnable groups (`false`).
    is_idle: bool,
}

/// Builds an ordered [`Rule`] iterator for one scheduler tick.
/// Each entry is spelled `Action Priority` (e.g. `Keep RealTime`); the
/// active half is selected by `$cond`, then chained with a shared idle half.
macro_rules! build_scheduling_rules {
    (
        shared_idle: [ $( $i_a:ident $i_p:ident ),* $(,)? ],
        if $cond:expr => [ $( $t_a:ident $t_p:ident ),* $(,)? ],
        else => [ $( $f_a:ident $f_p:ident ),* $(,)? ]
    ) => {{
        const IDLE: [Rule; 8] = [ $( Rule { action: Action::$i_a, priority: Priority::$i_p, is_idle: true } ),* ];
        let active = if $cond {
            [ $( Rule { action: Action::$t_a, priority: Priority::$t_p, is_idle: false } ),* ]
        } else {
            [ $( Rule { action: Action::$f_a, priority: Priority::$f_p, is_idle: false } ),* ]
        };
        core::iter::Iterator::chain(active.into_iter(), IDLE)
    }};
}

/// Identifies a group selected during rule evaluation.
#[derive(Copy, Clone)]
enum SelectedGroup {
    /// A hardware slot index that was chosen to be kept, its software priority,
    /// and current firmware priority.
    Kept(usize, Priority, u32),
    /// An index into the `pending_groups` array for a newly chosen group, and
    /// its software priority.
    Pending(usize, Priority),
}

/// Coarse class used as the primary key when sorting selections within a
/// software priority band. The class ordering depends on whether this is
/// a full tick (rotation) or a normal tick (stability).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SortClass {
    First,
    Second,
    Empty,
}

/// Sort key used by [`SelectedGroup::iter_prioritized`] to order selections
/// within a single software priority band.
fn sort_key(
    sel: Option<&SelectedGroup>,
    original_idx: usize,
    full_tick: bool,
) -> (SortClass, u32, usize) {
    match sel {
        // Empty slots always sort last and don't depend on the tick type.
        None => (SortClass::Empty, 0, 0),

        Some(SelectedGroup::Pending(_, _)) => {
            if full_tick {
                // Full tick: newly bound pending groups go first, getting the
                // highest firmware priority.
                (SortClass::First, 0, original_idx)
            } else {
                // Normal tick: pending groups go after retained groups.
                (SortClass::Second, 0, original_idx)
            }
        }

        Some(SelectedGroup::Kept(_, _, fw_prio)) => {
            if full_tick {
                // Full tick: retained groups go after pending, ordered from
                // lowest to highest previous firmware priority so the worst-off
                // gets bumped up the hardware queue this round.
                (SortClass::Second, *fw_prio, original_idx)
            } else {
                // Normal tick: retained groups go first, preserving their
                // existing firmware priority order (highest first).
                (SortClass::First, u32::MAX - *fw_prio, original_idx)
            }
        }
    }
}

impl SelectedGroup {
    fn priority(self) -> Priority {
        match self {
            Self::Kept(_, prio, _) => prio,
            Self::Pending(_, prio) => prio,
        }
    }

    /// Iterate selected groups, highest software priority first.
    ///
    /// Within each priority, normal ticks (`!full_tick`) preserve the
    /// previous hardware priority order: kept groups first (highest
    /// previous fw_prio first), then pending groups. Full ticks rotate
    /// to prevent starvation: pending groups first, then kept groups in
    /// ascending previous fw_prio (lowest goes to the front of the line).
    fn iter_prioritized(
        selections: &[Option<SelectedGroup>],
        full_tick: bool,
    ) -> impl Iterator<Item = SelectedGroup> + '_ {
        (0..Priority::num_priorities())
            .rev()
            .filter_map(|p| Priority::try_from(p as u8).ok())
            .flat_map(move |sw_prio| {
                // Collect all selections that match the current software priority band.
                let mut prio_selections = [(None, 0_usize); MAX_CSGS as usize];
                let mut count = 0;

                for (idx, selection) in selections.iter().enumerate() {
                    if let Some(sel) = selection {
                        if sel.priority() == sw_prio {
                            prio_selections[count] = (Some(*sel), idx);
                            count += 1;
                        }
                    }
                }

                let slice = &mut prio_selections[..count];

                slice.sort_unstable_by_key(|(s, original_idx)| {
                    sort_key(s.as_ref(), *original_idx, full_tick)
                });

                // Truncate the padded array to the actual count, then discard the stable-sort
                // index and unwrap the SelectedGroup.
                prio_selections
                    .into_iter()
                    .take(count)
                    .filter_map(|(s, _)| s)
            })
    }
}

/// Represents the outcome of evaluating scheduling rules.
struct SchedulingDecision {
    /// Whether this is a full tick.
    full_tick: bool,
    /// Bitmask of hardware CSG slots that will retain their currently bound group.
    keep_mask: u32,
    /// True if all selected groups are idle.
    all_idle: bool,
    /// Number of selected groups that are idle.
    idle_group_count: usize,
    /// Groups selected from the software queues to be bound to hardware.
    pending_groups: [Option<Arc<Group>>; MAX_CSGS as usize],
    /// Number of new groups selected from software queues.
    num_pending: usize,
    /// Total number of groups (kept + pending) selected for execution.
    num_selected: usize,
    /// The lowest priority among all selected groups.
    min_priority: Priority,
    /// Records the exact order in which groups were selected.
    selections: [Option<SelectedGroup>; MAX_CSGS as usize],
}

impl SchedulingDecision {
    /// Evaluates the priority rules to decide which groups to keep and which to take.
    fn evaluate_rules(
        tdev: &TyrDrmDeviceData,
        sched: &mut Scheduler,
        rules: impl IntoIterator<Item = Rule>,
        full_tick: bool,
    ) -> Result<Self> {
        let mut decision = Self {
            full_tick,
            keep_mask: 0,
            all_idle: true,
            idle_group_count: 0,
            pending_groups: [const { None }; MAX_CSGS as usize],
            num_selected: 0,
            num_pending: 0,
            min_priority: Priority::RealTime,
            selections: [const { None }; MAX_CSGS as usize],
        };

        // Hold the slot-manager lock once across the whole rule loop so a
        // slot's bound group cannot change between consecutive `Keep`
        // rules. `keep_bound` only reads through `slot_data()` and
        // `take_unbound` does not access the slot manager, so holding it
        // for the full pass is safe.
        let csg_slot_manager = tdev.csg_slot_manager.lock();
        for rule in rules {
            match rule.action {
                Action::Keep => {
                    decision.keep_bound(sched, &csg_slot_manager, rule.priority, rule.is_idle);
                }
                Action::Take => {
                    decision.take_unbound(sched, rule.priority, rule.is_idle)?;
                }
            }
        }
        Ok(decision)
    }

    /// Takes up to `groups.len()` eligible groups from a list.
    fn collect_groups(list: &mut List<Group>, groups: &mut [Option<Arc<Group>>]) -> Result<usize> {
        let mut count = 0;
        let mut cursor = list.cursor_front();

        while let Some(group) = cursor.peek_next() {
            if count >= groups.len() {
                break;
            }

            let status = group.arc().status();

            if !status.can_run || status.csg_id.is_some() {
                cursor.move_next();
                continue;
            }

            let group_arc: Arc<Group> = group.arc().into();
            cursor.move_next();
            groups[count] = Some(group_arc);
            count += 1;
        }

        Ok(count)
    }

    /// Selects currently bound groups matching the priority and idle state to be retained.
    fn keep_bound(
        &mut self,
        sched: &Scheduler,
        csg_slot_manager: &CsgSlotManager,
        priority: Priority,
        is_idle: bool,
    ) {
        let slot_count = sched.csg_slot_count as usize;

        for i in 0..slot_count {
            if self.num_selected >= slot_count {
                break;
            }

            let Some(slot_data) = csg_slot_manager.slot_data(i) else {
                continue;
            };

            let status = slot_data.group.status();
            if slot_data.group.priority != priority || !status.can_run || status.is_idle != is_idle
            {
                continue;
            }

            if (self.keep_mask & (1u32 << i)) != 0 {
                continue;
            }

            // Mark this slot index as 'kept'
            self.keep_mask |= 1u32 << i;

            let fw_priority = slot_data.fw_priority;
            self.selections[self.num_selected] =
                Some(SelectedGroup::Kept(i, priority, fw_priority));

            self.num_selected += 1;

            if !is_idle {
                self.all_idle = false;
            } else {
                self.idle_group_count += 1;
            }

            if (self.min_priority as u8) > (priority as u8) {
                self.min_priority = priority;
            }
        }
    }

    /// Selects unbound groups matching the priority and idle state to be scheduled.
    fn take_unbound(
        &mut self,
        sched: &mut Scheduler,
        priority: Priority,
        is_idle: bool,
    ) -> Result<()> {
        let slot_count = sched.csg_slot_count as usize;
        if self.num_selected >= slot_count {
            return Ok(());
        }

        // How many slots we are allowed to fill.
        let available_slots = slot_count - self.num_selected;
        let target = &mut self.pending_groups[self.num_pending..self.num_pending + available_slots];

        let queue = if is_idle {
            &mut sched.idle_groups[priority as usize]
        } else {
            &mut sched.runnable_groups[priority as usize]
        };

        // Collect available groups.
        let count = Self::collect_groups(queue, target)?;
        if count > 0 {
            if !is_idle {
                self.all_idle = false;
            } else {
                self.idle_group_count += count;
            }
            if (self.min_priority as u8) > (priority as u8) {
                self.min_priority = priority;
            }
            for i in 0..count {
                self.selections[self.num_selected + i] =
                    Some(SelectedGroup::Pending(self.num_pending + i, priority));
            }
        }
        self.num_pending += count;
        self.num_selected += count;

        Ok(())
    }
}

/// State for a single execution of the scheduler tick.
struct Tick<'a> {
    /// The scheduler instance being updated.
    sched: &'a mut Scheduler,
    /// Groups evicted during this tick that need subsequent cleanup.
    teardown_groups: &'a mut [Option<Arc<Group>>; TEARDOWN_ARRAY_SIZE],
    /// Number of groups in the teardown_groups array.
    num_teardown: usize,
}

impl<'a> Tick<'a> {
    /// Initializes a new scheduler tick context.
    fn new(
        sched: &'a mut Scheduler,
        teardown_groups: &'a mut [Option<Arc<Group>>; TEARDOWN_ARRAY_SIZE],
    ) -> Self {
        Self {
            sched,
            teardown_groups,
            num_teardown: 0,
        }
    }

    /// Evaluates groups and applies the scheduling decisions to the hardware.
    fn tick(&mut self, data: &ARef<TyrDrmDevice>) -> Result<()> {
        // Synchronize the software state with the hardware. We request the latest status
        // for all bound groups to ensure we know if any group has naturally finished,
        // faulted, or hit an unbounded syncwait before making new scheduling decisions.
        self.sched
            .sync_group_states(data.clone())
            .inspect_err(|_| pr_err!("sync_group_states failed\n"))?;

        let full_tick =
            self.sched.last_tick.elapsed().as_millis() >= i64::from(super::TICK_PERIOD_MS);

        let rules = build_scheduling_rules! {
            // Idle groups are processed identically in both normal and full
            // ticks. Prefer keeping them bound unless a hardware slot is
            // needed, walking priorities high to low.
            shared_idle: [
                Keep RealTime, Take RealTime,
                Keep High,     Take High,
                Keep Medium,   Take Medium,
                Keep Low,      Take Low,
            ],
            // A full tick forces a re-evaluation of currently bound active
            // groups to ensure fairness. Issuing `Take` before `Keep` at
            // each priority lets pending groups preempt currently bound
            // groups of the same priority, time-slicing the hardware.
            if full_tick => [
                Take RealTime, Keep RealTime,
                Take High,     Keep High,
                Take Medium,   Keep Medium,
                Take Low,      Keep Low,
            ],
            // A normal tick prefers to keep currently bound active groups
            // running to minimise context-switching overhead. Evaluate all
            // `Keep`s for non-RT priorities before any `Take`.
            else => [
                Keep RealTime, Take RealTime,
                Keep High,     Keep Medium,   Keep Low,
                Take High,     Take Medium,   Take Low,
            ]
        };

        let mut decision = SchedulingDecision::evaluate_rules(data, self.sched, rules, full_tick)?;
        self.apply(data, &mut decision)
    }

    /// Suspends and unbinds groups not marked to be kept.
    fn halt_and_unbind_evicted_groups(
        &mut self,
        data: &ARef<TyrDrmDevice>,
        decision: &SchedulingDecision,
    ) -> Result<()> {
        let slot_count = self.sched.csg_slot_count as usize;
        let mut context = CsgUpdateContext::new();

        // Build the halt request set under the slot-manager lock, then
        // drop the lock before issuing the firmware update — `apply_csg_updates`
        // re-acquires it itself across its wait phase.
        {
            let csg_slot_manager = data.csg_slot_manager.lock();
            for i in 0..slot_count {
                if (decision.keep_mask & (1u32 << i)) != 0 {
                    continue;
                }
                let Some(slot_data) = csg_slot_manager.slot_data(i) else {
                    continue;
                };

                context.set_state(
                    i,
                    if slot_data.group.can_run() {
                        GroupState::Suspend
                    } else {
                        GroupState::Terminate
                    },
                );
            }
        }

        // Flush the state updates to the hardware and wait for it to acknowledge the halt.
        self.sched
            .apply_csg_updates(data.clone(), &mut context)
            .inspect_err(|_| pr_err!("apply_csg_updates (halt) failed\n"))?;

        // Unbind the evicted groups.
        let mut csg_slot_manager = data.csg_slot_manager.lock();
        for i in 0..slot_count {
            if (decision.keep_mask & (1u32 << i)) != 0 {
                continue;
            }

            let (group, can_run) = {
                let Some(slot_data) = csg_slot_manager.slot_data(i) else {
                    continue;
                };
                (slot_data.group.clone(), slot_data.group.can_run())
            };

            // Process interrupts to clear any pending interrupts.
            if let Err(e) = data.fw.with_locked_global_iface(|glb_iface| {
                self.sched
                    .process_csg_irq(data.clone(), glb_iface, i as u32, Some(group.clone()))
            }) {
                pr_err!("process_csg_irq {} failed: {}\n", i, e.to_errno());
            }

            csg_slot_manager.evict(&group.csg_seat, &mut context)?;

            if can_run {
                // If the group is still healthy, requeue it.
                if let Ok(list_arc) = ListArc::try_from_arc(group.clone()) {
                    self.sched.requeue_group(list_arc);
                }
            } else {
                self.teardown_groups[self.num_teardown] = Some(group.clone());
                self.num_teardown += 1;
            }
        }

        Ok(())
    }

    /// Updates priorities for retained groups and binds new pending groups into
    /// available hardware slots in a single prioritized pass.
    fn apply_priorities_and_bind(
        &mut self,
        data: &ARef<TyrDrmDevice>,
        decision: &mut SchedulingDecision,
    ) -> Result<()> {
        let mut context = CsgUpdateContext::new();
        let mut next_fw_prio = super::MAX_CSG_PRIO;

        // Build the priority/bind request set under the slot-manager lock,
        // then drop the lock before issuing the firmware update —
        // `apply_csg_updates` re-acquires the lock itself across its wait
        // phase.
        {
            let mut csg_slot_manager = data.csg_slot_manager.lock();

            for selection in SelectedGroup::iter_prioritized(
                &decision.selections[..decision.num_selected],
                decision.full_tick,
            ) {
                let fw_prio = next_fw_prio;
                next_fw_prio = next_fw_prio.saturating_sub(1);

                match selection {
                    SelectedGroup::Kept(slot_idx, _sw_prio, cur_fw_prio) => {
                        if cur_fw_prio == fw_prio {
                            continue;
                        }

                        if let Err(e) = self.sched.update_csg_slot_priority(
                            data,
                            &csg_slot_manager,
                            slot_idx,
                            fw_prio,
                            &mut context,
                        ) {
                            pr_err!(
                                "update_csg_slot_priority {} failed: {}\n",
                                slot_idx,
                                e.to_errno()
                            );
                        }
                    }
                    SelectedGroup::Pending(idx, _sw_prio) => {
                        let Some(group) = decision.pending_groups[idx].take() else {
                            continue;
                        };

                        if let Err(e) = csg_slot_manager.activate(
                            &group.csg_seat,
                            CsgSlotData {
                                group: group.clone(),
                                fw_priority: fw_prio,
                            },
                            &mut context,
                        ) {
                            pr_err!("activate (pending) failed: {}\n", e.to_errno());
                            continue;
                        }

                        let list_state = group.with_locked_inner(|inner| {
                            let state = inner.list_state;
                            inner.list_state = crate::sched::group::GroupListState::None;
                            Ok(state)
                        })?;
                        let _ = self.sched.remove_group_from_list(
                            &group,
                            group.priority as usize,
                            list_state,
                        );
                    }
                }
            }
        }

        let res = self.sched.apply_csg_updates(data.clone(), &mut context);

        if res.is_err() {
            pr_err!("apply_csg_updates (priorities & bind) failed\n");
        }

        res
    }

    /// Updates scheduler statuses and schedules a periodic tick if there is contention.
    fn update_status_and_resched(
        &mut self,
        data: &ARef<TyrDrmDevice>,
        decision: &SchedulingDecision,
    ) {
        self.sched.resched_target = None;
        self.sched.last_tick = Instant::<Monotonic>::now();
        self.sched.used_csg_slot_count = decision.num_selected as u32;
        self.sched.might_have_idle_groups = decision.idle_group_count > 0;

        // We only need to time-slice (reschedule periodically) if there is actual
        // contention for the hardware.
        let is_full = decision.num_selected >= self.sched.csg_slot_count as usize;
        let has_runnable_groups_waiting_for_slot =
            !self.sched.runnable_groups[decision.min_priority as usize].is_empty();

        if is_full && decision.idle_group_count == 0 && has_runnable_groups_waiting_for_slot {
            self.sched.resched_target =
                Some(self.sched.last_tick + Delta::from_millis(i64::from(super::TICK_PERIOD_MS)));
            TyrDrmDeviceData::schedule_periodic_tick(data, msecs_to_jiffies(super::TICK_PERIOD_MS));
        }
    }

    /// Executes the scheduling steps and updates subsequent tick targets.
    fn apply(
        &mut self,
        data: &ARef<TyrDrmDevice>,
        decision: &mut SchedulingDecision,
    ) -> Result<()> {
        self.halt_and_unbind_evicted_groups(data, decision)?;
        self.apply_priorities_and_bind(data, decision)?;

        let count = self
            .sched
            .prune_destroyed_groups(&mut self.teardown_groups[self.num_teardown..]);
        self.num_teardown += count;

        self.update_status_and_resched(data, decision);
        Ok(())
    }
}

kernel::workqueue::impl_has_delayed_work! {
    impl HasDelayedWork<TyrDrmDevice, { work_id::PERIODIC_TICK }> for TyrDrmDeviceData {
        self.periodic_tick_work
    }
}

impl WorkItem<{ work_id::PERIODIC_TICK }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    fn run(this: Self::Pointer) {
        TyrDrmDeviceData::schedule_tick(&this);
    }
}

impl_has_dma_fence_work! {
    impl HasDmaFenceWork<TyrDrmDevice, { work_id::TICK }> for TyrDrmDeviceData {
        self.tick_work
    }
}

impl DmaFenceWorkItem<{ work_id::TICK }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    /// The core scheduler tick.
    fn run(this: Self::Pointer) {
        // Temporarily holds groups that were unbound or pruned during this tick.
        let mut teardown_groups: [Option<Arc<Group>>; TEARDOWN_ARRAY_SIZE] =
            [const { None }; TEARDOWN_ARRAY_SIZE];

        if let Err(e) =
            this.with_locked_scheduler(|sched| Tick::new(sched, &mut teardown_groups).tick(&this))
        {
            pr_err!("an error occurred in tick: {}\n", e.to_errno());
        }

        // Process final teardown for groups evicted due to a fatal error, timeout,
        // or destruction.
        for group_opt in &mut teardown_groups {
            if let Some(group) = group_opt.take() {
                group.schedule_term();
            } else {
                break;
            }
        }
    }
}
