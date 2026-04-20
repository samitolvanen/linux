// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::dma_fence::DmaFenceDelayedWorkItem;
use kernel::dma_fence::DmaFenceWorkItem;
use kernel::impl_has_dma_fence_delayed_work;
use kernel::impl_has_dma_fence_work;
use kernel::list::List;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::time::{msecs_to_jiffies, Delta, Instant, Monotonic};

use crate::driver::TyrData;
use crate::fw::global::csg::{GroupState, Priority, MAX_CSGS};
use crate::sched::group::Group;
use crate::sched::CsgUpdateContext;
use crate::sched::UnboundGroup;

use super::Scheduler;

/// A policy action taken during scheduler rule evaluation.
enum Action {
    /// Retain currently bound groups that match the rule criteria.
    Keep,
    /// Bind new, unbound groups from the software queues that match the rule criteria.
    Take,
}

/// A scheduling policy rule that determines how groups are selected for hardware slots.
struct Rule {
    /// The action (`Keep` or `Take`) to perform for groups matching this rule.
    action: Action,
    /// The software scheduling priority this rule applies to.
    priority: Priority,
    /// Whether this rule applies to idle groups (`true`) or runnable groups (`false`).
    is_idle: bool,
}

/// Constructs an array of `Rule`s based on idle, active, and conditional states.
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

impl SelectedGroup {
    fn priority(self) -> Priority {
        match self {
            Self::Kept(_, prio, _) => prio,
            Self::Pending(_, prio) => prio,
        }
    }

    /// Returns an iterator over the selected groups, ordered from highest to lowest
    /// software priority.
    ///
    /// If `full_tick` is false (normal tick), groups within the same priority are
    /// sorted to preserve their existing hardware priority order, ensuring the
    /// rotation from previous full ticks is not inadvertently reversed:
    /// 1. Kept groups are yielded first, ordered from highest to lowest previous
    ///    hardware priority.
    /// 2. Pending (newly bound) groups are yielded after kept groups.
    ///
    /// If `full_tick` is true, groups within the same priority are sorted to rotate
    /// their hardware priorities and prevent starvation:
    /// 1. Pending (newly bound) groups are yielded first.
    /// 2. Kept groups are yielded next, sorted in ascending order of their previous
    ///    hardware priority. The group that previously had the worst (lowest)
    ///    hardware priority is yielded first, bumping it to the front of the line
    ///    so it receives a higher hardware priority for the next scheduling period.
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

                if full_tick {
                    // During a full tick, reorder groups within the same priority band to prevent
                    // starvation of long-running groups.
                    slice.sort_unstable_by_key(|(s, original_idx)| match s {
                        // 1. Newly bound pending groups go first (highest firmware priority).
                        Some(SelectedGroup::Pending(_, _)) => (0, 0, *original_idx),
                        // 2. Retained groups go next, ordered from lowest to highest previous
                        //    firmware priority to rotate them up the hardware scheduling queue.
                        Some(SelectedGroup::Kept(_, _, fw_prio)) => (1, *fw_prio, *original_idx),
                        // 3. Empty slots.
                        None => (2, 0, 0),
                    });
                } else {
                    // During a normal tick, preserve the existing firmware priority order
                    // of retained groups.
                    slice.sort_unstable_by_key(|(s, original_idx)| match s {
                        // 1. Retained groups keep their relative ordering (highest fw_prio first).
                        Some(SelectedGroup::Kept(_, _, fw_prio)) => {
                            (0, u32::MAX - *fw_prio, *original_idx)
                        }
                        // 2. Newly bound pending groups go after kept groups.
                        Some(SelectedGroup::Pending(_, _)) => (1, 0, *original_idx),
                        // 3. Empty slots.
                        None => (2, 0, 0),
                    });
                }

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

        for rule in rules {
            match rule.action {
                Action::Keep => {
                    decision.keep_bound(sched, rule.priority, rule.is_idle);
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

            let group: Arc<Group> = group.arc().into();
            let status = group.status();

            cursor.move_next();

            if !status.can_run || status.csg_id.is_some() {
                continue;
            }

            groups[count] = Some(group);
            count += 1;
        }

        Ok(count)
    }

    /// Selects currently bound groups matching the priority and idle state to be retained.
    fn keep_bound(&mut self, sched: &Scheduler, priority: Priority, is_idle: bool) {
        let slot_count = sched.csg_slot_count as usize;

        for i in 0..slot_count {
            if self.num_selected >= slot_count {
                break;
            }

            let Some(slot) = &sched.csg_slots[i] else {
                continue;
            };

            let status = slot.group.status();
            if slot.group.priority != priority || !status.can_run || status.is_idle != is_idle {
                continue;
            }

            if (self.keep_mask & (1u32 << i)) != 0 {
                continue;
            }

            // Mark this slot index as 'kept'
            self.keep_mask |= 1u32 << i;

            let fw_priority = slot.fw_priority.unwrap_or(u32::MAX);
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
    evicted_groups: &'a mut [Option<UnboundGroup>; MAX_CSGS as usize],
    /// Number of groups in the evicted_groups array.
    num_evicted: &'a mut usize,
}

impl<'a> Tick<'a> {
    /// Initializes a new scheduler tick context.
    fn new(
        sched: &'a mut Scheduler,
        evicted_groups: &'a mut [Option<UnboundGroup>; MAX_CSGS as usize],
        num_evicted: &'a mut usize,
    ) -> Self {
        Self {
            sched,
            evicted_groups,
            num_evicted,
        }
    }

    /// Evaluates groups and applies the scheduling decisions to the hardware.
    fn tick(&mut self, data: &Arc<TyrData>) -> Result<()> {
        // Synchronize the software state with the hardware. We request the latest status
        // for all bound groups to ensure we know if any group has naturally finished,
        // faulted, or hit an unbounded syncwait before making new scheduling decisions.
        self.sched
            .sync_group_states(data)
            .inspect_err(|_| pr_err!("sync_group_states failed\n"))?;

        let full_tick =
            if self.sched.last_tick.elapsed().as_millis() >= super::TICK_PERIOD_MS as i64 {
                true
            } else {
                false
            };

        let rules = build_scheduling_rules! {
            // Idle groups are processed identically in both normal and full ticks.
            // We prioritize keeping them bound unless a hardware slot is needed.
            shared_idle: [
                Keep RealTime, Take RealTime,
                Keep High,     Take High,
                Keep Medium,   Take Medium,
                Keep Low,      Take Low,
            ],
            // A full tick forces a re-evaluation of currently bound active groups
            // to ensure fairness. By issuing a 'Take' before a 'Keep' for each
            // priority level, it allows pending groups to preempt currently bound
            // groups of the same priority, effectively time-slicing the hardware.
            if full_tick => [
                Take RealTime, Keep RealTime,
                Take High,     Keep High,
                Take Medium,   Keep Medium,
                Take Low,      Keep Low,
            ],
            // A normal tick prefers to keep currently bound active groups running
            // to minimize context switching overhead. It evaluates all 'Keep'
            // actions for non-RT priorities before attempting to 'Take' new ones.
            else => [
                Keep RealTime, Take RealTime,
                Keep High,     Keep Medium,   Keep Low,
                Take High,     Take Medium,   Take Low,
            ]
        };

        let mut decision = SchedulingDecision::evaluate_rules(self.sched, rules, full_tick)?;
        self.apply(data, &mut decision)
    }

    /// Suspends and unbinds groups not marked to be kept.
    fn halt_and_unbind_evicted_groups(
        &mut self,
        data: &Arc<TyrData>,
        decision: &SchedulingDecision,
    ) -> Result<()> {
        let slot_count = self.sched.csg_slot_count as usize;
        let mut context = CsgUpdateContext::new();

        // Suspend or terminate bound groups not in keep_mask.
        for i in 0..slot_count {
            if (decision.keep_mask & (1u32 << i)) != 0 {
                continue;
            }
            let Some(slot) = self.sched.csg_slots[i].as_ref() else {
                continue;
            };

            context.set_state(
                i,
                if slot.group.can_run() {
                    GroupState::Suspend
                } else {
                    GroupState::Terminate
                },
            );
        }

        // Flush the state updates to the hardware and wait for it to acknowledge the halt.
        self.sched
            .apply_csg_updates(data, &mut context)
            .inspect_err(|_| pr_err!("apply_csg_updates (halt) failed\n"))?;

        // Unbind the evicted groups.
        for i in 0..slot_count {
            if (decision.keep_mask & (1u32 << i)) != 0 || self.sched.csg_slots[i].is_none() {
                continue;
            }

            // Process interrupts to clear any pending interrupts.
            if let Err(e) = data.fw.with_locked_global_iface(|glb_iface| {
                self.sched
                    .process_csg_irq(data.clone(), glb_iface, i as u32)
            }) {
                pr_err!("process_csg_irq {} failed: {}\n", i, e.to_errno());
            }

            let mut unbound = match self.sched.unbind_group(data, i) {
                Ok(u) => u,
                Err(e) => {
                    pr_err!("unbind_group {} failed: {}\n", i, e.to_errno());
                    continue;
                }
            };

            // If the group is still healthy, requeue it.
            if let Some(list_arc) = unbound.list_arc.take() {
                self.sched.requeue_group(list_arc);
            }

            self.evicted_groups[*self.num_evicted] = Some(unbound);
            *self.num_evicted += 1;
        }

        Ok(())
    }

    /// Updates priorities for retained groups and binds new pending groups into
    /// available hardware slots in a single prioritized pass.
    fn apply_priorities_and_bind(
        &mut self,
        data: &Arc<TyrData>,
        decision: &mut SchedulingDecision,
    ) -> Result<()> {
        let slot_count = self.sched.csg_slot_count as usize;
        let mut context = CsgUpdateContext::new();
        let mut next_fw_prio = super::MAX_CSG_PRIO;

        // Any slot not explicitly kept should be free at this stage.
        let mut free_slots = (!decision.keep_mask) & ((1u32 << slot_count) - 1);

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

                    if let Err(e) =
                        self.sched
                            .update_csg_slot_priority(data, slot_idx, fw_prio, &mut context)
                    {
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
                    if free_slots == 0 {
                        pr_err!("apply_priorities_and_bind: out of slots\n");
                        continue;
                    }

                    // Pop the lowest available slot index.
                    let slot_idx = free_slots.trailing_zeros() as usize;
                    free_slots &= !(1u32 << slot_idx);

                    if let Err(e) = self.sched.bind_group(data, group, slot_idx) {
                        pr_err!("bind_group {} failed: {}\n", slot_idx, e.to_errno());
                        continue;
                    }

                    if let Err(e) =
                        self.sched
                            .program_csg_slot(data, slot_idx, fw_prio, &mut context)
                    {
                        pr_err!("program_csg_slot {} failed: {}\n", slot_idx, e.to_errno());
                    }
                }
            }
        }

        self.sched
            .apply_csg_updates(data, &mut context)
            .inspect_err(|_| pr_err!("apply_csg_updates (priorities & bind) failed\n"))
    }

    /// Updates scheduler statuses and schedules a periodic tick if there is contention.
    fn update_status_and_resched(&mut self, data: &Arc<TyrData>, decision: &SchedulingDecision) {
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
                Some(self.sched.last_tick + Delta::from_millis(super::TICK_PERIOD_MS as i64));
            data.schedule_periodic_tick(msecs_to_jiffies(super::TICK_PERIOD_MS) as _);
        }
    }

    /// Executes the scheduling steps and updates subsequent tick targets.
    fn apply(&mut self, data: &Arc<TyrData>, decision: &mut SchedulingDecision) -> Result<()> {
        self.halt_and_unbind_evicted_groups(data, decision)?;
        self.apply_priorities_and_bind(data, decision)?;
        self.sched.prune_destroyed_groups();

        self.update_status_and_resched(data, decision);
        Ok(())
    }
}

impl_has_dma_fence_delayed_work! {
    impl HasDmaFenceDelayedWork<Self, 4> for TyrData {
        self.periodic_tick_work
    }
}

impl DmaFenceDelayedWorkItem<4> for TyrData {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        this.schedule_tick();
    }
}

impl_has_dma_fence_work! {
    impl HasDmaFenceWork<Self, 1> for TyrData {
        self.tick_work
    }
}

impl DmaFenceWorkItem<1> for TyrData {
    type Pointer = Arc<Self>;

    /// The core scheduler tick.
    fn run(this: Self::Pointer) {
        // Temporarily holds groups that were unbound during this tick.
        let mut evicted_groups: [Option<UnboundGroup>; MAX_CSGS as usize] =
            [const { None }; MAX_CSGS as usize];
        let mut num_evicted = 0;

        if let Err(e) = this.with_locked_scheduler(|sched| {
            Tick::new(sched, &mut evicted_groups, &mut num_evicted).tick(&this)
        }) {
            pr_err!("an error occurred in tick: {}\n", e.to_errno());
        }

        // Process final teardown for groups evicted due to a fatal error, timeout,
        // or destruction.
        for unbound in &mut evicted_groups[..num_evicted] {
            if let Some(UnboundGroup { group, .. }) = unbound.take() {
                if !group.can_run() {
                    group.schedule_term();
                }
            }
        }
    }
}
