// SPDX-License-Identifier: GPL-2.0 or MIT

//! Periodic scheduler tick that drives CSG slot residency.
//!
//! The tick worker is the central place where the scheduler decides
//! which idle groups should become resident on a CSG slot. It runs as
//! a `DmaFenceWork` item on `sched_wq` (see
//! [`TyrDrmDeviceData::tick_work`]) and is scheduled by
//! [`Scheduler::request_tick`]; the periodic re-arm is handled
//! separately by `periodic_tick_work` on the system unbound workqueue.
//!
//! [`Scheduler::request_tick`]: crate::sched::Scheduler::request_tick
//! [`TyrDrmDeviceData::tick_work`]: crate::driver::TyrDrmDeviceData

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
        Delta,
        Instant,
        Monotonic, //
    },
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    fw::{
        global::csg::Priority,
        CsgExecutionState, //
    },
    sched::{
        group::{
            Group,
            GroupListState, //
        },
        CsgSlotData,
        CsgSlotManager,
        CsgUpdateContext,
        Scheduler,
        MAX_CSGS,
        MAX_CSG_PRIO, //
    },
    trace,
};

const TEARDOWN_ARRAY_SIZE: usize = MAX_CSGS;

/// Period between two consecutive scheduler ticks, in milliseconds.
///
/// Matches the C panthor driver's `PANTHOR_SCHED_TICK_PERIOD_MS`. The
/// tick is short because every period also acts as the deadline for
/// firmware ack waits issued from the apply step.
pub(crate) const TICK_PERIOD_MS: u32 = 10;

/// A policy action taken during scheduler rule evaluation.
#[derive(Copy, Clone)]
enum Action {
    /// Retain currently bound groups that match the rule criteria.
    Keep,
    /// Bind new, unbound groups from the software queues that match
    /// the rule criteria.
    Take,
}

/// A scheduling policy rule that determines how groups are selected
/// for hardware slots.
#[derive(Copy, Clone)]
pub(crate) struct Rule {
    /// The action (`Keep` or `Take`) to perform for groups matching
    /// this rule.
    action: Action,
    /// The software scheduling priority this rule applies to.
    priority: Priority,
    /// Whether this rule applies to idle groups (`true`) or runnable
    /// groups (`false`).
    is_idle: bool,
}

/// Builds an ordered [`Rule`] iterator for one scheduler tick.
///
/// Each entry is spelled `Action Priority` (e.g. `Keep RealTime`); the
/// active half is selected by `$cond`, then chained with a shared idle
/// half. The macro shape encodes the design decisions about full-tick
/// rotation and same-priority fairness.
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

/// Runs one scheduler tick step.
///
/// Drives one [`Tick::tick`] cycle under the scheduler mutex: refresh
/// firmware-visible group state, evaluate the rule engine, halt and
/// unbind evicted groups, apply firmware priorities and bind pending
/// groups, prune destroyed groups, then update scheduler status and
/// arm the next tick. After the locked scope is dropped, terminal
/// teardown for evicted unhealthy groups runs without the scheduler
/// mutex so [`Group::schedule_term`] does not need to take it.
///
/// The firmware ack waits inside `Tick::tick` happen with the
/// scheduler mutex held but with [`csg_slot_manager`] dropped; see
/// [`Scheduler::apply_csg_updates`] for the lock contract.
///
/// If a slot shortage left some groups unbound, re-arms the tick so the
/// scheduler retries once a slot becomes free. Otherwise the tick
/// stays quiescent until something explicitly requests it via
/// [`Scheduler::request_tick`].
///
/// [`Group::schedule_term`]: crate::sched::group::Group::schedule_term
/// [`Scheduler::apply_csg_updates`]: crate::sched::Scheduler::apply_csg_updates
/// [`Scheduler::request_tick`]: crate::sched::Scheduler::request_tick
/// [`csg_slot_manager`]: crate::driver::TyrDrmDeviceData::csg_slot_manager
pub(crate) fn tick_step(tdev: &ARef<TyrDrmDevice>) -> Result {
    // Stack-allocated array for groups evicted during this tick that
    // need terminal cleanup (`!can_run()`). Sized to handle every
    // possible CSG slot eviction.
    let mut teardown_groups: [Option<Arc<Group>>; TEARDOWN_ARRAY_SIZE] =
        [const { None }; TEARDOWN_ARRAY_SIZE];

    let result =
        tdev.with_locked_scheduler(|sched| Tick::new(sched, &mut teardown_groups).tick(tdev));

    // schedule_term does not take the scheduler mutex; drain after
    // releasing it.
    for slot in teardown_groups.iter_mut() {
        let Some(group) = slot.take() else {
            break;
        };
        group.schedule_term();
    }

    result
}

/// Identifies a group selected during rule evaluation.
#[derive(Copy, Clone)]
pub(crate) enum SelectedGroup {
    /// A hardware slot index that was chosen to be kept, its software
    /// priority, and current firmware priority.
    Kept(usize, Priority, u32),
    /// An index into the `pending_groups` array for a newly chosen
    /// group, and its software priority.
    Pending(usize, Priority),
}

/// Coarse class used as the primary key when sorting selections within
/// a software priority band. The class ordering depends on whether
/// this is a full tick (rotation) or a normal tick (stability).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SortClass {
    First,
    Second,
}

/// Sort key used by [`SelectedGroup::iter_prioritized`] to order
/// selections within a single software priority band.
fn sort_key(sel: &SelectedGroup, original_idx: usize, full_tick: bool) -> (SortClass, u32, usize) {
    match sel {
        SelectedGroup::Pending(_, _) => {
            if full_tick {
                // Full tick: newly bound pending groups go first,
                // getting the highest firmware priority.
                (SortClass::First, 0, original_idx)
            } else {
                // Normal tick: pending groups go after retained groups.
                (SortClass::Second, 0, original_idx)
            }
        }

        SelectedGroup::Kept(_, _, fw_prio) => {
            if full_tick {
                // Full tick: retained groups go after pending, ordered
                // from lowest to highest previous firmware priority so
                // the worst-off gets bumped up the hardware queue
                // this round.
                (SortClass::Second, *fw_prio, original_idx)
            } else {
                // Normal tick: retained groups go first, preserving
                // their existing firmware priority order
                // (highest first).
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
    /// previous fw_prio first), then pending groups. Full ticks
    /// rotate to prevent starvation: pending groups first, then kept
    /// groups in ascending previous fw_prio (lowest goes to the front
    /// of the line).
    pub(crate) fn iter_prioritized(
        selections: &[Option<SelectedGroup>],
        full_tick: bool,
    ) -> impl Iterator<Item = SelectedGroup> + '_ {
        (0..Priority::num_priorities())
            .rev()
            .filter_map(|p| Priority::try_from(p as u8).ok())
            .flat_map(move |sw_prio| {
                // Collect all selections that match the current
                // software priority band. Slots beyond `..count` are
                // never read after the sort truncates the iterator;
                // the dummy fill value is only there to give the
                // fixed-size array a Copy initialiser.
                let mut prio_selections =
                    [(SelectedGroup::Pending(0, Priority::Low), 0_usize); MAX_CSGS];
                let mut count = 0;

                for (idx, selection) in selections.iter().enumerate() {
                    if let Some(sel) = selection {
                        if sel.priority() == sw_prio {
                            prio_selections[count] = (*sel, idx);
                            count += 1;
                        }
                    }
                }

                let slice = &mut prio_selections[..count];

                slice.sort_unstable_by_key(|(s, original_idx)| {
                    sort_key(s, *original_idx, full_tick)
                });

                // Truncate the padded array to the actual count and
                // discard the stable-sort index.
                prio_selections.into_iter().take(count).map(|(s, _)| s)
            })
    }
}

/// A group selected by [`SchedulingDecision::take_unbound`] and pending
/// hardware bind.
///
/// Owns the live list-link handle (`list_arc`) for the group while it
/// is staged for binding, and remembers `prior_state` (the
/// idle/runnable list it was sourced from) so a transient bind failure
/// can put the `ListArc` back where it came from. The `Arc<Group>`
/// callers need (e.g. `CsgSlotData::group`) is obtained via
/// [`ListArc::clone_arc`].
pub(crate) struct PendingBind {
    /// Live list-link handle removed from the scheduler list at
    /// selection time.
    pub(crate) list_arc: ListArc<Group, 0>,
    /// Which scheduler list the group was on before
    /// [`SchedulingDecision::collect_groups`] removed it. Used to
    /// re-insert on bind failure.
    pub(crate) prior_state: GroupListState,
}

/// Represents the outcome of evaluating scheduling rules.
pub(crate) struct SchedulingDecision {
    /// Whether this is a full tick (rotation) or a normal tick (stability).
    pub(crate) full_tick: bool,
    /// Bitmask of hardware CSG slots that will retain their currently
    /// bound group.
    pub(crate) keep_mask: u32,
    /// True if all selected groups are idle.
    pub(crate) all_idle: bool,
    /// Number of selected groups that are idle.
    pub(crate) idle_group_count: usize,
    /// Groups selected from the software queues to be bound to hardware.
    ///
    /// Each entry owns a [`ListArc`] that has already been removed
    /// from its idle/runnable list under the scheduler mutex. This
    /// prevents a concurrent `Pool::destroy_group` from observing
    /// the group on a list and removing it while the tick is
    /// mid-bind. The bind path drops the [`ListArc`] on success,
    /// or re-inserts it via the recorded `prior_state` on transient
    /// failure.
    pub(crate) pending_groups: [Option<PendingBind>; MAX_CSGS],
    /// Number of new groups selected from software queues.
    pub(crate) num_pending: usize,
    /// Total number of groups (kept + pending) selected for execution.
    pub(crate) num_selected: usize,
    /// The lowest priority among all selected groups.
    pub(crate) min_priority: Priority,
    /// Records the exact order in which groups were selected.
    pub(crate) selections: [Option<SelectedGroup>; MAX_CSGS],
}

impl SchedulingDecision {
    /// Evaluates the priority rules to decide which groups to keep and
    /// which to take.
    pub(crate) fn evaluate_rules(
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
            pending_groups: [const { None }; MAX_CSGS],
            num_selected: 0,
            num_pending: 0,
            min_priority: Priority::RealTime,
            selections: [const { None }; MAX_CSGS],
        };

        // Hold the slot-manager lock once across the whole rule loop
        // so a slot's bound group cannot change between consecutive
        // `Keep` rules. `keep_bound` only reads through `slot_data()`
        // and `take_unbound` does not access the slot manager, so
        // holding it for the full pass is safe.
        let csg_slot_manager = tdev.csg_slot_manager.lock();
        for rule in rules {
            match rule.action {
                Action::Keep => {
                    decision.keep_bound(&csg_slot_manager, rule.priority, rule.is_idle);
                }
                Action::Take => {
                    decision.take_unbound(sched, rule.priority, rule.is_idle)?;
                }
            }
        }
        Ok(decision)
    }

    /// Takes up to `groups.len()` eligible groups from a list.
    ///
    /// Each accepted group is removed from `list` under the
    /// scheduler mutex (which the caller holds) and its
    /// `inner.list_state` is cleared.
    fn collect_groups(
        list: &mut List<Group>,
        prior_state: GroupListState,
        groups: &mut [Option<PendingBind>],
    ) -> Result<usize> {
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

            // `peek.remove(self)` advances the cursor to the next
            // element internally, so no separate `move_next` is
            // needed. The returned `ListArc` is the authoritative
            // owner of the group's list-link slot for ID 0; with it
            // in `pending_groups` the group cannot be re-inserted
            // anywhere else without going through `requeue_group`
            // (which would take a fresh `ListArc::try_from_arc`).
            let list_arc = group.remove();
            list_arc.with_locked_inner(|inner| {
                inner.list_state = GroupListState::None;
            });
            trace::group_list(list_arc.handle(), GroupListState::None as u32);
            groups[count] = Some(PendingBind {
                list_arc,
                prior_state,
            });
            count += 1;
        }

        Ok(count)
    }

    /// Selects currently bound groups matching the priority and idle
    /// state to be retained.
    fn keep_bound(&mut self, csg_slot_manager: &CsgSlotManager, priority: Priority, is_idle: bool) {
        let slot_count = MAX_CSGS;

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

            // Mark this slot index as 'kept'.
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

    /// Selects unbound groups matching the priority and idle state to
    /// be scheduled.
    fn take_unbound(
        &mut self,
        sched: &mut Scheduler,
        priority: Priority,
        is_idle: bool,
    ) -> Result<()> {
        let slot_count = MAX_CSGS;
        if self.num_selected >= slot_count {
            return Ok(());
        }

        // How many slots we are allowed to fill.
        let available_slots = slot_count - self.num_selected;
        let target = &mut self.pending_groups[self.num_pending..self.num_pending + available_slots];

        let (queue, prior_state) = if is_idle {
            (
                &mut sched.idle_groups[priority as usize],
                GroupListState::Idle,
            )
        } else {
            (
                &mut sched.runnable_groups[priority as usize],
                GroupListState::Runnable,
            )
        };

        // Collect available groups.
        let count = Self::collect_groups(queue, prior_state, target)?;
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
pub(crate) struct Tick<'a> {
    sched: &'a mut Scheduler,
    /// Groups evicted during this tick that need subsequent cleanup.
    teardown_groups: &'a mut [Option<Arc<Group>>; TEARDOWN_ARRAY_SIZE],
    num_teardown: usize,
}

impl<'a> Tick<'a> {
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

    /// Evaluates groups and applies the scheduling decisions to the
    /// hardware.
    fn tick(&mut self, data: &ARef<TyrDrmDevice>) -> Result<()> {
        self.sched
            .sync_group_states(data.clone())
            .inspect_err(|_| pr_err!("sync_group_states failed\n"))?;

        let full_tick = self.sched.last_tick.elapsed().as_millis() >= i64::from(TICK_PERIOD_MS);

        let rules = build_scheduling_rules! {
            // Idle groups are processed identically in both normal and
            // full ticks. Prefer keeping them bound unless a hardware
            // slot is needed, walking priorities high to low.
            shared_idle: [
                Keep RealTime, Take RealTime,
                Keep High,     Take High,
                Keep Medium,   Take Medium,
                Keep Low,      Take Low,
            ],
            // A full tick forces a re-evaluation of currently bound
            // active groups to ensure fairness. Issuing `Take` before
            // `Keep` at each priority lets pending groups preempt
            // currently bound groups of the same priority,
            // time-slicing the hardware.
            if full_tick => [
                Take RealTime, Keep RealTime,
                Take High,     Keep High,
                Take Medium,   Keep Medium,
                Take Low,      Keep Low,
            ],
            // A normal tick prefers to keep currently bound active
            // groups running to minimise context-switching overhead.
            // Evaluate all `Keep`s for non-RT priorities before any
            // `Take`.
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
        let slot_count = MAX_CSGS;
        let mut context = CsgUpdateContext::new();

        // Build the halt request set under the slot-manager lock,
        // then drop the lock before issuing the firmware update.
        // `apply_csg_updates` re-acquires it itself across its wait
        // phase.
        {
            let csg_slot_manager = data.csg_slot_manager.lock();
            for i in 0..slot_count {
                if (decision.keep_mask & (1u32 << i)) != 0 {
                    continue;
                }
                let Some(slot_data) = csg_slot_manager.slot_data(i) else {
                    continue;
                };

                trace::sched_evict(
                    i as u32,
                    slot_data.group.handle(),
                    slot_data.group.priority as u8,
                );

                context.set_state(
                    i,
                    if slot_data.group.can_run() {
                        CsgExecutionState::Suspend
                    } else {
                        CsgExecutionState::Terminate
                    },
                );
            }
        }

        self.sched
            .apply_csg_updates(data.clone(), &mut context)
            .inspect_err(|_| pr_err!("apply_csg_updates (halt) failed\n"))?;

        // Drain any pending CSG IRQs on each evicted slot so the
        // group's per-queue / per-CSG bookkeeping reflects the latest
        // firmware state before we tear the binding down. Runs
        // *before* taking the slot-manager lock below because
        // `process_csg_irq` re-takes the slot-manager lock itself to
        // look the group up.
        for i in 0..slot_count {
            if (decision.keep_mask & (1u32 << i)) != 0 {
                continue;
            }
            if let Err(e) = self.sched.process_csg_irq(data, i) {
                pr_err!("process_csg_irq {} failed: {}\n", i, e.to_errno());
            }
        }

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

            csg_slot_manager.evict(&group.csg_seat, &mut context)?;

            if can_run {
                // Healthy groups go back onto an idle/runnable list so
                // the next tick can re-bind them.
                if let Ok(list_arc) = ListArc::try_from_arc(group.clone()) {
                    let is_idle = group.is_idle();
                    self.sched.requeue_group(list_arc, is_idle);
                }
            } else if self.num_teardown < self.teardown_groups.len() {
                // Cancelled / faulted: queue for terminal cleanup.
                self.teardown_groups[self.num_teardown] = Some(group.clone());
                self.num_teardown += 1;
            }
        }

        Ok(())
    }

    /// Updates priorities for retained groups and binds new pending
    /// groups into available hardware slots in a single prioritized
    /// pass.
    fn apply_priorities_and_bind(
        &mut self,
        data: &ARef<TyrDrmDevice>,
        decision: &mut SchedulingDecision,
    ) -> Result<()> {
        let mut context = CsgUpdateContext::new();
        let mut next_fw_prio = MAX_CSG_PRIO;

        // Build the priority/bind request set under the slot-manager
        // lock, then drop the lock before issuing the firmware update.
        {
            let mut csg_slot_manager = data.csg_slot_manager.lock();

            for selection in SelectedGroup::iter_prioritized(
                &decision.selections[..decision.num_selected],
                decision.full_tick,
            ) {
                let fw_prio = next_fw_prio;
                next_fw_prio = next_fw_prio.saturating_sub(1);

                match selection {
                    SelectedGroup::Kept(slot_idx, sw_prio, cur_fw_prio) => {
                        let group_id = csg_slot_manager
                            .slot_data(slot_idx)
                            .map(|s| s.group.handle())
                            .unwrap_or(0);
                        trace::sched_keep(slot_idx as u32, group_id, sw_prio as u8, fw_prio);
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
                    SelectedGroup::Pending(idx, sw_prio) => {
                        let Some(pending) = decision.pending_groups[idx].take() else {
                            continue;
                        };

                        let group: Arc<Group> = pending.list_arc.clone_arc();
                        if let Err(e) = csg_slot_manager.activate(
                            &group.csg_seat,
                            CsgSlotData {
                                group: group.clone(),
                                fw_priority: fw_prio,
                            },
                            &mut context,
                        ) {
                            pr_err!("activate (pending) failed: {}\n", e.to_errno());
                            // Activate failed; restore the list_arc to
                            // the list `take_unbound` sourced it from
                            // (recorded in `prior_state`) so the next
                            // tick can rediscover the group. Default
                            // any unexpected `None` to the idle list,
                            // matching `bind`'s pre-existing fallback.
                            let is_idle = !matches!(pending.prior_state, GroupListState::Runnable);
                            self.sched.requeue_group(pending.list_arc, is_idle);
                            continue;
                        }

                        let slot_idx = group.with_locked_inner(|inner| inner.csg_id).unwrap_or(0);
                        trace::sched_bind(slot_idx as u32, group.handle(), sw_prio as u8, fw_prio);
                        drop(pending.list_arc);
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

    /// Updates scheduler statuses and schedules a periodic tick if
    /// there is contention.
    fn update_status_and_resched(
        &mut self,
        data: &ARef<TyrDrmDevice>,
        decision: &SchedulingDecision,
    ) {
        self.sched.resched_target = None;
        self.sched.last_tick = Instant::<Monotonic>::now();
        self.sched.used_csg_slot_count = decision.num_selected as u32;
        self.sched.might_have_idle_groups = decision.idle_group_count > 0;

        let runnable_remaining: usize = self
            .sched
            .runnable_groups
            .iter()
            .map(|l| l.iter().count())
            .sum();
        trace::tick_decision_summary(
            self.sched
                .used_csg_slot_count
                .saturating_sub(decision.keep_mask.count_ones()),
            decision.num_pending as u32,
            decision.keep_mask.count_ones(),
            runnable_remaining as u32,
        );
        let total_slots = data.csg_slot_manager.lock().slot_count() as u32;
        trace::csg_slots_status(self.sched.used_csg_slot_count, total_slots);

        // We only need to time-slice (reschedule periodically) if
        // there is actual contention for the hardware.
        let is_full = decision.num_selected >= MAX_CSGS;
        let has_runnable_groups_waiting_for_slot =
            !self.sched.runnable_groups[decision.min_priority as usize].is_empty();

        if is_full && decision.idle_group_count == 0 && has_runnable_groups_waiting_for_slot {
            let period = Delta::from_millis(i64::from(TICK_PERIOD_MS));
            self.sched.resched_target = Some(self.sched.last_tick + period);
            Scheduler::request_tick(data);
        }
    }

    /// Executes the scheduling steps and updates subsequent tick
    /// targets.
    fn apply(
        &mut self,
        data: &ARef<TyrDrmDevice>,
        decision: &mut SchedulingDecision,
    ) -> Result<()> {
        self.halt_and_unbind_evicted_groups(data, decision)?;
        self.apply_priorities_and_bind(data, decision)?;

        if decision.all_idle {
            data.devfreq_state.lock().mark_idle();
        } else {
            data.devfreq_state.lock().mark_busy();
        }

        self.update_status_and_resched(data, decision);
        Ok(())
    }
}
