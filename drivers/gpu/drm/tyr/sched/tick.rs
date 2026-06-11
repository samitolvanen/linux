// SPDX-License-Identifier: GPL-2.0 or MIT

//! Periodic scheduler tick that drives CSG slot residency.
//!
//! The tick worker is the central place where the scheduler decides
//! which idle groups should become resident on a CSG slot. It runs as
//! a `DmaFenceWork` item on `sched_wq` (see
//! `TyrDrmDeviceData::tick_work`) and is scheduled by
//! `Scheduler::request_tick`; the periodic re-arm is handled
//! separately by `periodic_tick_work` on the system unbound workqueue.

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
        jiffies64,
        msecs_to_jiffies,
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
};

const TEARDOWN_ARRAY_SIZE: usize = MAX_CSGS;

/// Period between two consecutive scheduler ticks, in milliseconds.
///
/// The tick is short because every period also acts as the deadline
/// for firmware ack waits issued from the apply step.
pub(crate) const TICK_PERIOD_MS: u32 = 10;

/// A policy action taken during scheduler rule evaluation.
#[derive(Copy, Clone)]
enum Action {
    /// Retain currently bound groups that match the rule criteria.
    Keep,
    /// Retain currently bound groups that match the rule criteria,
    /// except the rotating one, whose slot is left to a subsequent
    /// `Take`.
    KeepExceptRotated,
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

/// Builds an ordered `Rule` iterator for one scheduler tick.
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
        let active: &[Rule] = if $cond {
            &[ $( Rule { action: Action::$t_a, priority: Priority::$t_p, is_idle: false } ),* ]
        } else {
            &[ $( Rule { action: Action::$f_a, priority: Priority::$f_p, is_idle: false } ),* ]
        };
        core::iter::Iterator::chain(active.iter().copied(), IDLE)
    }};
}

/// Runs one scheduler tick step.
///
/// Drives one `Tick::tick` cycle under the scheduler mutex. After
/// the locked scope is dropped, terminal teardown for evicted
/// unhealthy groups runs without the scheduler mutex so
/// `Group::schedule_term` does not need to take it.
///
/// The firmware ack waits inside `Tick::tick` happen with the
/// scheduler mutex held but with `csg_slot_manager` dropped; see
/// `Scheduler::apply_csg_updates` for the lock contract.
///
/// Re-arms the tick while any software priority level holds more than
/// one selected non-idle group, so groups sharing a level keep
/// rotating. A tick that runs and fails re-arms too. Without that,
/// `resched_target` would stay armed with nothing queued behind it.
/// Otherwise the tick stays idle until something requests it via
/// `Scheduler::request_tick`.
pub(crate) fn tick_step(tdev: &ARef<TyrDrmDevice>) -> Result {
    // Stack-allocated array for groups evicted during this tick that
    // need terminal cleanup (`!can_run()`). Sized to handle every
    // possible CSG slot eviction.
    let mut teardown_groups: [Option<Arc<Group>>; TEARDOWN_ARRAY_SIZE] =
        [const { None }; TEARDOWN_ARRAY_SIZE];

    let mut dead_groups = List::<Group, 0>::new();
    let mut dead_waiting = List::<Group, 1>::new();

    // The closure does not run until the scheduler is enabled, so a tick
    // step that fires during probe cannot re-arm itself and keep retrying.
    let result = tdev.with_locked_scheduler(|sched| {
        sched.detach_unrunnable_groups(&mut dead_groups, &mut dead_waiting);
        Tick::new(sched, &mut teardown_groups)
            .tick(tdev)
            .inspect_err(|_| Scheduler::request_tick(tdev))
    });

    // schedule_term does not take the scheduler mutex; drain after
    // releasing it.
    for slot in teardown_groups.iter_mut() {
        let Some(group) = slot.take() else {
            break;
        };
        group.schedule_term();
    }

    while let Some(list_arc) = dead_groups.pop_front() {
        let group: Arc<Group> = list_arc.into_arc();
        group.schedule_term();
    }

    while let Some(list_arc) = dead_waiting.pop_front() {
        let group: Arc<Group> = list_arc.into_arc();
        group.schedule_term();
    }

    result
}

/// Identifies a group selected during rule evaluation.
#[derive(Copy, Clone)]
pub(crate) enum SelectedGroup {
    /// A hardware slot index that was chosen to be kept, its software
    /// priority, whether the rule that selected it matched idle
    /// groups, and its current firmware priority.
    Kept(usize, Priority, bool, u32),
    /// An index into the `pending_groups` array for a newly chosen
    /// group, its software priority, and whether the rule that
    /// selected it matched idle groups.
    Pending(usize, Priority, bool),
}

/// Coarse class used as the primary key when sorting selections within
/// a software priority band. Variants are declared in the order they
/// sort.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SortClass {
    KeptActive,
    PendingActive,
    RotatedActive,
    KeptIdle,
    RotatedIdle,
    PendingIdle,
}

/// Finds the slot holding the group that rotates in each software
/// priority band.
///
/// The resident holding the highest firmware priority in a band
/// rotates. Ties resolve to the lowest slot index. A normal tick
/// only considers idle or non-runnable residents, so an active,
/// runnable resident can only rotate on a full tick.
fn find_rotated_slots(
    csg_slot_manager: &CsgSlotManager,
    slot_count: usize,
    full_tick: bool,
) -> [Option<usize>; Priority::num_priorities()] {
    let mut rotated = [const { None }; Priority::num_priorities()];
    let mut highest = [0u32; Priority::num_priorities()];

    for i in 0..slot_count {
        let Some(slot_data) = csg_slot_manager.slot_data(i) else {
            continue;
        };

        let status = slot_data.group.status();
        if !full_tick && !status.is_idle && status.can_run {
            continue;
        }

        let band = slot_data.group.priority as usize;
        if rotated[band].is_none() || slot_data.fw_priority > highest[band] {
            rotated[band] = Some(i);
            highest[band] = slot_data.fw_priority;
        }
    }

    rotated
}

/// Key for ordering selections within one software priority band.
///
/// `rotated` is the band's entry in `SchedulingDecision::rotated_slots`.
fn sort_key(
    sel: &SelectedGroup,
    original_idx: usize,
    rotated: Option<usize>,
) -> (SortClass, u32, usize) {
    match sel {
        SelectedGroup::Pending(_, _, is_idle) => {
            let class = if *is_idle {
                SortClass::PendingIdle
            } else {
                SortClass::PendingActive
            };
            (class, 0, original_idx)
        }

        SelectedGroup::Kept(slot_idx, _, is_idle, fw_prio) => {
            let class = match (*is_idle, rotated == Some(*slot_idx)) {
                (false, false) => SortClass::KeptActive,
                (false, true) => SortClass::RotatedActive,
                (true, false) => SortClass::KeptIdle,
                (true, true) => SortClass::RotatedIdle,
            };
            (class, u32::MAX - *fw_prio, original_idx)
        }
    }
}

impl SelectedGroup {
    fn priority(self) -> Priority {
        match self {
            Self::Kept(_, prio, _, _) => prio,
            Self::Pending(_, prio, _) => prio,
        }
    }

    /// Iterate selected groups, highest software priority first.
    ///
    /// Within a band, active groups come before idle ones. In each
    /// half, retained groups sort by descending previous fw_prio
    /// ahead of the newly bound ones. At most one group rotates. An
    /// active one drops below the newly bound active groups, yielding
    /// priority to work that has not run yet. An idle one drops
    /// behind the other retained idle groups but stays ahead of the
    /// newly bound idle groups.
    pub(crate) fn iter_prioritized(
        selections: &[Option<SelectedGroup>],
        rotated_slots: [Option<usize>; Priority::num_priorities()],
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
                    [(SelectedGroup::Pending(0, Priority::Low, false), 0_usize); MAX_CSGS];
                let mut count = 0;

                for (idx, selection) in selections.iter().enumerate() {
                    if let Some(sel) = selection {
                        if sel.priority() == sw_prio {
                            prio_selections[count] = (*sel, idx);
                            count += 1;
                        }
                    }
                }

                let rotated = rotated_slots[sw_prio as usize];

                prio_selections[..count]
                    .sort_unstable_by_key(|(s, original_idx)| sort_key(s, *original_idx, rotated));

                // Truncate the padded array to the actual count and
                // discard the stable-sort index.
                prio_selections.into_iter().take(count).map(|(s, _)| s)
            })
    }
}

/// A group selected by `SchedulingDecision::take_unbound` and pending
/// hardware bind.
///
/// Owns the live list-link handle (`list_arc`) for the group while it
/// is staged for binding, and remembers `prior_state` (the
/// idle/runnable list it was sourced from) so a transient bind failure
/// can put the `ListArc` back where it came from. The `Arc<Group>`
/// callers need (e.g. `CsgSlotData::group`) is obtained via
/// `ListArc::clone_arc`.
pub(crate) struct PendingBind {
    /// Live list-link handle removed from the scheduler list at
    /// selection time.
    pub(crate) list_arc: ListArc<Group, 0>,
    /// Which scheduler list the group was on before
    /// `SchedulingDecision::collect_groups` removed it. Used to
    /// re-insert on bind failure.
    pub(crate) prior_state: GroupListState,
}

/// Represents the outcome of evaluating scheduling rules.
pub(crate) struct SchedulingDecision {
    /// Slot holding the group that rotates in each software priority
    /// band, as returned by `find_rotated_slots`.
    pub(crate) rotated_slots: [Option<usize>; Priority::num_priorities()],
    /// Bitmask of hardware CSG slots that will retain their currently
    /// bound group.
    pub(crate) keep_mask: u32,
    /// True if all selected groups are idle.
    pub(crate) all_idle: bool,
    /// Number of selected groups that are idle.
    pub(crate) idle_group_count: usize,
    /// Groups selected from the software queues to be bound to hardware.
    ///
    /// Each entry owns a `ListArc` that has already been removed
    /// from its idle/runnable list under the scheduler mutex. This
    /// prevents a concurrent `Pool::destroy_group` from observing
    /// the group on a list and removing it while the tick is
    /// mid-bind. The bind path drops the `ListArc` on success,
    /// or re-inserts it via the recorded `prior_state` on transient
    /// failure.
    pub(crate) pending_groups: [Option<PendingBind>; MAX_CSGS],
    /// Number of new groups selected from software queues.
    pub(crate) num_pending: usize,
    /// Total number of groups (kept + pending) selected for execution.
    pub(crate) num_selected: usize,
    /// Number of non-idle groups selected per software priority.
    nonidle_group_counts: [usize; Priority::num_priorities()],
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
        // Hold the slot-manager lock once across the whole rule loop
        // so a slot's bound group cannot change between the rotation
        // scan and the `Keep` rules that consume it.
        // `find_rotated_slots` and `keep_bound` only read through
        // `slot_data()` and `take_unbound` does not access the slot
        // manager, so holding it for the full pass is safe.
        let csg_slot_manager = tdev.csg_slot_manager.lock();
        let slot_count = csg_slot_manager.slot_count();

        let mut decision = Self {
            rotated_slots: find_rotated_slots(&csg_slot_manager, slot_count, full_tick),
            keep_mask: 0,
            all_idle: true,
            idle_group_count: 0,
            pending_groups: [const { None }; MAX_CSGS],
            num_selected: 0,
            num_pending: 0,
            nonidle_group_counts: [0; Priority::num_priorities()],
            selections: [const { None }; MAX_CSGS],
        };

        for rule in rules {
            match rule.action {
                Action::Keep | Action::KeepExceptRotated => {
                    decision.keep_bound(
                        &csg_slot_manager,
                        slot_count,
                        rule.priority,
                        rule.is_idle,
                        matches!(rule.action, Action::KeepExceptRotated),
                    );
                }
                Action::Take => {
                    decision.take_unbound(sched, slot_count, rule.priority, rule.is_idle)?;
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

            // Don't re-bind a syncwait group from the idle list; it
            // sits on `waiting_groups` waiting for sync_upd to promote
            // it back to runnable.
            if matches!(prior_state, GroupListState::Idle) && status.has_blocked_queues {
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
            groups[count] = Some(PendingBind {
                list_arc,
                prior_state,
            });
            count += 1;
        }

        Ok(count)
    }

    /// Selects currently bound groups matching the priority and idle
    /// state to be retained, in descending firmware priority order.
    ///
    /// The rotating group is retained last, or not at all when
    /// `skip_rotated` is set. When a band has more eligible groups than
    /// slots, the highest-priority ones are kept and the rest are
    /// dropped.
    fn keep_bound(
        &mut self,
        csg_slot_manager: &CsgSlotManager,
        slot_count: usize,
        priority: Priority,
        is_idle: bool,
        skip_rotated: bool,
    ) {
        let rotated = self.rotated_slots[priority as usize];
        let mut candidates = [(0u32, 0usize); MAX_CSGS];
        let mut count = 0;

        for i in 0..slot_count {
            let Some(slot_data) = csg_slot_manager.slot_data(i) else {
                continue;
            };

            let status = slot_data.group.status();
            if slot_data.group.priority != priority || !status.can_run || status.is_idle != is_idle
            {
                continue;
            }

            if (self.keep_mask & (1u32 << i)) != 0 || (skip_rotated && rotated == Some(i)) {
                continue;
            }

            candidates[count] = (slot_data.fw_priority, i);
            count += 1;
        }

        candidates[..count].sort_unstable_by_key(|&(fw_priority, i)| {
            (rotated == Some(i), u32::MAX - fw_priority, i)
        });

        for &(fw_priority, i) in &candidates[..count] {
            if self.num_selected >= slot_count {
                break;
            }

            self.keep_mask |= 1u32 << i;

            self.selections[self.num_selected] =
                Some(SelectedGroup::Kept(i, priority, is_idle, fw_priority));

            self.num_selected += 1;

            if !is_idle {
                self.all_idle = false;
                self.nonidle_group_counts[priority as usize] += 1;
            } else {
                self.idle_group_count += 1;
            }
        }
    }

    /// Selects unbound groups matching the priority and idle state to
    /// be scheduled.
    fn take_unbound(
        &mut self,
        sched: &mut Scheduler,
        slot_count: usize,
        priority: Priority,
        is_idle: bool,
    ) -> Result<()> {
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
                self.nonidle_group_counts[priority as usize] += count;
            } else {
                self.idle_group_count += count;
            }
            for i in 0..count {
                self.selections[self.num_selected + i] = Some(SelectedGroup::Pending(
                    self.num_pending + i,
                    priority,
                    is_idle,
                ));
            }
        }
        self.num_pending += count;
        self.num_selected += count;

        Ok(())
    }

    /// Returns whether more than one non-idle group was selected at
    /// the same software priority.
    fn needs_resched(&self) -> bool {
        self.nonidle_group_counts.iter().any(|&count| count > 1)
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

        let now = jiffies64();
        let full_tick = now.wrapping_sub(self.sched.last_full_tick_jiffies)
            >= msecs_to_jiffies(TICK_PERIOD_MS) as u64;

        let rules = build_scheduling_rules! {
            // Idle groups are processed identically in both normal and
            // full ticks. Prefer keeping them bound unless a hardware
            // slot is needed, walking priorities high to low. This
            // includes idle-because-syncwait groups: while on-slot, the
            // firmware keeps polling the wait and the job deadline keeps
            // running. The runnable rules above run first and fill every
            // slot under genuine overcommit, so these idle keeps become
            // no-ops and the blocked group is evicted to make room.
            shared_idle: [
                Keep RealTime, Take RealTime,
                Keep High,     Take High,
                Keep Medium,   Take Medium,
                Keep Low,      Take Low,
            ],
            // The trailing `Keep` re-admits the rotating group when no
            // runnable group claimed the slot it left.
            if full_tick => [
                KeepExceptRotated RealTime, Take RealTime, Keep RealTime,
                KeepExceptRotated High,     Take High,     Keep High,
                KeepExceptRotated Medium,   Take Medium,   Keep Medium,
                KeepExceptRotated Low,      Take Low,      Keep Low,
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
        self.apply(data, &mut decision)?;

        if full_tick {
            self.sched.last_full_tick_jiffies = now;
        }

        Ok(())
    }

    /// Suspends and unbinds groups not marked to be kept.
    fn halt_and_unbind_evicted_groups(
        &mut self,
        data: &ARef<TyrDrmDevice>,
        decision: &SchedulingDecision,
    ) -> Result<()> {
        let slot_count = MAX_CSGS;
        let mut context = CsgUpdateContext::new();
        // An eviction reclaims the slot for other work only when this
        // pass selected some.
        context.reclaim = decision.num_selected != 0;

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

                if slot_data.group.can_run() {
                    context.set_state(i, CsgExecutionState::Suspend);
                } else {
                    context.set_state(i, CsgExecutionState::Terminate);
                }
            }
        }

        self.sched
            .apply_csg_updates(data, &mut context)
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
                if let Ok(list_arc) = ListArc::try_from_arc(group.clone()) {
                    let is_idle = group.is_idle_live();
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

    /// Puts a staged bind back on a scheduler list so a later tick can
    /// rediscover the group.
    ///
    /// The idle state is rechecked live, so a group that turned runnable
    /// while staged does not land back on the idle list.
    fn requeue_pending_bind(&mut self, pending: PendingBind) {
        let group: Arc<Group> = pending.list_arc.clone_arc();
        let is_idle =
            !matches!(pending.prior_state, GroupListState::Runnable) && group.is_idle_live();
        self.sched.requeue_group(pending.list_arc, is_idle);
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
        let mut bind_timed_out = false;

        // Build the priority/bind request set under the slot-manager
        // lock, then drop the lock before issuing the firmware update.
        {
            let mut csg_slot_manager = data.csg_slot_manager.lock();

            for selection in SelectedGroup::iter_prioritized(
                &decision.selections[..decision.num_selected],
                decision.rotated_slots,
            ) {
                let fw_prio = next_fw_prio;
                next_fw_prio = next_fw_prio.saturating_sub(1);

                match selection {
                    SelectedGroup::Kept(slot_idx, _sw_prio, _is_idle, cur_fw_prio) => {
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
                    SelectedGroup::Pending(idx, _sw_prio, _is_idle) => {
                        let Some(pending) = decision.pending_groups[idx].take() else {
                            continue;
                        };

                        // An earlier bind in this pass timed out on its
                        // address space. Requeue the rest rather than
                        // repeat the wait for each remaining group.
                        if bind_timed_out {
                            self.requeue_pending_bind(pending);
                            continue;
                        }

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
                            // ETIMEDOUT reaches here from the AS-ready
                            // and cache-flush polls under vm.activate().
                            if e == ETIMEDOUT {
                                bind_timed_out = true;
                            }
                            self.requeue_pending_bind(pending);
                            continue;
                        }

                        drop(pending.list_arc);
                    }
                }
            }
        }

        let res = self.sched.apply_csg_updates(data, &mut context);
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

        if decision.needs_resched() {
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
            data.devfreq_data.devfreq_state.lock().mark_idle();
            self.sched.pm_ref = None;
        } else {
            data.devfreq_data.devfreq_state.lock().mark_busy();
            if self.sched.pm_ref.is_none() {
                self.sched.pm_ref = data.sched_pm_get();
            }
        }

        self.update_status_and_resched(data, decision);
        Ok(())
    }
}
