// SPDX-License-Identifier: GPL-2.0 or MIT

//! Periodic scheduler tick that drives CSG slot residency.
//!
//! The tick worker is the central place where the scheduler decides
//! which idle groups should become resident on a CSG slot. It runs as
//! a `DmaFenceWork` item on `sched_wq` (see
//! `TyrDrmDeviceData::tick_work`) and is scheduled by
//! `Scheduler::request_tick`. The periodic re-arm is handled
//! separately by `periodic_tick_work` on `system_dfl()`.

use core::cmp::Reverse;

use kernel::{
    list::{
        List,
        ListArc, //
    },
    prelude::*,
    sync::{
        aref::ARef,
        atomic::Relaxed,
        Arc, //
    },
    time::{
        jiffies64,
        msecs_to_jiffies,
        Delta,
        Instant,
        Monotonic, //
    }, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData,
        TyrDrmRegistrationData, //
    },
    fw::{
        global::csg::Priority,
        CsgExecutionState,
        Firmware, //
    },
    regs::MAX_AS,
    sched::{
        group::{
            Group,
            GroupListState,
            State, //
        },
        CsgSlotData,
        CsgSlotIdx,
        CsgSlotManager,
        CsgUpdateContext,
        Scheduler,
        MAX_CSGS,
        MAX_CSG_PRIO, //
    },
    vm::Vm, //
};

const TEARDOWN_ARRAY_SIZE: usize = MAX_CSGS;

/// Period between two consecutive scheduler ticks, in milliseconds.
///
/// The tick is short because every period also acts as the deadline
/// for firmware ack waits issued from the apply step.
pub(crate) const TICK_PERIOD_MS: u32 = 10;

/// Delay between retries of a failed runtime resume. A failed attempt waits
/// out the one-second MCU halt poll in its unwind, so retrying at the
/// scheduler tick period would churn the PM usage count for no extra attempt.
pub(crate) const RESUME_RETRY_MS: u32 = 1000;

/// A policy action taken during scheduler rule evaluation.
#[derive(Copy, Clone)]
enum Action {
    /// Retain currently bound groups that match the rule criteria.
    Keep,
    /// Retain currently bound groups that match the rule criteria,
    /// except the rotating one and the others on its VM. The rotating
    /// group's slot is left to a subsequent `Take`.
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
/// Each entry is spelled `Action Priority` (e.g. `Keep RealTime`). The
/// active half is selected by `$cond`, then chained with a shared idle
/// half.
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
/// scheduler mutex held but with `csg_slot_manager` dropped. See
/// `Scheduler::apply_csg_updates` for the lock contract.
///
/// Re-arms the tick while any software priority level holds more than
/// one selected non-idle group, so groups sharing a level keep
/// rotating. It also re-arms while a runnable group waits and either
/// every slot holds a non-idle group or a group was refused an address
/// space. A tick that runs and fails re-arms too. Without that,
/// `resched_target` would stay armed with nothing queued behind it.
/// Otherwise the tick stays idle until something requests it via
/// `Scheduler::request_tick`.
pub(crate) fn tick_step(tdev: &ARef<TyrDrmDevice>, fw: &Firmware<'_>) -> Result {
    if tdev.is_unusable() {
        return Ok(());
    }

    // The token blocks a suspend mid-tick without itself resuming. When the
    // device is down the tick defers, holding a usage reference for any
    // runnable work so the asynchronous resume reissues the tick.
    let Some(_active) = tdev.pm_get_if_active() else {
        let (resume_pending, resume_failed) = tdev.with_locked_scheduler(|sched| {
            // A reference taken against a failing resume arms nothing, so
            // release it before asking.
            if sched.resume_failed {
                sched.pm_ref = None;
            }
            if sched.pm_ref.is_none() && sched.has_runnable_groups() {
                sched.pm_ref = tdev.sched_pm_get();
            }
            Ok((sched.pm_ref.is_some(), sched.resume_failed))
        })?;

        // A denied token with a held reference means a resume is in flight
        // and this tick may be its kick, so re-arm a tick period out rather
        // than spinning against the resume's own immediate tick. The driver
        // flags cover the force-suspend window `pm_suspended` misses.
        if !tdev.sched_suspended.load(Relaxed) {
            if resume_failed && resume_pending {
                Scheduler::request_resume_retry(tdev);
            } else if resume_pending && !tdev.pm_suspended() && !tdev.pm_powered_down() {
                Scheduler::request_tick(tdev);
            }
        }
        return Ok(());
    };

    if tdev.reset.in_progress() {
        // The reset worker owns the CSG slots. It evicts every group itself
        // and reissues the tick once the reset completes.
        return Ok(());
    }

    // The fw-events drain defers the same way this tick does, but
    // nothing re-kicks it once its IRQ has fired. Pick up events
    // latched while the device was down or a transition was in flight.
    if tdev.fw_events_pending() {
        TyrDrmDeviceData::schedule_fw_events(tdev);
    }

    // Stack-allocated array for groups evicted during this tick that
    // need terminal cleanup (`!can_run()`). Sized to handle every
    // possible CSG slot eviction.
    let mut teardown_groups: [Option<Arc<Group>>; TEARDOWN_ARRAY_SIZE] =
        [const { None }; TEARDOWN_ARRAY_SIZE];
    let mut evicted_groups: [Option<Arc<Group>>; MAX_CSGS] = [const { None }; MAX_CSGS];

    let mut dead_groups = List::<Group, 0>::new();
    let mut dead_waiting = List::<Group, 1>::new();

    // The closure does not run until the scheduler is enabled, so a tick
    // step that fires during probe cannot re-arm itself and keep retrying.
    let result = tdev.with_locked_scheduler(|sched| {
        // The gate above was passed before this lock, so a scheduler suspend
        // may have begun in between. It sets the flag under this same lock
        // before evicting.
        if tdev.sched_suspended.load(Relaxed) {
            return Ok(());
        }
        sched.detach_unrunnable_groups(&mut dead_groups, &mut dead_waiting);
        Tick::new(sched, &mut teardown_groups, &mut evicted_groups)
            .tick(tdev, fw)
            .inspect_err(|_| Scheduler::request_tick(tdev))
    });

    if result == Err(ETIMEDOUT) {
        tdev.reset.schedule();
    }

    // schedule_term needs no scheduler state, so drain after the mutex
    // is released, keeping the tick's critical section short.
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

    Scheduler::drain_queue_completions(tdev, &evicted_groups);

    result
}

/// Suspends the scheduler for runtime PM.
///
/// Evicts every resident group so none is bound when the MCU halts,
/// with the device still powered.
///
/// Must not be called with the scheduler mutex held.
pub(crate) fn suspend(tdev: &ARef<TyrDrmDevice>, reg_data: &TyrDrmRegistrationData<'_>) {
    let mut teardown_groups: [Option<Arc<Group>>; TEARDOWN_ARRAY_SIZE] =
        [const { None }; TEARDOWN_ARRAY_SIZE];
    let mut evicted_groups: [Option<Arc<Group>>; MAX_CSGS] = [const { None }; MAX_CSGS];

    let result = tdev.with_locked_scheduler(|sched| {
        // Record the suspend under the scheduler mutex so tick paths that
        // re-check it there observe it once the eviction below begins.
        tdev.sched_suspended.store(true, Relaxed);
        Tick::new(sched, &mut teardown_groups, &mut evicted_groups).suspend(tdev, reg_data)
    });
    if let Err(e) = result {
        dev_err!(
            tdev.as_ref(),
            "scheduler suspend failed: {}\n",
            e.to_errno()
        );
    }

    for slot in teardown_groups.iter_mut() {
        let Some(group) = slot.take() else {
            break;
        };
        group.schedule_term();
    }

    Scheduler::drain_queue_completions(tdev, &evicted_groups);
}

/// Resumes the scheduler after a runtime resume. Reissues the
/// firmware-event drain for events latched across the suspend, the
/// sync-update sweep for syncwaits satisfied while no group was
/// resident, and the tick so evicted-but-runnable groups rebind.
pub(crate) fn resume(tdev: &ARef<TyrDrmDevice>) {
    // Clear the suspend under the scheduler mutex, the counterpart to the
    // store in `suspend`, before reissuing work.
    let _ = tdev.with_locked_scheduler(|sched| {
        sched.resume_failed = false;
        tdev.sched_suspended.store(false, Relaxed);
        Ok(())
    });
    TyrDrmDeviceData::schedule_fw_events(tdev);
    TyrDrmDeviceData::schedule_sync_upd(tdev);
    TyrDrmDeviceData::schedule_tick(tdev);
    Scheduler::request_tick(tdev);
}

/// Latches a failed runtime resume and arms a retry. Returns whether this
/// is the first failure since the last successful resume.
///
/// The tick and the submit path ask the PM core to resume only when the
/// scheduler holds no usage reference. Clearing the reference here would
/// race the core's own status update, so the tick clears it instead while
/// the latch is set.
pub(crate) fn retry_after_failed_resume(tdev: &ARef<TyrDrmDevice>) -> bool {
    let first = tdev
        .with_locked_scheduler(|sched| Ok(!core::mem::replace(&mut sched.resume_failed, true)))
        .unwrap_or(true);
    Scheduler::request_resume_retry(tdev);
    first
}

/// Recovers the scheduler after a system resume. Runtime PM is disabled
/// for the duration of a system sleep, so a tick that ran in that window
/// could not take a usage reference. Without one it cannot arm a resume.
/// Reissue the tick when the scheduler has runnable groups but holds no
/// reference.
pub(crate) fn resume_after_system_sleep(tdev: &ARef<TyrDrmDevice>) {
    let kick = tdev
        .with_locked_scheduler(|sched| Ok(sched.pm_ref.is_none() && sched.has_runnable_groups()))
        .unwrap_or(false);

    if kick {
        TyrDrmDeviceData::schedule_tick(tdev);
    }
}

/// Marks the device unusable and terminates every group at unbind.
///
/// Runs after the halt or after the suspend that already evicted every
/// resident group.
pub(crate) fn unbind(tdev: &ARef<TyrDrmDevice>) {
    let _ = tdev.with_locked_scheduler(|sched| {
        tdev.mark_unusable();
        sched.fail_all_groups();
        Ok(())
    });
}

/// The groups `pre_reset` parked, handed back to `post_reset`.
#[must_use]
pub(crate) struct ParkedGroups(KVec<Arc<Group>>);

impl ParkedGroups {
    /// Releases every queue `pre_reset` parked.
    ///
    /// The unpark is unconditional because a group whose terminal
    /// cleanup finished while the reset ran has no other release path.
    /// Unparking a group that is being torn down is harmless, since a
    /// job reaching submit behind it signals ECANCELED there.
    ///
    /// A group that can no longer run is then routed to cleanup. No tick
    /// would do that for it. The termination request wins when the
    /// destroy path has not made one yet, and latches as a no-op
    /// otherwise.
    fn release(self) {
        for group in self.0.iter() {
            group.unpark_queues();
            if !group.can_run() {
                group.schedule_term();
            }
        }
    }
}

/// Stops scheduling for a GPU reset.
///
/// The scheduler workers bail out while the reset worker is executing a
/// claimed reset. Flush the in-flight ones, then evict every resident
/// group through the same machinery as runtime suspend, including
/// escalating to termination on ack timeout.
///
/// The eviction leaves every group that can still run on a scheduler
/// list, so parking the listed groups covers all of them. Groups it
/// routed to terminal cleanup instead are canceled by
/// `Group::cancel_queues`.
pub(crate) fn pre_reset(
    tdev: &ARef<TyrDrmDevice>,
    reg_data: &TyrDrmRegistrationData<'_>,
) -> ParkedGroups {
    let data: &TyrDrmDeviceData = tdev;
    data.drain_sched_work();
    suspend(tdev, reg_data);

    let groups = tdev
        .with_locked_scheduler(|sched| Ok(sched.collect_listed_groups(tdev)))
        .unwrap_or_default();
    for group in groups.iter() {
        group.park_queues();
    }

    ParkedGroups(groups)
}

/// Restores the scheduler state after a GPU reset.
///
/// Every queue `pre_reset` parked is released here, on both legs. After
/// a successful reset the worker reissues the tick, and the groups that
/// can still run rebind. A failed reset leaves the hardware
/// unusable, so every group is terminated first, and terminal cleanup
/// signals the queued and in-flight fences of a terminated group.
pub(crate) fn post_reset(tdev: &ARef<TyrDrmDevice>, parked: ParkedGroups, reset_failed: bool) {
    if reset_failed {
        let _ = tdev.with_locked_scheduler(|sched| {
            sched.fail_all_groups();
            Ok(())
        });
    }

    parked.release();
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
        selections: &[Option<SelectedGroup>; MAX_CSGS],
        rotated_slots: [Option<usize>; Priority::num_priorities()],
    ) -> impl Iterator<Item = SelectedGroup> + '_ {
        let mut order: [usize; MAX_CSGS] = core::array::from_fn(|idx| idx);

        order.sort_unstable_by_key(|&idx| {
            selections.get(idx).copied().flatten().map(|sel| {
                let band = sel.priority() as usize;
                (Reverse(band), sort_key(&sel, idx, rotated_slots[band]))
            })
        });

        order
            .into_iter()
            .filter_map(move |idx| selections.get(idx).copied().flatten())
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

/// Address spaces taken by the groups selected in one tick.
pub(in crate::sched) struct AsBudget {
    /// Addresses of the VMs of the selected groups, one per address space.
    /// Addresses rather than pointers keep the scheduler `Send`.
    vms: [Option<usize>; MAX_AS],
    /// Number of AS slots available to user VMs.
    limit: usize,
    /// Whether a group was refused because no address space was left.
    refused: bool,
}

impl AsBudget {
    /// Creates an empty budget of `limit` address spaces, at most `MAX_AS`.
    pub(in crate::sched) fn new(limit: usize) -> Self {
        Self {
            vms: [None; MAX_AS],
            limit: limit.min(MAX_AS),
            refused: false,
        }
    }

    /// Releases the address spaces taken by the previous tick.
    fn reset(&mut self) {
        self.vms = [None; MAX_AS];
        self.refused = false;
    }

    /// Takes an address space for `vm`, unless an earlier selection already
    /// took one for it. Returns `false` if none is left.
    fn take(&mut self, vm: &Vm) -> bool {
        let vm = Some(core::ptr::from_ref(vm).addr());
        if self.vms.contains(&vm) {
            return true;
        }
        let free = self
            .vms
            .iter_mut()
            .take(self.limit)
            .find(|slot| slot.is_none());
        let Some(slot) = free else {
            self.refused = true;
            return false;
        };
        *slot = vm;
        true
    }

    /// Returns whether `take` would succeed for `vm`.
    fn can_take(&self, vm: &Vm) -> bool {
        let vm = Some(core::ptr::from_ref(vm).addr());
        self.vms.iter().take(self.limit).any(Option::is_none) || self.vms.contains(&vm)
    }
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
    /// Creates an empty decision for `Self::evaluate_rules` to fill.
    fn new() -> Self {
        Self {
            rotated_slots: [const { None }; Priority::num_priorities()],
            keep_mask: 0,
            all_idle: true,
            idle_group_count: 0,
            pending_groups: [const { None }; MAX_CSGS],
            num_selected: 0,
            num_pending: 0,
            nonidle_group_counts: [0; Priority::num_priorities()],
            selections: [const { None }; MAX_CSGS],
        }
    }

    /// Evaluates the priority rules to decide which groups to keep and
    /// which to take.
    pub(crate) fn evaluate_rules(
        &mut self,
        tdev: &TyrDrmDeviceData,
        sched: &mut Scheduler,
        rules: impl IntoIterator<Item = Rule>,
        full_tick: bool,
    ) -> Result {
        // Hold the slot-manager lock once across the whole rule loop
        // so a slot's bound group cannot change between the rotation
        // scan and the `Keep` rules that consume it.
        // `find_rotated_slots` and `keep_bound` only read through
        // `slot_data()` and `take_unbound` does not access the slot
        // manager, so holding it for the full pass is safe.
        let csg_slot_manager = tdev.csg_slot_manager.lock();
        let slot_count = csg_slot_manager.slot_count();

        self.rotated_slots = find_rotated_slots(&csg_slot_manager, slot_count, full_tick);
        sched.as_budget.reset();

        let mut reserved = 0;
        for rule in rules {
            match rule.action {
                Action::Keep | Action::KeepExceptRotated => {
                    reserved = self.keep_bound(
                        &csg_slot_manager,
                        &mut sched.as_budget,
                        slot_count,
                        rule.priority,
                        rule.is_idle,
                        matches!(rule.action, Action::KeepExceptRotated),
                    )?;
                }
                Action::Take => {
                    let available = slot_count.checked_sub(reserved).ok_or(EINVAL)?;
                    self.take_unbound(sched, available, rule.priority, rule.is_idle)?;
                }
            }
        }
        Ok(())
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
        as_budget: &mut AsBudget,
    ) -> Result<usize> {
        let mut count = 0;
        let mut cursor = list.cursor_front();

        while let Some(group) = cursor.peek_next() {
            if count >= groups.len() {
                break;
            }

            let status = group.arc().status();

            if !status.can_run || status.csg_id.is_some() || !as_budget.take(&group.arc().vm) {
                cursor.move_next();
                continue;
            }

            // `peek.remove(self)` advances the cursor to the next
            // element internally, so no separate `move_next` is
            // needed. The returned `ListArc` is the authoritative
            // owner of the group's list-link slot for ID 0. With it
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
    ///
    /// When the rotating group is skipped, the others on its VM are
    /// skipped too. Their slots are reserved while that VM can still get
    /// an address space. Returns the number of reserved slots.
    fn keep_bound(
        &mut self,
        csg_slot_manager: &CsgSlotManager,
        as_budget: &mut AsBudget,
        slot_count: usize,
        priority: Priority,
        is_idle: bool,
        skip_rotated: bool,
    ) -> Result<usize> {
        let rotated = self.rotated_slots[priority as usize];
        let mut skipped = None;
        let mut candidates = [(0u32, 0usize); MAX_CSGS];
        let mut count = 0;

        for i in 0..slot_count {
            let Some(slot_data) = csg_slot_manager.slot_data(i) else {
                continue;
            };

            if (self.keep_mask & (1u32 << i)) != 0 {
                continue;
            }

            if skip_rotated && rotated == Some(i) {
                skipped = Some(i);
                continue;
            }

            let status = slot_data.group.status();
            if slot_data.group.priority != priority || !status.can_run || status.is_idle != is_idle
            {
                continue;
            }

            if let Some(candidate) = candidates.get_mut(count) {
                *candidate = (slot_data.fw_priority, i);
                count += 1;
            }
        }

        candidates[..count].sort_unstable_by_key(|&(fw_priority, i)| {
            (rotated == Some(i), u32::MAX - fw_priority, i)
        });

        let rotated_vm = skipped
            .and_then(|i| csg_slot_manager.slot_data(i))
            .map(|slot_data| &slot_data.group.vm);
        let mut reserved = 0;
        for &(fw_priority, i) in &candidates[..count] {
            if self.num_selected + reserved >= slot_count {
                break;
            }

            let Some(slot_data) = csg_slot_manager.slot_data(i) else {
                continue;
            };
            if rotated_vm.is_some_and(|vm| Arc::ptr_eq(vm, &slot_data.group.vm)) {
                if as_budget.can_take(&slot_data.group.vm) {
                    reserved += 1;
                }
                continue;
            }
            let selection = self.selections.get_mut(self.num_selected).ok_or(EINVAL)?;
            if !as_budget.take(&slot_data.group.vm) {
                continue;
            }

            self.keep_mask |= 1u32 << i;

            *selection = Some(SelectedGroup::Kept(i, priority, is_idle, fw_priority));

            self.num_selected += 1;

            if !is_idle {
                self.all_idle = false;
                self.nonidle_group_counts[priority as usize] += 1;
            } else {
                self.idle_group_count += 1;
            }
        }

        Ok(reserved)
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

        let selections = self
            .selections
            .get_mut(self.num_selected..slot_count)
            .ok_or(EINVAL)?;
        // How many slots we are allowed to fill.
        let available_slots = selections.len();
        let end = self
            .num_pending
            .checked_add(available_slots)
            .ok_or(EINVAL)?;
        let target = self
            .pending_groups
            .get_mut(self.num_pending..end)
            .ok_or(EINVAL)?;

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
        let count = Self::collect_groups(queue, prior_state, target, &mut sched.as_budget)?;
        if count > 0 {
            if !is_idle {
                self.all_idle = false;
                self.nonidle_group_counts[priority as usize] += count;
            } else {
                self.idle_group_count += count;
            }
            for (i, selection) in selections.iter_mut().take(count).enumerate() {
                *selection = Some(SelectedGroup::Pending(
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
    /// Groups evicted during this tick that can still run, by slot. The
    /// caller drains their queue completions after releasing the scheduler
    /// mutex.
    evicted_groups: &'a mut [Option<Arc<Group>>; MAX_CSGS],
}

impl<'a> Tick<'a> {
    fn new(
        sched: &'a mut Scheduler,
        teardown_groups: &'a mut [Option<Arc<Group>>; TEARDOWN_ARRAY_SIZE],
        evicted_groups: &'a mut [Option<Arc<Group>>; MAX_CSGS],
    ) -> Self {
        Self {
            sched,
            teardown_groups,
            num_teardown: 0,
            evicted_groups,
        }
    }

    /// Evaluates groups and applies the scheduling decisions to the
    /// hardware.
    fn tick(&mut self, tdev: &ARef<TyrDrmDevice>, fw: &Firmware<'_>) -> Result<()> {
        self.sched
            .sync_group_states(tdev, fw)
            .inspect_err(|_| dev_err!(tdev.as_ref(), "sync_group_states failed\n"))?;

        let now = jiffies64();
        let full_tick = now.wrapping_sub(self.sched.last_full_tick_jiffies)
            >= msecs_to_jiffies(TICK_PERIOD_MS) as u64;

        let rules = build_scheduling_rules! {
            // Idle groups are processed identically in both normal and
            // full ticks. Prefer keeping them bound unless a hardware
            // slot is needed, walking priorities high to low. This
            // includes idle-because-syncwait groups. While on-slot, the
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
            // The trailing `Keep` re-admits the groups skipped by
            // `KeepExceptRotated` when the `Take` left them a slot and an
            // address space.
            if full_tick => [
                KeepExceptRotated RealTime, Take RealTime, Keep RealTime,
                KeepExceptRotated High,     Take High,     Keep High,
                KeepExceptRotated Medium,   Take Medium,   Keep Medium,
                KeepExceptRotated Low,      Take Low,      Keep Low,
            ],
            // A normal tick prefers to keep currently bound active
            // groups running to minimize context-switching overhead.
            // Evaluate all `Keep`s for non-RT priorities before any
            // `Take`.
            else => [
                Keep RealTime, Take RealTime,
                Keep High,     Keep Medium,   Keep Low,
                Take High,     Take Medium,   Take Low,
            ]
        };

        let mut decision = SchedulingDecision::new();
        if let Err(e) = decision
            .evaluate_rules(tdev, self.sched, rules, full_tick)
            .and_then(|()| self.apply(tdev, fw, &mut decision))
        {
            for pending in decision.pending_groups.iter_mut().filter_map(Option::take) {
                self.requeue_pending_bind(pending);
            }
            return Err(e);
        }

        if full_tick {
            self.sched.last_full_tick_jiffies = now;
        }

        Ok(())
    }

    /// Stages a `Suspend` (or `Terminate` for unhealthy groups) state
    /// transition for every bound slot not covered by `keep_mask`.
    fn stage_evictions(
        &mut self,
        tdev: &ARef<TyrDrmDevice>,
        keep_mask: u32,
        context: &mut CsgUpdateContext,
    ) {
        // Build the halt request set under the slot-manager lock,
        // then drop the lock before issuing the firmware update.
        // `apply_csg_updates` re-acquires it itself across its wait
        // phase.
        let csg_slot_manager = tdev.csg_slot_manager.lock();
        for csg_idx in CsgSlotIdx::all() {
            if (keep_mask & csg_idx.bit()) != 0 {
                continue;
            }
            let Some(slot_data) = csg_slot_manager.slot_data(csg_idx.get()) else {
                continue;
            };

            if slot_data.group.can_run() {
                context.set_state(csg_idx, CsgExecutionState::Suspend);
            } else {
                context.set_state(csg_idx, CsgExecutionState::Terminate);
            }
        }
    }

    /// Tears down the binding of every slot not covered by `keep_mask`, after
    /// the firmware acked (or timed out on) the staged state transitions.
    fn unbind_evicted_groups(
        &mut self,
        tdev: &ARef<TyrDrmDevice>,
        fw: &Firmware<'_>,
        keep_mask: u32,
    ) -> Result<()> {
        // Drain any pending CSG IRQs on each evicted slot so the
        // group's per-queue / per-CSG bookkeeping reflects the latest
        // firmware state before we tear the binding down. Runs
        // *before* taking the slot-manager lock below because
        // `process_csg_irq` re-takes the slot-manager lock itself to
        // look the group up.
        for csg_idx in CsgSlotIdx::all() {
            if (keep_mask & csg_idx.bit()) != 0 {
                continue;
            }
            if let Err(e) = self.sched.process_csg_irq(tdev, fw, csg_idx.get()) {
                dev_err!(
                    tdev.as_ref(),
                    "process_csg_irq {} failed: {}\n",
                    csg_idx.get(),
                    e.to_errno()
                );
            }
        }

        let mut csg_slot_manager = tdev.csg_slot_manager.lock();
        // Evict every slot even when one fails, so no group is left bound when
        // the caller halts the MCU.
        let mut ret = Ok(());
        let mut poll = false;
        for csg_idx in CsgSlotIdx::all() {
            if (keep_mask & csg_idx.bit()) != 0 {
                continue;
            }

            let (group, can_run) = {
                let Some(slot_data) = csg_slot_manager.slot_data(csg_idx.get()) else {
                    continue;
                };
                (slot_data.group.clone(), slot_data.group.can_run())
            };

            if let Err(e) = csg_slot_manager.evict_forced(&group.csg_seat) {
                dev_err!(
                    tdev.as_ref(),
                    "evict {} failed: {}\n",
                    csg_idx.get(),
                    e.to_errno()
                );
                if ret.is_ok() {
                    ret = Err(e);
                }
            }

            if can_run {
                if let Ok(list_arc) = ListArc::try_from_arc(group.clone()) {
                    let is_idle = group.is_idle_live();
                    self.sched.requeue_group(list_arc, is_idle);
                }
                poll |= group.blocked_idle_queues() != 0;
                self.evicted_groups[csg_idx.get()] = Some(group.clone());
            } else if self.num_teardown < self.teardown_groups.len() {
                // Canceled / faulted: queue for terminal cleanup.
                self.sched.remove_group_from_wait_list(&group);
                self.teardown_groups[self.num_teardown] = Some(group.clone());
                self.num_teardown += 1;
            }
        }

        if poll {
            TyrDrmDeviceData::schedule_syncwait_poll(tdev);
        }

        ret
    }

    /// Suspends and unbinds groups not marked to be kept.
    fn halt_and_unbind_evicted_groups(
        &mut self,
        tdev: &ARef<TyrDrmDevice>,
        fw: &Firmware<'_>,
        decision: &SchedulingDecision,
    ) -> Result<()> {
        let mut context = CsgUpdateContext::new();

        self.stage_evictions(tdev, decision.keep_mask, &mut context);

        if let Err(e) = self.sched.apply_csg_updates(tdev, fw, &mut context) {
            dev_err!(tdev.as_ref(), "apply_csg_updates (halt) failed\n");
            let csg_slot_manager = tdev.csg_slot_manager.lock();
            for csg_idx in CsgSlotIdx::all() {
                if !context.timedout_mask.contains(csg_idx) {
                    continue;
                }
                if let Some(slot_data) = csg_slot_manager.slot_data(csg_idx.get()) {
                    slot_data
                        .group
                        .with_locked_inner(|inner| inner.mark_evicted_by_timeout());
                }
            }
            return Err(e);
        }

        self.unbind_evicted_groups(tdev, fw, decision.keep_mask)
    }

    /// Evicts every resident group for runtime suspend.
    ///
    /// Like `halt_and_unbind_evicted_groups` with nothing kept, but leaves no
    /// group bound even on failure. The L2/LSC caches are then cleaned so the
    /// firmware-written suspend buffers reach memory before power loss.
    fn suspend(
        &mut self,
        tdev: &ARef<TyrDrmDevice>,
        reg_data: &TyrDrmRegistrationData<'_>,
    ) -> Result<()> {
        let mut context = CsgUpdateContext::new();

        self.stage_evictions(tdev, 0, &mut context);

        if self
            .sched
            .apply_csg_updates(tdev, &reg_data.fw, &mut context)
            .is_err()
        {
            dev_err!(
                tdev.as_ref(),
                "CSG suspend failed, escalating to termination\n"
            );
            let mut term_context = CsgUpdateContext::new();
            {
                let csg_slot_manager = tdev.csg_slot_manager.lock();
                for csg_idx in CsgSlotIdx::all() {
                    if !context.timedout_mask.contains(csg_idx) {
                        continue;
                    }
                    let Some(slot_data) = csg_slot_manager.slot_data(csg_idx.get()) else {
                        continue;
                    };
                    slot_data
                        .group
                        .with_locked_inner(|inner| inner.mark_evicted_by_timeout());
                    term_context.set_state(csg_idx, CsgExecutionState::Terminate);
                }
            }
            if let Err(e) = self
                .sched
                .apply_csg_updates(tdev, &reg_data.fw, &mut term_context)
            {
                dev_err!(
                    tdev.as_ref(),
                    "CSG terminate on suspend failed: {}\n",
                    e.to_errno()
                );
            }
        }

        if reg_data.mmu.flush_caches().is_err() {
            dev_err!(
                tdev.as_ref(),
                "cache clean on suspend failed, terminating suspended groups\n"
            );
            let csg_slot_manager = tdev.csg_slot_manager.lock();
            for i in 0..MAX_CSGS {
                let Some(slot_data) = csg_slot_manager.slot_data(i) else {
                    continue;
                };
                slot_data.group.set_state(State::Terminated);
            }
        }

        let res = self.unbind_evicted_groups(tdev, &reg_data.fw, 0);

        if self.sched.has_runnable_groups() {
            TyrDrmDeviceData::schedule_tick(tdev);
        }

        res
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
        tdev: &ARef<TyrDrmDevice>,
        fw: &Firmware<'_>,
        decision: &mut SchedulingDecision,
    ) -> Result<()> {
        let mut context = CsgUpdateContext::new();
        let mut next_fw_prio = MAX_CSG_PRIO;
        let mut bind_timed_out = false;

        // Build the priority/bind request set under the slot-manager
        // lock, then drop the lock before issuing the firmware update.
        {
            let mut csg_slot_manager = tdev.csg_slot_manager.lock();

            for selection in
                SelectedGroup::iter_prioritized(&decision.selections, decision.rotated_slots)
            {
                let fw_prio = next_fw_prio;
                next_fw_prio = next_fw_prio.saturating_sub(1);

                match selection {
                    SelectedGroup::Kept(slot_idx, _sw_prio, _is_idle, cur_fw_prio) => {
                        if cur_fw_prio == fw_prio {
                            continue;
                        }

                        if let Err(e) = self.sched.update_csg_slot_priority(
                            tdev,
                            fw,
                            &csg_slot_manager,
                            slot_idx,
                            fw_prio,
                            &mut context,
                        ) {
                            dev_err!(
                                tdev.as_ref(),
                                "update_csg_slot_priority {} failed: {}\n",
                                slot_idx,
                                e.to_errno()
                            );
                        }
                    }
                    SelectedGroup::Pending(idx, _sw_prio, _is_idle) => {
                        let Some(pending) =
                            decision.pending_groups.get_mut(idx).and_then(Option::take)
                        else {
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
                        let slot_idx = match csg_slot_manager.activate(CsgSlotData {
                            group: group.clone(),
                            fw_priority: fw_prio,
                        }) {
                            Ok(slot_idx) => slot_idx,
                            Err(e) => {
                                dev_err!(
                                    tdev.as_ref(),
                                    "activate (pending) failed: {}\n",
                                    e.to_errno()
                                );
                                // ETIMEDOUT reaches here from the AS-ready
                                // and cache-flush polls under vm.activate().
                                if e == ETIMEDOUT {
                                    bind_timed_out = true;
                                }
                                self.requeue_pending_bind(pending);
                                if !group.can_run() {
                                    Scheduler::request_tick(tdev);
                                }
                                continue;
                            }
                        };

                        // The slot manager has recorded the binding, so
                        // any failure from here to the staged request
                        // has to release it again.
                        if let Err(e) = Scheduler::program_csg_activate(
                            fw,
                            &group,
                            slot_idx,
                            fw_prio,
                            &mut context,
                        ) {
                            dev_err!(
                                tdev.as_ref(),
                                "program_csg_activate failed: {}\n",
                                e.to_errno()
                            );
                            if let Err(err) = csg_slot_manager.evict(&group.csg_seat) {
                                dev_err!(
                                    tdev.as_ref(),
                                    "bind rollback: evict failed: {}\n",
                                    err.to_errno()
                                );
                                // A failed hardware eviction keeps the
                                // seat bound, so the group would look
                                // resident with no firmware programming
                                // behind it.
                                group.with_locked_inner(|inner| {
                                    inner.state = State::Unknown;
                                    inner.fatal = true;
                                });
                            }
                            self.requeue_pending_bind(pending);
                            continue;
                        }

                        drop(pending.list_arc);
                    }
                }
            }
        }

        let res = self.sched.apply_csg_updates(tdev, fw, &mut context);
        if res.is_err() {
            dev_err!(
                tdev.as_ref(),
                "apply_csg_updates (priorities & bind) failed\n"
            );
        }
        res
    }

    /// Updates scheduler statuses and schedules a periodic tick if
    /// there is contention.
    fn update_status_and_resched(
        &mut self,
        tdev: &ARef<TyrDrmDevice>,
        decision: &SchedulingDecision,
    ) {
        self.sched.resched_target = None;
        self.sched.last_tick = Instant::<Monotonic>::now();
        self.sched.used_csg_slot_count = decision.num_selected as u32;
        self.sched.might_have_idle_groups = decision.idle_group_count > 0;

        let all_slots_busy = decision.num_selected == self.sched.csg_slot_count as usize
            && decision.idle_group_count == 0;

        if decision.needs_resched()
            || ((all_slots_busy || self.sched.as_budget.refused)
                && self.sched.has_runnable_groups())
        {
            let period = Delta::from_millis(i64::from(TICK_PERIOD_MS));
            self.sched.resched_target = Some(self.sched.last_tick + period);
            Scheduler::request_tick(tdev);
        }
    }

    /// Executes the scheduling steps and updates subsequent tick
    /// targets.
    fn apply(
        &mut self,
        tdev: &ARef<TyrDrmDevice>,
        fw: &Firmware<'_>,
        decision: &mut SchedulingDecision,
    ) -> Result<()> {
        self.halt_and_unbind_evicted_groups(tdev, fw, decision)?;
        self.apply_priorities_and_bind(tdev, fw, decision)?;

        if decision.all_idle {
            tdev.devfreq_data.devfreq_state.lock().mark_idle();
            self.sched.pm_ref = None;
        } else {
            tdev.devfreq_data.devfreq_state.lock().mark_busy();
            if self.sched.pm_ref.is_none() {
                self.sched.pm_ref = tdev.sched_pm_get();
            }
        }

        self.update_status_and_resched(tdev, decision);
        Ok(())
    }
}
