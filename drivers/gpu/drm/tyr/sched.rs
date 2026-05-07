// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    bits::{
        checked_bit_u32,
        genmask_u32, //
    },
    drm::gem::BaseObject,
    list::{
        List,
        ListArc, //
    },
    prelude::*,
    sync::Arc,
    time::{
        Instant,
        Monotonic, //
    },
    types::ARef, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    fw::{
        global::cs::{
            CommandStream,
            StreamState, //
        },
        global::csg::{
            self,
            constants::*,
            CommandStreamGroup,
            GroupState,
            Priority,
            MAX_CSGS, //
        },
        SharedSectionEntry, //
    },
    sched::group::{
        QueueParkAction,
        MAX_CS_PER_GROUP, //
    },
    slot::{
        SlotManager, //
        SlotOperations,
    },
};

use group::Group;

pub(crate) mod deps;
mod events;
pub(crate) mod group;
pub(crate) mod job;
pub(crate) mod queue;
mod syncs;
mod tick;

/// Period in milliseconds between scheduler ticks.
pub(crate) const TICK_PERIOD_MS: u32 = 10;

const MAX_CSG_PRIO: u32 = 0xf;

/// The scheduler object.
pub(crate) enum SchedulerState {
    /// The driver is probing.
    Disabled,
    /// The firmware has booted and the scheduler has been initialized.
    Enabled(Scheduler),
}

impl SchedulerState {
    pub(crate) fn enabled_mut(&mut self) -> Result<&mut Scheduler> {
        match self {
            SchedulerState::Enabled(scheduler) => Ok(scheduler),
            SchedulerState::Disabled => Err(EINVAL),
        }
    }
}

/// Context for accumulating command stream group updates.
pub(crate) struct CsgUpdateContext {
    /// Bitmap of CSG slot indices with pending updates.
    pub(crate) update_mask: u32,
    /// Bitmap of CSG slot indices whose request has timed out.
    pub(crate) timedout_mask: u32,
    /// Per-slot bits actually acknowledged by the firmware in response
    /// to this tick's `req_vals` writes.  Bits in `req_masks` that fail
    /// to appear here mark the slot as timed out (see `timedout_mask`).
    pub(crate) acked_reqs: [u32; MAX_CSGS as usize],
    /// Per-slot accumulated new request bits to write into the firmware
    /// `req` field.
    pub(crate) req_vals: [u32; MAX_CSGS as usize],
    /// Per-slot mask selecting which bits of `req_vals` are meaningful.
    pub(crate) req_masks: [u32; MAX_CSGS as usize],
}

impl CsgUpdateContext {
    /// Bits that the firmware expects to be toggled instead of set.
    const TOGGLE_BITS: u32 = CSG_ENDPOINT_CONFIG | CSG_STATUS_UPDATE;

    /// Creates a new, empty update context.
    pub(crate) fn new() -> Self {
        Self {
            update_mask: 0,
            timedout_mask: 0,
            acked_reqs: [0; MAX_CSGS as usize],
            req_vals: [0; MAX_CSGS as usize],
            req_masks: [0; MAX_CSGS as usize],
        }
    }

    /// Queues requests for a given CSG.
    pub(crate) fn queue_reqs(&mut self, csg_idx: usize, req_val: u32, req_mask: u32) {
        self.update_mask |= 1 << csg_idx;
        self.req_vals[csg_idx] &= !req_mask;
        self.req_vals[csg_idx] |= req_val;
        self.req_masks[csg_idx] |= req_mask;
    }

    /// Toggles the specified request bits for a given CSG.
    pub(crate) fn toggle_reqs(&mut self, csg_idx: usize, toggle_bit: u32) {
        self.queue_reqs(csg_idx, toggle_bit, toggle_bit);
    }

    /// Sets the state request for a given CSG.
    pub(crate) fn set_state(&mut self, csg_idx: usize, state: GroupState) {
        self.queue_reqs(csg_idx, state as u32, CSG_STATE_MASK);
    }
}

/// Data stored in a CSG slot.
pub(crate) struct CsgSlotData {
    /// The group currently bound to this slot.
    pub(crate) group: Arc<Group>,
    /// Firmware-side priority value programmed for this slot.
    pub(crate) fw_priority: u32,
}

/// Operations for CSG slots. The per-tick state needed by the
/// callbacks is passed via [`SlotOperations::Context`]
/// ([`CsgUpdateContext`]).
pub(crate) struct CsgSlotOperations;

/// Slot manager specialised for CSG slots driven by [`CsgSlotOperations`].
pub(crate) type CsgSlotManager = SlotManager<CsgSlotOperations, { MAX_CSGS as usize }>;

impl SlotOperations for CsgSlotOperations {
    type SlotData = CsgSlotData;
    type Context = CsgUpdateContext;

    /// Activates a command stream group slot.
    fn activate(
        &mut self,
        slot_idx: usize,
        slot_data: &Self::SlotData,
        upd_ctx: &mut Self::Context,
    ) -> Result {
        let group = &slot_data.group;
        let fw_priority = slot_data.fw_priority;

        group.vm.activate()?;
        let as_nr = group.vm.address_space().map(|a| a as u32).ok_or(EINVAL)?;

        group.tdev.fw.with_locked_global_iface(|glb_iface| {
            let csg_iface = glb_iface.csg_mut(slot_idx).ok_or(EINVAL)?;
            Self::program_csg_slot(group, csg_iface, fw_priority, as_nr, slot_idx, upd_ctx)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Evicts a command stream group from its hardware slot.
    ///
    /// This handles unbinding the group from the hardware slot, deactivating
    /// its VM, and clearing doorbells.
    fn evict(
        &mut self,
        _slot_idx: usize,
        slot_data: &Self::SlotData,
        _ctx: &mut Self::Context,
    ) -> Result {
        let group = &slot_data.group;

        group.vm.deactivate()?;

        // Park actions are applied after `Group::inner` is dropped (lock
        // ordering); buffer them on the stack to keep evict allocation-free.
        let mut park_actions: [Option<QueueParkAction>; MAX_CS_PER_GROUP] =
            [const { None }; MAX_CS_PER_GROUP];

        group.with_locked_inner(|inner| {
            inner.csg_id = None;

            for i in 0..inner.queues.len() {
                inner.queues[i].doorbell_id = None;
                park_actions[i] = inner.sync_queue_state(i);
            }
            Ok(())
        })?;

        for action in park_actions.into_iter().flatten() {
            action.apply();
        }

        Ok(())
    }
}

impl CsgSlotOperations {
    /// Programs a command stream slot with the queue's ring buffer and doorbell.
    fn program_cs_slot(queue: &mut queue::Queue, cs_iface: &mut CommandStream) -> Result {
        let doorbell_id = queue.doorbell_id.ok_or(EINVAL)?;
        let mut cs_input = cs_iface.read_input()?;

        let ringbuf_input = queue.interfaces.read_input()?;
        let ringbuf_output = queue.interfaces.read_output()?;
        queue.interfaces.write_extract_init(ringbuf_output.extract);
        queue.interfaces.write_insert(ringbuf_input.insert);

        cs_input.ringbuf_base = queue.ringbuf.kernel_va().ok_or(EINVAL)?.start;
        cs_input.ringbuf_size = queue.ringbuf.size() as u32;

        cs_input.ringbuf_input = queue.interfaces.input_va.start;
        cs_input.ringbuf_output = queue.interfaces.output_va.start;

        cs_input.set_priority(queue.priority)?;
        cs_input.set_doorbell_id(doorbell_id as u32)?;
        cs_input.ack_irq_mask = u32::MAX;

        cs_iface.write_input(cs_input)?;
        cs_iface.set_state(StreamState::Start)?;

        Ok(())
    }

    /// Programs a command stream group slot and activates its command streams.
    fn program_csg_slot(
        group: &Group,
        csg_iface: &mut CommandStreamGroup,
        fw_priority: u32,
        as_nr: u32,
        slot_idx: usize,
        upd_ctx: &mut CsgUpdateContext,
    ) -> Result {
        let mut park_actions: [Option<QueueParkAction>; MAX_CS_PER_GROUP] =
            [const { None }; MAX_CS_PER_GROUP];

        let queue_mask = group.with_locked_inner(|inner| {
            if !inner.can_run() {
                pr_err!("program_csg_slot: group cannot run\n");
                return Err(EINVAL);
            }

            if let group::State::Active = inner.state {
                pr_err!("program_csg_slot: group is already active\n");
                return Err(EINVAL);
            }

            let mut queue_mask = 0;

            inner.csg_id = Some(slot_idx);
            inner.idle = false;

            for cs_idx in 0..inner.queues.len() {
                let queue = &mut inner.queues[cs_idx];
                queue.doorbell_id = Some(slot_idx + 1);
                let cs_iface = csg_iface.cs_mut(cs_idx).ok_or(EINVAL)?;
                Self::program_cs_slot(queue, cs_iface)?;
                queue_mask |= checked_bit_u32(cs_idx as u32).ok_or(EINVAL)?;
                park_actions[cs_idx] = inner.sync_queue_state(cs_idx);
            }

            Ok(queue_mask)
        })?;

        for action in park_actions.into_iter().flatten() {
            action.apply();
        }

        let mut input = csg_iface.read_input()?;

        input.allow_compute = group.compute_core_mask;
        input.allow_fragment = group.fragment_core_mask;
        input.allow_other = group.tiler_core_mask.try_into()?;

        input.set_endpoint_req(
            group.max_compute_cores.into(),
            group.max_fragment_cores.into(),
            group.max_tiler_cores.into(),
            fw_priority as usize,
        );

        input.csg_config = as_nr;

        input.suspend_buf = group.suspend_buf.kernel_va().ok_or(EINVAL)?.start;
        input.protm_suspend_buf = group.protm_suspend_buf.kernel_va().ok_or(EINVAL)?.start;

        input.ack_irq_mask = u32::MAX;

        csg_iface.write_input(input)?;
        csg_iface.doorbell_request()?.toggle_reqs(queue_mask)?;

        let group_state = group.state();
        let csg_state = if group_state == group::State::Suspended {
            GroupState::Resume
        } else {
            GroupState::Start
        };

        upd_ctx.set_state(slot_idx, csg_state);
        upd_ctx.toggle_reqs(slot_idx, CSG_ENDPOINT_CONFIG);

        Ok(())
    }
}

/// The scheduler managing groups, queues, and hardware execution slots.
pub(crate) struct Scheduler {
    /// Groups that have at least one queue that can be currently scheduled.
    runnable_groups: [List<Group>; Priority::num_priorities()],
    /// Groups that have all their queues idle, either because they have nothing
    /// to execute, or because they are blocked.
    idle_groups: [List<Group>; Priority::num_priorities()],
    /// List of groups whose queues are blocked on a sync object.
    waiting_groups: [List<Group, 1>; Priority::num_priorities()],

    /// Number of command stream group slots exposed by the firmware.
    csg_slot_count: u32,

    /// Number of command stream slots per group slot exposed by the firmware.
    #[expect(dead_code)]
    cs_slot_count: u32,

    /// Number of address space slots supported by the MMU.
    #[expect(dead_code)]
    as_slot_count: u32,

    /// Number of command stream group slots currently in use.
    used_csg_slot_count: u32,

    /// True if an active group might have become idle.
    pub(crate) might_have_idle_groups: bool,

    /// Number of scoreboard slots.
    #[expect(dead_code)]
    sb_slot_count: u32,

    /// When the next tick should occur.
    resched_target: Option<Instant<Monotonic>>,

    /// When the last tick occurred.
    pub(crate) last_tick: Instant<Monotonic>,
}

impl Scheduler {
    pub(crate) fn init(tdev: &TyrDrmDevice) -> Result<Self> {
        let (group_num, sb_slot_count, cs_slot_count, cs_reg_count) =
            tdev.fw.with_locked_global_iface(|glb_iface| {
                let glb_control = glb_iface.read_control()?;

                let csg = glb_iface.csg(0).ok_or(EINVAL)?;
                let csg_control = csg.read_control()?;

                let cs = csg.cs(0).ok_or(EINVAL)?;
                let cs_control = cs.read_control()?;

                let group_num = glb_control.group_num;
                let sb_slot_count = cs_control.scoreboards();
                let cs_slot_count = csg_control.stream_num;
                let cs_reg_count = cs_control.work_regs();

                Ok((group_num, sb_slot_count, cs_slot_count, cs_reg_count))
            })?;

        let num_groups = core::cmp::min(MAX_CSGS, group_num);

        // The firmware-side scheduler might deadlock if two groups with the same
        // priority try to access a set of resources that overlaps, with part of the
        // resources being allocated to one group and the other part to the other group,
        // both groups waiting for the remaining resources to be allocated.
        //
        // To avoid that, it is recommended to assign each Command Stream Group (CSG)
        // a different priority. In theory, several groups could have the same CSG
        // priority if they don't request the same resources, but that would make the
        // scheduling logic more complicated.
        //
        // For now, the number of CSG slots is clamped to `MAX_CSG_PRIO + 1`.
        let num_groups = core::cmp::min(MAX_CSG_PRIO + 1, num_groups);

        // We need at least one AS for the MCU and one for the GPU contexts.
        let gpu_as_count = tdev.gpu_info.as_present & genmask_u32(1..=31);
        let gpu_as_count = gpu_as_count.count_ones();

        // Each CSG needs its own AS, so limit CSG count to available AS count
        let csg_slot_count = core::cmp::min(num_groups, gpu_as_count);
        let as_slot_count = gpu_as_count;

        // Populate CSIF info in TyrDrmDevice
        {
            use crate::fw::global::cs::CSF_UNPRESERVED_REG_COUNT;
            let mut csif = tdev.csif_info.lock();
            csif.csg_slot_count = csg_slot_count;
            csif.cs_slot_count = cs_slot_count;
            csif.cs_reg_count = cs_reg_count;
            csif.scoreboard_slot_count = sb_slot_count;
            csif.unpreserved_cs_reg_count = CSF_UNPRESERVED_REG_COUNT;
        }

        Ok(Self {
            runnable_groups: [const { List::new() }; Priority::num_priorities()],
            idle_groups: [const { List::new() }; Priority::num_priorities()],
            waiting_groups: [const { List::new() }; Priority::num_priorities()],
            csg_slot_count,
            cs_slot_count,
            as_slot_count,
            used_csg_slot_count: 0,
            might_have_idle_groups: false,
            sb_slot_count,
            resched_target: None,
            last_tick: Instant::<Monotonic>::now(),
        })
    }

    /// Apply accumulated CSG updates. Caller must NOT hold
    /// `csg_slot_manager`: this waits for firmware acks and the lock
    /// should not be held across that wait.
    pub(crate) fn apply_csg_updates(
        &mut self,
        data: ARef<TyrDrmDevice>,
        context: &mut CsgUpdateContext,
    ) -> Result {
        if context.update_mask == 0 {
            return Ok(());
        }

        data.fw.with_locked_global_iface(|glb_iface| {
            for csg_idx in 0..self.csg_slot_count as usize {
                if context.update_mask & (1 << csg_idx) != 0 {
                    let req_mask = context.req_masks[csg_idx];
                    if req_mask != 0 {
                        let req_val = context.req_vals[csg_idx] & !CsgUpdateContext::TOGGLE_BITS;

                        if let Some(csg_iface) = glb_iface.csg_mut(csg_idx) {
                            csg_iface.input_request()?.update_and_toggle_reqs(
                                req_val,
                                req_mask & !CsgUpdateContext::TOGGLE_BITS,
                                req_mask & CsgUpdateContext::TOGGLE_BITS,
                            )?;
                        }
                    }
                }
            }

            glb_iface.ring_csg_doorbells(context.update_mask)?;
            Ok(())
        })?;

        // Wait for the firmware to acknowledge each requested update.
        // No driver locks are held here; only the firmware ack mailbox is
        // polled.
        for csg_idx in 0..self.csg_slot_count as usize {
            if context.update_mask & (1 << csg_idx) != 0 {
                let req_mask = context.req_masks[csg_idx];

                match data.fw.wait_csg_acks(csg_idx, req_mask, 100) {
                    Ok(acked) => {
                        context.acked_reqs[csg_idx] = acked;

                        if acked != req_mask {
                            pr_err!("CSG {} update request timed out\n", csg_idx);
                            context.timedout_mask |= 1 << csg_idx;
                        }
                    }
                    Err(e) => {
                        pr_err!("wait_csg_acks {} failed: {}\n", csg_idx, e.to_errno());
                        context.timedout_mask |= 1 << csg_idx;
                    }
                }
            }
        }

        // Now that acks are received, sync the states. These need the
        // slot map, so grab it once and run the whole sync pass under a
        // single lock acquisition.
        let mut csg_slot_manager = data.csg_slot_manager.lock();
        for csg_idx in 0..self.csg_slot_count as usize {
            if context.update_mask & (1 << csg_idx) != 0 {
                let acked_reqs = context.acked_reqs[csg_idx];

                if acked_reqs & CSG_ENDPOINT_CONFIG != 0 {
                    data.fw.with_locked_global_iface(|glb_iface| {
                        self.sync_csg_slot_priority(glb_iface, &mut csg_slot_manager, csg_idx)
                    })?;
                }

                if acked_reqs & CSG_STATE_MASK != 0 {
                    data.fw.with_locked_global_iface(|glb_iface| {
                        self.sync_csg_slot_state(&data, glb_iface, &csg_slot_manager, csg_idx)
                    })?;
                }

                if acked_reqs & CSG_STATUS_UPDATE != 0 {
                    data.fw.with_locked_global_iface(|glb_iface| {
                        self.sync_csg_slot_queues_state(
                            &data,
                            glb_iface,
                            &csg_slot_manager,
                            csg_idx,
                        )
                    })?;
                }
            }
        }

        if context.timedout_mask != 0 {
            return Err(ETIMEDOUT);
        }

        Ok(())
    }

    /// Updates the hardware priority of a CSG slot.
    pub(crate) fn update_csg_slot_priority(
        &mut self,
        data: &TyrDrmDeviceData,
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

        if csg_idx >= MAX_CSGS as usize {
            pr_err!("update_csg_slot_priority: invalid csg {}\n", csg_idx);
            return Err(EINVAL);
        }

        let slot_data = csg_slot_manager.slot_data(csg_idx).ok_or(EINVAL)?;
        let group = slot_data.group.clone();

        data.fw.with_locked_global_iface(|glb_iface| {
            let csg_iface = glb_iface.csg_mut(csg_idx).ok_or(EINVAL)?;
            let mut input = csg_iface.read_input()?;

            input.set_endpoint_req(
                group.max_compute_cores.into(),
                group.max_fragment_cores.into(),
                group.max_tiler_cores.into(),
                fw_prio as usize,
            );

            csg_iface.write_input(input)?;
            Ok(())
        })?;

        context.toggle_reqs(csg_idx, CSG_ENDPOINT_CONFIG);

        Ok(())
    }

    /// Removes destroyed groups from the scheduler lists.
    pub(crate) fn prune_destroyed_groups(
        &mut self,
        pruned_groups: &mut [Option<Arc<Group>>],
    ) -> usize {
        let mut count = 0;
        for priority in 0..Priority::num_priorities() {
            for list in [
                &mut self.idle_groups[priority],
                &mut self.runnable_groups[priority],
            ] {
                let mut cursor = list.cursor_front();
                while let Some(group) = cursor.peek_next() {
                    if !group.arc().can_run() {
                        if count >= pruned_groups.len() {
                            return count;
                        }
                        let group_arc: Arc<Group> = group.arc().into();
                        group.remove();
                        pruned_groups[count] = Some(group_arc);
                        count += 1;
                    } else {
                        cursor.move_next();
                    }
                }
            }

            let mut cursor = self.waiting_groups[priority].cursor_front();
            while let Some(group) = cursor.peek_next() {
                if !group.arc().can_run() {
                    if count >= pruned_groups.len() {
                        return count;
                    }
                    let group_arc: Arc<Group> = group.arc().into();
                    group.remove();
                    pruned_groups[count] = Some(group_arc);
                    count += 1;
                } else {
                    cursor.move_next();
                }
            }
        }
        count
    }

    /// Removes a group from its current list.
    ///
    /// The caller must ensure that `list_state` correctly reflects the list
    /// the group is currently in; otherwise the group is not removed and an
    /// error is logged.
    fn remove_group_from_list(
        &mut self,
        group: &Group,
        priority: usize,
        list_state: group::GroupListState,
    ) -> Option<ListArc<Group>> {
        let list = match list_state {
            group::GroupListState::Idle => Some(&mut self.idle_groups[priority]),
            group::GroupListState::Runnable => Some(&mut self.runnable_groups[priority]),
            group::GroupListState::None => None,
        };

        if let Some(list) = list {
            // SAFETY: We verified that the group was in the list via its `list_state`.
            let list_arc = unsafe { list.remove(group) };
            if list_arc.is_none() {
                pr_err!("group was marked {:?} but not found\n", list_state);
            }
            list_arc
        } else {
            None
        }
    }

    /// Requeues a group into the appropriate list (idle or runnable).
    pub(crate) fn requeue_group(&mut self, list_arc: ListArc<Group>) {
        let priority = list_arc.priority as usize;
        let is_idle = list_arc.is_idle();

        let _ = list_arc.with_locked_inner(|inner| {
            if is_idle {
                inner.list_state = group::GroupListState::Idle;
            } else {
                inner.list_state = group::GroupListState::Runnable;
            }

            Ok(())
        });

        if is_idle {
            self.idle_groups[priority].push_back(list_arc);
        } else {
            self.runnable_groups[priority].push_back(list_arc);
        }
    }

    /// Marks a group as runnable, moving it to the runnable list if needed.
    pub(crate) fn mark_group_runnable(&mut self, group: &Arc<Group>) {
        let priority = group.priority as usize;

        let _ = group.with_locked_inner(|inner| {
            inner.idle = false;

            if inner.list_state == group::GroupListState::None {
                if inner.csg_id.is_none() {
                    if let Ok(list_arc) = ListArc::try_from_arc(group.clone()) {
                        self.runnable_groups[priority].push_back(list_arc);
                        inner.list_state = group::GroupListState::Runnable;
                    }
                }
            } else if inner.list_state != group::GroupListState::Runnable {
                if let Some(list_arc) =
                    self.remove_group_from_list(group.as_ref(), priority, inner.list_state)
                {
                    self.runnable_groups[priority].push_back(list_arc);
                    inner.list_state = group::GroupListState::Runnable;
                }
            }

            Ok(())
        });
    }
}
