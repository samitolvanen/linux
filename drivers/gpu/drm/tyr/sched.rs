// SPDX-License-Identifier: GPL-2.0 or MIT

use group::Group;
use kernel::bits::genmask_u32;
use kernel::list::{List, ListArc};
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::time::{Instant, Monotonic};
use queue::Queue;

use crate::driver::TyrData;
use crate::driver::TyrDevice;
use crate::fw::global::cs::CommandStream;
use crate::fw::global::cs::StreamState;
use crate::fw::global::csg;
use crate::fw::global::csg::constants::*;
use crate::fw::global::csg::Priority;
use crate::fw::global::csg::MAX_CSGS;
use crate::fw::SharedSectionEntry;

mod events;
pub(crate) mod group;
pub(crate) mod job;
pub(crate) mod queue;
mod tick;

pub(crate) const TICK_PERIOD_MS: u32 = 10;

pub(crate) const MAX_CSG_PRIO: u32 = 0xf;

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

pub(crate) struct CsgUpdateContext {
    pub(crate) update_mask: u32,
    pub(crate) timedout_mask: u32,
    pub(crate) acked_reqs: [u32; MAX_CSGS as usize],
    pub(crate) req_vals: [u32; MAX_CSGS as usize],
    pub(crate) req_masks: [u32; MAX_CSGS as usize],
}

impl CsgUpdateContext {
    const TOGGLE_BITS: u32 = CSG_ENDPOINT_CONFIG | CSG_STATUS_UPDATE;

    pub(crate) fn new() -> Self {
        Self {
            update_mask: 0,
            timedout_mask: 0,
            acked_reqs: [0; MAX_CSGS as usize],
            req_vals: [0; MAX_CSGS as usize],
            req_masks: [0; MAX_CSGS as usize],
        }
    }

    pub(crate) fn queue_reqs(&mut self, csg_idx: usize, req_val: u32, req_mask: u32) {
        self.update_mask |= 1 << csg_idx;
        self.req_vals[csg_idx] &= !req_mask;
        self.req_vals[csg_idx] |= req_val;
        self.req_masks[csg_idx] |= req_mask;
    }

    pub(crate) fn toggle_reqs(&mut self, csg_idx: usize, toggle_bit: u32) {
        self.queue_reqs(csg_idx, toggle_bit, toggle_bit);
    }

    pub(crate) fn set_state(&mut self, csg_idx: usize, state: csg::GroupState) {
        self.queue_reqs(csg_idx, state as u32, CSG_STATE_MASK);
    }
}

/// Context returned when a group is unbound from the hardware.
///
/// This struct holds the information needed by the scheduler to perform the final software
/// teardown and list management after the firmware has acknowledged the group's eviction.
pub(crate) struct UnboundGroup {
    /// The software group instance that was unbound.
    pub(crate) group: Arc<Group>,
    /// The `ListArc` used to insert this group into the scheduler's software queues
    /// (e.g., `runnable_groups` or `idle_groups`). This will be `Some` if the group
    /// remains healthy (`can_run == true`), allowing it to be re-scheduled later.
    pub(crate) list_arc: Option<ListArc<Group>>,
}

pub(crate) struct Scheduler {
    /// Groups that have at least one queue that can be currently scheduled.
    runnable_groups: [List<Group>; Priority::num_priorities()],
    /// Groups that have all their queues idle, either because they have nothing
    /// to execute, or because they are blocked.
    idle_groups: [List<Group>; Priority::num_priorities()],
    /// List of groups whose queues are blocked on a sync object.
    waiting_groups: [List<Group, 1>; Priority::num_priorities()],

    csg_slots: [Option<CommandStreamGroupSlot>; MAX_CSGS as usize],

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
    pub(crate) fn prune_destroyed_groups(&mut self) {
        for priority in 0..Priority::num_priorities() {
            for list in [
                &mut self.idle_groups[priority as usize],
                &mut self.runnable_groups[priority as usize],
            ] {
                let mut cursor = list.cursor_front();
                while let Some(group) = cursor.peek_next() {
                    let group_arc: Arc<Group> = group.arc().into();
                    if !group_arc.can_run() {
                        group.remove();
                    } else {
                        cursor.move_next();
                    }
                }
            }

            let mut cursor = self.waiting_groups[priority as usize].cursor_front();
            while let Some(group) = cursor.peek_next() {
                let group_arc: Arc<Group> = group.arc().into();
                if !group_arc.can_run() {
                    group.remove();
                } else {
                    cursor.move_next();
                }
            }
        }
    }

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
            } else {
            }
            list_arc
        } else {
            None
        }
    }

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

    /// Requeues a group into the appropriate scheduler list based on its current idle state.
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

    pub(crate) fn init(tdev: &TyrDevice) -> Result<Self> {
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

        // Populate CSIF info in TyrDevice
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
            csg_slots: [const { None }; MAX_CSGS as usize],
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

    /// Bind a group to a group slot.
    ///
    /// A group needs to be bound before it can be programmed into one of the
    /// firmware slots for execution.
    pub(crate) fn bind_group(
        &mut self,
        data: &TyrData,
        group: Arc<Group>,
        csg_idx: usize,
    ) -> Result {
        if csg_idx >= self.csg_slot_count as usize {
            pr_err!("bind_group: invalid group index {}", csg_idx);
            return Err(EINVAL);
        }

        group.with_locked_inner(|inner| {
            if inner.csg_id.is_some() {
                pr_err!("bind_group: group already bound to a CSG");
                return Err(EINVAL);
            }
            Ok(())
        })?;

        if self.csg_slots[csg_idx].is_some() {
            pr_err!("bind_group: group slot already in use");
            return Err(EINVAL);
        }

        let gpu_info = &data.gpu_info;
        let iomem = &data.iomem;

        data.with_locked_mmu(|mmu| mmu.bind_vm(group.vm.clone(), gpu_info, iomem))?;

        self.csg_slots[csg_idx] = Some(CommandStreamGroupSlot {
            group: group.clone(),
            fw_priority: None,
        });

        let priority = group.priority as usize;
        let mut list_state = group::GroupListState::None;

        group.with_locked_inner(|inner| {
            list_state = inner.list_state;
            inner.csg_id = Some(csg_idx);
            inner.idle = false;
            inner.list_state = group::GroupListState::None;
            // Dummy doorbell allocation: doorbell is assigned to the group and all
            // queues use the same doorbell.
            //
            // TODO: Implement LRU-based doorbell assignment, so the most often
            // updated queues get their own doorbell, thus avoiding useless checks
            // on queues belonging to the same group that are rarely updated.
            for i in 0..inner.queues.len() {
                inner.queues[i].doorbell_id = Some(csg_idx + 1);
                inner.sync_queue_state(i);
            }

            Ok(())
        })?;

        let _ = self.remove_group_from_list(group.as_ref(), priority, list_state);
        Ok(())
    }

    pub(crate) fn apply_csg_updates(
        &mut self,
        data: &Arc<TyrData>,
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
                        pr_err!("CSG {} update request failed: {}\n", csg_idx, e.to_errno());
                        return Err(e);
                    }
                }
            }
        }

        // Now that acks are received, sync the states.
        for csg_idx in 0..self.csg_slot_count as usize {
            if context.update_mask & (1 << csg_idx) != 0 {
                let acked_reqs = context.acked_reqs[csg_idx];

                if acked_reqs & CSG_ENDPOINT_CONFIG != 0 {
                    data.fw.with_locked_global_iface(|glb_iface| {
                        self.sync_csg_slot_priority(glb_iface, csg_idx)
                    })?;
                }

                if acked_reqs & CSG_STATE_MASK != 0 {
                    data.fw.with_locked_global_iface(|glb_iface| {
                        self.sync_csg_slot_state(glb_iface, csg_idx)
                    })?;
                }

                if acked_reqs & CSG_STATUS_UPDATE != 0 {
                    data.fw.with_locked_global_iface(|glb_iface| {
                        self.sync_csg_slot_queues_state(glb_iface, csg_idx)
                    })?;
                }
            }
        }

        if context.timedout_mask != 0 {
            return Err(ETIMEDOUT);
        }

        Ok(())
    }

    /// Unbind a group from group slot.
    pub(crate) fn unbind_group(&mut self, data: &TyrData, csg_idx: usize) -> Result<UnboundGroup> {
        if csg_idx >= self.csg_slot_count as usize {
            pr_err!("unbind_group: invalid group index {}", csg_idx);
            return Err(EINVAL);
        }
        if self.csg_slots[csg_idx].is_none() {
            pr_err!("unbind_group: group slot already empty");
            return Err(EINVAL);
        }

        let slot = self.csg_slots[csg_idx].as_mut().ok_or(EINVAL)?;

        slot.group.with_locked_inner(|inner| {
            inner.csg_id = None;

            for i in 0..inner.queues.len() {
                inner.queues[i].doorbell_id = None;
                inner.sync_queue_state(i);
            }
            Ok(())
        })?;

        data.with_locked_mmu(|mmu| {
            mmu.unbind_vm(&slot.group.vm, &data.iomem)?;
            Ok(())
        })?;

        let slot = self.csg_slots[csg_idx].take().ok_or(EINVAL)?;
        let mut list_arc_opt = None;

        if slot.group.can_run() {
            match ListArc::try_from_arc(slot.group.clone()) {
                Ok(list_arc) => {
                    list_arc_opt = Some(list_arc);
                }
                Err(_) => {
                    pr_err!("unbind_group: failed to create ListArc for group\n");
                }
            }
        }

        Ok(UnboundGroup {
            group: slot.group,
            list_arc: list_arc_opt,
        })
    }

    /// Program a group (and its queues) into a firmware slot. This will make
    /// the group eligible for execution from a FW perspective.
    pub(crate) fn program_csg_slot(
        &mut self,
        data: &TyrData,
        csg_idx: usize,
        fw_priority: u32,
        upd_ctx: &mut CsgUpdateContext,
    ) -> Result {
        if fw_priority > MAX_CSG_PRIO {
            pr_err!("program_csg_slot: invalid fw_priority {}\n", fw_priority);
            return Err(EINVAL);
        }

        if csg_idx > MAX_CSGS as usize {
            pr_err!("program_csg_slot: invalid csg {}\n", csg_idx);
            return Err(EINVAL);
        }

        let slot = self.csg_slots[csg_idx].as_mut().ok_or(EINVAL)?;
        let group = slot.group.clone();
        slot.fw_priority = Some(fw_priority);
        let as_nr = group
            .vm
            .lock()
            .address_space()
            .map(|a| a as u32)
            .ok_or(EINVAL)?;

        let fw = &data.fw;

        // Controls which CSn doorbells will be rung.
        //
        // This will process any requests in the CSn request field, and also
        // check for new work on the ring buffer.
        let queue_mask = fw.with_locked_global_iface(|glb_iface| {
            group.with_locked_inner(|inner| {
                if let group::State::Active = inner.state {
                    pr_err!("program_csg_slot: group is already active\n");
                    return Err(EINVAL);
                }

                let mut queue_mask = 0;
                let csg_iface = glb_iface.csg_mut(csg_idx).ok_or(EINVAL)?;

                for (cs_idx, queue) in inner.queues.iter_mut().enumerate() {
                    let cs_iface = csg_iface.cs_mut(cs_idx).ok_or(EINVAL)?;

                    self.program_cs_slot(queue, cs_iface)?;
                    queue_mask |= 1u32 << cs_idx;
                }

                Ok(queue_mask)
            })
        })?;

        let group_state = group.state();
        let csg_state = if group_state == group::State::Suspended {
            csg::GroupState::Resume
        } else {
            csg::GroupState::Start
        };

        fw.with_locked_global_iface(|glb_iface| {
            let csg_iface = glb_iface.csg_mut(csg_idx).ok_or(EINVAL)?;
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
            Ok(())
        })?;

        upd_ctx.set_state(csg_idx, csg_state);
        upd_ctx.toggle_reqs(csg_idx, CSG_ENDPOINT_CONFIG);

        Ok(())
    }

    /// Updates the firmware priority of a bound group slot.
    pub(crate) fn update_csg_slot_priority(
        &mut self,
        data: &TyrData,
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

        let slot = self.csg_slots[csg_idx].as_mut().ok_or(EINVAL)?;
        let group = slot.group.clone();
        slot.fw_priority = Some(fw_prio);

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

    /// Program a queue in a firmware slot. This makes the queue eligible for
    /// execution from a FW perspective.
    ///
    /// Queues are alloted slots when their group is itself programmed into a
    /// CSG slot.
    fn program_cs_slot(&mut self, queue: &mut Queue, cs_iface: &mut CommandStream) -> Result {
        let doorbell_id = queue.doorbell_id.ok_or(EINVAL)?;
        let mut cs_input = cs_iface.read_input()?;

        let ringbuf_input = queue.interfaces.read_input()?;
        let ringbuf_output = queue.interfaces.read_output()?;
        queue
            .interfaces
            .write_extract_init(ringbuf_output.extract)?;
        queue.interfaces.write_insert(ringbuf_input.insert)?;

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
}
pub(crate) struct CommandStreamGroupSlot {
    /// The group that is bound to this slot.
    pub(crate) group: Arc<Group>,
    /// The firmware priority assigned to this group.
    pub(crate) fw_priority: Option<u32>,
}
