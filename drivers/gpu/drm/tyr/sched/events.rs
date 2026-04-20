// SPDX-License-Identifier: GPL-2.0 or MIT
//! Firmware event processing.
//!
//! The firmware events are used to notify the driver of the overall progress of
//! the work currently submitted, as well as other scheduler-related events,
//! like device idleness, CSG/CS interrupts, fault decoding and etc.

use kernel::dma_fence::DmaFenceWorkItem;
use kernel::impl_has_dma_fence_work;
use kernel::list::ListArc;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::time::{msecs_to_jiffies, Delta, Instant, Monotonic};

use crate::driver::TyrData;
use crate::fw::global::constants::{GLB_EVT_MASK, GLB_IDLE};
use crate::fw::global::cs::constants::*;
use crate::fw::global::cs::{BlockedReason, StreamState};
use crate::fw::global::csg::constants::*;
use crate::fw::global::GlobalInterface;
use crate::fw::SharedSectionEntry;
use crate::regs::JOB_IRQ_GLOBAL_IF;
use crate::sched::csg::CommandStreamGroup;
use crate::sched::csg::GroupState;
use crate::sched::group::State;
use crate::sched::queue;
use crate::sched::CsgUpdateContext;
use crate::sched::Priority;
use crate::sched::Scheduler;

use super::group::Group;

impl Scheduler {
    // TODO: this does not work, we need to get the heap pool from the VM
    // somehow.
    fn process_tiler_oom(
        &mut self,
        csg: &mut CommandStreamGroup,
        csg_id: u32,
        cs_id: u32,
    ) -> Result {
        let cs = csg.cs_mut(cs_id as usize).ok_or(EINVAL)?;
        let output = cs.read_output()?;

        let heap_address = output.heap_address;
        let vt_start = output.heap_vt_start;
        let vt_end = output.heap_vt_end;
        let frag_end = output.heap_frag_end;

        let _renderpasses_in_flight = vt_start.wrapping_sub(frag_end);
        let _pending_frag_count = vt_end.wrapping_sub(frag_end);

        pr_info!(
            "Tiler OOM: heap_addr={:#x}, vt_start={}, vt_end={}, frag_end={}\n",
            heap_address,
            vt_start,
            vt_end,
            frag_end
        );

        let slot = self.csg_slots[csg_id as usize].as_ref().ok_or(EINVAL)?;
        let _vm = slot.group.vm.clone();

        unimplemented!("We can't get the heap pool from the VM yet");

        // let new_chunk_va = 0u64; // <this needs to come from grow_heap_context()

        // let mut input = cs.read_input()?;
        // input.heap_start = new_chunk_va;
        // input.heap_end = new_chunk_va;
        // cs.write_input(input)?;

        // let req = cs.input_request()?;
        // req.update_reqs(output.ack, cs::constants::CS_TILER_OOM)?;

        // let doorbell = csg.doorbell_request()?;
        // doorbell.toggle_reqs(1 << cs_id)?;

        // Ok(())
    }

    pub(crate) fn process_events(&mut self, data: Arc<TyrData>) -> Result {
        let fw = &data.fw;
        let mut events = data
            .fw_events
            .swap(0, core::sync::atomic::Ordering::Acquire);

        fw.with_locked_global_iface(|glb| {
            if events & JOB_IRQ_GLOBAL_IF != 0 {
                self.process_global_irq(&data, glb)?;
                events &= !JOB_IRQ_GLOBAL_IF;
            }

            while events != 0 {
                let csg_id = events.trailing_zeros();
                let mask = 1u32 << csg_id;

                self.process_csg_irq(data.clone(), glb, csg_id)?;
                events &= !mask;
            }

            Ok(())
        })
    }

    fn process_global_irq(&mut self, data: &Arc<TyrData>, glb: &mut GlobalInterface) -> Result {
        let input = glb.read_input()?;
        let output = glb.read_output()?;

        let evts = (input.req ^ output.ack) & GLB_EVT_MASK;

        if evts == 0 {
            return Ok(());
        }

        if evts & GLB_IDLE != 0 {
            let req = glb.input_request()?;
            req.update_reqs(output.ack, GLB_IDLE)?;
            data.schedule_tick();
        }

        Ok(())
    }

    pub(crate) fn process_csg_irq(
        &mut self,
        data: Arc<TyrData>,
        glb: &mut GlobalInterface,
        csg_id: u32,
    ) -> Result {
        let csg = glb.csg_mut(csg_id as usize).ok_or(EINVAL)?;

        let input = csg.read_input()?;
        let output = csg.read_output()?;

        // // We may have no pending CSG/CS interrupts to process.
        if input.req == output.ack && output.irq_req == input.irq_ack {
            return Ok(());
        }

        let csg_events = (input.req ^ output.ack) & CSG_EVT_MASK;
        let mut cs_irqs = output.irq_req ^ input.irq_ack;

        // Immediately set IRQ_ACK bits to be same as the IRQ_REQ bits before
        // examining the CS_ACK & CS_REQ bits. This would ensure that Host
        // doesn't miss an interrupt for the CS in the race scenario where
        // whilst Host is servicing an interrupt for the CS, firmware sends
        // another interrupt for that CS.
        csg.interrupt_ack()?.write_req(output.irq_req)?;

        let req = csg.input_request()?;
        req.update_reqs(
            output.ack,
            CSG_SYNC_UPDATE | CSG_IDLE | CSG_PROGRESS_TIMER_EVENT,
        )?;

        let mut needs_tick = false;

        if csg_events & CSG_IDLE != 0 {
            self.might_have_idle_groups = true;
            needs_tick = true;
        }

        if csg_events & CSG_PROGRESS_TIMER_EVENT != 0 {
            pr_warn!("sched: CSG slot {} progress timeout\n", csg_id);

            if let Some(slot) = &mut self.csg_slots[csg_id as usize] {
                let _ = slot.group.with_locked_inner(|inner| {
                    inner.fatal_error = Some(ETIMEDOUT);
                    Ok(())
                });
            }

            needs_tick = true;
        }

        if needs_tick {
            data.schedule_tick();
        }

        let mut ring_cs_db_mask = 0;

        while cs_irqs != 0 {
            let cs_id = cs_irqs.trailing_zeros();
            let mask = 1u32 << cs_id;

            let processed = self.process_cs_irq(&data, csg, csg_id, cs_id)?;
            if processed {
                ring_cs_db_mask |= mask;
            }

            cs_irqs &= !mask;
        }

        if csg_events & CSG_SYNC_UPDATE != 0 {
            if let Some(slot) = &mut self.csg_slots[csg_id as usize] {
                slot.group.schedule_sync_upd();
            }

            data.schedule_sync_upd();
        }

        if ring_cs_db_mask != 0 {
            csg.doorbell_request()?.toggle_reqs(ring_cs_db_mask)?;
        }

        glb.ring_csg_doorbell(csg_id as usize)
    }

    fn process_cs_irq(
        &mut self,
        data: &Arc<TyrData>,
        csg: &mut CommandStreamGroup,
        csg_id: u32,
        cs_id: u32,
    ) -> Result<bool> {
        let cs = csg.cs_mut(cs_id as usize).ok_or(EINVAL)?;

        let input = cs.read_input()?;
        let output = cs.read_output()?;

        let cs_events = (input.req ^ output.ack) & CS_EVT_MASK;

        if cs_events & CS_FATAL != 0 {
            cs.decode_fatal()?;

            if let Some(slot) = &mut self.csg_slots[csg_id as usize] {
                slot.group.with_locked_inner(|inner| {
                    inner.set_queue_fatal(cs_id as usize);
                    Ok(())
                })?;
            }

            if output.cs_fatal_exception_type() == CS_UNRECOVERABLE {
                // If this exception is unrecoverable, queue a reset, and make
                // sure we stop scheduling groups until the reset has happened.
                // TODO: schedule a reset and cancel tick work.
            } else {
                data.schedule_tick();
            }
        }

        if cs_events & CS_FAULT != 0 {
            cs.decode_fault()?;

            if output.cs_fault_exception_type() == CS_INHERIT_FAULT {
                if let Some(slot) = &mut self.csg_slots[csg_id as usize] {
                    let _ = slot.group.with_locked_inner(|inner| {
                        let queue = &mut inner.queues[cs_id as usize];

                        if let Ok(ringbuf_output) = queue.interfaces.read_output() {
                            let cs_extract = ringbuf_output.extract;

                            for pending in queue
                                .pending_submit_fences
                                .iter()
                                .skip(queue.pending_submit_fences_head)
                            {
                                if cs_extract >= pending.ringbuf_end {
                                    continue;
                                }
                                if cs_extract < pending.ringbuf_start {
                                    break;
                                }
                                if let Some(fence) = &pending.fence {
                                    fence.set_error(EINVAL);
                                }
                            }
                        }
                        Ok(())
                    });
                }
            }
        }

        if cs_events & CS_TILER_OOM != 0 {
            self.process_tiler_oom(csg, csg_id, cs_id)?;
        }

        let req = csg.cs_mut(cs_id as usize).ok_or(EINVAL)?.input_request()?;
        req.update_reqs(output.ack, CS_FATAL | CS_FAULT)?;

        let ring_db = cs_events & (CS_FAULT | CS_TILER_OOM) != 0;
        Ok(ring_db)
    }

    pub(crate) fn schedule_group(&mut self, data: &Arc<TyrData>, priority: Option<Priority>) {
        if priority == Some(Priority::RealTime) || self.might_have_idle_groups {
            data.schedule_tick();
            return;
        }

        if self.resched_target.is_some() {
            if self.used_csg_slot_count < self.csg_slot_count {
                data.schedule_tick();
            }
            return;
        }

        let now = Instant::<Monotonic>::now();
        let target = self.last_tick + Delta::from_millis(super::TICK_PERIOD_MS as i64);
        self.resched_target = Some(target);

        let delay_jiffies =
            if self.used_csg_slot_count == self.csg_slot_count && (target - now).as_nanos() > 0 {
                msecs_to_jiffies((target - now).as_millis() as _)
            } else {
                0
            };

        if delay_jiffies > 0 {
            data.schedule_periodic_tick(delay_jiffies as _);
        } else {
            data.schedule_tick();
        }
    }

    pub(crate) fn sync_csg_slot_priority(
        &mut self,
        glb_iface: &mut GlobalInterface,
        csg_idx: usize,
    ) -> Result {
        if let Some(slot) = self.csg_slots[csg_idx].as_mut() {
            let csg = glb_iface.csg(csg_idx).ok_or(EINVAL)?;
            let input = csg.read_input()?;
            slot.fw_priority =
                Some((input.csg_ep_req & CSG_EP_REQ_PRIORITY_MASK) >> CSG_EP_REQ_PRIORITY_SHIFT);
        }
        Ok(())
    }

    pub(crate) fn sync_csg_slot_state(
        &mut self,
        glb_iface: &mut GlobalInterface,
        csg_idx: usize,
    ) -> Result {
        let group = self.csg_slots[csg_idx]
            .as_ref()
            .ok_or(EINVAL)?
            .group
            .clone();

        let old_state = group.state();

        let csg = glb_iface.csg(csg_idx).ok_or(EINVAL)?;
        let output = csg.read_output()?;

        let new_state = match GroupState::try_from(output.ack) {
            Ok(GroupState::Start) => State::Active,
            Ok(GroupState::Resume) => State::Active,
            Ok(GroupState::Terminate) => State::Terminated,
            Ok(GroupState::Suspend) => State::Suspended,
            _ => State::Unknown,
        };

        if old_state == new_state {
            return Ok(());
        }

        if new_state == State::Unknown {
            let _ = group.with_locked_inner(|inner| {
                inner.fatal_error = Some(EINVAL);
                Ok(())
            });
            // TODO: schedule reset
        }
        if new_state == State::Suspended {
            self.sync_csg_slot_queues_state(glb_iface, csg_idx)?;
        }

        if old_state == State::Active {
            if let Some(csg) = glb_iface.csg_mut(csg_idx) {
                // Reset the queue slots so we start from a clean
                // state when starting/resuming a new group on this
                // CSG slot. No wait needed here, and no ringbell
                // either, since the CS slot will only be re-used
                // on the next CSG start operation.
                let mut i = 0;
                while let Some(cs) = csg.cs_mut(i) {
                    let _ = cs.set_state(StreamState::Stop);
                    i += 1;
                }
            }
        }

        group.set_state(new_state);
        Ok(())
    }

    pub(crate) fn sync_group_states(&mut self, data: &Arc<TyrData>) -> Result {
        let mut context = CsgUpdateContext::new();

        // Request the current state of all bound groups.
        for csg_idx in 0..self.csg_slot_count as usize {
            let unhandled_fault = if let Some(slot) = &self.csg_slots[csg_idx] {
                slot.group.vm.lock().unhandled_fault
            } else {
                false
            };

            // If there was unhandled faults on the VM, force processing of CSG IRQs, so
            // we can flag the faulty queue.
            if unhandled_fault {
                data.fw.with_locked_global_iface(|glb_iface| {
                    self.process_csg_irq(data.clone(), glb_iface, csg_idx as u32)
                })?;

                if let Some(slot) = &self.csg_slots[csg_idx] {
                    slot.group.with_locked_inner(|inner| {
                        // No fatal fault reported, flag all queues as faulty.
                        if !inner.has_fatal_queues() {
                            let len = inner.queues.len() as u32;
                            for i in 0..len {
                                inner.set_queue_fatal(i as usize);
                            }
                        }
                        Ok(())
                    })?;
                }
            }

            if self.csg_slots[csg_idx].is_some() {
                context.toggle_reqs(csg_idx, CSG_STATUS_UPDATE);
            }
        }

        // Apply the request and wait for the firmware's response.
        self.apply_csg_updates(data, &mut context)?;

        Ok(())
    }

    pub(crate) fn sync_csg_slot_queues_state(
        &mut self,
        glb_iface: &mut GlobalInterface,
        csg_idx: usize,
    ) -> Result {
        let group = self.csg_slots[csg_idx]
            .as_ref()
            .ok_or(EINVAL)?
            .group
            .clone();
        let priority = group.priority as usize;

        let csg = glb_iface.csg(csg_idx).ok_or(EINVAL)?;
        let output = csg.read_output()?;

        let wait_arc_opt = group.with_locked_inner(|inner| {
            inner.idle = output.is_idle();
            let mut has_sync_wait = false;

            for cs_id in 0..inner.queues.len() {
                let mut idle = false;
                let mut blocked = false;

                if let Some(cs) = csg.cs(cs_id) {
                    let cs_out = cs.read_output()?;
                    let blocked_reason = cs_out.blocked_reason()?;

                    match blocked_reason {
                        BlockedReason::Unblocked => {
                            let mut empty = false;
                            if let Some(queue) = inner.queues.get_mut(cs_id) {
                                if let (Ok(input), Ok(output)) = (
                                    queue.interfaces.read_input(),
                                    queue.interfaces.read_output(),
                                ) {
                                    empty = input.insert == output.extract;
                                }
                            }
                            // Checked through scoreboard
                            if empty && cs_out.status_scoreboards == 0 {
                                idle = true;
                            }
                        }
                        BlockedReason::SyncWait => {
                            has_sync_wait = true;
                            let status_wait = cs_out.status_wait()?;

                            let mut ref_val = cs_out.status_wait_sync_value as u64;
                            if status_wait.sync64 {
                                ref_val |= (cs_out.status_wait_sync_value_hi as u64) << 32;
                            }

                            let syncwait = queue::SyncWait {
                                gpu_va: cs_out.status_wait_sync_ptr,
                                ref_val,
                                sync64: status_wait.sync64,
                                gt: status_wait.gt,
                            };

                            if let Some(queue) = inner.queues.get_mut(cs_id) {
                                queue.syncwait = syncwait;
                            }

                            // Only blocked if there's no deferred operation pending
                            if cs_out.status_scoreboards == 0 {
                                blocked = true;
                            }
                        }
                        _ => {
                            // Other reasons are not blocking. Consider the queue as
                            // runnable in those cases.
                        }
                    }
                }

                inner.set_queue_idle(cs_id, idle);
                inner.set_queue_blocked(cs_id, blocked);
            }

            if has_sync_wait {
                if let Ok(wait_arc) = ListArc::<Group, 1>::try_from_arc(group.clone()) {
                    return Ok(Some(wait_arc));
                }
            }

            Ok(None)
        })?;

        if let Some(wait_arc) = wait_arc_opt {
            self.waiting_groups[priority].push_back(wait_arc);
        }

        Ok(())
    }
}

impl_has_dma_fence_work! {
    impl HasDmaFenceWork<Self, 2> for TyrData {
        self.fw_events_work
    }
}

impl DmaFenceWorkItem<2> for TyrData {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        let _ = this.with_locked_scheduler(|sched| {
            sched.process_events(this.clone()).inspect_err(|e| {
                pr_err!("Failed to process firmware events: {}", e.to_errno());
            })
        });
    }
}

impl_has_dma_fence_work! {
    impl HasDmaFenceWork<Self, 3> for TyrData {
        self.sync_upd_work
    }
}

impl DmaFenceWorkItem<3> for TyrData {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        let _ = this.with_locked_scheduler(|sched| {
            let mut immediate_tick = false;

            for prio in 0..Priority::num_priorities() {
                // Collect groups that need to be made runnable to avoid borrowing `sched`
                // mutably while iterating over `sched.waiting_groups`.
                let mut make_runnable = kernel::list::List::<Group, 1>::new();

                {
                    let mut cursor = sched.waiting_groups[prio].cursor_front();
                    while let Some(peek) = cursor.peek_next() {
                        let group: Arc<Group> = peek.arc().into();

                        let mut tested_queues = group
                            .with_locked_inner(|inner| Ok(inner.blocked_queues()))
                            .unwrap_or(0);
                        let mut unblocked_queues = 0;

                        while tested_queues != 0 {
                            let cs_id = tested_queues.trailing_zeros();

                            match group.eval_syncwait(cs_id as usize) {
                                Ok(true) => {
                                    unblocked_queues |= 1 << cs_id;
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    pr_err!("eval_syncwait failed: {}", e.to_errno());
                                    unblocked_queues |= 1 << cs_id;
                                }
                            }

                            tested_queues &= !(1 << cs_id);
                        }

                        let action = group
                            .with_locked_inner(|inner| {
                                if unblocked_queues != 0 {
                                    for i in 0..inner.queues.len() {
                                        if (unblocked_queues & (1 << i)) != 0 {
                                            inner.set_queue_blocked(i, false);
                                            inner.sync_queue_state(i);
                                        }
                                    }

                                    if inner.csg_id.is_none() {
                                        return Ok(Some((!inner.has_blocked_queues(), true)));
                                    }
                                }

                                Ok(Some((!inner.has_blocked_queues(), false)))
                            })
                            .unwrap_or(None);

                        if let Some((unblocked, move_to_runnable)) = action {
                            if unblocked {
                                let list_arc = peek.remove();

                                if move_to_runnable {
                                    make_runnable.push_back(list_arc);

                                    if prio == Priority::RealTime as usize {
                                        immediate_tick = true;
                                    }
                                }
                            } else {
                                cursor.move_next();
                            }
                        } else {
                            cursor.move_next();
                        }
                    }
                }

                // Now we can mutate `sched` safely
                while let Some(list_arc) = make_runnable.pop_front() {
                    let group = list_arc.into_arc();
                    sched.mark_group_runnable(&group);
                }
            }

            if immediate_tick {
                this.schedule_tick();
            }

            Ok(())
        });
    }
}
