// SPDX-License-Identifier: GPL-2.0 or MIT
//! Firmware event processing.
//!
//! The firmware events are used to notify the driver of the overall progress of
//! the work currently submitted, as well as other scheduler-related events,
//! like device idleness, CSG/CS interrupts, fault decoding and etc.

use core::ops::Deref;

use kernel::dma_fence::DmaFenceSignallingAnnotation;
use kernel::dma_fence::DmaFenceWorkItem;
use kernel::impl_has_dma_fence_work;
use kernel::prelude::*;
use kernel::sync::Arc;

use crate::driver::TyrData;
use crate::driver::TyrDevice;
use crate::fw::global::cs;
use crate::fw::global::csg;
use crate::fw::global::csg::CommandStreamGroup;
use crate::fw::global::GlobalInterface;
use crate::fw::SharedSectionEntry;
use crate::regs::JOB_IRQ_GLOBAL_IF;
use crate::sched::csg::GroupState;
use crate::sched::group::State;
use crate::sched::Scheduler;

use super::group::Group;
use super::syncs;

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
        // TODO: we need to annotate this function with the dma signalling token.

        let fw = &data.fw;
        let mut events = self.events.take().unwrap_or_default();

        if events & JOB_IRQ_GLOBAL_IF != 0 {
            // We don't support global events yet.
            events &= !JOB_IRQ_GLOBAL_IF;
        }

        fw.with_locked_global_iface(|glb| {
            while events != 0 {
                let csg_id = events.trailing_zeros();
                let mask = kernel::bits::bit_u32(csg_id);

                self.process_csg_irq(data.clone(), glb, csg_id)?;
                events &= !mask;
            }

            Ok(())
        })?;

        Ok(())
    }

    fn process_csg_irq(
        &mut self,
        data: Arc<TyrData>,
        glb: &mut GlobalInterface,
        csg_id: u32,
    ) -> Result {
        // TODO: we need to annotate this function with the dma signalling token.

        let csg = glb.csg_mut(csg_id as usize).ok_or(EINVAL)?;

        let mut input = csg.read_input()?;
        let output = csg.read_output()?;

        let csg_events = (input.req ^ output.ack) & csg::constants::CSG_EVT_MASK;

        // // We may have no pending CSG/CS interrupts to process.
        if input.req == output.ack && output.irq_req == input.irq_ack {
            return Ok(());
        }

        let mut cs_irqs = output.irq_req ^ input.irq_ack;

        // Immediately set IRQ_ACK bits to be same as the IRQ_REQ bits before
        // examining the CS_ACK & CS_REQ bits. This would ensure that Host
        // doesn't miss an interrupt for the CS in the race scenario where
        // whilst Host is servicing an interrupt for the CS, firmware sends
        // another interrupt for that CS.
        input.irq_ack = output.irq_req;
        csg.write_input(input)?;

        let req = csg.input_request()?;
        let reenable_mask = csg::constants::CSG_SYNC_UPDATE;

        req.update_reqs(csg.read_output()?.ack, reenable_mask)?;
        let mut ring_cs_db_mask = 0;

        while cs_irqs != 0 {
            let cs_id = cs_irqs.trailing_zeros();
            let mask = kernel::bits::bit_u32(cs_id);

            let processed = self.process_cs_irq(csg, csg_id, cs_id)?;

            if processed {
                ring_cs_db_mask |= mask;
            }

            cs_irqs &= !mask;
        }

        if ring_cs_db_mask != 0 {
            let req = csg.doorbell_request()?;
            req.toggle_reqs(ring_cs_db_mask)?;
        }

        if csg_events & csg::constants::CSG_SYNC_UPDATE != 0 {
            let group = self.csg_slots[csg_id as usize]
                .as_mut()
                .ok_or(EINVAL)?
                .group
                .clone();

            self.unsynced_groups.push(group, GFP_KERNEL)?;

            let _ = self.wq.enqueue::<_, 3>(data.clone());
        }

        glb.ring_csg_doorbell(csg_id as usize)
    }

    fn process_cs_irq(
        &mut self,
        csg: &mut CommandStreamGroup,
        csg_id: u32,
        cs_id: u32,
    ) -> Result<bool> {
        let cs = csg.cs_mut(cs_id as usize).ok_or(EINVAL)?;

        let input = cs.read_input()?;
        let output = cs.read_output()?;

        let cs_events = (input.req ^ output.ack) & cs::constants::CS_EVT_MASK;

        let faulty =
            cs_events & cs::constants::CS_FATAL != 0 || cs_events & cs::constants::CS_FAULT != 0;

        if cs_events & cs::constants::CS_FATAL != 0 {
            cs.decode_fatal()?;
            if let Some(slot) = &mut self.csg_slots[csg_id as usize] {
                slot.group.with_locked_inner(|inner| {
                    inner.fatal_queues |= 1 << cs_id;
                    Ok(())
                })?;
            }
        }

        if cs_events & cs::constants::CS_FAULT != 0 {
            cs.decode_fault()?;
        }

        if cs_events & cs::constants::CS_TILER_OOM != 0 {
            self.process_tiler_oom(csg, csg_id, cs_id)?;
        }

        if faulty {
            // TODO: we cannot sleep in the signalling path.
            self.csg_slots[csg_id as usize]
                .as_mut()
                .ok_or(EINVAL)?
                .group
                .with_locked_inner(|inner| {
                    let queue = &mut inner.queues[cs_id as usize];

                    // Signal all in-flight submit fences as failed.
                    {
                        let _ann = DmaFenceSignallingAnnotation::new();
                        queue.signal_submit_fences_up_to(u64::MAX, Err(EINVAL));
                    }

                    // Let's also mark this group as destroyed just so we don't
                    // take anymore work. We will come back to this when the
                    // driver is more developed.
                    inner.destroyed = true;
                    Ok(())
                })?;
        }

        let ring_db = cs_events & cs::constants::CS_FAULT != 0;
        Ok(ring_db)
    }

    pub(crate) fn set_events(&mut self, tdev: &TyrDevice, events: u32) {
        let old_events = self.events.unwrap_or_default();
        self.events = Some(events | old_events);

        let _ = self.wq.enqueue::<_, 2>(tdev.deref().clone());
    }

    fn update_group(&mut self, group: Arc<Group>, _data: &Arc<TyrData>) -> Result {
        // TODO: we cannot sleep in the signalling path.
        group.with_locked_inner(|inner| {
            for (queue_idx, queue) in inner.queues.iter_mut().enumerate() {
                let sync_offset = queue_idx * core::mem::size_of::<syncs::SyncObj64b>();
                let sync_obj = syncs::SyncObj64b::read(&mut inner.syncobjs, sync_offset)?;

                {
                    let _ann = DmaFenceSignallingAnnotation::new();
                    queue.signal_submit_fences_up_to(sync_obj.seqno, Ok(()));
                }
            }
            Ok(())
        })?;

        Ok(())
    }

    #[allow(dead_code)]
    fn mark_group_idle(
        &mut self,
        _group: Arc<Group>,
        data: &Arc<TyrData>,
        csg_id: Option<usize>,
    ) -> Result {
        // data.with_locked_mmu(|mmu| mmu.unbind_vm(&group.vm, &data.iomem))?;
        // self.idle_groups[group.priority as usize].push(group, GFP_KERNEL)?;
        if let Some(csg_idx) = csg_id {
            if let Some(slot) = &mut self.csg_slots[csg_idx] {
                slot.idle = true;
            } else {
                pr_warn!("Cannot mark empty slot {} idle\n", csg_idx);
            }
        }

        if let None = &self.resched_target {
            self.resched_target = Some(kernel::time::Instant::now());
            let arc: Arc<TyrData> = data.clone();
            let _ = self.wq.enqueue::<_, 1>(arc);
        }
        Ok(())
    }

    /// update group at `csg_idx` as it changes from `old_state` to `new_state`.
    fn handle_state_change(
        &mut self,
        new_state: State,
        old_state: State,
        data: &Arc<TyrData>,
        glb_iface: &mut GlobalInterface,
        csg_idx: usize,
    ) -> Result {
        self.process_csg_irq(data.clone(), glb_iface, csg_idx as _)?;
        self.csg_slots[csg_idx]
            .as_ref()
            .ok_or(EINVAL)?
            .group
            .with_locked_inner(|inner| {
                if new_state == State::Unknown {
                    //TODO: schedule reset
                }
                if new_state == State::Suspended {
                    // TODO: handle reg `status_blocked_reason` here
                }
                if old_state == State::Active {
                    let csg_iface = glb_iface.csg_mut(csg_idx).ok_or(EINVAL)?;
                    for (cs_idx, _) in inner.queues.iter_mut().enumerate() {
                        let cs_iface = csg_iface.cs_mut(cs_idx).ok_or(EINVAL)?;
                        pr_info!("Stopping cs id {}\n", cs_idx);
                        cs_iface.set_state(crate::sched::StreamState::Stop)?;
                    }
                }
                Ok(())
            })
    }

    /// inform the firmware of the changes of the group at `csg_idx` and update the group
    /// based on the response.
    pub(crate) fn sync_group_state(&mut self, data: &Arc<TyrData>, csg_idx: usize) -> Result {
        if csg_idx >= self.csg_slot_count as usize {
            pr_err!("sync_group: invalid group index {}", csg_idx);
            return Err(EINVAL);
        }
        if self.csg_slots[csg_idx].is_none() {
            pr_err!("sync_group: group slot is empty");
            return Err(EINVAL);
        }

        let slot = self.csg_slots[csg_idx].as_ref().ok_or(EINVAL)?;
        let is_idle = self.csg_slots[csg_idx].as_ref().ok_or(EINVAL)?.idle;
        let (old_state, can_run) = slot.group.with_locked_inner(|inner| {
            Ok((inner.state, {
                inner.state != State::Terminated
                    && inner.state != State::Unknown
                    && inner.destroyed == false
                    && inner.fatal_queues == 0
            }))
        })?;

        let update = if is_idle {
            if can_run {
                GroupState::Suspend
            } else {
                GroupState::Terminate
            }
        } else {
            if old_state == State::Suspended {
                GroupState::Resume
            } else {
                GroupState::Start
            }
        };

        let fw = &data.fw;
        fw.with_locked_global_iface(|glb_iface| {
            pr_info!(
                "Syncing group at csg_idx {}: {:?} -> {:?}\n",
                csg_idx,
                old_state,
                update
            );
            glb_iface.set_csg_state(csg_idx, update)?;
            glb_iface.ring_csg_doorbell(csg_idx)?;
            let output = glb_iface.read_output()?;
            let ack = output.ack;

            let new_state = match GroupState::try_from(ack) {
                Ok(GroupState::Start) => State::Active,
                Ok(GroupState::Resume) => State::Active,
                Ok(GroupState::Terminate) => State::Terminated,
                Ok(GroupState::Suspend) => State::Suspended,
                _ => State::Unknown,
            };
            if old_state == new_state {
                return Ok(());
            }
            self.handle_state_change(new_state, old_state, data, glb_iface, csg_idx)
        })?;

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
        self.group_upd_work
    }
}

impl DmaFenceWorkItem<3> for TyrData {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        let _ = this.with_locked_scheduler(|sched| {
            while let Some(group) = sched.unsynced_groups.pop() {
                sched.update_group(group, &this).inspect_err(|e| {
                    pr_err!("Failed to process firmware events: {}", e.to_errno());
                })?;
            }

            Ok(())
        });
    }
}
