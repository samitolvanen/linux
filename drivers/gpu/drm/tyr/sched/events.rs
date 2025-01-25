// SPDX-License-Identifier: GPL-2.0 or MIT
//! Firmware event processing.
//!
//! The firmware events are used to notify the driver of the overall progress of
//! the work currently submitted, as well as other scheduler-related events,
//! like device idleness, CSG/CS interrupts, fault decoding and etc.

use core::ops::Deref;

use kernel::dma_fence::FenceOps;
use kernel::dma_fence::RawDmaFence;
use kernel::impl_has_work;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::workqueue::WorkItem;

use crate::driver::TyrData;
use crate::driver::TyrDevice;
use crate::fw::global::cs;
use crate::fw::global::csg;
use crate::fw::global::csg::CommandStreamGroup;
use crate::fw::global::GlobalInterface;
use crate::fw::SharedSectionEntry;
use crate::regs::JOB_INT_GLOBAL_IF;
use crate::sched::Scheduler;

use super::group::Group;
use super::syncs;

impl Scheduler {
    pub(crate) fn process_events(&mut self, data: Arc<TyrData>) -> Result {
        // TODO: we need to annotate this function with the dma signalling token.

        let fw = &data.fw;
        let mut events = self.events.take().unwrap_or_default();

        if events & JOB_INT_GLOBAL_IF != 0 {
            // We don't support global events yet.
            events &= !JOB_INT_GLOBAL_IF;
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
            let req = csg.doobell_request()?;
            req.toggle_reqs(ring_cs_db_mask)?;
        }

        if csg_events & csg::constants::CSG_SYNC_UPDATE != 0 {
            let group = self.csg_slots[csg_id as usize]
                .as_mut()
                .ok_or(EINVAL)?
                .group
                .clone();

            self.unsynced_groups.push(group, GFP_KERNEL)?;

            if self.wq.enqueue::<_, 3>(data.clone()).is_err() {
                pr_err!("Failed to enqueue the group update work\n");
            }
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

        if faulty {
            // TODO: we cannot sleep in the signalling path.
            self.csg_slots[csg_id as usize]
                .as_mut()
                .ok_or(EINVAL)?
                .group
                .with_locked_inner(|inner| {
                    for job_fence in &inner.queues[cs_id as usize].in_flight_jobs {
                        // Just mark everything in flight as failed.
                        //
                        // This is not exactly the right thing to do, but while
                        // the driver is being developed, this will let us at
                        // least signal all fences, even if we have errored out.
                        //
                        // Also, there is no error recovery for now. If we have
                        // failed, we just want to stop everything and further
                        // debug the driver code.
                        job_fence.set_error(EINVAL);
                        job_fence.signal()?;
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
        self.events = Some(events);

        if self.wq.enqueue::<_, 2>(tdev.deref().clone()).is_err() {
            pr_err!("Failed to enqueue firmware events work\n");
        }
    }

    fn update_group(&mut self, group: &Group) -> Result {
        // TODO: we need to annotate this function with the dma signalling token.
        // TODO: we cannot sleep in the signalling path.
        group.with_locked_inner(|inner| {
            for (queue_idx, queue) in inner.queues.iter_mut().enumerate() {
                let sync_offset = queue_idx * core::mem::size_of::<syncs::SyncObj64b>();
                let sync_obj = syncs::SyncObj64b::read(&mut inner.syncobjs, sync_offset)?;

                // TODO: this has to be moved somewhere else. It should probably
                // be in TyrData, or anywhere else we can easily access from
                // here. It should also be protected by a SpinLock instead,
                // because we cannot sleep in the signalling path.
                for job_fence in &queue.in_flight_jobs {
                    // We have executed everything up until this point.
                    if sync_obj.seqno < job_fence.seqno() {
                        break;
                    }

                    // Add this debug aid for a while. It will be important
                    // while we develop the driver.
                    pr_info!("Signalling fence: {}\n", job_fence.seqno());

                    job_fence.signal()?;
                }

                // Ok: this does not allocate, so it is ok to use in the signalling path.
                queue.in_flight_jobs.retain(|fence| !fence.signaled());
            }

            Ok(())
        })?;

        Ok(())
    }
}

impl_has_work! {
    impl HasWork<Self, 2> for TyrData {
        self.fw_events_work
    }
}

impl WorkItem<2> for TyrData {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        let _ = this.with_locked_scheduler(|sched| {
            sched.process_events(this.clone()).inspect_err(|e| {
                pr_err!("Failed to process firmware events: {}", e.to_errno());
            })
        });
    }
}

impl_has_work! {
    impl HasWork<Self, 3> for TyrData {
        self.group_upd_work
    }
}

impl WorkItem<3> for TyrData {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        let _ = this.with_locked_scheduler(|sched| {
            while let Some(group) = sched.unsynced_groups.pop() {
                sched.update_group(&group).inspect_err(|e| {
                    pr_err!("Failed to process firmware events: {}", e.to_errno());
                })?;
            }

            Ok(())
        });
    }
}
