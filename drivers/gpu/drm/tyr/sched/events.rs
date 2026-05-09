// SPDX-License-Identifier: GPL-2.0 or MIT

//! Deferred scheduler event handling.
//!
//! This keeps the TILER_OOM path out of threaded IRQ context: the IRQ side only
//! records pending CS bits, while the work item grows heaps and writes the
//! firmware acknowledgements back once allocation can sleep.

use core::sync::atomic::Ordering;

use kernel::{
    alloc::KVec,
    prelude::*,
    sync::{aref::ARef, Arc},
    workqueue::WorkItem,
};

use crate::{
    driver::{
        work_id,
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    fw::{
        CsFaultExceptionType,
        CSG_REQ, //
    },
    heap,
};

use super::{group::Group, Scheduler};

struct PendingOom {
    group: Arc<Group>,
    csg_id: usize,
    cs_id: u32,
    saved_tiler_oom_ack: bool,
    heap_address: u64,
    vt_start: u32,
    vt_end: u32,
    frag_end: u32,
}

kernel::impl_has_work! {
    impl HasWork<TyrDrmDevice, { work_id::TILER_OOM }> for TyrDrmDeviceData { self.tiler_oom_work }
}

impl WorkItem<{ work_id::TILER_OOM }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    fn run(this: Self::Pointer) {
        let tdev = &*this;

        let pending = tdev.with_locked_scheduler(|sched| sched.collect_pending_tiler_ooms(tdev));

        let pending = match pending {
            Ok(pending) => pending,
            Err(err) => {
                pr_err!("tiler_oom_work: failed to collect OOM events: {:?}\n", err);
                return;
            }
        };

        let mut chunk_vas = KVec::new();
        for oom in pending.iter() {
            let chunk_va = oom
                .group
                .get_heap_pool()
                .ok_or(EINVAL)
                .and_then(|pool| {
                    pool.grow_heap_context(
                        tdev,
                        heap::ContextGrowArgs {
                            heap_gpu_va: oom.heap_address,
                            renderpasses_in_flight: oom.vt_start.wrapping_sub(oom.frag_end),
                            pending_frag_count: oom.vt_end.wrapping_sub(oom.frag_end),
                        },
                    )
                })
                .unwrap_or(0);

            if chunk_vas.push(chunk_va, GFP_KERNEL).is_err() {
                pr_err!("tiler_oom_work: failed to store chunk VA\n");
                return;
            }
        }

        let _ = tdev
            .with_locked_scheduler(|sched| {
                sched.finish_pending_tiler_ooms(tdev, &pending, &chunk_vas)
            })
            .inspect_err(|err| {
                pr_err!(
                    "tiler_oom_work: failed to complete OOM handling: {:?}\n",
                    err
                );
            });
    }
}

impl Scheduler {
    pub(crate) fn process_csg_irqs(
        &mut self,
        mut events: u32,
        tdev: &TyrDrmDevice,
    ) -> Result<bool> {
        let mut queued_tiler_oom = false;

        while events != 0 {
            let csg_id = events.trailing_zeros() as usize;
            let mask = 1u32 << csg_id;

            queued_tiler_oom |= self.process_csg_irq(tdev, csg_id)?;
            events &= !mask;
        }

        Ok(queued_tiler_oom)
    }

    pub(super) fn process_csg_irq(&mut self, tdev: &TyrDrmDevice, csg_id: usize) -> Result<bool> {
        // Take a snapshot of the group binding under the slot-manager
        // lock and drop the lock before calling into the firmware
        // interface. Holding slot-manager across with_csg_mut() would
        // order it ahead of fw.inner, but other paths take fw.inner
        // standalone; introducing that order would risk ABBA.
        let group = {
            let slot_manager = tdev.csg_slot_manager.lock();
            match slot_manager.slot_data(csg_id) {
                Some(data) => data.group.clone(),
                None => return Ok(false),
            }
        };

        let pending_mask =
            CSG_REQ::IDLE_MASK | CSG_REQ::SYNC_UPDATE_MASK | CSG_REQ::PROGRESS_TIMER_EVENT_MASK;

        let (idle_event, sync_event, progress_event) = tdev.fw.with_csg_mut(csg_id, |csg| {
            let req = csg.read_input_req()?.into_raw();
            let ack = csg.read_output_ack()?.into_raw();
            let pending = (req ^ ack) & pending_mask;
            if pending != 0 {
                csg.update_input_req(ack & pending, pending)?;
            }
            Ok((
                pending & CSG_REQ::IDLE_MASK != 0,
                pending & CSG_REQ::SYNC_UPDATE_MASK != 0,
                pending & CSG_REQ::PROGRESS_TIMER_EVENT_MASK != 0,
            ))
        })?;

        if idle_event {
            // Tell the rule engine that at least one resident group may
            // now be idle so it considers the `Take from idle_groups`
            // rules on the next tick. The actual per-queue idle state
            // is refreshed from the firmware in
            // `sync_csg_slot_queues_state` when the tick runs.
            self.might_have_idle_groups = true;
        }
        if progress_event {
            // Progress-timer expiry: the firmware-imposed forward-progress
            // window elapsed without the group advancing.
            group.with_locked_inner(|inner| {
                if inner.fatal_error.is_none() {
                    inner.fatal_error = Some(ETIMEDOUT);
                }
            });
        }
        if sync_event {
            let tdev_aref: ARef<TyrDrmDevice> = tdev.into();
            TyrDrmDeviceData::schedule_sync_upd(&tdev_aref);
        }

        let mut queued_tiler_oom = false;
        let mut cs_fatal_mask: u32 = 0;
        let mut cs_inherit_fault_mask: u32 = 0;
        tdev.fw.with_csg_mut(csg_id, |csg| {
            let irq_req = csg.read_output_irq_req()?.mask();
            let irq_ack = csg.read_input_irq_ack()?;
            let pending_cs_irqs = irq_req ^ irq_ack.mask();

            if pending_cs_irqs == 0 {
                return Ok(());
            }

            csg.write_input_irq_ack(irq_ack.with_mask(irq_req));

            for cs_id in 0u32..32 {
                if pending_cs_irqs & (1u32 << cs_id) == 0 {
                    continue;
                }

                let cs = match csg.cs_mut(cs_id as usize) {
                    Some(cs) => cs,
                    None => continue,
                };
                let input_req = cs.read_input_req()?;
                let output_ack = cs.read_output_ack()?;

                if input_req.tiler_oom() != output_ack.tiler_oom() && output_ack.tiler_oom() {
                    group.tiler_oom.fetch_or(1u32 << cs_id, Ordering::Relaxed);
                    queued_tiler_oom = true;
                }

                let fatal_event = input_req.fatal() != output_ack.fatal() && output_ack.fatal();
                let fault_event = input_req.fault() != output_ack.fault() && output_ack.fault();

                if fatal_event {
                    let _ = cs.decode_fatal(csg_id, cs_id)?;
                    cs_fatal_mask |= 1u32 << cs_id;
                }

                if fault_event {
                    if cs.decode_fault(csg_id, cs_id)?
                        == CsFaultExceptionType::CsInheritFault as u32
                    {
                        cs_inherit_fault_mask |= 1u32 << cs_id;
                    }
                }

                if fatal_event || fault_event {
                    let new_req = input_req
                        .with_fatal(output_ack.fatal())
                        .with_fault(output_ack.fault());
                    cs.write_input_req(new_req);
                }
            }

            Ok(())
        })?;

        if cs_fatal_mask != 0 {
            group.with_locked_inner(|inner| {
                let mut mask = cs_fatal_mask;
                while mask != 0 {
                    let cs_id = mask.trailing_zeros() as usize;
                    mask &= !(1u32 << cs_id);
                    inner.set_queue_fatal(cs_id);
                }
            });
        }

        let mut mask = cs_inherit_fault_mask;
        while mask != 0 {
            let cs_id = mask.trailing_zeros() as usize;
            mask &= !(1u32 << cs_id);
            if let Some(queue) = group.queues.get(cs_id) {
                queue.fail_inflight_submit_fences(EINVAL)?;
            }
        }

        if cs_fatal_mask != 0 {
            let tdev_aref: ARef<TyrDrmDevice> = tdev.into();
            TyrDrmDeviceData::schedule_tick(&tdev_aref);
        }

        Ok(queued_tiler_oom)
    }

    fn collect_pending_tiler_ooms(&mut self, tdev: &TyrDrmDevice) -> Result<KVec<PendingOom>> {
        let mut pending = KVec::new();

        // Snapshot the (csg_id, group) pairs that have a pending
        // tiler-OOM bit set, then drop the slot-manager lock before
        // we read the per-CS OOM state from the firmware. Holding
        // slot-manager across with_csg_mut() would order it ahead of
        // fw.inner, but other paths take fw.inner standalone;
        // introducing that order would risk ABBA.
        let mut to_visit: KVec<(usize, Arc<Group>, u32)> = KVec::new();
        {
            let slot_manager = tdev.csg_slot_manager.lock();
            for csg_id in 0..super::MAX_CSGS {
                let data = match slot_manager.slot_data(csg_id) {
                    Some(data) => data,
                    None => continue,
                };

                let oom_mask = data.group.tiler_oom.swap(0, Ordering::Relaxed);
                if oom_mask == 0 {
                    continue;
                }

                to_visit.push((csg_id, data.group.clone(), oom_mask), GFP_KERNEL)?;
            }
        }

        for (csg_id, group, oom_mask) in to_visit.into_iter() {
            for cs_id in 0u32..32 {
                if oom_mask & (1u32 << cs_id) == 0 {
                    continue;
                }

                let (saved_tiler_oom_ack, heap_address, vt_start, vt_end, frag_end) =
                    tdev.fw.with_csg_mut(csg_id, |csg| {
                        let cs = csg.cs_mut(cs_id as usize).ok_or(EINVAL)?;
                        let ack = cs.read_output_ack()?;
                        let heap = cs.read_heap_output_state()?;

                        Ok((
                            ack.tiler_oom(),
                            heap.heap_address,
                            heap.vt_start,
                            heap.vt_end,
                            heap.frag_end,
                        ))
                    })?;

                pending.push(
                    PendingOom {
                        group: group.clone(),
                        csg_id,
                        cs_id,
                        saved_tiler_oom_ack,
                        heap_address,
                        vt_start,
                        vt_end,
                        frag_end,
                    },
                    GFP_KERNEL,
                )?;
            }
        }

        Ok(pending)
    }

    fn finish_pending_tiler_ooms(
        &mut self,
        tdev: &TyrDrmDevice,
        pending: &KVec<PendingOom>,
        chunk_vas: &KVec<u64>,
    ) -> Result {
        for (index, oom) in pending.iter().enumerate() {
            // The collect phase dropped the slot-manager lock so that
            // the firmware MMIO below can run without ordering
            // slot-manager ahead of fw.inner (which other paths take
            // standalone). Re-acquire briefly to confirm the slot is
            // still owned by the same group.
            {
                let slot_manager = tdev.csg_slot_manager.lock();
                match slot_manager.slot_data(oom.csg_id) {
                    Some(data) if Arc::ptr_eq(&data.group, &oom.group) => {}
                    _ => continue,
                }
            }

            let new_chunk_va = *chunk_vas.get(index).ok_or(EINVAL)?;

            tdev.fw.with_csg_mut(oom.csg_id, |csg| {
                {
                    let cs = csg.cs_mut(oom.cs_id as usize).ok_or(EINVAL)?;
                    cs.write_tiler_heap_raw(new_chunk_va, new_chunk_va);

                    let req = cs.read_input_req()?.with_tiler_oom(oom.saved_tiler_oom_ack);
                    cs.write_input_req(req);
                }

                let db_req = csg.read_input_db_req()?;
                csg.write_input_db_req(db_req.with_mask(db_req.mask() ^ (1u32 << oom.cs_id)));
                Ok(())
            })?;

            tdev.fw.ring_csg_doorbell(oom.csg_id)?;
        }

        Ok(())
    }
}
