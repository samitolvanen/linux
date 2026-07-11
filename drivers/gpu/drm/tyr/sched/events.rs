// SPDX-License-Identifier: GPL-2.0 or MIT

//! Deferred scheduler event handling.
//!
//! This keeps the TILER_OOM path out of threaded IRQ context: the IRQ side only
//! records pending CS bits, while per-group work items grow heaps and write the
//! firmware acknowledgments back once allocation can sleep.

use core::sync::atomic::Ordering;

use kernel::{
    alloc::KVec,
    prelude::*,
    sync::{aref::ARef, Arc},
    workqueue::WorkItem,
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    fw::{
        CsDbMask,
        CsFatalExceptionType,
        CsFaultExceptionType,
        CsgSlotMask,
        CSG_REQ, //
    },
    heap,
};

use super::{
    group::{
        Group,
        MAX_CS_PER_GROUP, //
    },
    CsgSlotManager,
    Scheduler, //
};

struct PendingOom {
    csg_id: usize,
    cs_id: u32,
    heap_address: u64,
    vt_start: u32,
    vt_end: u32,
    frag_end: u32,
    /// Grow-phase result, overwritten for every entry before the
    /// firmware-write phase reads it.
    outcome: GrowOutcome,
}

/// Result of growing a heap for a pending tiler OOM, carried from the grow
/// phase to the firmware-write phase.
enum GrowOutcome {
    /// A new chunk was linked into the heap context at this GPU address.
    /// The second field is the cookie of the grown context, used to detect
    /// slot recycling if the chunk has to be returned.
    Grown(u64, u64),
    /// The heap is out of memory; ask the firmware to reclaim.
    Reclaim,
    /// The grow failed for an unexpected reason; the queue is marked fatal
    /// and the firmware write is skipped.
    Fatal,
}

fn slot_holds(slot_manager: &CsgSlotManager, csg_id: usize, group: &Arc<Group>) -> bool {
    matches!(
        slot_manager.slot_data(csg_id),
        Some(data) if Arc::ptr_eq(&data.group, group)
    )
}

impl WorkItem<2> for Group {
    type Pointer = Arc<Group>;

    fn run(this: Self::Pointer) {
        let tdev = &this.tdev;

        // Growing a heap reads the firmware interface and rings a doorbell,
        // so skip while the device is down or a transition is in flight.
        let Some(_active) = tdev.pm_get_if_active() else {
            return;
        };

        // Suspend and reset both evict every slot, and eviction clears the
        // pending request, so a skipped run leaves nothing behind.
        if tdev.reset.in_progress() {
            return;
        }

        let pending = Scheduler::collect_pending_tiler_ooms(tdev, &this);

        let mut pending = match pending {
            Ok(pending) => pending,
            Err(err) => {
                pr_err!("tiler_oom_work: failed to collect OOM events: {:?}\n", err);
                return;
            }
        };

        if pending.is_empty() {
            return;
        }

        for oom in pending.iter_mut() {
            let grow_result = if oom.frag_end > oom.vt_end || oom.vt_end >= oom.vt_start {
                pr_err!(
                    "tiler_oom_work: CSG {} CS {} bad counters vt_start={} vt_end={} frag_end={}\n",
                    oom.csg_id,
                    oom.cs_id,
                    oom.vt_start,
                    oom.vt_end,
                    oom.frag_end
                );
                Err(EINVAL)
            } else {
                this.get_heap_pool().ok_or(EINVAL).and_then(|pool| {
                    pool.grow_heap_context(
                        tdev,
                        heap::ContextGrowArgs {
                            heap_gpu_va: oom.heap_address,
                            renderpasses_in_flight: oom.vt_start.wrapping_sub(oom.frag_end),
                            pending_frag_count: oom.vt_end.wrapping_sub(oom.frag_end),
                        },
                    )
                })
            };

            oom.outcome = match grow_result {
                Ok((va, cookie)) => GrowOutcome::Grown(va, cookie),
                Err(e) if e == ENOMEM => GrowOutcome::Reclaim,
                Err(_) => {
                    this.with_locked_inner(|inner| inner.set_queue_fatal(oom.cs_id as usize));
                    TyrDrmDeviceData::schedule_tick(tdev);
                    GrowOutcome::Fatal
                }
            };
        }

        let _ = tdev
            .with_locked_scheduler(|sched| sched.finish_pending_tiler_ooms(tdev, &this, &pending))
            .inspect_err(|err| {
                pr_err!(
                    "tiler_oom_work: failed to complete OOM handling: {:?}\n",
                    err
                );
            });
    }
}

impl Scheduler {
    pub(crate) fn process_csg_irqs(&mut self, mut events: u32, tdev: &TyrDrmDevice) -> Result {
        while events != 0 {
            let csg_id = events.trailing_zeros() as usize;
            let mask = 1u32 << csg_id;

            self.process_csg_irq(tdev, csg_id)?;
            events &= !mask;
        }

        Ok(())
    }

    pub(super) fn process_csg_irq(&mut self, tdev: &TyrDrmDevice, csg_id: usize) -> Result {
        // Callers walk the whole slot array, which can be wider than the
        // slot count the firmware reports.
        if csg_id >= self.csg_slot_count as usize {
            return Ok(());
        }

        let pending_mask =
            CSG_REQ::IDLE_MASK | CSG_REQ::SYNC_UPDATE_MASK | CSG_REQ::PROGRESS_TIMER_EVENT_MASK;

        let (pending, pending_cs_irqs) = tdev.fw.with_csg_mut(csg_id, |csg| {
            let req = csg.read_input_req()?.into_raw();
            let ack = csg.read_output_ack()?.into_raw();
            let irq_req = csg.read_output_irq_req()?.mask();
            let irq_ack = csg.read_input_irq_ack()?;
            let pending = (req ^ ack) & pending_mask;
            let pending_cs_irqs = irq_req ^ irq_ack.mask();

            if pending != 0 {
                csg.update_input_req(CSG_REQ::from_raw(ack & pending), CSG_REQ::from_raw(pending))?;
            }
            if pending_cs_irqs != 0 {
                csg.write_input_irq_ack(irq_ack.with_mask(irq_req));
            }

            Ok((pending, pending_cs_irqs))
        })?;

        if pending == 0 && pending_cs_irqs == 0 {
            return Ok(());
        }

        let tdev_aref: ARef<TyrDrmDevice> = tdev.into();

        let group = {
            let slot_manager = tdev.csg_slot_manager.lock();
            slot_manager
                .slot_data(csg_id)
                .map(|data| data.group.clone())
        };

        if pending & CSG_REQ::IDLE_MASK != 0 {
            // At least one resident group may now be idle.
            self.might_have_idle_groups = true;
            TyrDrmDeviceData::schedule_tick(&tdev_aref);
        }
        if pending & CSG_REQ::PROGRESS_TIMER_EVENT_MASK != 0 {
            // Progress-timer expiry: the firmware-imposed forward-progress
            // window elapsed without the group advancing.
            pr_warn!("CSG slot {} progress timeout\n", csg_id);
            if let Some(group) = &group {
                pr_warn!(
                    "CSG_PROGRESS_TIMER_EVENT: pid={}, comm={}\n",
                    group.task_pid(),
                    group.task_comm()
                );
                group.with_locked_inner(|inner| inner.mark_timedout());
            }
            TyrDrmDeviceData::schedule_tick(&tdev_aref);
        }
        if pending & CSG_REQ::SYNC_UPDATE_MASK != 0 {
            TyrDrmDeviceData::schedule_sync_upd(&tdev_aref);
        }

        let mut tiler_oom_mask: u32 = 0;
        let mut cs_fatal_mask: u32 = 0;
        let mut cs_unrecoverable = false;
        let mut cs_inherit_fault_mask: u32 = 0;
        tdev.fw.with_csg_mut(csg_id, |csg| {
            let mut cs_irqs = pending_cs_irqs;

            while cs_irqs != 0 {
                let cs_id = cs_irqs.trailing_zeros();
                cs_irqs &= !(1u32 << cs_id);

                let cs = match csg.cs_mut(cs_id as usize) {
                    Some(cs) => cs,
                    None => continue,
                };
                let input_req = cs.read_input_req()?;
                let output_ack = cs.read_output_ack()?;

                if input_req.tiler_oom() != output_ack.tiler_oom() {
                    tiler_oom_mask |= 1u32 << cs_id;
                }

                let fatal_event = input_req.fatal() != output_ack.fatal();
                let fault_event = input_req.fault() != output_ack.fault();

                if fatal_event {
                    if let Some(group) = &group {
                        pr_warn!(
                            "CS_FATAL: pid={}, comm={}\n",
                            group.task_pid(),
                            group.task_comm()
                        );
                    }
                    let exception_type = cs.decode_fatal(csg_id, cs_id)?;
                    if exception_type == CsFatalExceptionType::CsUnrecoverable as u32 {
                        cs_unrecoverable = true;
                    }
                    cs_fatal_mask |= 1u32 << cs_id;
                }

                if fault_event {
                    if let Some(group) = &group {
                        pr_warn!(
                            "CS_FAULT: pid={}, comm={}\n",
                            group.task_pid(),
                            group.task_comm()
                        );
                    }
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

        if let Some(group) = &group {
            if tiler_oom_mask != 0 {
                group.tiler_oom.fetch_or(tiler_oom_mask, Ordering::Relaxed);
                group.schedule_tiler_oom();
            }

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
                    let syncobj_seqno = group.read_syncobj(cs_id)?.seqno;
                    queue.fail_inflight_submit_fences(syncobj_seqno, EINVAL);
                }
            }
        }

        if cs_unrecoverable {
            tdev.reset.schedule();
        }

        if cs_fatal_mask != 0 {
            TyrDrmDeviceData::schedule_tick(&tdev_aref);
        }

        let mut mask = CsgSlotMask::empty();
        mask.insert(csg_id);
        tdev.fw.ring_csg_doorbells(mask)?;

        Ok(())
    }

    /// Takes the pending tiler OOM mask and reads the heap counters of
    /// every CS it names.
    ///
    /// Must be called *outside* `TyrDrmDeviceData::with_locked_scheduler`:
    /// this takes the scheduler mutex itself and holds it across the mask
    /// swap and the counter reads, so a tick cannot be partway through a
    /// firmware sequence on the group's slot.
    fn collect_pending_tiler_ooms(tdev: &TyrDrmDevice, group: &Group) -> Result<KVec<PendingOom>> {
        // Reserve before taking the mask so an allocation failure leaves
        // the pending bits in place for a later requeue.
        let mut pending = KVec::with_capacity(MAX_CS_PER_GROUP, GFP_KERNEL)?;

        tdev.with_locked_scheduler(|_| {
            let mut oom_mask = group.tiler_oom.swap(0, Ordering::Relaxed);
            while oom_mask != 0 {
                let cs_id = oom_mask.trailing_zeros();
                oom_mask &= !(1u32 << cs_id);

                // The counters are indexed by slot, so resolve the binding and
                // read under one acquisition. An unbound group makes the rest
                // of its mask stale, and the firmware re-raises the event when
                // the group runs again.
                let (csg_id, heap_address, vt_start, vt_end, frag_end) = {
                    let slot_manager = tdev.csg_slot_manager.lock();
                    let Some(slot) = group.csg_seat.access(&slot_manager).slot() else {
                        break;
                    };
                    let csg_id = usize::from(slot);

                    let (heap_address, vt_start, vt_end, frag_end) =
                        tdev.fw.with_csg_mut(csg_id, |csg| {
                            let cs = csg.cs_mut(cs_id as usize).ok_or(EINVAL)?;
                            let heap = cs.read_heap_output_state()?;

                            Ok((heap.heap_address, heap.vt_start, heap.vt_end, heap.frag_end))
                        })?;

                    (csg_id, heap_address, vt_start, vt_end, frag_end)
                };

                pending.push_within_capacity(PendingOom {
                    csg_id,
                    cs_id,
                    heap_address,
                    vt_start,
                    vt_end,
                    frag_end,
                    outcome: GrowOutcome::Reclaim,
                })?;
            }

            Ok(())
        })?;

        Ok(pending)
    }

    fn finish_pending_tiler_ooms(
        &mut self,
        tdev: &TyrDrmDevice,
        group: &Arc<Group>,
        pending: &KVec<PendingOom>,
    ) -> Result {
        for oom in pending.iter() {
            let (new_chunk_va, cookie) = match &oom.outcome {
                GrowOutcome::Grown(va, cookie) => (*va, *cookie),
                GrowOutcome::Reclaim => (0, 0),
                GrowOutcome::Fatal => continue,
            };

            // The grow ran with no lock held, so confirm the same group
            // still owns the slot before writing to its interface.
            let owned = {
                let slot_manager = tdev.csg_slot_manager.lock();
                slot_holds(&slot_manager, oom.csg_id, group)
            };
            if !owned {
                if new_chunk_va != 0 {
                    if let Some(pool) = group.get_heap_pool() {
                        let _ = pool
                            .return_chunk(tdev, oom.heap_address, new_chunk_va, cookie)
                            .inspect_err(|e| {
                                pr_err!("tiler_oom: failed to return orphaned chunk: {:?}\n", e);
                            });
                    }
                }
                continue;
            }

            tdev.fw.with_csg_mut_ring_doorbell(oom.csg_id, |csg| {
                {
                    let cs = csg.cs_mut(oom.cs_id as usize).ok_or(EINVAL)?;
                    cs.write_tiler_heap_raw(new_chunk_va, new_chunk_va);

                    let ack = cs.read_output_ack()?.tiler_oom();
                    let req = cs.read_input_req()?.with_tiler_oom(ack);
                    cs.write_input_req(req);
                }

                csg.toggle_input_db_req(CsDbMask::from_raw(1u32 << oom.cs_id))
            })?;
        }

        Ok(())
    }
}
