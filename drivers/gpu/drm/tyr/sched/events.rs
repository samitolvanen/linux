// SPDX-License-Identifier: GPL-2.0 or MIT

//! Firmware event handling for the scheduler.
//!
//! CSG interrupts are decoded in the threaded job IRQ handler. The work they
//! schedule runs from per-group work items, where allocating tiler heap chunks
//! is allowed to sleep.

use kernel::{
    prelude::*,
    sync::{
        aref::ARef,
        atomic::Relaxed,
        Arc, //
    },
    workqueue::WorkItem, //
};

use crate::{
    driver::{
        parent_dev,
        TyrDrmDevice,
        TyrDrmDeviceData,
        TyrDrmRegistrationData, //
    },
    fw::{
        CsDbMask,
        CsgSlotMask,
        Firmware,
        CSG_REQ, //
    },
    heap, //
};

use super::{
    group::{
        work_id,
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
}

/// Result of growing a heap for a pending tiler OOM, carried from the grow
/// phase to the firmware-write phase.
enum GrowOutcome {
    /// A new chunk was linked into the heap context at this GPU address.
    /// The second field is the cookie of the grown context, used to detect
    /// slot recycling if the chunk has to be returned.
    Grown(u64, u64),
    /// The heap is out of memory. Ask the firmware to reclaim.
    Reclaim,
    /// The grow failed for an unexpected reason. The queue is marked fatal
    /// and the firmware write is skipped.
    Fatal,
}

fn slot_holds(slot_manager: &CsgSlotManager, csg_id: usize, group: &Arc<Group>) -> bool {
    matches!(
        slot_manager.slot_data(csg_id),
        Some(data) if Arc::ptr_eq(&data.group, group)
    )
}

impl WorkItem<{ work_id::TILER_OOM }> for Group {
    type Pointer = Arc<Group>;

    fn run(this: Self::Pointer) {
        let tdev = &this.tdev;

        let Some(guard) = tdev.registration_guard() else {
            return;
        };

        guard.registration_data_with(|reg_data| {
            // Service only the OOMs pending now, so a re-raised OOM cannot starve
            // the others. The IRQ handler records an OOM and requeues the work
            // under the scheduler mutex, so an OOM recorded later gets a new run.
            let Ok(mut todo) = tdev.with_locked_scheduler(|_| Ok(this.tiler_oom.load(Relaxed)))
            else {
                return;
            };

            loop {
                let pending = Scheduler::take_pending_tiler_oom(tdev, &reg_data.fw, &this, todo);

                let oom = match pending {
                    Ok(Some(oom)) => oom,
                    Ok(None) => return,
                    Err(err) => {
                        dev_err!(
                            tdev.as_ref(),
                            "tiler_oom_work: failed to collect OOM events: {:?}\n",
                            err
                        );
                        return;
                    }
                };
                todo &= !(1u32 << oom.cs_id);

                let grow_result = if oom.frag_end > oom.vt_end || oom.vt_end >= oom.vt_start {
                    dev_err!(
                        tdev.as_ref(),
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
                            reg_data,
                            heap::ContextGrowArgs {
                                heap_gpu_va: oom.heap_address,
                                renderpasses_in_flight: oom.vt_start.wrapping_sub(oom.frag_end),
                                pending_frag_count: oom.vt_end.wrapping_sub(oom.frag_end),
                            },
                        )
                    })
                };

                let outcome = match grow_result {
                    Ok((va, cookie)) => GrowOutcome::Grown(va, cookie),
                    Err(e) if e == ENOMEM => GrowOutcome::Reclaim,
                    Err(_) => {
                        this.with_locked_inner(|inner| inner.set_queue_fatal(oom.cs_id as usize));
                        TyrDrmDeviceData::schedule_tick(tdev);
                        GrowOutcome::Fatal
                    }
                };

                let _ = tdev
                    .with_locked_scheduler(|sched| {
                        sched.finish_pending_tiler_oom(tdev, reg_data, &this, &oom, outcome)
                    })
                    .inspect_err(|err| {
                        dev_err!(
                            tdev.as_ref(),
                            "tiler_oom_work: failed to complete OOM handling: {:?}\n",
                            err
                        );
                    });
            }
        });
    }
}

impl Scheduler {
    pub(crate) fn process_csg_irqs(
        &mut self,
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        mut events: u32,
    ) {
        while events != 0 {
            let csg_id = events.trailing_zeros() as usize;
            let mask = 1u32 << csg_id;

            if let Err(e) = self.process_csg_irq(tdev, fw, csg_id) {
                dev_err!(
                    tdev.as_ref(),
                    "Failed to process the CSG slot {} IRQ: {:?}\n",
                    csg_id,
                    e
                );
            }
            events &= !mask;
        }
    }

    pub(super) fn process_csg_irq(
        &mut self,
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        csg_id: usize,
    ) -> Result {
        // The lock order documented on `Scheduler` allows holding the
        // slot lock across the firmware reads below.
        let group = {
            let slot_manager = tdev.csg_slot_manager.lock();
            match slot_manager.slot_data(csg_id) {
                Some(data) => data.group.clone(),
                None => return Ok(()),
            }
        };

        let pending_mask =
            CSG_REQ::IDLE_MASK | CSG_REQ::SYNC_UPDATE_MASK | CSG_REQ::PROGRESS_TIMER_EVENT_MASK;

        let (idle_event, sync_event, progress_event) = fw.with_csg_mut(csg_id, |csg| {
            let req = csg.read_input_req()?.into_raw();
            let ack = csg.read_output_ack()?.into_raw();
            let pending = (req ^ ack) & pending_mask;
            if pending != 0 {
                csg.update_input_req(CSG_REQ::from_raw(ack & pending), CSG_REQ::from_raw(pending))?;
            }
            Ok((
                pending & CSG_REQ::IDLE_MASK != 0,
                pending & CSG_REQ::SYNC_UPDATE_MASK != 0,
                pending & CSG_REQ::PROGRESS_TIMER_EVENT_MASK != 0,
            ))
        })?;

        let tdev_aref: ARef<TyrDrmDevice> = tdev.into();

        if idle_event {
            // At least one resident group may now be idle.
            self.might_have_idle_groups = true;
            TyrDrmDeviceData::schedule_tick(&tdev_aref);
        }

        if progress_event {
            // Progress-timer expiry: the firmware-imposed forward-progress
            // window elapsed without the group advancing.
            group.with_locked_inner(|inner| {
                if inner.fatal_error.is_none() {
                    inner.fatal_error = Some(ETIMEDOUT);
                }
            });
            dev_warn!(tdev.as_ref(), "CSG slot {} progress timeout\n", csg_id);
            TyrDrmDeviceData::schedule_tick(&tdev_aref);
        }

        if sync_event {
            TyrDrmDeviceData::schedule_sync_upd(&tdev_aref);
        }

        let mut tiler_oom_mask: u32 = 0;
        let mut cs_fatal_mask: u32 = 0;
        // `EXTRACT` of each faulted queue, read before the fault is acknowledged.
        let mut cs_fault_extract: [Option<u64>; MAX_CS_PER_GROUP] = [None; MAX_CS_PER_GROUP];
        let mut ring_cs_db_mask: u32 = 0;
        fw.with_csg_mut(csg_id, |csg| {
            let irq_req = csg.read_output_irq_req()?.mask();
            let irq_ack = csg.read_input_irq_ack()?;
            let pending_cs_irqs = irq_req ^ irq_ack.mask();

            if pending_cs_irqs == 0 {
                return Ok(());
            }

            csg.write_input_irq_ack(irq_ack.with_mask(irq_req));

            for cs_id in 0..group.queue_count() as u32 {
                if pending_cs_irqs & (1u32 << cs_id) == 0 {
                    continue;
                }

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
                    let _ = cs.decode_fatal(parent_dev(tdev), csg_id, cs_id)?;
                    cs_fatal_mask |= 1u32 << cs_id;
                }

                if fault_event {
                    cs.decode_fault(parent_dev(tdev), csg_id, cs_id)?;
                    let queue = group.queues.get(cs_id as usize);
                    let extract = cs_fault_extract.get_mut(cs_id as usize);
                    if let (Some(queue), Some(extract)) = (queue, extract) {
                        *extract = queue.read_extract().ok();
                    }
                    ring_cs_db_mask |= 1u32 << cs_id;
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

        if tiler_oom_mask != 0 {
            // The kernel atomics have no fetch_or.
            let tiler_oom = &group.tiler_oom;
            let mut old = tiler_oom.load(Relaxed);
            while let Err(current) = tiler_oom.cmpxchg(old, old | tiler_oom_mask, Relaxed) {
                old = current;
            }

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

        for (queue, extract) in group.queues.iter().zip(cs_fault_extract) {
            if let Some(extract) = extract {
                queue.fail_job_at_extract(extract, EINVAL);
            }
        }

        if cs_fatal_mask != 0 {
            TyrDrmDeviceData::schedule_tick(&tdev_aref);
        }

        if ring_cs_db_mask != 0 {
            fw.with_csg_mut(csg_id, |csg| {
                csg.toggle_input_db_req(CsDbMask::from_raw(ring_cs_db_mask))
            })?;
        }

        let mut mask = CsgSlotMask::empty();
        mask.insert(csg_id);
        fw.ring_csg_doorbells(mask)?;

        Ok(())
    }

    /// Takes one pending tiler OOM of `group` on a CS in `todo` and reads
    /// the heap counters of that CS. Returns `None` when none is pending
    /// or the group holds no slot.
    ///
    /// Must be called *outside* `TyrDrmDeviceData::with_locked_scheduler`.
    /// This takes the scheduler mutex itself and holds it across the mask
    /// update and the counter reads, so a tick cannot be partway through a
    /// firmware sequence on the group's slot.
    fn take_pending_tiler_oom(
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        group: &Group,
        todo: u32,
    ) -> Result<Option<PendingOom>> {
        tdev.with_locked_scheduler(|_| loop {
            // The kernel atomics have no fetch_and.
            let tiler_oom = &group.tiler_oom;
            let mut mask = tiler_oom.load(Relaxed);
            let cs_id = loop {
                let pending = mask & todo;
                if pending == 0 {
                    return Ok(None);
                }
                let cs_id = pending.trailing_zeros();
                match tiler_oom.cmpxchg(mask, mask & !(1u32 << cs_id), Relaxed) {
                    Ok(_) => break cs_id,
                    Err(current) => mask = current,
                }
            };

            // The counters are indexed by slot, so resolve the binding and
            // read under one acquisition. An unbound group makes the rest
            // of its mask stale, and the firmware re-raises the event when
            // the group runs again.
            let slot_manager = tdev.csg_slot_manager.lock();
            let Some(slot) = group.csg_seat.access(&slot_manager).slot() else {
                tiler_oom.store(0, Relaxed);
                return Ok(None);
            };
            let csg_id = usize::from(slot);

            let counters = fw.with_csg_mut(csg_id, |csg| {
                let cs = csg.cs_mut(cs_id as usize).ok_or(EINVAL)?;
                if cs.read_input_req()?.tiler_oom() == cs.read_output_ack()?.tiler_oom() {
                    return Ok(None);
                }
                let heap = cs.read_heap_output_state()?;

                Ok(Some((
                    heap.heap_address,
                    heap.vt_start,
                    heap.vt_end,
                    heap.frag_end,
                )))
            })?;
            let Some((heap_address, vt_start, vt_end, frag_end)) = counters else {
                continue;
            };

            return Ok(Some(PendingOom {
                csg_id,
                cs_id,
                heap_address,
                vt_start,
                vt_end,
                frag_end,
            }));
        })
    }

    fn finish_pending_tiler_oom(
        &mut self,
        tdev: &TyrDrmDevice,
        reg_data: &TyrDrmRegistrationData<'_>,
        group: &Arc<Group>,
        oom: &PendingOom,
        outcome: GrowOutcome,
    ) -> Result {
        let (new_chunk_va, cookie) = match outcome {
            GrowOutcome::Grown(va, cookie) => (va, cookie),
            GrowOutcome::Reclaim => (0, 0),
            GrowOutcome::Fatal => return Ok(()),
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
                        .return_chunk(reg_data, oom.heap_address, new_chunk_va, cookie)
                        .inspect_err(|e| {
                            dev_err!(
                                tdev.as_ref(),
                                "tiler_oom: failed to return orphaned chunk: {:?}\n",
                                e
                            );
                        });
                }
            }
            return Ok(());
        }

        reg_data.fw.with_csg_mut(oom.csg_id, |csg| {
            {
                let cs = csg.cs_mut(oom.cs_id as usize).ok_or(EINVAL)?;
                cs.write_tiler_heap_raw(new_chunk_va, new_chunk_va);

                let ack = cs.read_output_ack()?.tiler_oom();
                let req = cs.read_input_req()?.with_tiler_oom(ack);
                cs.write_input_req(req);
            }

            csg.toggle_input_db_req(CsDbMask::from_raw(1u32 << oom.cs_id))
        })?;

        let mut mask = CsgSlotMask::empty();
        mask.insert(oom.csg_id);
        reg_data.fw.ring_csg_doorbells(mask)
    }
}
