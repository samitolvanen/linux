// SPDX-License-Identifier: GPL-2.0 or MIT

//! Firmware event handling for the scheduler.
//!
//! CSG interrupts are decoded in the threaded job IRQ handler. The work they
//! schedule runs from per-group work items, where allocating tiler heap chunks
//! is allowed to sleep.

use kernel::{
    dma_buf::dma_fence::DmaFenceSignallingAnnotation,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::Relaxed,
        barrier::{
            dma_mb,
            Full,
            Read, //
        },
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
        global::CsgInterface,
        CsDbMask,
        CsFatalExceptionType,
        CsgExecutionState,
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
        QueueIdx,
        MAX_CS_PER_GROUP, //
    },
    CsgSlotIdx,
    CsgSlotManager,
    Scheduler,
    MAX_CSGS, //
};

struct PendingOom {
    csg_id: usize,
    cs_id: QueueIdx,
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

/// CS events collected from one CSG interrupt.
struct CsIrqEvents<'a> {
    tiler_oom_mask: u32,
    cs_fatal_mask: u32,
    /// Streams whose `EXTRACT_EVENT` request is acked (REQ == ACK).
    extract_acked_mask: u32,
    cs_unrecoverable: bool,
    /// `EXTRACT` of each faulted queue, read before the fault is acknowledged.
    cs_fault_extract: &'a mut [Option<u64>; MAX_CS_PER_GROUP],
}

impl CsIrqEvents<'_> {
    /// Collects the events of CS `cs_id` and acknowledges its fatal and
    /// fault events. Returns `true` if a fault was acknowledged.
    fn process_cs_irq(
        &mut self,
        tdev: &TyrDrmDevice,
        csg: &mut CsgInterface,
        csg_id: usize,
        cs_id: u32,
        group: Option<&Group>,
    ) -> Result<bool> {
        let Some(cs) = csg.cs_mut(cs_id as usize) else {
            return Ok(false);
        };
        let input_req = cs.read_input_req()?;
        let output_ack = cs.read_output_ack()?;

        if input_req.tiler_oom() != output_ack.tiler_oom() {
            if let Some(group) = group {
                let bit = 1u32 << cs_id;
                let seen = group.tiler_oom_seen.load(Relaxed);
                if seen & bit == 0 {
                    group.tiler_oom_seen.store(seen | bit, Relaxed);
                    self.tiler_oom_mask |= bit;
                }
            }
        }

        if input_req.extract_event() == output_ack.extract_event() {
            self.extract_acked_mask |= 1u32 << cs_id;
        }

        let fatal_event = input_req.fatal() != output_ack.fatal();
        let fault_event = input_req.fault() != output_ack.fault();

        // The firmware stores the event's output words before `CS_ACK`, so
        // order their loads after the `CS_ACK` load.
        if fatal_event || fault_event {
            dma_mb(Read);
        }

        if fatal_event {
            if let Some(group) = group {
                dev_warn!(
                    tdev.as_ref(),
                    "CS_FATAL: pid={}, comm={}\n",
                    group.task_pid(),
                    group.task_comm()
                );
            }
            let exception_type = cs.decode_fatal(parent_dev(tdev), csg_id, cs_id)?;
            if exception_type == CsFatalExceptionType::CsUnrecoverable as u32 {
                self.cs_unrecoverable = true;
            }
            self.cs_fatal_mask |= 1u32 << cs_id;
        }

        if fault_event {
            if let Some(group) = group {
                dev_warn!(
                    tdev.as_ref(),
                    "CS_FAULT: pid={}, comm={}\n",
                    group.task_pid(),
                    group.task_comm()
                );
            }
            cs.decode_fault(parent_dev(tdev), csg_id, cs_id)?;
            let queue = group.and_then(|group| group.queues.get(cs_id as usize));
            let extract = self.cs_fault_extract.get_mut(cs_id as usize);
            if let (Some(queue), Some(extract)) = (queue, extract) {
                *extract = queue.read_extract().ok();
            }
        }

        if fatal_event || fault_event {
            let new_req = input_req
                .with_fatal(output_ack.fatal())
                .with_fault(output_ack.fault());
            cs.write_input_req(new_req);
        }

        Ok(fault_event)
    }
}

/// Returns the streams of `group` outside `flagged` with an unhandled
/// event. The firmware can raise one without toggling `CSG_IRQ_REQ`.
fn unflagged_cs_events(csg: &mut CsgInterface, group: &Group, flagged: u32) -> u32 {
    let oom_seen = group.tiler_oom_seen.load(Relaxed);
    let mut events = 0;

    for (cs_id, queue) in group.indexed_queues() {
        let bit = cs_id.bit();
        if flagged & bit != 0 {
            continue;
        }
        let Some(cs) = csg.cs_mut(cs_id.get()) else {
            continue;
        };
        let (Ok(req), Ok(ack)) = (cs.read_input_req(), cs.read_output_ack()) else {
            continue;
        };
        if req.fatal() != ack.fatal()
            || req.fault() != ack.fault()
            || (req.tiler_oom() != ack.tiler_oom() && oom_seen & bit == 0)
            || (req.extract_event() == ack.extract_event() && queue.ring_full())
        {
            events |= bit;
        }
    }

    events
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

        let Some(guard) = tdev.registration_guard() else {
            return;
        };

        guard.registration_data_with(|reg_data| {
            // The heap pool mutex must not be taken under the scheduler
            // mutex, so fetch the pool before locking the scheduler.
            let heap_pool = this.vm.heap_pool();

            // Service only the OOMs pending now, so a re-raised OOM cannot starve
            // the others. The IRQ handler records an OOM and requeues the work
            // under the slot-manager mutex, so an OOM recorded later gets a new run.
            let mut todo = {
                let _slots = tdev.csg_slot_manager.lock();
                this.tiler_oom.load(Relaxed)
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
                todo &= !oom.cs_id.bit();

                let grow_result = if oom.frag_end > oom.vt_end || oom.vt_end >= oom.vt_start {
                    dev_err!(
                        tdev.as_ref(),
                        "tiler_oom_work: CSG {} CS {} bad counters vt_start={} vt_end={} frag_end={}\n",
                        oom.csg_id,
                        oom.cs_id.get(),
                        oom.vt_start,
                        oom.vt_end,
                        oom.frag_end
                    );
                    Err(EINVAL)
                } else {
                    heap_pool.as_ref().ok_or(EINVAL).and_then(|pool| {
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
                        this.with_locked_inner(|inner| inner.set_queue_fatal(oom.cs_id));
                        TyrDrmDeviceData::schedule_tick(tdev);
                        GrowOutcome::Fatal
                    }
                };

                let _ = tdev
                    .with_locked_scheduler(|sched| {
                        sched.finish_pending_tiler_oom(
                            tdev,
                            reg_data,
                            &this,
                            &oom,
                            outcome,
                            heap_pool.as_ref(),
                        )
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
    /// Processes the CSG events latched in `fw_events`, drains the submit
    /// fences of the groups that reported a `SYNC_UPDATE`, then rings the
    /// CSG doorbells and queues any tick the events asked for.
    ///
    /// Sleeps, takes the slot-manager mutex and drains fences in a dma-fence
    /// signalling section, so it must not be called under the scheduler or
    /// slot-manager mutex.
    pub(crate) fn process_fw_events(tdev: &TyrDrmDevice) {
        // Processing rings CSG doorbells, so leave the events latched while
        // the device is suspended. The tick queued on resume processes them.
        let Some(_active) = tdev.pm_get_if_active() else {
            return;
        };

        // Skip while a reset owns the firmware interface. The reset worker
        // reissues the tick when the reset completes.
        if tdev.reset.in_progress() {
            return;
        }

        let Some(guard) = tdev.registration_guard() else {
            return;
        };

        let events = tdev.fw_events_take();
        if events == 0 {
            return;
        }

        let _annotation = DmaFenceSignallingAnnotation::new();
        let mut tick = false;
        guard.registration_data_with(|reg_data| {
            let mut doorbells = CsgSlotMask::empty();
            let groups =
                Self::process_csg_irqs(tdev, &reg_data.fw, events, &mut tick, &mut doorbells);
            Self::drain_queue_completions(tdev, &groups);
            Self::ring_csg_irq_doorbells(tdev, &reg_data.fw, doorbells);
        });

        if tick {
            TyrDrmDeviceData::schedule_tick(&tdev.into());
        }
    }

    /// Processes the events of the CSG slots in `events`, collecting the
    /// groups `process_csg_irq` returns and the `tick` and `doorbells` it
    /// sets. Each carries a duty documented there.
    #[must_use]
    fn process_csg_irqs(
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        mut events: u32,
        tick: &mut bool,
        doorbells: &mut CsgSlotMask,
    ) -> [Option<Arc<Group>>; MAX_CSGS] {
        let mut groups = [const { None }; MAX_CSGS];
        let mut slot_manager = tdev.csg_slot_manager.lock();

        while events != 0 {
            let csg_id = events.trailing_zeros() as usize;
            let mask = 1u32 << csg_id;

            match Self::process_csg_irq(tdev, fw, &mut slot_manager, csg_id, tick, doorbells) {
                Ok(group) => {
                    if let Some(slot) = groups.get_mut(csg_id) {
                        *slot = group;
                    }
                }
                Err(e) => dev_err!(
                    tdev.as_ref(),
                    "Failed to process the CSG slot {} IRQ: {:?}\n",
                    csg_id,
                    e
                ),
            }
            events &= !mask;
        }

        groups
    }

    /// Processes the events of CSG slot `csg_id`. Returns the slot's group
    /// if the slot reported a `SYNC_UPDATE`, sets `tick` if an event asks
    /// for a scheduler tick, and adds the slot to `doorbells` if its
    /// acknowledgment still needs a CSG doorbell.
    ///
    /// Every bind and evict holds the slot-manager mutex. Holding it across
    /// the call keeps the slot's group fixed while its events are
    /// acknowledged and handled.
    ///
    /// The caller must drain the fences of a returned group after releasing
    /// the slot-manager mutex, and before canceling them. It must ring
    /// `doorbells`, and queue a tick if `tick` is set, even on error.
    pub(super) fn process_csg_irq(
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        slot_manager: &mut CsgSlotManager,
        csg_id: usize,
        tick: &mut bool,
        doorbells: &mut CsgSlotMask,
    ) -> Result<Option<Arc<Group>>> {
        // The IRQ event mask is wider than the scheduler's slot count.
        if csg_id >= slot_manager.slot_count() {
            return Ok(None);
        }
        let csg_slot = CsgSlotIdx::new(csg_id).ok_or(EINVAL)?;

        let pending_mask =
            CSG_REQ::IDLE_MASK | CSG_REQ::SYNC_UPDATE_MASK | CSG_REQ::PROGRESS_TIMER_EVENT_MASK;

        let (pending, pending_cs_irqs) = fw.with_csg_mut(csg_id, |csg| {
            let req = csg.read_input_req()?.into_raw();
            let ack_reg = csg.read_output_ack()?;
            let ack = ack_reg.into_raw();
            let irq_req = csg.read_output_irq_req()?.mask();
            let irq_ack = csg.read_input_irq_ack()?;
            let pending = (req ^ ack) & pending_mask;
            let pending_cs_irqs = irq_req ^ irq_ack.mask();

            if pending != 0 {
                csg.update_input_req(CSG_REQ::from_raw(ack & pending), CSG_REQ::from_raw(pending))?;
            }
            // The firmware writes a sync object before it samples CSG_REQ, so
            // order the SYNC_UPDATE ack before the sync object reads.
            if pending & CSG_REQ::SYNC_UPDATE_MASK != 0 {
                dma_mb(Full);
            }
            if pending_cs_irqs != 0 {
                csg.write_input_irq_ack(irq_ack.with_mask(irq_req));
            }
            // Skip a staged binding until Start or Resume runs on the slot.
            let running = matches!(
                ack_reg.state(),
                Ok(CsgExecutionState::Start | CsgExecutionState::Resume)
            );
            let unflagged = slot_manager
                .slot_data(csg_id)
                .filter(|data| data.started || running)
                .map_or(0, |data| {
                    unflagged_cs_events(csg, &data.group, pending_cs_irqs)
                });

            Ok((pending, pending_cs_irqs | unflagged))
        })?;

        if pending == 0 && pending_cs_irqs == 0 {
            return Ok(None);
        }

        let tdev_aref: ARef<TyrDrmDevice> = tdev.into();

        let group = slot_manager
            .slot_data(csg_id)
            .map(|data| data.group.clone());

        if pending & CSG_REQ::IDLE_MASK != 0 {
            // At least one resident group may now be idle.
            tdev.might_have_idle_groups.store(true, Relaxed);
            *tick = true;
        }
        if pending & CSG_REQ::PROGRESS_TIMER_EVENT_MASK != 0 {
            // Progress-timer expiry: the firmware-imposed forward-progress
            // window elapsed without the group advancing.
            dev_warn!(tdev.as_ref(), "CSG slot {} progress timeout\n", csg_id);
            if let Some(group) = &group {
                dev_warn!(
                    tdev.as_ref(),
                    "CSG_PROGRESS_TIMER_EVENT: pid={}, comm={}\n",
                    group.task_pid(),
                    group.task_comm()
                );
                group.with_locked_inner(|inner| inner.mark_timedout());
            }
            *tick = true;
        }
        let sync_update = pending & CSG_REQ::SYNC_UPDATE_MASK != 0;
        if sync_update {
            if tdev.waiting_groups.load(Relaxed) {
                TyrDrmDeviceData::schedule_sync_upd(&tdev_aref);
            } else {
                tdev.skipped_sync_updates.add(1, Relaxed);
            }
        }

        let mut events = CsIrqEvents {
            tiler_oom_mask: 0,
            cs_fatal_mask: 0,
            extract_acked_mask: 0,
            cs_unrecoverable: false,
            cs_fault_extract: slot_manager.cs_fault_extract(),
        };
        let ring_cs_db_mask = fw.with_csg_mut(csg_id, |csg| {
            let mut cs_irqs = pending_cs_irqs;
            let mut ring_cs_db_mask = 0u32;

            while cs_irqs != 0 {
                let cs_id = cs_irqs.trailing_zeros();
                cs_irqs &= !(1u32 << cs_id);

                match events.process_cs_irq(tdev, csg, csg_id, cs_id, group.as_deref()) {
                    Ok(true) => ring_cs_db_mask |= 1u32 << cs_id,
                    Ok(false) => {}
                    Err(e) => dev_err!(
                        tdev.as_ref(),
                        "Failed to process the CSG slot {} CS {} IRQ: {:?}\n",
                        csg_id,
                        cs_id,
                        e
                    ),
                }
            }

            Ok(ring_cs_db_mask)
        })?;
        let CsIrqEvents {
            mut tiler_oom_mask,
            mut cs_fatal_mask,
            extract_acked_mask,
            cs_unrecoverable,
            cs_fault_extract,
        } = events;

        if let Some(group) = &group {
            let queue_mask = group.queue_mask();
            let stray_mask = (tiler_oom_mask | cs_fatal_mask) & !queue_mask;
            if stray_mask != 0 {
                dev_warn!(
                    tdev.as_ref(),
                    "CSG slot {}: fatal or tiler OOM event on CS mask {:#x} with no queue\n",
                    csg_id,
                    stray_mask
                );
            }
            tiler_oom_mask &= queue_mask;
            cs_fatal_mask &= queue_mask;

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
                    for cs_id in QueueIdx::iter_mask(cs_fatal_mask) {
                        inner.set_queue_fatal(cs_id);
                    }
                });
            }

            for (queue, &extract) in group.queues.iter().zip(cs_fault_extract.iter()) {
                if let Some(extract) = extract {
                    queue.fail_job_at_extract(extract, EINVAL);
                }
            }

            for (cs_id, queue) in group.indexed_queues() {
                if extract_acked_mask & cs_id.bit() != 0 {
                    queue.wake_ring_full();
                }
            }
        }

        if cs_unrecoverable {
            tdev.reset.schedule();
        }

        if cs_fatal_mask != 0 {
            *tick = true;
        }

        if ring_cs_db_mask != 0 {
            fw.with_csg_mut_ring_doorbell(csg_id, |csg| {
                if let Err(e) = csg.toggle_input_db_req(CsDbMask::from_raw(ring_cs_db_mask)) {
                    dev_err!(
                        tdev.as_ref(),
                        "Failed to toggle the CSG slot {} CS doorbell requests: {:?}\n",
                        csg_id,
                        e
                    );
                }
                Ok(())
            })?;
        } else {
            doorbells.insert(csg_slot);
        }

        Ok(group.filter(|_| sync_update))
    }

    /// Rings the CSG doorbells that `process_csg_irq` left to its caller.
    pub(super) fn ring_csg_irq_doorbells(
        tdev: &TyrDrmDevice,
        fw: &Firmware<'_>,
        doorbells: CsgSlotMask,
    ) {
        if let Err(e) = fw.ring_csg_doorbells(doorbells) {
            dev_err!(
                tdev.as_ref(),
                "Failed to ring the CSG doorbells {:#x}: {:?}\n",
                doorbells.into_raw(),
                e
            );
        }
    }

    /// Takes one pending tiler OOM of `group` on a CS in `todo` and reads
    /// the heap counters of that CS. Returns `None` when none is pending
    /// or the group holds no slot.
    ///
    /// Must be called *outside* `TyrDrmDeviceData::with_locked_scheduler`.
    /// This takes the scheduler mutex itself, so a tick cannot be partway
    /// through a firmware sequence on the group's slot. It reads the counters
    /// under the slot-manager mutex, which also excludes CSG event processing
    /// in the job IRQ thread.
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
                let Some(cs_id) = QueueIdx::iter_mask(mask & todo).next() else {
                    return Ok(None);
                };
                match tiler_oom.cmpxchg(mask, mask & !cs_id.bit(), Relaxed) {
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
                let cs = csg.cs_mut(cs_id.get()).ok_or(EINVAL)?;
                if cs.read_input_req()?.tiler_oom() == cs.read_output_ack()?.tiler_oom() {
                    let seen = group.tiler_oom_seen.load(Relaxed);
                    group.tiler_oom_seen.store(seen & !cs_id.bit(), Relaxed);
                    return Ok(None);
                }
                // The firmware stores the heap words before `CS_ACK`, so order their
                // loads after the `CS_ACK` load.
                dma_mb(Read);
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
        heap_pool: Option<&Arc<heap::Pool>>,
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
                if let Some(pool) = heap_pool {
                    let _ = pool
                        .return_chunk(oom.heap_address, new_chunk_va, cookie)
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

        reg_data.fw.with_csg_mut_ring_doorbell(oom.csg_id, |csg| {
            {
                let cs = csg.cs_mut(oom.cs_id.get()).ok_or(EINVAL)?;
                cs.write_tiler_heap_raw(new_chunk_va, new_chunk_va);

                let ack = cs.read_output_ack()?.tiler_oom();
                let req = cs.read_input_req()?.with_tiler_oom(ack);
                let seen = group.tiler_oom_seen.load(Relaxed);
                group.tiler_oom_seen.store(seen & !oom.cs_id.bit(), Relaxed);
                cs.write_input_req(req);
            }

            csg.toggle_input_db_req(CsDbMask::from_raw(oom.cs_id.bit()))
        })
    }
}
