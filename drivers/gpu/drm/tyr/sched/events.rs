// SPDX-License-Identifier: GPL-2.0 or MIT

//! Firmware event handling for the scheduler.
//!
//! CSG interrupts are decoded in the threaded job IRQ handler. The work they
//! schedule runs from per-group work items, where allocating tiler heap chunks
//! is allowed to sleep.

use kernel::{
    bindings,
    c_str,
    drm::gem::{
        BaseObject,
        IntoGEMObject, //
    },
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
        global::CsgInterface,
        CsDbMask,
        CsFatalExceptionType,
        CsgSlotMask,
        Firmware,
        CSG_REQ, //
    },
    gem::Bo,
    heap,
    trace,
    vm::Vm, //
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
    Scheduler, //
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
#[derive(Default)]
struct CsIrqEvents {
    tiler_oom_mask: u32,
    cs_fatal_mask: u32,
    cs_unrecoverable: bool,
    /// `EXTRACT` of each faulted queue, read before the fault is acknowledged.
    cs_fault_extract: [Option<u64>; MAX_CS_PER_GROUP],
    cs_fault_dump_mask: u32,
}

impl CsIrqEvents {
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
        let group_id = group.map(|g| g.handle()).unwrap_or(0);
        let input_req = cs.read_input_req()?;
        let output_ack = cs.read_output_ack()?;
        trace::cs_irq(
            csg_id as u32,
            cs_id,
            input_req.into_raw(),
            output_ack.into_raw(),
        );

        if input_req.tiler_oom() != output_ack.tiler_oom() {
            self.tiler_oom_mask |= 1u32 << cs_id;
        }

        let fatal_event = input_req.fatal() != output_ack.fatal();
        let fault_event = input_req.fault() != output_ack.fault();

        let (cs_insert, cs_extract, ringbuf_words, user_stream, instr_dump) =
            if fatal_event || fault_event {
                group
                    .and_then(|g| g.queues.get(cs_id as usize).map(|q| (g, q)))
                    .map(|(g, q)| {
                        let (insert, extract) = q.ringbuf_ptrs().unwrap_or((0, 0));
                        (
                            insert,
                            extract,
                            q.ringbuf_window_around_extract(extract),
                            q.user_stream_window_around(extract, &g.vm),
                            Some(q.ringbuf_instructions_at_extract(extract)),
                        )
                    })
                    .unwrap_or_else(|| (0, 0, [0u64; 8], trace::CsUserStreamDump::default(), None))
            } else {
                (0, 0, [0u64; 8], trace::CsUserStreamDump::default(), None)
            };

        if fatal_event {
            if let Some(group) = group {
                dev_warn!(
                    tdev.as_ref(),
                    "CS_FATAL: pid={}, comm={}\n",
                    group.task_pid(),
                    group.task_comm()
                );
            }
            let decoded = cs.decode_fatal(parent_dev(tdev), csg_id, cs_id)?;
            trace::cs_fault_event(
                group_id,
                cs_id,
                trace::CsFaultEventKind::Fatal,
                decoded.exception_type,
                decoded.exception_data,
                decoded.info,
                cs_insert,
                cs_extract,
                ringbuf_words,
            );
            trace::cs_user_stream_dump(group_id, cs_id, cs_extract, &user_stream);
            if let Some((ringbuf_va, bytes, len)) = instr_dump {
                trace::cs_fault_instruction_decode(
                    group_id,
                    cs_id,
                    cs_extract,
                    ringbuf_va,
                    &bytes[..len as usize],
                );
            }
            if let Some(g) = group {
                dump_cs_fault_info(group_id, cs_id, decoded.info, &g.vm);
            }
            if decoded.exception_type == CsFatalExceptionType::CsUnrecoverable as u32 {
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
            let decoded = cs.decode_fault(parent_dev(tdev), csg_id, cs_id)?;
            trace::cs_fault_event(
                group_id,
                cs_id,
                trace::CsFaultEventKind::Fault,
                decoded.exception_type,
                decoded.exception_data,
                decoded.info,
                cs_insert,
                cs_extract,
                ringbuf_words,
            );
            trace::cs_user_stream_dump(group_id, cs_id, cs_extract, &user_stream);
            if let Some((ringbuf_va, bytes, len)) = instr_dump {
                trace::cs_fault_instruction_decode(
                    group_id,
                    cs_id,
                    cs_extract,
                    ringbuf_va,
                    &bytes[..len as usize],
                );
            }
            if let Some(g) = group {
                dump_cs_fault_info(group_id, cs_id, decoded.info, &g.vm);
            }
            let queue = group.and_then(|group| group.queues.get(cs_id as usize));
            let extract = self.cs_fault_extract.get_mut(cs_id as usize);
            if let (Some(queue), Some(extract)) = (queue, extract) {
                *extract = queue.read_extract().ok();
            }
        }

        if fatal_event || fault_event {
            self.cs_fault_dump_mask |= 1u32 << cs_id;
            let new_req = input_req
                .with_fatal(output_ack.fatal())
                .with_fault(output_ack.fault());
            cs.write_input_req(new_req);
        }

        Ok(fault_event)
    }
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
        trace::work_run(c_str!("tiler_oom_work"));
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
                                group_uid: this.uid(),
                                cs_id: oom.cs_id.get() as u32,
                                vt_start: oom.vt_start,
                                vt_end: oom.vt_end,
                                frag_end: oom.frag_end,
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
        // Callers walk the whole slot array, which can be wider than the
        // slot count the firmware reports.
        if csg_id >= self.csg_slot_count as usize {
            return Ok(());
        }
        let csg_slot = CsgSlotIdx::new(csg_id).ok_or(EINVAL)?;

        let pending_mask =
            CSG_REQ::IDLE_MASK | CSG_REQ::SYNC_UPDATE_MASK | CSG_REQ::PROGRESS_TIMER_EVENT_MASK;

        let group = {
            let slot_manager = tdev.csg_slot_manager.lock();
            slot_manager
                .slot_data(csg_id)
                .map(|data| data.group.clone())
        };
        let group_id = group.as_ref().map(|g| g.handle()).unwrap_or(0);

        let (pending, pending_cs_irqs) = fw.with_csg_mut(csg_id, |csg| {
            let req = csg.read_input_req()?.into_raw();
            let ack = csg.read_output_ack()?.into_raw();
            let irq_req = csg.read_output_irq_req()?.mask();
            let irq_ack = csg.read_input_irq_ack()?;
            trace::csg_irq(
                csg_id as u32,
                group_id,
                req,
                ack,
                irq_req.get(),
                irq_ack.mask().get(),
            );
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

        if pending & CSG_REQ::IDLE_MASK != 0 {
            trace::csg_slot_idle(csg_id as u32, group_id, true);
        }
        if pending & CSG_REQ::PROGRESS_TIMER_EVENT_MASK != 0 {
            trace::csg_slot_progress_timeout(csg_id as u32);
        }

        if pending & CSG_REQ::IDLE_MASK != 0 {
            // At least one resident group may now be idle.
            self.might_have_idle_groups = true;
            TyrDrmDeviceData::schedule_tick(&tdev_aref);
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
                for (cs_idx, _queue) in group.queues.iter().enumerate() {
                    trace::queue_fatal_state(group_id, cs_idx as u32, true);
                }
            }
            TyrDrmDeviceData::schedule_tick(&tdev_aref);
        }
        if pending & CSG_REQ::SYNC_UPDATE_MASK != 0 {
            TyrDrmDeviceData::schedule_sync_upd(&tdev_aref);
        }

        let mut events = CsIrqEvents::default();
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
            cs_unrecoverable,
            cs_fault_extract,
            cs_fault_dump_mask,
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

            if cs_fault_dump_mask != 0 {
                if let Some(pool) = group.try_get_heap_pool() {
                    let dump_cs_id = cs_fault_dump_mask.trailing_zeros();
                    pool.dump_for_trace(group_id, dump_cs_id);
                }
            }

            if cs_fatal_mask != 0 {
                group.with_locked_inner(|inner| {
                    for cs_id in QueueIdx::iter_mask(cs_fatal_mask) {
                        inner.set_queue_fatal(cs_id);
                        trace::queue_fatal_state(group_id, cs_id.get() as u32, true);
                    }
                });
            }

            for (queue, extract) in group.queues.iter().zip(cs_fault_extract) {
                if let Some(extract) = extract {
                    queue.fail_job_at_extract(extract, EINVAL);
                }
            }
        }

        if cs_unrecoverable {
            trace::reset_request(trace::ResetReason::CsUnrecoverable);
            tdev.reset.schedule();
        }

        if cs_fatal_mask != 0 {
            TyrDrmDeviceData::schedule_tick(&tdev_aref);
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
            let mut mask = CsgSlotMask::empty();
            mask.insert(csg_slot);
            fw.ring_csg_doorbells(mask)?;
        }

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
                cs.write_input_req(req);
            }

            csg.toggle_input_db_req(CsDbMask::from_raw(oom.cs_id.bit()))
        })
    }
}

/// Resolves `CS_FAULT_INFO` (`info_va`) to a BO via the group's VM
/// and emits [`crate::trace::cs_fault_info_dump`] with the located
/// BO's metadata. When the BO has an existing kernel vmap (its
/// `drm_gem_shmem_object::vaddr` is non-NULL) the helper additionally
/// copies up to 256 bytes centred on `info_va` into the trace payload.
/// Mesa-owned user BOs typically have no kernel vmap, in which case
/// the trace records the metadata with an empty byte payload so the
/// consumer can still see which BO covers the fault VA. The payload is
/// also empty when the BO's reservation lock is contended.
///
/// Safe for use from the dma-fence signalling section that runs the CSG event
/// handler, because the GPUVM lookup uses `Vm::try_with_bo_for_va` (returns
/// immediately on lock contention) and the byte read goes through whatever
/// kernel vmap was already installed on the BO, under a trylock of its
/// reservation lock. It does not allocate, block on `dma_resv_lock` or sleep.
fn dump_cs_fault_info(group_id: u64, cs_id: u32, info_va: u64, vm: &Vm) {
    let mut bytes = [0u8; 256];
    let hit = vm.try_with_bo_for_va(info_va, |bo, bo_offset| {
        let len = read_vmap_bytes(bo, bo_offset as usize, &mut bytes);
        (bo.size() as u64, bo_offset, len)
    });
    let (bo_size, bo_offset, len) = match hit {
        Ok(Some(hit)) => hit,
        Ok(None) | Err(()) => {
            trace::cs_fault_info_dump(group_id, cs_id, info_va, 0, 0, 0, &[]);
            return;
        }
    };

    let bo_va_base = info_va.saturating_sub(bo_offset);

    trace::cs_fault_info_dump(
        group_id,
        cs_id,
        info_va,
        bo_va_base,
        bo_size,
        bo_offset,
        &bytes[..len],
    );
}

/// Copies up to 256 bytes of `bo` centered on `offset` into `bytes` through
/// the existing kernel vmap of `bo`.
///
/// Returns the number of bytes copied, or 0 if the reservation lock is
/// contended, `bo` has no kernel vmap, or `offset` is out of bounds.
fn read_vmap_bytes(bo: &Bo, offset: usize, bytes: &mut [u8; 256]) -> usize {
    let Some(_resv) = bo.try_lock_resv() else {
        return 0;
    };

    let shmem = IntoGEMObject::as_raw(bo).cast::<bindings::drm_gem_shmem_object>();
    // SAFETY: `bo` is a `gem::shmem::Object<_>`, so the `as_raw` pointer coincides with the
    // embedded shmem object. `_resv` holds the reservation lock, which protects `vaddr`.
    let vaddr = unsafe { core::ptr::read_volatile(&raw const (*shmem).vaddr) };
    if vaddr.is_null() {
        return 0;
    }

    let bo_size_usz = bo.size();
    if offset >= bo_size_usz {
        return 0;
    }

    let start = offset.saturating_sub(128);
    let end = offset.saturating_add(128).min(bo_size_usz);
    let len = end - start;
    // SAFETY: `vaddr` was non-NULL on a `READ_ONCE`-style read above,
    // indicating the shmem helpers have an installed kernel mapping
    // covering `bo_size_usz` bytes starting at `vaddr`. The mapping
    // stays installed while `_resv` is held. `start..end` is in bounds
    // by construction. The mapping is shared with the GPU, so the reads
    // are volatile to defeat compiler caching.
    unsafe {
        let src = (vaddr as *const u8).add(start);
        for (i, slot) in bytes[..len].iter_mut().enumerate() {
            *slot = core::ptr::read_volatile(src.add(i));
        }
    }
    len
}

/// Reads back the value currently stored at the scoreboard slot a CS
/// is waiting on, so the trace can show whether the producer ever
/// writes the awaited value. Resolves `gpu_va` to a BO via the
/// group's VM, maps the backing page covering the slot and reads a
/// `u32` (`sync64 == false`) or `u64` (`sync64 == true`).
///
/// Returns `(value, true)` on a successful read, or `(0, false)` when
/// the BO cannot be resolved, its reservation lock is contended, it has
/// no backing pages, or the offset is out of bounds.
///
/// Safe for use from the dma-fence signalling section that runs the CSG event
/// handler and the blocked-group poll, because the GPUVM lookup uses
/// `Vm::try_with_bo_for_va` (returns immediately on lock contention) and the
/// value is read through a transient `kmap_local_page` of a backing page
/// while a trylock holds the reservation lock; no allocation, no blocking
/// `dma_resv_lock`, no sleeping wait.
pub(super) fn read_syncwait_cur_val(vm: &Vm, gpu_va: u64, sync64: bool) -> (u64, bool) {
    let hit = vm.try_with_bo_for_va(gpu_va, |bo, bo_offset| {
        read_sync_value(bo, bo_offset, sync64)
    });
    match hit {
        Ok(Some(value)) => value,
        Ok(None) | Err(()) => (0, false),
    }
}

/// Reads the `u32` or `u64` sync object value at `bo_offset` in `bo`.
fn read_sync_value(bo: &Bo, bo_offset: u64, sync64: bool) -> (u64, bool) {
    let width = if sync64 { 8u64 } else { 4u64 };
    let bo_size = bo.size() as u64;
    if bo_offset >= bo_size || bo_size - bo_offset < width {
        return (0, false);
    }

    let page_index = (bo_offset >> kernel::page::PAGE_SHIFT) as usize;
    let in_page = (bo_offset as usize) & (kernel::page::PAGE_SIZE - 1);
    // A slot straddling a page boundary would need two mappings; bail
    // instead, since CSF sync objects are naturally aligned and never
    // straddle in practice.
    if in_page + width as usize > kernel::page::PAGE_SIZE {
        return (0, false);
    }

    // Eviction frees the pages under the reservation lock.
    let Some(_resv) = bo.try_lock_resv() else {
        return (0, false);
    };

    let shmem = IntoGEMObject::as_raw(bo).cast::<bindings::drm_gem_shmem_object>();
    // SAFETY: `bo` is a `gem::shmem::Object<_>`, so the `as_raw` pointer coincides with the
    // embedded shmem object. `_resv` holds the reservation lock, which protects `pages`, so a
    // non-NULL `pages` is a populated `*mut *mut page` array. `page_index` is in bounds because
    // `bo_offset + width <= bo_size` and the array spans the whole BO.
    let pages = unsafe { core::ptr::read_volatile(&raw const (*shmem).pages) };
    if pages.is_null() {
        return (0, false);
    }
    // SAFETY: `pages` is non-NULL and `_resv` is held, so the entry
    // at `page_index` is a valid `struct page` pointer.
    let page = unsafe { core::ptr::read_volatile(pages.add(page_index)) };
    if page.is_null() {
        return (0, false);
    }

    // SAFETY: `page` is a backing page of the live BO, kept while `_resv`
    // is held. `kmap_local_page` returns a mapping valid for `PAGE_SIZE`
    // bytes on this task until the matching `kunmap_local`.
    let vaddr = unsafe { bindings::kmap_local_page(page) };
    // SAFETY: The guard above ensures `in_page + width <= PAGE_SIZE`,
    // so the read stays within the mapped page. The mapping is shared
    // with the GPU, so the read is volatile to defeat compiler
    // caching; a racing producer write or teardown is tolerated for
    // this debug aid.
    let value = unsafe {
        let ptr = (vaddr as *const u8).add(in_page);
        if sync64 {
            core::ptr::read_volatile(ptr.cast::<u64>())
        } else {
            u64::from(core::ptr::read_volatile(ptr.cast::<u32>()))
        }
    };
    // SAFETY: `vaddr` was returned by the `kmap_local_page` above and
    // has not been unmapped; `kunmap_local` balances that mapping.
    unsafe { bindings::kunmap_local(vaddr) };

    (value, true)
}
