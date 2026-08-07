// SPDX-License-Identifier: GPL-2.0 or MIT

//! Deferred scheduler event handling.
//!
//! This keeps the TILER_OOM path out of threaded IRQ context: the IRQ side only
//! records pending CS bits, while per-group work items grow heaps and write the
//! firmware acknowledgments back once allocation can sleep.

use core::sync::atomic::Ordering;

use kernel::{
    alloc::KVec,
    bindings, c_str,
    drm::gem::{
        BaseObject,
        IntoGEMObject, //
    },
    pr_warn_once,
    prelude::*,
    sync::{aref::ARef, barrier::wmb, Arc},
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
    heap, trace,
    vm::Vm,
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
                            group_uid: this.uid(),
                            cs_id: oom.cs_id,
                            vt_start: oom.vt_start,
                            vt_end: oom.vt_end,
                            frag_end: oom.frag_end,
                        },
                    )
                })
            };

            oom.outcome = match grow_result {
                Ok((va, cookie)) => GrowOutcome::Grown(va, cookie),
                Err(e) if e == ENOMEM => {
                    if trace::heap_event_dump_enabled() {
                        if let Some(pool) = this.get_heap_pool() {
                            pool.dump_for_trace(
                                tdev,
                                this.handle(),
                                this.uid(),
                                oom.cs_id,
                                Some(oom.heap_address),
                                Some(trace::HeapDumpTrigger::Reclaim),
                            );
                        }
                    }
                    GrowOutcome::Reclaim
                }
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

        let group = {
            let slot_manager = tdev.csg_slot_manager.lock();
            slot_manager
                .slot_data(csg_id)
                .map(|data| data.group.clone())
        };
        let group_id = group.as_ref().map(|g| g.handle()).unwrap_or(0);

        let (pending, pending_cs_irqs) = tdev.fw.with_csg_mut(csg_id, |csg| {
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
            pr_warn!("CSG slot {} progress timeout\n", csg_id);
            if let Some(group) = &group {
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

        let mut tiler_oom_mask: u32 = 0;
        let mut cs_fatal_mask: u32 = 0;
        let mut cs_unrecoverable = false;
        let mut cs_inherit_fault_mask: u32 = 0;
        let mut cs_fault_dump_mask: u32 = 0;
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
                trace::cs_irq(
                    csg_id as u32,
                    cs_id,
                    input_req.into_raw(),
                    output_ack.into_raw(),
                );

                if input_req.tiler_oom() != output_ack.tiler_oom() {
                    tiler_oom_mask |= 1u32 << cs_id;
                }

                let fatal_event = input_req.fatal() != output_ack.fatal();
                let fault_event = input_req.fault() != output_ack.fault();

                let (cs_insert, cs_extract, ringbuf_words, user_stream, instr_dump) =
                    if fatal_event || fault_event {
                        group
                            .as_ref()
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
                            .unwrap_or_else(|| {
                                (0, 0, [0u64; 8], trace::CsUserStreamDump::default(), None)
                            })
                    } else {
                        (0, 0, [0u64; 8], trace::CsUserStreamDump::default(), None)
                    };

                if fatal_event {
                    let decoded = cs.decode_fatal(csg_id, cs_id)?;
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
                    if let Some(g) = &group {
                        dump_cs_fault_info(group_id, cs_id, decoded.info, &g.vm);
                    }
                    if decoded.exception_type == CsFatalExceptionType::CsUnrecoverable as u32 {
                        cs_unrecoverable = true;
                    }
                    cs_fatal_mask |= 1u32 << cs_id;
                }

                if fault_event {
                    let decoded = cs.decode_fault(csg_id, cs_id)?;
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
                    if let Some(g) = &group {
                        dump_cs_fault_info(group_id, cs_id, decoded.info, &g.vm);
                    }
                    if decoded.exception_type == CsFaultExceptionType::CsInheritFault as u32 {
                        cs_inherit_fault_mask |= 1u32 << cs_id;
                    }
                }

                if fatal_event || fault_event {
                    cs_fault_dump_mask |= 1u32 << cs_id;
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

            if cs_fault_dump_mask != 0 {
                if let Some(pool) = group.try_get_heap_pool() {
                    let dump_cs_id = cs_fault_dump_mask.trailing_zeros();
                    pool.dump_for_trace(tdev, group_id, group.uid(), dump_cs_id, None, None);
                }
            }

            if cs_fatal_mask != 0 {
                group.with_locked_inner(|inner| {
                    let mut mask = cs_fatal_mask;
                    while mask != 0 {
                        let cs_id = mask.trailing_zeros() as usize;
                        mask &= !(1u32 << cs_id);
                        inner.set_queue_fatal(cs_id);
                        trace::queue_fatal_state(group_id, cs_id as u32, true);
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
            trace::reset_request(trace::ResetReason::CsUnrecoverable);
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

                    if trace::tiler_heap_readback_enabled() {
                        // The doorbell's barrier comes too late to keep
                        // the read below from being answered out of the
                        // store buffer.
                        wmb();
                        let (start, end) = cs.read_tiler_heap_raw()?;
                        if tiler_heap_readback(
                            group,
                            oom,
                            trace::ReadbackPhase::BeforeDoorbell,
                            new_chunk_va,
                            start,
                            end,
                        ) {
                            pr_warn_once!(
                                "tiler_oom: CSG {} CS {} heap words changed before the doorbell: wrote {:#x} read {:#x}/{:#x}\n",
                                oom.csg_id,
                                oom.cs_id,
                                new_chunk_va,
                                start,
                                end,
                            );
                        }
                    }

                    let ack = cs.read_output_ack()?.tiler_oom();
                    let req = cs.read_input_req()?.with_tiler_oom(ack);
                    cs.write_input_req(req);
                }

                csg.toggle_input_db_req(CsDbMask::from_raw(1u32 << oom.cs_id))
            })?;

            if trace::tiler_heap_readback_enabled() {
                // A readback that cannot reach the interface must not
                // skip the pending OOMs behind this one.
                let _ = tdev.fw.with_csg_mut(oom.csg_id, |csg| {
                    let cs = csg.cs_mut(oom.cs_id as usize).ok_or(EINVAL)?;
                    let (start, end) = cs.read_tiler_heap_raw()?;
                    if tiler_heap_readback(
                        group,
                        oom,
                        trace::ReadbackPhase::AfterDoorbell,
                        new_chunk_va,
                        start,
                        end,
                    ) {
                        pr_warn_once!(
                            "tiler_oom: CSG {} CS {} heap words changed across the doorbell: wrote {:#x} read {:#x}/{:#x}\n",
                            oom.csg_id,
                            oom.cs_id,
                            new_chunk_va,
                            start,
                            end,
                        );
                    }
                    Ok(())
                });
            }
        }

        Ok(())
    }
}

/// Emits `tyr_tiler_heap_readback` for the `CS_TILER_HEAP_START` /
/// `CS_TILER_HEAP_END` pair read out of the CS input block. Returns
/// whether either word differs from what the worker wrote.
fn tiler_heap_readback(
    group: &Group,
    oom: &PendingOom,
    phase: trace::ReadbackPhase,
    written: u64,
    read_start: u64,
    read_end: u64,
) -> bool {
    trace::tiler_heap_readback(
        group.uid(),
        oom.csg_id as u32,
        oom.cs_id,
        phase,
        written,
        read_start,
        read_end,
    );

    read_start != written || read_end != written
}

/// Resolves `CS_FAULT_INFO` (`info_va`) to a BO via the group's VM
/// and emits [`crate::trace::cs_fault_info_dump`] with the located
/// BO's metadata. When the BO has an existing kernel vmap (its
/// `drm_gem_shmem_object::vaddr` is non-NULL) the helper additionally
/// copies up to 256 bytes centred on `info_va` into the trace payload.
/// Mesa-owned user BOs typically have no kernel vmap, in which case
/// the trace records the metadata with an empty byte payload so the
/// consumer can still see which BO covers the fault VA.
///
/// Safe for use from the dma-fence signalling section that runs the CSG event
/// handler, because the GPUVM lookup uses [`Vm::try_get_bo_for_va`] (returns
/// immediately on lock contention) and the byte read goes through whatever
/// kernel vmap was already installed on the BO; no allocation, no
/// `dma_resv_lock` acquisition, no sleeping wait.
fn dump_cs_fault_info(group_id: u64, cs_id: u32, info_va: u64, vm: &Vm) {
    let (bo, bo_offset) = match vm.try_get_bo_for_va(info_va) {
        Ok(Some(hit)) => hit,
        Ok(None) | Err(()) => {
            trace::cs_fault_info_dump(group_id, cs_id, info_va, 0, 0, 0, &[]);
            return;
        }
    };

    let bo_size = bo.size() as u64;
    let bo_va_base = info_va.saturating_sub(bo_offset);

    let shmem = IntoGEMObject::as_raw(&*bo).cast::<bindings::drm_gem_shmem_object>();
    // SAFETY: `bo` is an `ARef<Bo>` where `Bo = gem::shmem::Object<_>`.
    // `Bo` is `repr(C)` with `obj: Opaque<drm_gem_shmem_object>` as its
    // first field, and `drm_gem_shmem_object` is `repr(C)` with `base:
    // drm_gem_object` as its first field, so the address returned by
    // `IntoGEMObject::as_raw` coincides with the embedded shmem
    // object. The `ARef` keeps the allocation alive for the duration
    // of this borrow. A racing `drm_gem_shmem_vunmap` could clear
    // `vaddr` between this load and the bytes loop below; if it does
    // the volatile read returns NULL and the helper falls through to
    // the no-bytes path. A racing vunmap that drops `vmap_use_count`
    // to zero after this load could in theory tear the mapping down
    // under the subsequent reads; this is a downstream-only debug aid
    // running in the dma-fence signalling section where the safe
    // alternative (re-vmap under `dma_resv_lock`) is forbidden. The
    // same direct-binding pattern is used in
    // `sched::queue::QueueData::user_stream_window_around` to read
    // `import_attach`.
    let vaddr = unsafe { core::ptr::read_volatile(&raw const (*shmem).vaddr) };
    if vaddr.is_null() {
        trace::cs_fault_info_dump(
            group_id,
            cs_id,
            info_va,
            bo_va_base,
            bo_size,
            bo_offset,
            &[],
        );
        return;
    }

    let bo_size_usz = bo_size as usize;
    let offset = bo_offset as usize;
    if offset >= bo_size_usz {
        trace::cs_fault_info_dump(
            group_id,
            cs_id,
            info_va,
            bo_va_base,
            bo_size,
            bo_offset,
            &[],
        );
        return;
    }

    let start = offset.saturating_sub(128);
    let end = offset.saturating_add(128).min(bo_size_usz);
    let len = end - start;
    let mut bytes = [0u8; 256];
    // SAFETY: `vaddr` was non-NULL on a `READ_ONCE`-style read above,
    // indicating the shmem helpers have an installed kernel mapping
    // covering `bo_size_usz` bytes starting at `vaddr`. `start..end`
    // is in bounds by construction; the mapping is shared with the
    // GPU so the reads are volatile to defeat compiler caching.
    unsafe {
        let src = (vaddr as *const u8).add(start);
        for (i, slot) in bytes[..len].iter_mut().enumerate() {
            *slot = core::ptr::read_volatile(src.add(i));
        }
    }

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

/// Reads back the value currently stored at the scoreboard slot a CS
/// is waiting on, so the trace can show whether the producer ever
/// writes the awaited value. Resolves `gpu_va` to a BO via the
/// group's VM, maps the backing page covering the slot and reads a
/// `u32` (`sync64 == false`) or `u64` (`sync64 == true`).
///
/// Returns `(value, true)` on a successful read, or `(0, false)` when
/// the BO cannot be resolved, has no backing pages, or the offset is
/// out of bounds.
///
/// Safe for use from the dma-fence signalling section that runs the CSG event
/// handler and the blocked-group poll, because the GPUVM lookup uses
/// [`Vm::try_get_bo_for_va`] (returns immediately on lock contention) and the
/// value is read through a transient `kmap_local_page` of an already-pinned
/// backing page; no allocation, no `dma_resv_lock` acquisition, no sleeping
/// wait.
pub(super) fn read_syncwait_cur_val(vm: &Vm, gpu_va: u64, sync64: bool) -> (u64, bool) {
    let (bo, bo_offset) = match vm.try_get_bo_for_va(gpu_va) {
        Ok(Some(hit)) => hit,
        Ok(None) | Err(()) => return (0, false),
    };

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

    let shmem = IntoGEMObject::as_raw(&*bo).cast::<bindings::drm_gem_shmem_object>();
    // SAFETY: `bo` is an `ARef<Bo>` where `Bo = gem::shmem::Object<_>`,
    // which is `repr(C)` with the embedded `drm_gem_shmem_object` as
    // its first field, so `IntoGEMObject::as_raw` coincides with the
    // shmem object. The `ARef` keeps the allocation alive for this
    // borrow. The BO is GPU-mapped, so its backing pages are pinned
    // and `pages` is a populated `*mut *mut page` array; `page_index`
    // is in bounds because `bo_offset + width <= bo_size` and the
    // array spans the whole BO.
    let pages = unsafe { core::ptr::read_volatile(&raw const (*shmem).pages) };
    if pages.is_null() {
        return (0, false);
    }
    // SAFETY: `pages` is non-NULL and the BO is pinned, so the entry
    // at `page_index` is a valid `struct page` pointer.
    let page = unsafe { core::ptr::read_volatile(pages.add(page_index)) };
    if page.is_null() {
        return (0, false);
    }

    // SAFETY: `page` is a pinned backing page of the live BO.
    // `kmap_local_page` returns a mapping valid for `PAGE_SIZE` bytes
    // on this task until the matching `kunmap_local`.
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
