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
    driver::{TyrDrmDevice, TyrDrmDeviceData},
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
    impl HasWork<TyrDrmDevice, 4> for TyrDrmDeviceData { self.tiler_oom_work }
}

impl WorkItem<4> for TyrDrmDeviceData {
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

    fn process_csg_irq(&mut self, tdev: &TyrDrmDevice, csg_id: usize) -> Result<bool> {
        let group = match self.csg_slots.get(csg_id).and_then(Option::as_ref) {
            Some(slot) => slot.group.clone(),
            None => return Ok(false),
        };

        let mut queued_tiler_oom = false;
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
            }

            Ok(())
        })?;

        Ok(queued_tiler_oom)
    }

    fn collect_pending_tiler_ooms(&mut self, tdev: &TyrDrmDevice) -> Result<KVec<PendingOom>> {
        let mut pending = KVec::new();

        for (csg_id, slot) in self.csg_slots.iter().enumerate() {
            let slot = match slot.as_ref() {
                Some(slot) => slot,
                None => continue,
            };

            let oom_mask = slot.group.tiler_oom.swap(0, Ordering::Relaxed);
            if oom_mask == 0 {
                continue;
            }

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
                        group: slot.group.clone(),
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
            match self.csg_slots.get(oom.csg_id).and_then(Option::as_ref) {
                Some(slot) if Arc::ptr_eq(&slot.group, &oom.group) => {}
                _ => continue,
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
