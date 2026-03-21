// SPDX-License-Identifier: GPL-2.0 or MIT

use group::Group;
use kernel::bits::checked_bit_u32;
use kernel::bits::genmask_u32;
use kernel::dma_fence::DmaFenceWorkqueue;
use kernel::drm::gem::BaseObject;
use kernel::kvec;
use kernel::prelude::*;
use kernel::sizes::SZ_4K;
use kernel::sync::Arc;
use kernel::time::Delta;
use kernel::time::Instant;
use queue::Queue;

use crate::driver::TyrData;
use crate::driver::TyrDevice;
use crate::file::DrmFile;
use crate::file::QueueSubmit;
use crate::file::SyncOp;
use crate::fw::global::cs::CommandStream;
use crate::fw::global::cs::StreamState;
use crate::fw::global::csg;
use crate::fw::global::csg::Priority;
use crate::fw::global::csg::MAX_CSGS;
use crate::fw::SharedSectionEntry;
use crate::gem;
use crate::mmu::vm::WithLockedVm;

pub(crate) mod deps;
mod events;
pub(crate) mod group;
pub(crate) mod job;
pub(crate) mod queue;
mod syncs;
mod tick;

const MAX_CSG_PRIO: u32 = 0xf;

/// The scheduler object.
pub(crate) enum SchedulerState {
    /// The driver is probing.
    Disabled,
    /// The firmware has booted and the scheduler has been initialized.
    Enabled(Scheduler),
}

impl SchedulerState {
    pub(crate) fn init(&mut self, tdev: &TyrDevice) -> Result {
        let scheduler = Scheduler::init(tdev)?;
        *self = SchedulerState::Enabled(scheduler);
        Ok(())
    }

    pub(crate) fn enabled_mut(&mut self) -> Result<&mut Scheduler> {
        match self {
            SchedulerState::Enabled(scheduler) => Ok(scheduler),
            SchedulerState::Disabled => Err(EINVAL),
        }
    }
}

pub(crate) struct Scheduler {
    /// Groups that have at least one queue that can be currently scheduled.
    runnable_groups: [KVec<Arc<Group>>; Priority::num_priorities()],
    /// Groups that have all their queues idle, either because they have nothing
    /// to execute, or because they are blocked.
    idle_groups: [KVec<Arc<Group>>; Priority::num_priorities()],
    /// List of groups whose queues are blocked on a sync object.
    #[expect(dead_code)]
    waiting_groups: [KVec<Arc<Group>>; Priority::num_priorities()],

    /// Groups that have been flagged by a STATUS_UPDATE event, but that have
    /// not yet been processed.
    unsynced_groups: KVec<Arc<Group>>,

    csg_slots: [Option<CommandStreamGroupSlot>; 31],

    /// Number of command stream group slots exposed by the firmware.
    csg_slot_count: u32,

    /// Number of command stream slots per group slot exposed by the firmware.
    #[expect(dead_code)]
    cs_slot_count: u32,

    /// Number of address space slots supported by the MMU.
    #[expect(dead_code)]
    as_slot_count: u32,

    /// Number of command stream group slots currently in use.
    #[expect(dead_code)]
    used_csg_slot_count: u32,

    /// Number of scoreboard slots.
    #[expect(dead_code)]
    sb_slot_count: u32,

    /// Workqueue used by our internal scheduler logic.
    ///
    /// Used for the scheduler tick, group update or other kinds of FW event
    /// processing that cannot be handled in the threaded interrupt path. Also
    /// passed to the job queues embedded in our GPU queues.
    wq: Arc<DmaFenceWorkqueue>,

    /// When the next tick should occur.
    resched_target: Option<Instant<kernel::time::RealTime>>,

    /// Outstanding firmware events.
    events: Option<u32>,
}

impl Scheduler {
    pub(crate) fn init(tdev: &TyrDevice) -> Result<Self> {
        let (group_num, sb_slot_count, cs_slot_count, cs_reg_count) =
            tdev.fw.with_locked_global_iface(|glb_iface| {
                let glb_control = glb_iface.read_control()?;

                let csg = glb_iface.csg(0).ok_or(EINVAL)?;
                let csg_control = csg.read_control()?;

                let cs = csg.cs(0).ok_or(EINVAL)?;
                let cs_control = cs.read_control()?;

                let group_num = glb_control.group_num;
                let sb_slot_count = cs_control.scoreboards();
                let cs_slot_count = csg_control.stream_num;
                let cs_reg_count = cs_control.work_regs();

                Ok((group_num, sb_slot_count, cs_slot_count, cs_reg_count))
            })?;

        let num_groups = core::cmp::min(MAX_CSGS, group_num);

        // The firmware-side scheduler might deadlock if two groups with the same
        // priority try to access a set of resources that overlaps, with part of the
        // resources being allocated to one group and the other part to the other group,
        // both groups waiting for the remaining resources to be allocated.
        //
        // To avoid that, it is recommended to assign each Command Stream Group (CSG)
        // a different priority. In theory, several groups could have the same CSG
        // priority if they don't request the same resources, but that would make the
        // scheduling logic more complicated.
        //
        // For now, the number of CSG slots is clamped to `MAX_CSG_PRIO + 1`.
        let num_groups = core::cmp::min(MAX_CSG_PRIO + 1, num_groups);

        // We need at least one AS for the MCU and one for the GPU contexts.
        let gpu_as_count = tdev.gpu_info.as_present & genmask_u32(1..=31);
        let gpu_as_count = gpu_as_count.count_ones();

        // Each CSG needs its own AS, so limit CSG count to available AS count
        let csg_slot_count = core::cmp::min(num_groups, gpu_as_count);
        let as_slot_count = gpu_as_count;

        let wq = tdev.wq.clone();

        // Populate CSIF info in TyrDevice
        {
            use crate::fw::global::cs::CSF_UNPRESERVED_REG_COUNT;
            let mut csif = tdev.csif_info.lock();
            csif.csg_slot_count = csg_slot_count;
            csif.cs_slot_count = cs_slot_count;
            csif.cs_reg_count = cs_reg_count;
            csif.scoreboard_slot_count = sb_slot_count;
            csif.unpreserved_cs_reg_count = CSF_UNPRESERVED_REG_COUNT;
        }

        Ok(Self {
            runnable_groups: [const { KVec::new() }; Priority::num_priorities()],
            idle_groups: [const { KVec::new() }; Priority::num_priorities()],
            waiting_groups: [const { KVec::new() }; Priority::num_priorities()],
            unsynced_groups: KVec::new(),
            csg_slots: [const { None }; 31],
            csg_slot_count,
            cs_slot_count,
            as_slot_count,
            used_csg_slot_count: 0,
            sb_slot_count,
            wq,
            resched_target: None,
            events: None,
        })
    }

    /// Bind a group to a group slot.
    ///
    /// A group needs to be bound before it can be programmed into one of the
    /// firmware slots for execution.
    pub(crate) fn bind_group(
        &mut self,
        data: &TyrData,
        group: Arc<Group>,
        csg_idx: usize,
    ) -> Result {
        if csg_idx >= self.csg_slot_count as usize {
            pr_err!("bind_group: invalid group index {}", csg_idx);
            return Err(EINVAL);
        }

        group.with_locked_inner(|inner| {
            if inner.csg_id.is_some() {
                pr_err!("bind_group: group already bound to a CSG");
                return Err(EINVAL);
            }
            Ok(())
        })?;

        if self.csg_slots[csg_idx].is_some() {
            pr_err!("bind_group: group slot already in use");
            return Err(EINVAL);
        }

        let gpu_info = &data.gpu_info;
        let iomem = &data.iomem;

        data.with_locked_mmu(|mmu| mmu.bind_vm(group.vm.clone(), gpu_info, iomem))?;

        self.csg_slots[csg_idx] = Some(CommandStreamGroupSlot {
            group: group.clone(),
            priority: Priority::Low,
            idle: false,
        });

        group.with_locked_inner(|inner| {
            inner.csg_id = Some(csg_idx);
            // Dummy doorbell allocation: doorbell is assigned to the group and all
            // queues use the same doorbell.
            //
            // TODO: Implement LRU-based doorbell assignment, so the most often
            // updated queues get their own doorbell, thus avoiding useless checks
            // on queues belonging to the same group that are rarely updated.
            for queue in &mut inner.queues {
                queue.doorbell_id = Some(csg_idx + 1);
                queue.job_queue.unpark();
            }

            Ok(())
        })
    }

    pub(crate) fn set_csg_state(
        &mut self,
        data: &TyrData,
        csg_idx: usize,
        state: csg::GroupState,
    ) -> Result {
        if csg_idx >= self.csg_slot_count as usize {
            return Err(EINVAL);
        }

        data.fw.with_locked_global_iface(|glb_iface| {
            glb_iface.set_csg_state(csg_idx, state)?;
            glb_iface.ring_csg_doorbell(csg_idx)?;
            glb_iface.wait_csg_acks(csg_idx, csg::constants::CSG_STATE_MASK, 100)?;
            Ok(())
        })
    }

    /// Unbind a group from group slot.
    pub(crate) fn unbind_group(
        &mut self,
        data: &TyrData,
        csg_idx: usize,
    ) -> Result<CommandStreamGroupSlot> {
        if csg_idx >= self.csg_slot_count as usize {
            pr_err!("unbind_group: invalid group index {}", csg_idx);
            return Err(EINVAL);
        }
        if self.csg_slots[csg_idx].is_none() {
            pr_err!("unbind_group: group slot already empty");
            return Err(EINVAL);
        }

        let slot = self.csg_slots[csg_idx].as_mut().ok_or(EINVAL)?;

        slot.group.with_locked_inner(|inner| {
            // Park all queues first, before releasing any hardware resources.
            // This ensures tick_exec() cannot attempt to submit jobs after
            // we've unbound the VM and cleared the doorbells.
            for queue in &mut inner.queues {
                queue.job_queue.park();
            }

            inner.csg_id = None;

            for queue in &mut inner.queues {
                queue.doorbell_id = None;
            }
            Ok(())
        })?;

        data.with_locked_mmu(|mmu| {
            mmu.unbind_vm(&slot.group.vm, &data.iomem)?;
            Ok(())
        })?;

        let slot = self.csg_slots[csg_idx].take().ok_or(EINVAL)?;
        return Ok(slot);
    }

    /// Program a group (and its queues) into a firmware slot. This will make
    /// the group eligible for execution from a FW perspective.
    // TODO: this can be private
    pub(crate) fn program_csg_slot(
        &mut self,
        data: &TyrData,
        csg_idx: usize,
        priority: Priority,
    ) -> Result {
        if priority as u32 > MAX_CSG_PRIO {
            pr_err!("program_csg_slot: invalid priority {}\n", priority as u32);
            return Err(EINVAL);
        }

        if csg_idx > MAX_CSGS as usize {
            pr_err!("program_csg_slot: invalid csg {}\n", csg_idx);
            return Err(EINVAL);
        }

        let slot = self.csg_slots[csg_idx].as_ref().ok_or(EINVAL)?;
        let group = slot.group.clone();
        let as_nr = group
            .vm
            .lock()
            .address_space()
            .map(|a| a as u32)
            .ok_or(EINVAL)?;

        // let group_inner = group.inner.lock();

        let fw = &data.fw;

        // Controls which CSn doorbells will be rung.
        //
        // This will process any requests in the CSn request field, and also
        // check for new work on the ring buffer.
        let queue_mask = fw.with_locked_global_iface(|glb_iface| {
            group.with_locked_inner(|inner| {
                if let group::State::Active = inner.state {
                    pr_err!("program_csg_slot: group is already active\n");
                    return Err(EINVAL);
                }

                let mut queue_mask = 0;

                let csg_iface = glb_iface.csg_mut(csg_idx).ok_or(EINVAL)?;

                for (cs_idx, queue) in inner.queues.iter_mut().enumerate() {
                    let cs_iface = csg_iface.cs_mut(cs_idx).ok_or(EINVAL)?;

                    self.program_cs_slot(queue, cs_iface)?;
                    queue_mask |= checked_bit_u32(cs_idx as u32).ok_or(EINVAL)?;
                }

                Ok(queue_mask)
            })
        })?;

        let mut input = fw.with_locked_global_iface(|glb_iface| {
            glb_iface.csg_mut(csg_idx).ok_or(EINVAL)?.read_input()
        })?;

        input.allow_compute = group.compute_core_mask;
        input.allow_fragment = group.fragment_core_mask;
        input.allow_other = group.tiler_core_mask.try_into()?;

        input.set_endpoint_req(
            group.max_compute_cores.into(),
            group.max_fragment_cores.into(),
            group.max_tiler_cores.into(),
            csg_idx,
        );

        input.csg_config = as_nr;

        input.suspend_buf = group.suspend_buf.kernel_va().ok_or(EINVAL)?.start;
        input.protm_suspend_buf = group.protm_suspend_buf.kernel_va().ok_or(EINVAL)?.start;

        input.ack_irq_mask = u32::MAX;

        let group_state = group.with_locked_inner(|inner| Ok(inner.state))?;
        let csg_state = if group_state == group::State::Suspended {
            csg::GroupState::Resume
        } else {
            csg::GroupState::Start
        };

        fw.with_locked_global_iface(|glb_iface| {
            let csg_iface = glb_iface.csg_mut(csg_idx).ok_or(EINVAL)?;
            csg_iface.write_input(input)?;

            let db_req = csg_iface.doorbell_request()?;
            db_req.toggle_reqs(queue_mask)?;

            glb_iface.set_csg_state(csg_idx, csg_state)?;
            glb_iface.ring_csg_doorbell(csg_idx)
        })?;

        group.with_locked_inner(|inner| {
            inner.state = group::State::Active;
            Ok(())
        })
    }

    /// Program a queue in a firmware slot. This makes the queue eligible for
    /// execution from a FW perspective.
    ///
    /// Queues are alloted slots when their group is itself programmed into a
    /// CSG slot.
    fn program_cs_slot(&mut self, queue: &mut Queue, cs_iface: &mut CommandStream) -> Result {
        let doorbell_id = queue.doorbell_id.ok_or(EINVAL)?;
        let mut cs_input = cs_iface.read_input()?;

        let mut ringbuf_input = queue.interfaces.read_input()?;
        let ringbuf_output = queue.interfaces.read_output()?;
        ringbuf_input.extract_init = ringbuf_output.extract;
        let _ = queue.interfaces.write_input(ringbuf_input);

        cs_input.ringbuf_base = queue.ringbuf.kernel_va().ok_or(EINVAL)?.start;
        cs_input.ringbuf_size = queue.ringbuf.size() as u32;

        cs_input.ringbuf_input = queue.interfaces.input_va.start;
        cs_input.ringbuf_output = queue.interfaces.output_va.start;

        cs_input.set_priority(queue.priority)?;
        cs_input.set_doorbell_id(doorbell_id as u32)?;
        cs_input.ack_irq_mask = u32::MAX;

        cs_iface.write_input(cs_input)?;

        cs_iface.set_state(StreamState::Start)
    }

    pub(crate) fn bind(&mut self, tdev: &TyrDevice, group: Arc<Group>) -> Result {
        let already_bound = group.with_locked_inner(|inner| Ok(inner.csg_id.is_some()))?;

        if already_bound {
            return Ok(());
        }

        let csg_idx = self.find_free_slot(tdev)?;
        pr_info!("Binding group to CSG slot {}\n", csg_idx);
        self.bind_group(tdev, group, csg_idx)?;
        self.program_csg_slot(tdev, csg_idx, Priority::Low)
    }

    /// Find a free slot by either searching within the valid CSG slots (those
    /// initialized in firmware) or evicting an idle group.
    fn find_free_slot(&mut self, tdev: &TyrDevice) -> Result<usize> {
        let csg_idx = self
            .csg_slots
            .iter()
            .take(self.csg_slot_count as usize)
            .position(|slot| slot.is_none());

        if let Some(idx) = csg_idx {
            Ok(idx)
        } else {
            self.evict_idle_group(tdev)
        }
    }

    fn evict_idle_group(&mut self, tdev: &TyrDevice) -> Result<usize> {
        let mut idx = None;
        for (i, slot) in self
            .csg_slots
            .iter()
            .take(self.csg_slot_count as usize)
            .enumerate()
        {
            let Some(s) = slot else { continue };

            let has_idle_queues = s
                .group
                .with_locked_inner(|inner| Ok(inner.queues.iter().all(|q| q.timeline.is_idle())))?;

            if has_idle_queues {
                idx = Some(i);
                break;
            }
        }

        let idx = idx.ok_or_else(|| {
            pr_info!("No idle group to evict\n");
            EBUSY
        })?;

        if let Some(s) = &mut self.csg_slots[idx] {
            s.idle = true;
        }

        self.set_csg_state(tdev, idx, csg::GroupState::Suspend)?;

        if let Some(s) = &self.csg_slots[idx] {
            s.group.with_locked_inner(|inner| {
                inner.state = group::State::Suspended;
                Ok(())
            })?;
        }

        let evicted_slot = self.unbind_group(tdev, idx)?;
        let priority = evicted_slot.priority;
        self.idle_groups[priority as usize].push(evicted_slot.group.clone(), GFP_KERNEL)?;

        pr_info!("Evicted idle group from CSG slot {}\n", idx);
        Ok(idx)
    }

    // place a dummy instruction in the first CS for the given group and kick
    // it, just to make sure the ringbuf code is working.
    #[expect(dead_code)]
    pub(crate) fn issue_dummy_instr(&mut self, group: Arc<Group>, tdev: &TyrDevice) -> Result {
        self.bind(tdev, group.clone())?;

        let iomem = tdev.iomem.clone();

        use crate::mmu::vm::map_flags;
        let flags =
            map_flags::Flags::from(map_flags::NOEXEC) | map_flags::Flags::from(map_flags::UNCACHED);

        let mut debug_gem = group.vm.with_lock_taken(|vm| {
            gem::new_kernel_object(
                tdev,
                iomem,
                vm,
                gem::KernelVaPlacement::Auto { size: SZ_4K },
                flags,
            )
        })?;

        let mut instrs = kvec![];

        // load the source register ([r64; r65]) with the right address to store.
        let opcode = 0x1;
        let reg_num = 64;
        let immd = debug_gem.kernel_va().ok_or(EINVAL)?.start;
        let mov48: u64 = opcode << 56 | reg_num << 48 | immd;

        instrs.extend_from_slice(&mov48.to_le_bytes(), GFP_KERNEL)?;

        // load a known constant into r66.
        let opcode = 0x1;
        let reg_num = 66;
        let immd = 0xdeadbeef;
        let mov48: u64 = opcode << 56 | reg_num << 48 | immd;

        instrs.extend_from_slice(&mov48.to_le_bytes(), GFP_KERNEL)?;

        let opcode = 0x15; // STORE_MULTIPLE
        let register_bitmap = 1; // store the first register
        let sr = 66; // starting from register 66
        let src0 = 64; // to the address pointed to by [r64; r65]
        let offset = 0; // and this offset

        let store_multiple: u64 =
            opcode << 56 | sr << 48 | src0 << 40 | register_bitmap << 16 | offset;

        instrs.extend_from_slice(&store_multiple.to_le_bytes(), GFP_KERNEL)?;

        group.with_locked_inner(|inner| {
            let queue = inner.queues.get_mut(0).ok_or(EINVAL)?;
            queue.append_instrs(&instrs)?;
            queue.kick()
        })?;

        // We are not using any syncobjs, so we must sleep for a while to check
        // for completion.
        kernel::time::delay::fsleep(Delta::from_millis(100));

        // Read the address where the GPU is supposed to have written the value.
        let vmap = debug_gem.vmap()?;
        let size = vmap.owner().size();
        let vmap = vmap.get();
        let bytes = unsafe { vmap.as_slice(0, size)? };
        let value = u32::from_le_bytes(bytes[0..4].try_into().unwrap());

        pr_info!("issue_dummy_instr expected 0xdeadbeef, got 0x{:x}\n", value);
        Ok(())
    }

    pub(crate) fn submit(
        &mut self,
        syncs: KVec<SyncOp>,
        group: Arc<Group>,
        queue_submits: KVec<QueueSubmit>,
        file: &DrmFile,
    ) -> Result {
        group.submit(syncs, queue_submits, file)?;
        Ok(())
    }
}

pub(crate) struct CommandStreamGroupSlot {
    /// The group that is bound to this slot.
    pub(crate) group: Arc<Group>,

    /// Group priority.
    pub(crate) priority: Priority,

    /// The if the group bound to the slot is idle.
    pub(crate) idle: bool,
}
