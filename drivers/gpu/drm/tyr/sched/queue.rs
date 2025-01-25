// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;

use kernel::c_str;
use kernel::devres::Devres;
use kernel::dma_fence::FenceContexts;
use kernel::dma_fence::UserFence;
use kernel::drm::sched;
use kernel::drm::sched::Entity;
use kernel::drm::sched::Scheduler;
use kernel::drm::syncobj::SyncObj;
use kernel::io::mem::IoMem;
use kernel::prelude::*;
use kernel::sizes::SZ_4K;
use kernel::sizes::SZ_64K;
use kernel::sync::Arc;
use kernel::sync::Mutex;

use crate::driver::TyrDevice;
use crate::file::QueueCreate;
use crate::file::QueueSubmit;
use crate::fw::global::cs::RingBufferInput;
use crate::fw::global::cs::RingBufferOutput;
use crate::gem;
use crate::mmu::vm::map_flags;
use crate::mmu::vm::PreparedVm;
use crate::mmu::vm::Vm;
use crate::regs::Doorbell;
use crate::sched::job::Job;
use crate::TyrDriver;

use super::group::Group;
use super::job;

const JOB_TIMEOUT_MS: usize = 5000;
pub(crate) const CSF_MAX_QUEUE_PRIO: u32 = 15;

/// Represents a hardware executiion queue.
pub(crate) struct Queue {
    /// The DRM scheduler used for this queue.
    scheduler: Scheduler<Job>,

    /// The DRM entity used for this queue.
    entity: Entity<Job>,

    /// A priority number, between 0 and 15.
    pub(crate) priority: u8,

    // Doorbell assigned to this queue, if any.
    //
    // Doorbell assignment happens when the group that owns this queue is bound
    // to a specific hardware slot.
    //
    // Right now, all groups share the same doorbell, and the doorbell ID
    // is assigned to `group_slot + 1` when the group is assigned a slot.
    // However, we might decide to provide fine-grained doorbell assignment
    // at some point, so we don't have to wake up all queues in a group
    // every time one of them is updated.
    pub(crate) doorbell_id: Option<usize>,

    /// The ring buffer used to communicate with the firmware.
    pub(super) ringbuf: gem::ObjectRef,

    pub(super) interfaces: Interfaces,

    iomem: Arc<Devres<IoMem>>,

    pub(super) fence_ctx: FenceContexts,

    /// The in-flight jobs for this queue.
    pub(super) in_flight_jobs: KVec<UserFence<job::Fence>>,
}

impl Queue {
    pub(crate) fn new(
        tdev: &TyrDevice,
        queue_args: &QueueCreate,
        vm: Arc<Mutex<Vm>>,
    ) -> Result<Self> {
        // ugh..
        let queue_args = &queue_args.0;

        if queue_args.pad[0] != 0 || queue_args.pad[1] != 0 || queue_args.pad[2] != 0 {
            return Err(EINVAL);
        }

        if queue_args.ringbuf_size < SZ_4K as u32
            || queue_args.ringbuf_size > SZ_64K as u32
            || !queue_args.ringbuf_size.is_power_of_two()
        {
            pr_err!("Invalid ring buffer size: {:#x}\n", queue_args.ringbuf_size);
            return Err(EINVAL);
        }

        if u32::from(queue_args.priority) > CSF_MAX_QUEUE_PRIO {
            pr_err!("Invalid queue priority: {:#x}\n", queue_args.priority);
            return Err(EINVAL);
        }

        let priority = queue_args.priority;
        let credit_limit = queue_args.ringbuf_size / core::mem::size_of::<u64>() as u32;

        let scheduler = Scheduler::new(
            tdev.as_ref(),
            1,
            credit_limit,
            0,
            JOB_TIMEOUT_MS,
            c_str!("tyr-queue"),
        )?;

        let entity = Entity::new(&scheduler, sched::Priority::Kernel)?;

        let iomem = tdev.iomem.clone();
        let ringbuf = gem::new_kernel_object(
            tdev,
            iomem.clone(),
            vm.clone(),
            gem::KernelVaPlacement::Auto {
                size: queue_args.ringbuf_size as usize,
            },
            map_flags::Flags::from(map_flags::NOEXEC) | map_flags::Flags::from(map_flags::UNCACHED),
        )?;

        let mem = tdev.fw.alloc_queue_mem(tdev)?;

        let input_va = mem.kernel_va().ok_or(EINVAL)?;
        let output_start = input_va.start + SZ_4K as u64;
        let output_end = output_start + SZ_4K as u64;
        let output_va = output_start..output_end;

        let interfaces = Interfaces {
            mem,
            input_va,
            output_va,
            input_offset: 0,
            output_offset: SZ_4K,
        };

        let fence_ctx = FenceContexts::new(1, c_str!("tyr_fence"), None)?;

        Ok(Queue {
            scheduler,
            entity,
            doorbell_id: None,
            priority,
            ringbuf,
            interfaces,
            iomem,
            fence_ctx,
            in_flight_jobs: KVec::new(),
        })
    }

    /// Append instructions to this queue for execution.
    ///
    /// The queue's doorbell needs to be rung after this function is called in
    /// order to get CSF to act on the new values.
    pub(crate) fn append_instrs(&mut self, instrs: &[u8]) -> Result {
        let mut ringbuf_input = self.interfaces.read_input()?;
        let ringbuf_sz = self.ringbuf.size() as u64;

        let cs_insert = ringbuf_input.insert & (ringbuf_sz - 1);
        let cs_insert = cs_insert as usize;

        let range = cs_insert..cs_insert + instrs.len();

        let ringbuf = self.ringbuf.vmap()?;
        let ringbuf = ringbuf.as_mut_slice();

        ringbuf[range].copy_from_slice(instrs);

        // Make sure that the ring buffer is updated before the INSERT register.
        kernel::sync::barrier::smp_wmb();

        ringbuf_input.insert += instrs.len() as u64;

        self.interfaces.write_input(ringbuf_input)?;
        Ok(())
    }

    /// Kick the queue. This will notify CSF that new instructions are ready to
    /// be executed.
    pub(crate) fn kick(&self) -> Result {
        Doorbell::new(self.doorbell_id.ok_or(EINVAL)?).write(&self.iomem, 1)
    }

    pub(crate) fn submit(
        &mut self,
        in_syncs: &KVec<SyncObj<TyrDriver>>,
        out_syncs: &KVec<SyncObj<TyrDriver>>,
        group: Arc<Group>,
        sync_addr: u64,
        queue_submit: QueueSubmit,
        _: &PreparedVm<'_>,
    ) -> Result<UserFence<job::Fence>> {
        let fence: UserFence<_> = self
            .fence_ctx
            .new_fence(0, crate::sched::job::Fence)?
            .into();

        let job = Job::create(queue_submit, group, fence.clone(), sync_addr)?;

        let mut job = self.entity.new_job(1, job)?.arm();
        let out_fence = job.fences().finished();

        job.push();

        for sync in out_syncs {
            sync.replace_fence(Some(&out_fence));
        }

        Ok(fence)
    }
}

/// The interface for ring buffer control.
pub(crate) struct Interfaces {
    /// The memory used to hold the user input/output blocks.
    mem: gem::ObjectRef,

    /// The input VA range for the interface.
    pub(super) input_va: Range<u64>,

    /// The output VA range for the interface.
    pub(super) output_va: Range<u64>,

    /// The input area for the ring buffer control.
    input_offset: usize,
    /// The output area for the ring buffer control.
    output_offset: usize,
}

impl Interfaces {
    pub(super) fn read_input(&mut self) -> Result<RingBufferInput> {
        let vmap = self.mem.vmap()?;
        let input = unsafe {
            vmap.as_mut_ptr()
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .read_volatile()
        };

        Ok(input)
    }

    pub(super) fn write_input(&mut self, value: RingBufferInput) -> Result {
        let vmap = self.mem.vmap()?;
        unsafe {
            vmap.as_mut_ptr()
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .write_volatile(value)
        };

        Ok(())
    }

    pub(super) fn read_output(&mut self) -> Result<RingBufferOutput> {
        let vmap = self.mem.vmap()?;
        let output = unsafe {
            vmap.as_mut_ptr()
                .add(self.output_offset)
                .cast::<RingBufferOutput>()
                .read_volatile()
        };

        Ok(output)
    }
}
