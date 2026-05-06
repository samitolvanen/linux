// SPDX-License-Identifier: GPL-2.0 or MIT

use core::{
    ops::{
        Deref,
        Range,
    },
    sync::atomic::{
        AtomicU64,
        AtomicUsize,
        Ordering,
    },
};

use kernel::{
    alloc::KVec,
    bindings,
    c_str,
    dma_buf::dma_fence::{
        DmaFenceSignallingAnnotation,
        DmaFenceWorkqueue,
        DriverDmaFence,
        DriverDmaFenceOps,
        PublicDmaFence,
        Published,
    },
    drm::{
        gem::BaseObject,
        job_queue::{
            JobQueue,
            JobQueueLockClasses,
            JobRef,
            PipelineBuilder,
            PreparedJob,
            QueueOps,
            StageAdvance,
            StageContext,
            StageOps,
            SubmitResult,
        },
    },
    io::Io,
    io::register::Array,
    new_mutex,
    prelude::*,
    sizes::SZ_4K,
    sizes::SZ_64K,
    sync::{
        aref::ARef,
        Arc,
        LockClassKey,
        Mutex,
    },
    time::{
        Jiffies,
        msecs_to_jiffies,
    },
    transmute::FromBytes,
    uapi,
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice,
    },
    gem,
    regs::doorbell_block,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags,
    },
};

const UNASSIGNED_DOORBELL_ID: usize = usize::MAX;
const JOB_POLL_INTERVAL_MS: u32 = 1;
const JOB_TIMEOUT_MS: u32 = 5000;

static TYR_QUEUE_INBOX_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_STATE_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_CLEANUP_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_STAGE_WORK_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_STAGE_TIMER_LOCK_CLASS: LockClassKey = unsafe { LockClassKey::new_static() };
static TYR_QUEUE_DRIVER_FENCE_LOCK_CLASS: LockClassKey =
    unsafe { LockClassKey::new_static() };

#[repr(transparent)]
pub(crate) struct QueueCreate(uapi::drm_panthor_queue_create);

// SAFETY: This wrapper is layout-identical to the UAPI queue-create record
// read from userspace.
unsafe impl FromBytes for QueueCreate {}

impl QueueCreate {
    pub(crate) fn validate(&self) -> Result {
        if self.0.pad != [0; 3] {
            return Err(EINVAL);
        }

        if self.0.priority > 15 {
            return Err(EINVAL);
        }

        if self.0.ringbuf_size < SZ_4K as u32
            || self.0.ringbuf_size > SZ_64K as u32
            || !self.0.ringbuf_size.is_power_of_two()
        {
            return Err(EINVAL);
        }

        Ok(())
    }

    pub(crate) fn priority(&self) -> u8 {
        self.0.priority
    }

    pub(crate) fn ringbuf_size(&self) -> u32 {
        self.0.ringbuf_size
    }
}

#[derive(Default)]
pub(super) struct QueueFenceData;

#[vtable]
impl DriverDmaFenceOps for QueueFenceData {
    fn driver_name(&self) -> &'static CStr {
        c_str!("tyr")
    }

    fn timeline_name(&self) -> &'static CStr {
        c_str!("tyr_queue")
    }
}

struct PendingSubmitFence {
    completion_point: u64,
    fence: DriverDmaFence<QueueFenceData, Published>,
}

pub(super) struct QueueJob {
    stream: KVec<u8>,
    completion_point: AtomicU64,
}

impl QueueJob {
    pub(super) fn new(stream: KVec<u8>) -> Self {
        Self {
            stream,
            completion_point: AtomicU64::new(0),
        }
    }

    fn completion_point(&self) -> Option<u64> {
        match self.completion_point.load(Ordering::Acquire) {
            0 => None,
            completion_point => Some(completion_point),
        }
    }

    fn set_completion_point(&self, completion_point: u64) {
        self.completion_point
            .store(completion_point, Ordering::Release);
    }
}

#[pin_data]
pub(crate) struct QueueData {
    #[allow(dead_code)]
    priority: u8,
    ringbuf: Arc<gem::MappedBo>,
    interfaces: Interfaces,
    doorbell_id: AtomicUsize,
    next_seqno: AtomicU64,
    iomem: Arc<kernel::devres::Devres<IoMem>>,
    #[pin]
    pending_submit_fences: Mutex<KVec<PendingSubmitFence>>,
}

impl QueueData {
    fn ringbuf_space_for(&self, instr_count: usize) -> Result<RingBufferInput> {
        let ringbuf_input = self.interfaces.read_input()?;
        let ringbuf_sz = self.ringbuf.size() as u64;
        let ringbuf_output = self.interfaces.read_output()?;
        let used = ringbuf_input
            .insert
            .checked_sub(ringbuf_output.extract)
            .ok_or(EIO)?;

        if instr_count as u64 > ringbuf_sz {
            return Err(ENOSPC);
        }

        if used > ringbuf_sz || instr_count as u64 > ringbuf_sz - used {
            return Err(ENOSPC);
        }

        Ok(ringbuf_input)
    }

    fn doorbell_id(&self) -> Option<usize> {
        let doorbell_id = self.doorbell_id.load(Ordering::Relaxed);

        if doorbell_id == UNASSIGNED_DOORBELL_ID {
            None
        } else {
            Some(doorbell_id)
        }
    }

    pub(super) fn set_doorbell_id(&self, doorbell_id: Option<usize>) {
        self.doorbell_id.store(
            doorbell_id.unwrap_or(UNASSIGNED_DOORBELL_ID),
            Ordering::Relaxed,
        );
    }

    pub(super) fn can_append(&self, instr_count: usize) -> Result {
        self.ringbuf_space_for(instr_count)?;
        Ok(())
    }

    pub(super) fn claim_seqno(&self) -> u64 {
        self.next_seqno.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn append_instrs(&self, instrs: &[u8]) -> Result<u64> {
        let mut ringbuf_input = self.ringbuf_space_for(instrs.len())?;
        let ringbuf_sz = self.ringbuf.size() as u64;
        let ringbuf_output = self.interfaces.read_output()?;

        let cs_insert = (ringbuf_input.insert & (ringbuf_sz - 1)) as usize;

        let ringbuf = self.ringbuf.vmap();
        let size = ringbuf.owner().size();
        // SAFETY: `ringbuf` owns a writable CPU mapping for the queue ring buffer
        // and `size` matches the mapped object size.
        let bytes = unsafe { core::slice::from_raw_parts_mut(ringbuf.addr() as *mut u8, size) };

        let first_chunk = core::cmp::min(size - cs_insert, instrs.len());
        bytes[cs_insert..cs_insert + first_chunk].copy_from_slice(&instrs[..first_chunk]);
        if first_chunk < instrs.len() {
            bytes[..instrs.len() - first_chunk].copy_from_slice(&instrs[first_chunk..]);
        }

        kernel::sync::barrier::smp_wmb();

        ringbuf_input.extract_init = ringbuf_output.extract;
        ringbuf_input.insert += instrs.len() as u64;
        let completion_point = ringbuf_input.insert;

        self.interfaces.write_input(ringbuf_input)?;
        kernel::sync::barrier::smp_wmb();
        Ok(completion_point)
    }

    pub(super) fn kick(&self) -> Result {
        let io = self.iomem.try_access().ok_or(EINVAL)?;
        let doorbell_reg =
            doorbell_block::DOORBELL::try_at(self.doorbell_id().ok_or(EINVAL)?).ok_or(EINVAL)?;

        io.try_write(
            doorbell_reg,
            doorbell_block::DOORBELL::zeroed().with_ring(true),
        )
    }

    fn reserve_pending_submit_fence(&self) -> Result {
        self.pending_submit_fences
            .lock()
            .reserve(1, GFP_KERNEL)
            .map_err(Error::from)
    }

    fn add_pending_submit_fence(
        &self,
        completion_point: u64,
        fence: DriverDmaFence<QueueFenceData, Published>,
    ) -> core::result::Result<(), (Error, DriverDmaFence<QueueFenceData, Published>)> {
        let pending_fence = PendingSubmitFence {
            completion_point,
            fence,
        };

        match self
            .pending_submit_fences
            .lock()
            .push_within_capacity(pending_fence)
        {
            Ok(()) => Ok(()),
            Err(err) => Err((EINVAL, err.0.fence)),
        }
    }

    fn signal_submit_fences_up_to(&self, completion_point: u64, result: Result) {
        loop {
            let pending_fence = {
                let mut pending = self.pending_submit_fences.lock();

                match pending.first() {
                    Some(pending_fence) if pending_fence.completion_point <= completion_point => {
                        pending.remove(0).ok()
                    }
                    _ => None,
                }
            };

            let Some(pending_fence) = pending_fence else {
                break;
            };

            let _annotation = DmaFenceSignallingAnnotation::new();
            pending_fence.fence.signal(result);
        }
    }

    fn signal_submit_fence(&self, completion_point: u64, result: Result) -> bool {
        let pending_fence = {
            let mut pending = self.pending_submit_fences.lock();
            let mut position = None;

            for (index, pending_fence) in pending.iter().enumerate() {
                if pending_fence.completion_point == completion_point {
                    position = Some(index);
                    break;
                }
            }

            position.and_then(|index| pending.remove(index).ok())
        };

        let Some(pending_fence) = pending_fence else {
            return false;
        };

        let _annotation = DmaFenceSignallingAnnotation::new();
        pending_fence.fence.signal(result);
        true
    }

    fn complete_submit_fences(&self) -> Result {
        let ringbuf_output = self.interfaces.read_output()?;
        self.signal_submit_fences_up_to(ringbuf_output.extract, Ok(()));
        Ok(())
    }
}

pub(super) struct TyrQueueOps {
    data: Arc<QueueData>,
}

impl QueueOps for TyrQueueOps {
    type Job = QueueJob;
    type FenceData = QueueFenceData;

    fn lock_classes() -> JobQueueLockClasses {
        JobQueueLockClasses {
            inbox: &TYR_QUEUE_INBOX_LOCK_CLASS,
            state: &TYR_QUEUE_STATE_LOCK_CLASS,
            work: &TYR_QUEUE_WORK_LOCK_CLASS,
            cleanup_work: &TYR_QUEUE_CLEANUP_WORK_LOCK_CLASS,
            stage_work: &TYR_QUEUE_STAGE_WORK_LOCK_CLASS,
            stage_timer: &TYR_QUEUE_STAGE_TIMER_LOCK_CLASS,
            driver_fence: &TYR_QUEUE_DRIVER_FENCE_LOCK_CLASS,
        }
    }

    fn submit(
        &self,
        job: &JobRef<'_, Self::Job>,
        fence: DriverDmaFence<Self::FenceData, Published>,
        _wq: &DmaFenceWorkqueue,
    ) -> Result<SubmitResult<Self::FenceData>> {
        if job.job.stream.is_empty() {
            fence.signal(Ok(()));
            return Ok(SubmitResult::Submitted);
        }

        if self.data.doorbell_id().is_none() {
            return Ok(SubmitResult::NoResources(fence));
        }

        if job.job.stream.len() as u64 > self.data.ringbuf.size() as u64 {
            fence.signal(Err(ENOSPC));
            return Err(ENOSPC);
        }

        if let Err(err) = self.data.can_append(job.job.stream.len()) {
            if err == ENOSPC {
                return Ok(SubmitResult::NoResources(fence));
            }

            fence.signal(Err(err));
            return Err(err);
        }

        if let Err(err) = self.data.reserve_pending_submit_fence() {
            fence.signal(Err(err));
            return Err(err);
        }

        let completion_point = match self.data.append_instrs(&job.job.stream) {
            Ok(completion_point) => completion_point,
            Err(err) => {
                fence.signal(Err(err));
                return Err(err);
            }
        };

        job.job.set_completion_point(completion_point);

        if let Err((err, fence)) = self.data.add_pending_submit_fence(completion_point, fence) {
            fence.signal(Err(err));
            return Err(err);
        }

        if let Err(err) = self.data.kick() {
            self.data.signal_submit_fence(completion_point, Err(err));
            return Err(err);
        }

        Ok(SubmitResult::Submitted)
    }
}

struct QueueCompletionStage {
    data: Arc<QueueData>,
    poll_interval: Jiffies,
    timeout: Jiffies,
}

impl StageOps<TyrQueueOps> for QueueCompletionStage {
    fn process(&self, ctx: &StageContext<'_, TyrQueueOps>) -> StageAdvance {
        if ctx.submit_fence.is_signaled() {
            return StageAdvance::Advance;
        }

        if let Err(err) = self.data.complete_submit_fences() {
            if let Some(completion_point) = ctx.job.completion_point() {
                self.data.signal_submit_fence(completion_point, Err(err));
            }
            return StageAdvance::TimedOut(err);
        }

        if ctx.submit_fence.is_signaled() {
            return StageAdvance::Advance;
        }

        let elapsed = msecs_to_jiffies(ctx.stage_elapsed().as_millis().max(0) as u32);
        if elapsed >= self.timeout {
            pr_err!("Tyr queue job {} timed out\n", ctx.counter);
            if let Some(completion_point) = ctx.job.completion_point() {
                self.data
                    .signal_submit_fence(completion_point, Err(ETIMEDOUT));
            }
            return StageAdvance::TimedOut(ETIMEDOUT);
        }

        StageAdvance::WaitFor(self.poll_interval)
    }

    fn teardown(&self, job: &QueueJob, _counter: u64) {
        if let Some(completion_point) = job.completion_point() {
            self.data.signal_submit_fence(
                completion_point,
                Err(Error::from_errno(-(bindings::ECANCELED as i32))),
            );
        }
    }
}

pub(super) type PreparedQueueJob = PreparedJob<TyrQueueOps>;

/// A minimal hardware queue object owned by a scheduling group.
pub(crate) struct Queue {
    data: Arc<QueueData>,
    job_queue: JobQueue<TyrQueueOps>,
}

impl Queue {
    pub(crate) fn new(
        tdev: &TyrDrmDevice,
        queue_args: &QueueCreate,
        vm: Arc<Vm>,
    ) -> Result<Self> {
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let ringbuf =
            gem::new_kernel_object(tdev, &vm, queue_args.ringbuf_size() as usize, flags)?;
        let iface_mem = tdev.fw.alloc_queue_mem(tdev)?;
        let interfaces = Interfaces::new(iface_mem)?;

        let data = Arc::pin_init(
            pin_init!(QueueData {
                priority: queue_args.priority(),
                ringbuf,
                interfaces,
                doorbell_id: AtomicUsize::new(UNASSIGNED_DOORBELL_ID),
                next_seqno: AtomicU64::new(0),
                iomem: tdev.iomem.clone(),
                pending_submit_fences <- new_mutex!(KVec::new()),
            }),
            GFP_KERNEL,
        )?;

        let pipeline = PipelineBuilder::new()
            .set_cancel_timeout(msecs_to_jiffies(JOB_TIMEOUT_MS))
            .add_stage(QueueCompletionStage {
                data: data.clone(),
                poll_interval: msecs_to_jiffies(JOB_POLL_INTERVAL_MS),
                timeout: msecs_to_jiffies(JOB_TIMEOUT_MS),
            })?;
        let job_queue = JobQueue::new(
            TyrQueueOps { data: data.clone() },
            tdev.wq.clone(),
            tdev.wq.clone(),
            pipeline,
        )?;

        Ok(Self { data, job_queue })
    }

    pub(super) fn prepare_job(
        &self,
        job: QueueJob,
        deps: &[ARef<PublicDmaFence>],
    ) -> Result<PreparedQueueJob> {
        self.job_queue.prepare(job, deps, QueueFenceData)
    }

    pub(super) fn commit_job(&self, prepared: PreparedQueueJob) -> ARef<PublicDmaFence> {
        self.job_queue.commit(prepared)
    }
}

impl Deref for Queue {
    type Target = QueueData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

#[allow(dead_code)]
#[repr(C)]
pub(super) struct RingBufferInput {
    insert: u64,
    extract_init: u64,
}

#[allow(dead_code)]
#[repr(C)]
pub(super) struct RingBufferOutput {
    extract: u64,
    active: u32,
}

pub(crate) struct Interfaces {
    mem: Arc<gem::MappedBo>,
    #[allow(dead_code)]
    pub(super) input_va: Range<u64>,
    #[allow(dead_code)]
    pub(super) output_va: Range<u64>,
    input_offset: usize,
    output_offset: usize,
}

impl Interfaces {
    fn new(mem: Arc<gem::MappedBo>) -> Result<Self> {
        let input_va = mem.kernel_va().ok_or(EINVAL)?;
        let output_start = input_va.start + SZ_4K as u64;
        let output_va = output_start..(output_start + SZ_4K as u64);

        Ok(Self {
            mem,
            input_va,
            output_va,
            input_offset: 0,
            output_offset: SZ_4K,
        })
    }

    #[allow(dead_code)]
    pub(super) fn read_input(&self) -> Result<RingBufferInput> {
        let vmap = self.mem.vmap();
        // SAFETY: `input_offset` selects the queue input structure inside the
        // writable CPU mapping owned by `mem`.
        let input = unsafe {
            (vmap.addr() as *mut u8)
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .read_volatile()
        };

        Ok(input)
    }

    #[allow(dead_code)]
    pub(super) fn write_input(&self, value: RingBufferInput) -> Result {
        let vmap = self.mem.vmap();

        // SAFETY: `input_offset` selects the queue input structure inside the
        // writable CPU mapping owned by `mem`.
        unsafe {
            (vmap.addr() as *mut u8)
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .write_volatile(value)
        };

        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn read_output(&self) -> Result<RingBufferOutput> {
        let vmap = self.mem.vmap();
        // SAFETY: `output_offset` selects the queue output structure inside the
        // writable CPU mapping owned by `mem`.
        let output = unsafe {
            (vmap.addr() as *mut u8)
                .add(self.output_offset)
                .cast::<RingBufferOutput>()
                .read_volatile()
        };

        Ok(output)
    }
}
