// SPDX-License-Identifier: GPL-2.0 or MIT

//! VM bind jobs for asynchronous VM operations.

use core::ops::Range;

use kernel::c_str;
use kernel::dma_fence::{DmaFenceContext, DriverDmaFence, DriverDmaFenceOps};
use kernel::drm::job_queue::{JobRef, QueueOps, SubmitResult};
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::sync::Mutex;

use super::map_flags;
use super::Vm;

/// VM operation types for asynchronous VM bind.
pub(crate) enum VmOperation {
    /// Map a buffer object into the VM address space.
    Map {
        va_range: Range<u64>,
        bo: crate::gem::ObjectRef,
        bo_offset: u64,
        flags: map_flags::Flags,
    },
    /// Unmap a VA range from the VM address space.
    Unmap { va_range: Range<u64> },
}

/// A VM bind job that performs asynchronous page table modifications.
pub(crate) struct VmBindJob {
    /// The VM being operated on.
    pub(crate) vm: Arc<Mutex<Vm>>,

    /// The operation to perform.
    pub(crate) operation: VmOperation,
}

impl VmBindJob {
    pub(crate) fn new(vm: Arc<Mutex<Vm>>, operation: VmOperation) -> Self {
        Self { vm, operation }
    }
}

// SAFETY: VmBindJob is used only through the JobQueue, which requires Send +
// Sync. Arc<Mutex<Vm>> is Send + Sync; gem::ObjectRef follows the same pattern
// as Job in sched/job.rs.
unsafe impl Send for VmBindJob {}
unsafe impl Sync for VmBindJob {}

/// Opaque driver data attached to each VM bind fence.
struct VmBindFenceData;

#[vtable]
impl DriverDmaFenceOps for VmBindFenceData {
    fn driver_name(&self) -> &'static CStr {
        c_str!("tyr")
    }

    fn timeline_name(&self) -> &'static CStr {
        c_str!("tyr_vm_bind")
    }
}

/// Handler for VM bind jobs on a [`kernel::drm::job_queue::JobQueue`].
///
/// Executes page-table operations synchronously inside `submit()`, then
/// produces an already-signaled fence so the job queue can immediately retire
/// the job without waiting for hardware.
pub(crate) struct VmBindJobHandler {
    /// Fence context and seqno counter for fences produced by this handler.
    fence_ctx: DmaFenceContext,
}

impl VmBindJobHandler {
    pub(crate) fn new() -> Self {
        Self {
            fence_ctx: DmaFenceContext::new(0),
        }
    }
}

impl QueueOps for VmBindJobHandler {
    type Job = VmBindJob;

    fn submit(&self, job: &JobRef<'_, VmBindJob>) -> Result<SubmitResult> {
        let (ctx, seqno) = self.fence_ctx.next_seqno();
        let (drv_fence, pub_fence) = DriverDmaFence::new(VmBindFenceData, ctx, seqno)?.publish();

        let mut vm = job.job.vm.lock();
        let iomem = vm.iomem.clone();

        let result = match &job.job.operation {
            VmOperation::Map {
                va_range,
                bo,
                bo_offset,
                flags,
            } => vm.bind_gem(iomem.clone(), &bo.gem, *bo_offset, va_range.clone(), *flags),
            VmOperation::Unmap { va_range } => vm.unmap_range(iomem, va_range.clone()),
        };

        if result.is_err() {
            pr_err!("Async VM bind operation failed, marking VM as unusable\n");
            vm.unusable = true;
        }

        drop(vm);

        // Signal the fence immediately — VM bind executes synchronously.
        // The job queue sees AlreadySignaled when registering its callback and
        // retires the submit fence right away.
        drv_fence.signal(result);

        Ok(SubmitResult::Submitted(pub_fence))
    }

    fn timed_out(&self, _job: &JobRef<'_, VmBindJob>) {
        pr_err!("Async VM bind job timed out\n");
    }
}
