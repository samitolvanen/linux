// SPDX-License-Identifier: GPL-2.0 or MIT

//! VM bind jobs for asynchronous VM operations.

use core::cell::UnsafeCell;
use core::ops::Range;

use kernel::{
    drm::job_queue::{
        JobRef,
        SubmitResult, //
    },
    prelude::*,
    sync::Arc,
    types::ARef, //
};

use crate::vm::{
    Vm,
    VmMapFlags,
    VmOpResources, //
};

/// VM operation types for asynchronous VM bind.
pub(crate) enum VmOperation {
    /// Map a buffer object into the VM address space.
    Map {
        va_range: Range<u64>,
        bo: ARef<crate::gem::Bo>,
        bo_offset: u64,
        flags: VmMapFlags,
    },
    /// Unmap a VA range from the VM address space.
    Unmap { va_range: Range<u64> },
}

/// A VM bind job that performs asynchronous page table modifications.
pub(crate) struct VmBindJob {
    /// The VM being operated on.
    pub(crate) vm: Arc<Vm>,

    /// The operation to perform.
    pub(crate) operation: VmOperation,

    /// Preallocated resources for the operation.
    ///
    /// Not a `Mutex`: `submit()` runs serially per queue, so the cell
    /// is never aliased.
    resources: UnsafeCell<VmOpResources>,
}

// SAFETY: `resources` is only accessed in `submit()`, which the job-queue
// framework runs serially per queue.
unsafe impl Sync for VmBindJob {}

impl VmBindJob {
    pub(crate) fn new(vm: Arc<Vm>, operation: VmOperation, resources: VmOpResources) -> Self {
        Self {
            vm,
            operation,
            resources: UnsafeCell::new(resources),
        }
    }
}

pub(crate) struct VmBindJobHandler;

impl VmBindJobHandler {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self)
    }
}

impl kernel::drm::job_queue::QueueOps for VmBindJobHandler {
    type Job = VmBindJob;

    fn submit(&self, job: &JobRef<'_, Self::Job>) -> Result<SubmitResult> {
        // SAFETY: We are inside `submit()`, which the framework runs
        // serially per queue, so this is the only reference to `resources`.
        let resources = unsafe { &mut *job.job.resources.get() };
        let result = match &job.job.operation {
            VmOperation::Map {
                va_range,
                bo,
                bo_offset,
                flags,
            } => {
                let size = va_range.end - va_range.start;
                job.job.vm.map_bo_range(
                    &bo,
                    *bo_offset,
                    size,
                    va_range.start,
                    *flags,
                    resources,
                    GFP_NOWAIT,
                )
            }
            VmOperation::Unmap { va_range } => {
                let size = va_range.end - va_range.start;
                job.job
                    .vm
                    .unmap_range(va_range.start, size, resources, GFP_NOWAIT)
            }
        };

        if let Err(ref e) = result {
            pr_err!(
                "Async VM bind operation failed, marking VM as unusable: {:?}\n",
                e
            );
            job.job.vm.mark_unusable();
        }

        let _ = job.submit_fence.signal();

        Ok(SubmitResult::Submitted)
    }
}
