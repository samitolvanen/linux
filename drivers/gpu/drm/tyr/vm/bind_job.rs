// SPDX-License-Identifier: GPL-2.0 or MIT

//! VM bind jobs for asynchronous VM operations.

use core::ops::Range;

use kernel::{
    drm::sched::JobImpl,
    prelude::*,
    sync::Arc,
    types::ARef, //
};

use crate::vm::{
    Vm,
    VmMapFlags, //
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
}

impl VmBindJob {
    pub(crate) fn new(vm: Arc<Vm>, operation: VmOperation) -> Self {
        Self { vm, operation }
    }
}

impl JobImpl for VmBindJob {
    fn run(job: &mut kernel::drm::sched::Job<Self>) -> Result<Option<kernel::dma_fence::Fence>> {
        let result = match &job.operation {
            VmOperation::Map {
                va_range,
                bo,
                bo_offset,
                flags,
            } => {
                let size = va_range.end - va_range.start;
                job.vm.map_bo_range(&bo, *bo_offset, size, va_range.start, *flags)
            }
            VmOperation::Unmap { va_range } => {
                let size = va_range.end - va_range.start;
                job.vm.unmap_range(va_range.start, size)
            }
        };

        if let Err(ref e) = result {
            pr_err!("Async VM bind operation failed, marking VM as unusable: {:?}\n", e);
            job.vm.mark_unusable();
        }

        result.map(|_| None)
    }

    fn timed_out(_job: &mut kernel::drm::sched::Job<Self>) -> kernel::drm::sched::Status {
        pr_info!("Async VM bind job timed out\n");
        kernel::drm::sched::Status::NoDevice
    }
}
