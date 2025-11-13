// SPDX-License-Identifier: GPL-2.0 or MIT

//! VM bind jobs for asynchronous VM operations.

use core::ops::Range;

use kernel::drm::sched::JobImpl;
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

impl JobImpl for VmBindJob {
    fn run(job: &mut kernel::drm::sched::Job<Self>) -> Result<Option<kernel::dma_fence::Fence>> {
        let mut vm = job.vm.lock();
        let iomem = vm.iomem.clone();

        let result = match &job.operation {
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

        result.map(|_| None)
    }

    fn timed_out(_job: &mut kernel::drm::sched::Job<Self>) -> kernel::drm::sched::Status {
        pr_info!("Async VM bind job timed out\n");
        kernel::drm::sched::Status::NoDevice
    }
}
