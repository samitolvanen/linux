// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU IRQ handler.
//!
//! The GPU interrupt line reports GPU-level faults, the soft-reset
//! completion event, and L2 power-changed events.

use kernel::{
    device::{
        Bound,
        Device, //
    },
    devres::Devres,
    io::Io,
    irq::ThreadedRegistration,
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    },
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice, //
    },
    irq::{
        TyrIrq,
        TyrIrqTrait, //
    },
    regs::{
        gpu_control,
        join_u64, //
    },
};

/// Returns the bitmask for the GPU interrupts the driver actively handles.
///
/// This selects the GPU faults, the protected-mode fault, the
/// reset-completed event raised at the end of a soft reset, and the
/// L2 power-changed events. Other GPU IRQ sources are left masked so
/// the driver does not have to ack them.
///
/// `issue_soft_reset` polls RAWSTAT for `reset_completed` and must run
/// before `gpu_irq_enable` unmasks this source. The handler's drain loop
/// clears the bit.
pub(crate) fn gpu_interrupts_mask() -> u32 {
    gpu_control::GPU_IRQ_MASK::zeroed()
        .with_gpu_fault(true)
        .with_gpu_protected_fault(true)
        .with_reset_completed(true)
        .with_power_changed_single(true)
        .with_power_changed_all(true)
        .into_raw()
}

pub(crate) struct GpuIrq {
    iomem: Arc<Devres<IoMem>>,
    /// Cached value of `gpu_interrupts_mask`.
    mask: u32,
}

/// Clears latched GPU IRQs and unmasks the sources the driver handles.
pub(crate) fn gpu_irq_enable(io: &IoMem) {
    io.write_reg(gpu_control::GPU_IRQ_CLEAR::from_raw(u32::MAX));
    io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(gpu_interrupts_mask()));
}

/// Masks all GPU IRQ sources.
#[expect(dead_code)]
pub(crate) fn gpu_irq_disable(io: &IoMem) {
    io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(0));
}

pub(crate) fn gpu_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<Bound>,
    iomem: Arc<Devres<IoMem>>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<GpuIrq>>, Error> + 'a> {
    let mask = gpu_interrupts_mask();
    let io = iomem.access(pdev.as_ref())?;
    // The caller unmasks the sources once the handler is registered.
    io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(0));

    let irq_type = GpuIrq {
        iomem: iomem.clone(),
        mask,
    };

    TyrIrq::request(pdev, tdev, c"gpu", irq_type)
}

impl TyrIrqTrait for GpuIrq {
    fn read_status(&self, dev: &Device<Bound>) -> u32 {
        self.iomem
            .access(dev)
            .map(|io| io.read(gpu_control::GPU_IRQ_STATUS).into_raw())
            .unwrap_or_default()
    }

    fn disable_all(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(0));
        }
    }

    fn reenable(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(self.mask));
        }
    }

    fn read_raw_status(&self, dev: &Device<Bound>) -> u32 {
        self.iomem
            .access(dev)
            .map(|io| io.read(gpu_control::GPU_IRQ_RAWSTAT).into_raw())
            .unwrap_or_default()
    }

    fn clear_status(&self, dev: &Device<Bound>, status: u32) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(gpu_control::GPU_IRQ_CLEAR::from_raw(status));
        }
    }

    fn mask(&self) -> u32 {
        self.mask
    }

    fn handle(&self, _tdev: &TyrDrmDevice, status: u32) {
        let status_reg = gpu_control::GPU_IRQ_STATUS::from_raw(status);

        if status_reg.gpu_fault() || status_reg.gpu_protected_fault() {
            if let Some(io) = self.iomem.try_access() {
                let fault_status = io.read(gpu_control::GPU_FAULTSTATUS).into_raw();
                let fault_addr = join_u64(
                    io.read(gpu_control::GPU_FAULTADDRESS_LO).into_raw(),
                    io.read(gpu_control::GPU_FAULTADDRESS_HI).into_raw(),
                );
                pr_err!(
                    "GPU fault: status=0x{:08x} address=0x{:016x} protected={}\n",
                    fault_status,
                    fault_addr,
                    status_reg.gpu_protected_fault()
                );
            }
        }
    }
}
