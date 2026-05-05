// SPDX-License-Identifier: GPL-2.0 or MIT

//! Shared threaded IRQ adapter for Tyr submodules.
//!
//! The MMU and firmware IRQ handlers share the same masking, threaded wakeup,
//! and status-drain flow, so the generic wrapper lives here instead of in the
//! probe path.

use core::marker::PhantomPinned;

use kernel::{
    device::{
        Bound,
        Device, //
    },
    io::mem::DevresIoMem,
    irq::{
        Flags,
        IrqReturn,
        ThreadedHandler,
        ThreadedIrqReturn,
        ThreadedRegistration, //
    },
    platform,
    prelude::*,
    sizes::SZ_2M,
    sync::{
        aref::ARef,
        Arc, //
    }, //
};

use crate::driver::{
    IoMem,
    TyrDrmDevice, //
};

pub(crate) trait TyrIrqTrait: Sync {
    fn read_status(&self, io: &IoMem<'_>) -> u32;
    fn disable_all(&self, io: &IoMem<'_>);
    fn reenable(&self, io: &IoMem<'_>);
    fn read_raw_status(&self, io: &IoMem<'_>) -> u32;
    fn clear_status(&self, io: &IoMem<'_>, status: u32);
    fn mask(&self) -> u32;
    fn handle(&self, tdev: &TyrDrmDevice, io: &IoMem<'_>, status: u32);
}

#[pin_data]
pub(crate) struct TyrIrq<'drm, T: TyrIrqTrait> {
    dev: &'drm Device<Bound>,
    tdev: ARef<TyrDrmDevice>,
    iomem: Arc<DevresIoMem<SZ_2M>>,
    irq: T,
    #[pin]
    _pin: PhantomPinned,
}

impl<'drm, T: TyrIrqTrait> TyrIrq<'drm, T> {
    /// Registers a threaded handler for the named IRQ line.
    ///
    /// # Safety
    ///
    /// Callers must not `mem::forget()` the resulting registration or otherwise prevent its
    /// `Drop` implementation from running.
    pub(crate) unsafe fn request(
        pdev: &'drm platform::Device<Bound>,
        tdev: ARef<TyrDrmDevice>,
        name: &'static CStr,
        iomem: Arc<DevresIoMem<SZ_2M>>,
        irq: T,
    ) -> impl PinInit<ThreadedRegistration<'drm, Self>, Error> + 'drm
    where
        T: 'drm,
    {
        let handler = try_pin_init!(Self {
            dev: pdev.as_ref(),
            tdev,
            iomem,
            irq,
            _pin: PhantomPinned,
        });

        // SAFETY: The caller guarantees that the registration is not leaked.
        unsafe { pdev.request_threaded_irq_by_name(Flags::SHARED, name, name, handler) }
    }
}

impl<T: TyrIrqTrait> ThreadedHandler for TyrIrq<'_, T> {
    fn handle(&self) -> ThreadedIrqReturn {
        let Ok(io) = self.iomem.access(self.dev) else {
            return ThreadedIrqReturn::None;
        };
        let masked_status = self.irq.read_status(io);

        if masked_status == 0 {
            return ThreadedIrqReturn::None;
        }
        self.irq.disable_all(io);
        ThreadedIrqReturn::WakeThread
    }

    fn handle_threaded(&self) -> IrqReturn {
        let Ok(io) = self.iomem.access(self.dev) else {
            return IrqReturn::None;
        };
        let mut ret = IrqReturn::None;

        loop {
            let raw_status = self.irq.read_raw_status(io) & self.irq.mask();
            if raw_status == 0 {
                break;
            }
            self.irq.clear_status(io, raw_status);
            self.irq.handle(&self.tdev, io, raw_status);
            ret = IrqReturn::Handled;
        }

        self.irq.reenable(io);
        ret
    }
}
