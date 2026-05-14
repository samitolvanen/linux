// SPDX-License-Identifier: GPL-2.0 or MIT

//! Shared threaded IRQ adapter for Tyr submodules.
//!
//! The MMU and firmware IRQ handlers share the same masking, threaded wakeup,
//! and status-drain flow, so the generic wrapper lives here instead of in the
//! probe path.

use core::marker::PhantomPinned;

use kernel::{
    device::{Bound, Device},
    irq::{Flags, IrqReturn, ThreadedHandler, ThreadedIrqReturn, ThreadedRegistration},
    platform,
    prelude::*,
    sync::aref::ARef,
};

use crate::driver::TyrDrmDevice;

pub(crate) trait TyrIrqTrait: Sync + 'static {
    fn read_status(&self, dev: &Device<Bound>) -> u32;
    fn disable_all(&self, dev: &Device<Bound>);
    fn reenable(&self, dev: &Device<Bound>);
    fn read_raw_status(&self, dev: &Device<Bound>) -> u32;
    fn clear_status(&self, dev: &Device<Bound>, status: u32);
    fn mask(&self) -> u32;
    fn handle(&self, tdev: &TyrDrmDevice, status: u32);
}

#[pin_data]
pub(crate) struct TyrIrq<T: TyrIrqTrait> {
    tdev: ARef<TyrDrmDevice>,
    irq: T,
    #[pin]
    _pin: PhantomPinned,
}

impl<T: TyrIrqTrait> TyrIrq<T> {
    pub(crate) fn request<'a>(
        pdev: &'a platform::Device<Bound>,
        tdev: ARef<TyrDrmDevice>,
        name: &'static CStr,
        irq: T,
    ) -> Result<impl PinInit<ThreadedRegistration<Self>, Error> + 'a> {
        let handler = try_pin_init!(Self {
            tdev,
            irq,
            _pin: PhantomPinned,
        });

        Ok(pdev.request_threaded_irq_by_name(Flags::SHARED, name, name, handler))
    }
}

impl<T: TyrIrqTrait> ThreadedHandler for TyrIrq<T> {
    fn handle(&self, dev: &Device<Bound>) -> ThreadedIrqReturn {
        let masked_status = self.irq.read_status(dev);

        if masked_status == 0 {
            return ThreadedIrqReturn::None;
        }

        self.irq.disable_all(dev);
        ThreadedIrqReturn::WakeThread
    }

    fn handle_threaded(&self, dev: &Device<Bound>) -> IrqReturn {
        let mut ret = IrqReturn::None;

        loop {
            let raw_status = self.irq.read_raw_status(dev) & self.irq.mask();
            if raw_status == 0 {
                break;
            }

            self.irq.clear_status(dev, raw_status);
            self.irq.handle(&self.tdev, raw_status);
            ret = IrqReturn::Handled;
        }

        self.irq.reenable(dev);
        ret
    }
}
