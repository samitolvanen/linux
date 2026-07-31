// SPDX-License-Identifier: GPL-2.0 or MIT

//! Shared threaded IRQ adapter for Tyr submodules.
//!
//! The MMU and firmware IRQ handlers share the same masking, threaded wakeup,
//! and status-drain flow, so the generic wrapper lives here instead of in the
//! probe path.

use core::marker::PhantomPinned;

use kernel::{
    device::{Bound, Device},
    devres::Devres,
    irq::{Flags, IrqReturn, ThreadedHandler, ThreadedIrqReturn, ThreadedRegistration},
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::{
            Acquire,
            Atomic,
            Release, //
        }, //
    },
};

use crate::driver::{
    IoMem,
    TyrDrmDevice, //
};

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
    /// Set while runtime suspend holds this line quiesced. Suspend masks
    /// the line before it sets the flag. The hard handler then leaves the
    /// shared line to its other users without touching a register, and the
    /// threaded handler leaves the line masked on exit.
    suspended: Atomic<bool>,
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
            suspended: Atomic::new(false),
            _pin: PhantomPinned,
        });

        Ok(pdev.request_threaded_irq_by_name(Flags::SHARED, name, name, handler))
    }

    fn set_suspended(&self, suspended: bool) {
        self.suspended.store(suspended, Release);
    }
}

impl<T: TyrIrqTrait> ThreadedHandler for TyrIrq<T> {
    fn handle(&self, dev: &Device<Bound>) -> ThreadedIrqReturn {
        if self.suspended.load(Acquire) {
            return ThreadedIrqReturn::None;
        }

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

        if !self.suspended.load(Acquire) {
            self.irq.reenable(dev);
        }
        ret
    }
}

/// Stops one IRQ line for runtime suspend. Masks the line through `mask`,
/// sets a per-line suspended flag, and waits for the in-flight threaded
/// handler.
///
/// The line is masked before the flag is set, so the hard handler starts
/// declining only once the sources are masked. The flag stops a finishing
/// threaded handler from re-enabling the line. The mask is rewritten after
/// the synchronize because a handler that raced the flag re-enables it on
/// exit. The flag stays set until the matching resume clears it.
#[expect(dead_code)]
pub(crate) fn quiesce<T: TyrIrqTrait + Send>(
    dev: &Device<Bound>,
    reg: &Devres<ThreadedRegistration<TyrIrq<T>>>,
    iomem: &Devres<IoMem>,
    mask: impl Fn(&IoMem),
) {
    let sync = reg.access(dev).and_then(|irq| {
        if let Ok(io) = iomem.access(dev) {
            mask(io);
        }
        irq.handler().set_suspended(true);
        irq.synchronize(dev)
    });
    if let Err(e) = sync {
        dev_warn!(dev, "IRQ synchronize on suspend failed: {:?}\n", e);
    }
    if let Ok(io) = iomem.access(dev) {
        mask(io);
    }
}

/// Clears the suspended flag on one IRQ line.
///
/// A flag left set stops the hard handler from handling the line again.
/// Call this before unmasking the line, or an interrupt taken in between
/// goes unclaimed.
#[expect(dead_code)]
pub(crate) fn clear_suspended<T: TyrIrqTrait + Send>(
    dev: &Device<Bound>,
    reg: &Devres<ThreadedRegistration<TyrIrq<T>>>,
) {
    if let Ok(irq) = reg.access(dev) {
        irq.handler().set_suspended(false);
    }
}
