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
    new_mutex, platform,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::{
            Acquire,
            Atomic,
            Release, //
        },
        Arc,
        Mutex, //
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
    /// Set while the driver holds this line quiesced. The line is created
    /// quiesced and probe clears the flag. A GPU reset and a runtime
    /// suspend set it again. A
    /// reset and a suspend both mask the line before they set the flag. The
    /// hard handler then leaves the shared line to its other users without
    /// touching a register, and the threaded handler leaves the line
    /// masked on exit.
    suspended: Atomic<bool>,
    #[pin]
    _pin: PhantomPinned,
}

impl<T: TyrIrqTrait> TyrIrq<T> {
    pub(crate) fn request<'a>(
        pdev: &'a platform::Device<Bound>,
        tdev: ARef<TyrDrmDevice>,
        irq_name: &'static CStr,
        devname: &'static CStr,
        irq: T,
    ) -> Result<impl PinInit<ThreadedRegistration<Self>, Error> + 'a> {
        // The line starts suspended, so an interrupt taken before the caller
        // clears the flag is left to the other users of the shared line.
        let handler = try_pin_init!(Self {
            tdev,
            irq,
            suspended: Atomic::new(true),
            _pin: PhantomPinned,
        });

        Ok(pdev.request_threaded_irq_by_name(Flags::SHARED, irq_name, devname, handler))
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

/// A revocable, refcounted IRQ registration held in a slot.
pub(crate) type SlotReg<T> = Devres<Arc<ThreadedRegistration<TyrIrq<T>>>>;

/// Slot holding a revocable IRQ registration.
///
/// The handler holds the device, so the slot would keep a refcount cycle
/// alive past unbind if devres did not revoke the registration.
#[pin_data]
pub(crate) struct IrqSlot<T: TyrIrqTrait + Send> {
    #[pin]
    inner: Mutex<Option<SlotReg<T>>>,
}

impl<T: TyrIrqTrait + Send> IrqSlot<T> {
    /// Creates an empty slot.
    pub(crate) fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            inner <- new_mutex!(None),
        })
    }

    /// Publishes the registration so the reset path can reach it.
    pub(crate) fn publish(&self, reg: SlotReg<T>) {
        *self.inner.lock() = Some(reg);
    }

    /// Clones the registration out for the reset path.
    ///
    /// The `Arc` is cloned out of the revocable guard so the RCU read-side
    /// critical section does not span a later synchronize. Returns `None`
    /// before probe publishes the registration and after devres revokes it,
    /// leaving the handlers to be drained by `free_irq()` at unbind.
    fn resolve(&self) -> Option<Arc<ThreadedRegistration<TyrIrq<T>>>> {
        let guard = self.inner.lock();
        guard
            .as_ref()
            .and_then(|d| d.try_access())
            .map(|reg| (*reg).clone())
    }

    /// Masks the slot IRQ for a GPU reset and waits out in-flight handlers.
    ///
    /// The line is masked before the suspended flag is set, so the hard
    /// handler starts declining only once the sources are masked. The flag
    /// stops a finishing threaded handler from re-enabling the line. The
    /// mask is rewritten after the synchronize because a handler that
    /// raced the flag re-enables it on exit. The wait is bounded. Does
    /// nothing when the registration is not published.
    pub(crate) fn reset_suspend(&self, iomem: &Devres<IoMem>, mask: impl Fn(&IoMem)) {
        let Some(reg) = self.resolve() else {
            return;
        };
        if let Some(io) = iomem.try_access() {
            mask(&io);
        }
        reg.handler().set_suspended(true);
        // A failed synchronize means the registration is already being torn
        // down, with handlers drained by free_irq().
        let _ = reg.try_synchronize();
        if let Some(io) = iomem.try_access() {
            mask(&io);
        }
    }

    /// Clears the suspended flag and unmasks the slot IRQ.
    ///
    /// Used by probe once the handler is registered, and after a GPU reset.
    pub(crate) fn reset_resume(&self, iomem: &Devres<IoMem>, enable: impl FnOnce(&IoMem)) {
        let Some(reg) = self.resolve() else {
            return;
        };
        reg.handler().set_suspended(false);
        if let Some(io) = iomem.try_access() {
            enable(&io);
        }
    }

    /// Clears the suspended flag on the slot IRQ.
    ///
    /// A flag left set stops the hard handler from handling the line again.
    /// Call this before unmasking the line, or an interrupt taken in
    /// between goes unclaimed.
    pub(crate) fn clear_suspended(&self) {
        if let Some(reg) = self.resolve() {
            reg.handler().set_suspended(false);
        }
    }

    /// Quiesces the slot IRQ for runtime suspend on the bound device.
    ///
    /// Follows the same order as `reset_suspend`. The flag stays set until
    /// the matching resume clears it.
    pub(crate) fn quiesce(
        &self,
        dev: &Device<Bound>,
        iomem: &Devres<IoMem>,
        mask: impl Fn(&IoMem),
    ) {
        let sync = match &*self.inner.lock() {
            Some(reg) => reg.access(dev).and_then(|irq| {
                if let Ok(io) = iomem.access(dev) {
                    mask(io);
                }
                irq.handler().set_suspended(true);
                irq.synchronize(dev)
            }),
            None => Err(ENODEV),
        };
        if let Err(e) = sync {
            dev_warn!(dev, "IRQ synchronize on suspend failed: {:?}\n", e);
        }
        if let Ok(io) = iomem.access(dev) {
            mask(io);
        }
    }
}
