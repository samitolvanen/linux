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
        atomic::{
            Acquire,
            Atomic,
            Release, //
        },
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
    /// Set while the driver holds this line quiesced. The line is created
    /// quiesced and probe clears the flag. A GPU reset and a runtime
    /// suspend set it again. The hard handler then leaves the shared line
    /// to its other users without touching a register, and the threaded
    /// handler leaves the line masked on exit.
    suspended: Atomic<bool>,
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
        // The line starts suspended, so an interrupt taken before the caller
        // clears the flag is left to the other users of the shared line.
        let handler = try_pin_init!(Self {
            dev: pdev.as_ref(),
            tdev,
            iomem,
            irq,
            suspended: Atomic::new(true),
            _pin: PhantomPinned,
        });

        // SAFETY: The caller guarantees that the registration is not leaked.
        unsafe { pdev.request_threaded_irq_by_name(Flags::SHARED, name, name, handler) }
    }

    fn set_suspended(&self, suspended: bool) {
        self.suspended.store(suspended, Release);
    }
}

impl<T: TyrIrqTrait> ThreadedHandler for TyrIrq<'_, T> {
    fn handle(&self) -> ThreadedIrqReturn {
        if self.suspended.load(Acquire) {
            return ThreadedIrqReturn::None;
        }

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

        if !self.suspended.load(Acquire) {
            self.irq.reenable(io);
        }
        ret
    }
}

/// Stops one IRQ line for runtime suspend or a GPU reset. Masks the line
/// through `mask`, sets a per-line suspended flag, and waits for the
/// in-flight threaded handler.
///
/// The line is masked before the flag is set, so the hard handler starts
/// declining only once the sources are masked. The mask is rewritten after
/// the synchronize because a handler that raced the flag re-enables it on
/// exit. The flag stays set until the matching resume clears it.
pub(crate) fn quiesce<T: TyrIrqTrait>(
    reg: &ThreadedRegistration<'_, TyrIrq<'_, T>>,
    io: &IoMem<'_>,
    mask: impl Fn(&IoMem<'_>),
) {
    mask(io);
    reg.handler().set_suspended(true);
    reg.synchronize();
    mask(io);
}

/// Clears the suspended flag on one IRQ line.
///
/// A flag left set stops the hard handler from handling the line again.
/// Call this before unmasking the line, or an interrupt taken in between
/// goes unclaimed.
pub(crate) fn clear_suspended<T: TyrIrqTrait>(reg: &ThreadedRegistration<'_, TyrIrq<'_, T>>) {
    reg.handler().set_suspended(false);
}

/// Clears the suspended flag and unmasks one IRQ line, reversing `quiesce`.
pub(crate) fn unquiesce<T: TyrIrqTrait>(
    reg: &ThreadedRegistration<'_, TyrIrq<'_, T>>,
    io: &IoMem<'_>,
    unmask: impl FnOnce(&IoMem<'_>),
) {
    clear_suspended(reg);
    unmask(io);
}
