// SPDX-License-Identifier: GPL-2.0 or MIT

//! SRCU based hardware access gate.
//!
//! `HwGate` is an SRCU based gate that serializes reset-sensitive hardware
//! access against the reset worker. A reader takes a bounded read section
//! around the MMIO the reset wipes. The reset worker closes the gate, drains
//! the in-flight readers, owns the hardware for the reset, then reopens it.

use kernel::{
    prelude::*,
    sync::{
        atomic::{
            Acquire,
            Atomic,
            Release, //
        },
        srcu,
        Srcu, //
    },
};

/// A gate that coordinates hardware access with asynchronous resets.
#[pin_data]
pub(crate) struct HwGate {
    /// Drains in-flight read sections at the reset barrier.
    #[pin]
    srcu: Srcu,
    /// Set while the reset worker owns the hardware.
    closed: Atomic<bool>,
}

impl HwGate {
    /// Creates a new open gate.
    #[expect(dead_code)]
    pub(super) fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            srcu <- kernel::new_srcu!(),
            closed: Atomic::new(false),
        })
    }

    /// Tries to enter a hardware-access read section, failing with `EBUSY`
    /// while the gate is closed for a reset.
    pub(crate) fn try_access(&self) -> Result<HwGuard<'_>> {
        let srcu = self.srcu.read_lock();
        if self.closed.load(Acquire) {
            return Err(EBUSY);
        }
        Ok(HwGuard { _srcu: srcu })
    }

    /// Runs `callback` in a hardware-access read section, failing fast with
    /// `EBUSY` while the gate is closed for a reset.
    #[expect(dead_code)]
    pub(crate) fn with_hw<R>(&self, callback: impl FnOnce(&HwGuard<'_>) -> Result<R>) -> Result<R> {
        let guard = self.try_access()?;
        callback(&guard)
    }

    /// Closes the gate and drains in-flight readers for the reset worker.
    #[expect(dead_code)]
    pub(super) fn close(&self) -> HwWriteGuard<'_> {
        self.closed.store(true, Release);
        self.srcu.synchronize();
        HwWriteGuard { gate: self }
    }
}

/// Read section that keeps the reset worker off the hardware while held.
#[must_use = "the hardware guard must be kept alive while using reset-sensitive state"]
pub(crate) struct HwGuard<'a> {
    _srcu: srcu::Guard<'a>,
}

/// Closed gate held by the reset worker. Reopens on drop.
#[must_use = "the gate stays closed until the guard is dropped"]
pub(super) struct HwWriteGuard<'a> {
    gate: &'a HwGate,
}

impl Drop for HwWriteGuard<'_> {
    fn drop(&mut self) {
        self.gate.closed.store(false, Release);
    }
}
