// SPDX-License-Identifier: GPL-2.0 or MIT

//! Blocking hardware-access gate for the GPU reset cycle.
//!
//! `HwGate` serializes reset-sensitive hardware access against the reset
//! worker. A reader holds a bounded read section around the MMIO the reset
//! wipes. The reset worker closes the gate, drains the in-flight readers, owns
//! the hardware for the reset, then reopens it.
//!
//! # Ordering
//!
//! A reader enters the SRCU read section, then checks `closed`. Observing it
//! open means the section began before any close(), so `synchronize` drains
//! it. SRCU is the reset barrier and the flag only skips the park, so the
//! flag is read `Relaxed`.
//!
//! # Locking
//!
//! A reader takes the gate outside the address-space manager lock, so a
//! parked reader holds no lock the reset worker needs.
//!
//! # Blocking rules
//!
//! A reader may park from a dma-fence signalling section because the gate is
//! only ever closed by a reset (the reset worker, or the resume path
//! completing a latched reset), which never waits on VM_BIND fences. Every
//! hardware wait in a read section has a poll timeout, so the drain returns.

use kernel::{
    prelude::*,
    sync::{
        atomic::{
            Atomic,
            Relaxed, //
        },
        new_condvar,
        new_mutex,
        srcu,
        CondVar,
        Mutex,
        Srcu, //
    },
};

/// Gate coordinating reset-sensitive hardware access with the reset worker.
///
/// # Invariants
///
/// `closed` is true only while a `HwWriteGuard` is live, and a read section is
/// taken only with `closed` observed false inside the SRCU read section.
#[pin_data]
pub(crate) struct HwGate {
    /// Drains in-flight read sections at the reset barrier.
    #[pin]
    srcu: Srcu,
    /// Set while the reset worker owns the hardware.
    closed: Atomic<bool>,
    /// Serializes the reopen against a parking reader. See `read()`.
    #[pin]
    park: Mutex<()>,
    /// Wakes readers parked on a closed gate once it reopens.
    #[pin]
    reopen: CondVar,
}

impl HwGate {
    /// Creates an open gate.
    pub(super) fn new() -> impl PinInit<Self, Error> {
        // INVARIANT: A new gate is open with no live write guard.
        try_pin_init!(Self {
            srcu <- kernel::new_srcu!(),
            closed: Atomic::new(false),
            park <- new_mutex!(()),
            reopen <- new_condvar!(),
        })
    }

    /// Enters a hardware-access read section, parking while the gate is closed.
    #[expect(dead_code)]
    pub(crate) fn read(&self) -> HwReadGuard<'_> {
        loop {
            let guard = self.srcu.read_lock();
            if !self.closed.load(Relaxed) {
                return HwReadGuard { _srcu: guard };
            }
            drop(guard);
            let mut park = self.park.lock();
            while self.closed.load(Relaxed) {
                self.reopen.wait(&mut park);
            }
        }
    }

    /// Closes the gate and drains in-flight readers for the reset worker.
    pub(crate) fn close(&self) -> HwWriteGuard<'_> {
        self.closed.store(true, Relaxed);
        self.srcu.synchronize_expedited();
        HwWriteGuard { gate: self }
    }
}

/// Read section that keeps the reset worker off the hardware while held.
#[must_use = "the gate is released when the guard is dropped"]
pub(crate) struct HwReadGuard<'a> {
    _srcu: srcu::Guard<'a>,
}

/// Closed gate held by the reset worker. Reopens on drop.
#[must_use = "the gate stays closed until the guard is dropped"]
pub(crate) struct HwWriteGuard<'a> {
    gate: &'a HwGate,
}

impl Drop for HwWriteGuard<'_> {
    fn drop(&mut self) {
        // Store and notify under `park` so a reader between its closed check
        // and its wait cannot miss the wakeup.
        let _park = self.gate.park.lock();
        self.gate.closed.store(false, Relaxed);
        self.gate.reopen.notify_all();
    }
}
