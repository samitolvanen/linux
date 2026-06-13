// SPDX-License-Identifier: GPL-2.0

//! Preemption and local interrupt control.
//!
//! [`with_preempt_irq_disabled()`] bounds a preemption- and interrupt-disabled atomic section to
//! a single closure. The closure receives a [`LocalInterruptDisabled`] token, which proves the
//! context to APIs that require it.

use crate::interrupt::{
    self,
    LocalInterruptDisabled, //
};

/// Runs `f` with preemption and local interrupts disabled on the current CPU.
///
/// Disabling local interrupts raises the hardirq-disable count in `preempt_count`, so `f` also
/// runs non-preemptible.
///
/// `f` runs in atomic context and must not sleep.
#[inline]
pub fn with_preempt_irq_disabled<T>(f: impl FnOnce(&LocalInterruptDisabled) -> T) -> T {
    let guard = interrupt::local_interrupt_disable();
    f(&guard)
}
