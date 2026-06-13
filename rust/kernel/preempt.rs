// SPDX-License-Identifier: GPL-2.0

//! Preemption and local interrupt control.
//!
//! C header: [`include/linux/preempt.h`](srctree/include/linux/preempt.h)

use crate::bindings;

/// Runs `f` with preemption and local interrupts disabled on the current CPU.
///
/// On `PREEMPT_RT`, `local_irq_save()` still masks interrupts, so `f` runs
/// with the same atomic-context guarantees as on a non-RT kernel.
///
/// `f` runs in atomic context and must not sleep.
#[inline]
pub fn with_preempt_irq_disabled<T>(f: impl FnOnce() -> T) -> T {
    // SAFETY: It is always safe to disable preemption, which is re-enabled below.
    unsafe { bindings::preempt_disable() };

    // SAFETY: It is always safe to save and disable local interrupts. The
    // saved flags are restored below.
    let flags = unsafe { bindings::local_irq_save() };

    let ret = f();

    // SAFETY: `flags` is the value saved by the `local_irq_save()` above on this CPU.
    unsafe { bindings::local_irq_restore(flags) };

    // SAFETY: Preemption was disabled by the matching `preempt_disable()`
    // above, so this is balanced.
    unsafe { bindings::preempt_enable() };

    ret
}
