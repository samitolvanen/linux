// SPDX-License-Identifier: GPL-2.0

//! Architected timer access.
//!
//! Thin wrappers around the architected timer interfaces that some drivers
//! need to query the timer frequency directly (e.g. firmware-driven GPUs that
//! program timer counters into device registers).
//!
//! Wraps `arch_timer_get_cntfrq()` from `<asm/arch_timer.h>`.

/// Returns the frequency of the architected timer in Hz, if available.
///
/// Returns `None` when `CONFIG_ARM_ARCH_TIMER` is not enabled, or when
/// `arch_timer_get_cntfrq()` returned 0 (e.g. the timer has not been
/// initialised).
#[inline]
pub fn cntfrq_hz() -> Option<u32> {
    #[cfg(CONFIG_ARM_ARCH_TIMER)]
    {
        // SAFETY: `arch_timer_get_cntfrq()` reads the `cntfrq` system register
        // and is sound to call on any CPU when CONFIG_ARM_ARCH_TIMER is set.
        let f = unsafe { bindings::arch_timer_get_cntfrq() };
        if f == 0 {
            None
        } else {
            Some(f)
        }
    }

    #[cfg(not(CONFIG_ARM_ARCH_TIMER))]
    {
        None
    }
}
