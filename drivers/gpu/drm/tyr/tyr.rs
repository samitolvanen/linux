// SPDX-License-Identifier: GPL-2.0 or MIT

//!Rust driver for ARM Mali CSF-based GPUs
//!
//! The skeleton is basically taken from Nova and also rust_platform_driver.rs.
//!
//! So far, this is just a very early-stage experiment, but it looks promissing:
//!
//! - We use the same uAPI as Panthor, although this needs a bit of work, since
//!   bindgen cannot translate #defines into Rust.
//!
//! - The DRM registration and a few IOCTLs are implemented. There is an igt
//!   branch with tests.
//!
//! - Basic iomem and register set implementation, so it's possible to program
//! the device.
//!
//! - IRQ handling, so we can receive notifications from the device.
//!
//! - We can boot the firmware.
//!
//! - We can communicate with CSF using the global interface. We can submit
//!   requests and the MCU will appropriately respond in the ack field.
//!
//! - There is GEM_CREATE and VM_BIND support.
//! - We can send a PING request to CSF, and it will acknowledge it
//!   successfully.
//!
//! Notably missing (apart from literally everything else):
//! - Job subission logic through drm_scheduler and completion through dma_fences
//! - Devfreq, pm_idle, etc.
//!
//! The name "Tyr" is inspired by Norse mythology, reflecting ARM's tradition of
//! naming their GPUs after Nordic mythological figures and places.

use crate::driver::TyrDriver;

mod driver;
mod file;
mod flags;
mod fw;
mod gem;
mod gpu;
mod mmu;
mod regs;
mod sched;
mod wait;

kernel::module_platform_driver! {
    type: TyrDriver,
    name: "tyr",
    authors: ["The Tyr driver authors"],
    description: "Rust driver for ARM Mali CSF-based GPUs",
    license: "Dual MIT/GPL",
}
