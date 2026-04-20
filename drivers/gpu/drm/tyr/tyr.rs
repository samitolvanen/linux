// SPDX-License-Identifier: GPL-2.0 or MIT
#![recursion_limit = "256"]

//! Arm Mali Tyr DRM driver.
//!
//! The name "Tyr" is inspired by Norse mythology, reflecting Arm's tradition of
//! naming their GPUs after Nordic mythological figures and places.

use crate::driver::TyrDriver;

mod driver;
mod file;
mod flags;
mod fw;
mod gem;
mod gpu;
mod heap;
mod mmap;
mod mmu;
mod regs;
mod sched;
mod wait;

kernel::module_platform_driver! {
    type: TyrDriver,
    name: "tyr",
    authors: ["The Tyr driver authors"],
    description: "Arm Mali Tyr DRM driver",
    license: "Dual MIT/GPL",
}

kernel::module_firmware!(fw::ModInfoBuilder);
