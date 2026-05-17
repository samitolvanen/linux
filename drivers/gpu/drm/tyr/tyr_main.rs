// SPDX-License-Identifier: GPL-2.0 or MIT

//! Arm Mali Tyr DRM driver.
//!
//! The name "Tyr" is inspired by Norse mythology, reflecting Arm's tradition of
//! naming their GPUs after Nordic mythological figures and places.

use kernel::{
    driver::Registration,
    platform,
    prelude::*,
    InPlaceModule,
    ModuleMetadata,
    ThisModule, //
};

use crate::driver::TyrPlatformDriverData;

mod cleanup;
#[cfg(CONFIG_DEBUG_FS)]
mod debugfs;
mod devfreq;
mod driver;
mod file;
mod fw;
mod gem;
mod gpu;
mod heap;
mod irq;
mod mmap;
mod mmu;
mod pm;
mod pool;
mod pwr;
mod regs;
mod reset;
mod sched;
mod slot;
mod trace;
mod vm;
mod wait;

/// The Tyr module.
///
/// The fields drop in declaration order, so the platform driver unregisters
/// before the cleanup workqueue is destroyed.
#[pin_data]
struct TyrModule {
    #[pin]
    _driver: Registration<platform::Adapter<TyrPlatformDriverData>>,
    _cleanup: cleanup::Registration,
}

impl InPlaceModule for TyrModule {
    fn init(module: &'static ThisModule) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            // SAFETY: The module initializer runs once per load, before the
            // driver registers.
            _cleanup: unsafe { cleanup::Registration::new() }?,
            _driver <- Registration::new(<Self as ModuleMetadata>::NAME, module),
        })
    }
}

module! {
    type: TyrModule,
    name: "tyr",
    authors: ["The Tyr driver authors"],
    description: "Arm Mali Tyr DRM driver",
    license: "Dual MIT/GPL",
}

kernel::module_firmware!(fw::ModInfoBuilder);
