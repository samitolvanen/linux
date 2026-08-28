// SPDX-License-Identifier: GPL-2.0 or MIT

//! Device-wide VM registry backing the `gpuvas` debugfs file.
//!
//! The registry tracks live VMs without referencing them, so a debugfs file
//! can dump them without walking per-file state. Without `CONFIG_DEBUG_FS`
//! the registry does nothing.

#[cfg(not(CONFIG_DEBUG_FS))]
pub(crate) use self::disabled::VmRegistry;
#[cfg(CONFIG_DEBUG_FS)]
pub(crate) use self::enabled::VmRegistry;

#[cfg(CONFIG_DEBUG_FS)]
mod enabled {
    use core::ptr::NonNull;

    use kernel::{
        list::{
            impl_list_arc_safe,
            impl_list_item,
            List,
            ListArc,
            ListLinks, //
        },
        pr_warn_once,
        prelude::*,
        sync::Mutex, //
    };

    use crate::vm::Vm;

    /// One registry entry, holding a non-owning pointer to a live VM.
    #[pin_data]
    struct VmEntry {
        vm: NonNull<Vm>,
        #[pin]
        links: ListLinks,
    }

    impl_list_arc_safe! {
        impl ListArcSafe<0> for VmEntry { untracked; }
    }

    impl_list_item! {
        impl ListItem<0> for VmEntry {
            using ListLinks { self.links };
        }
    }

    // SAFETY: It is safe to send a `VmEntry` to another thread because its
    // pointer is only dereferenced under the registry lock and `Vm` is
    // `Sync`. The VM's owner takes that lock to unregister the VM before
    // dropping it.
    unsafe impl Send for VmEntry {}

    // SAFETY: It is safe to share a `VmEntry` between threads because its
    // pointer is only dereferenced under the registry lock and `Vm` is `Sync`.
    unsafe impl Sync for VmEntry {}

    /// Device-wide registry of live VMs backing the `gpuvas` debugfs file.
    ///
    /// VMs are listed in registration order, and the registry holds no
    /// reference to them. A user VM registers at creation and unregisters
    /// when its pool destroys it. The pool holds an owning reference until
    /// then. The firmware VM registers at firmware load and unregisters at
    /// teardown. Both the dump and unregistration take the registry lock,
    /// so a listed VM stays valid for the dump.
    ///
    /// Entries are allocated before the lock is taken, so the lock never
    /// covers an allocation.
    ///
    /// The registry lock is acquired before a VM's `gpuvm_unique` lock,
    /// never the reverse.
    #[pin_data]
    pub(crate) struct VmRegistry {
        #[pin]
        vms: Mutex<List<VmEntry>>,
    }

    impl VmRegistry {
        pub(crate) fn new() -> impl PinInit<Self> {
            pin_init!(Self {
                vms <- kernel::new_mutex!(List::new()),
            })
        }

        /// Registers `vm` in the device-wide `gpuvas` registry.
        ///
        /// A failed allocation drops the VM from the dump but is otherwise
        /// harmless.
        pub(crate) fn register(&self, vm: &Vm) {
            let entry = ListArc::pin_init(
                try_pin_init!(VmEntry {
                    vm: vm.into(),
                    links <- ListLinks::new(),
                }? Error),
                GFP_KERNEL,
            );
            match entry {
                Ok(entry) => self.vms.lock().push_back(entry),
                Err(_) => {
                    pr_warn_once!("gpuvas debugfs registration failed under memory pressure\n")
                }
            }
        }

        /// Removes `vm` from the registry. A no-op if it was never registered.
        pub(crate) fn unregister(&self, vm: &Vm) {
            let vm = NonNull::from(vm);
            let mut vms = self.vms.lock();
            let mut cursor = vms.cursor_front();
            while let Some(entry) = cursor.peek_next() {
                if entry.vm == vm {
                    entry.remove();
                    return;
                }
                cursor.move_next();
            }
        }
    }
}

#[cfg(not(CONFIG_DEBUG_FS))]
mod disabled {
    use kernel::prelude::*;

    use crate::vm::Vm;

    /// Stand-in for the VM registry that tracks nothing.
    pub(crate) struct VmRegistry;

    impl VmRegistry {
        pub(crate) fn new() -> impl PinInit<Self> {
            Self
        }

        pub(crate) fn register(&self, _vm: &Vm) {}

        pub(crate) fn unregister(&self, _vm: &Vm) {}
    }
}
