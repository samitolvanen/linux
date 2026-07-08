// SPDX-License-Identifier: GPL-2.0 or MIT

//! Device-wide object registries and their debugfs files, the `shrink` file,
//! and the debugfs knobs for exercising the GPU reset machinery. The knobs are
//! a local debugging aid.
//!
//! Each registry tracks live objects without referencing them, so a debugfs
//! file can dump them without walking per-file state. Without
//! `CONFIG_DEBUG_FS` the registries do nothing.

use kernel::{
    debugfs::{
        Dir,
        File, //
    },
    prelude::*,
    sync::aref::ARef,
    uaccess::UserSliceReader, //
};

use crate::{
    driver::TyrDrmDevice,
    LocalModule, //
};

#[cfg(not(CONFIG_DEBUG_FS))]
pub(crate) use self::disabled::{
    GemLink,
    GemRegistry,
    VmRegistry, //
};
#[cfg(CONFIG_DEBUG_FS)]
pub(crate) use self::enabled::{
    GemLink,
    GemRegistry,
    GemsShow,
    GpuvasShow,
    ShrinkAttr,
    VmRegistry, //
};

/// BO is used only by the kernel driver.
pub(crate) const GEM_USAGE_KERNEL: u32 = 1 << 0;
/// BO is mapped into the firmware VM.
pub(crate) const GEM_USAGE_FW_MAPPED: u32 = 1 << 1;

/// Owns the debugfs entries. Dropped with the platform driver data at
/// unbind.
pub(crate) struct TyrDebugfs {
    _reset: Pin<KBox<File<ARef<TyrDrmDevice>>>>,
    _dir: Dir<LocalModule>,
}

impl TyrDebugfs {
    /// Creates the `tyr` debugfs directory and its entries.
    pub(crate) fn new(tdev: ARef<TyrDrmDevice>) -> Result<Self> {
        let dir = Dir::new(c"tyr");
        let reset = KBox::pin_init(
            dir.write_callback_file(c"reset", tdev, &reset_write),
            GFP_KERNEL,
        )?;
        Ok(Self {
            _reset: reset,
            _dir: dir,
        })
    }
}

/// Schedules an asynchronous GPU reset on any write to `tyr/reset`.
fn reset_write(tdev: &ARef<TyrDrmDevice>, _reader: &mut UserSliceReader) -> Result {
    dev_info!(tdev.as_ref(), "debug: scheduling a GPU reset\n");
    tdev.reset.schedule();
    Ok(())
}

#[cfg(CONFIG_DEBUG_FS)]
mod enabled {
    use core::{
        cmp::min,
        fmt::Write,
        ptr::NonNull, //
    };

    use kernel::{
        debugfs::{
            Attribute,
            SeqShow, //
        },
        drm::gem::BaseObject,
        list::{
            impl_list_arc_safe,
            impl_list_item,
            List,
            ListArc,
            ListLinks, //
        },
        pr_warn_once,
        prelude::*,
        seq_file::{
            seq_print,
            SeqFile, //
        },
        str::Formatter,
        sync::{
            atomic::{
                Atomic,
                Relaxed, //
            },
            Arc,
            Mutex, //
        },
        task::{
            Pid,
            TaskComm, //
        },
    };

    use crate::{
        driver::TyrDrmRegistrationData,
        gem::Bo,
        reclaim::ReclaimState,
        vm::Vm, //
    };

    const GEM_STATE_IMPORTED: u32 = 1 << 0;
    const GEM_STATE_EXPORTED: u32 = 1 << 1;
    const GEM_STATE_EVICTED: u32 = 1 << 2;

    /// One registry entry, holding a non-owning pointer to a live BO plus the
    /// immutable creator and usage snapshot captured at registration.
    #[pin_data]
    struct GemEntry {
        gem: NonNull<Bo>,
        creator_comm: TaskComm,
        creator_tgid: Pid,
        usage_flags: u32,
        #[pin]
        links: ListLinks,
    }

    impl_list_arc_safe! {
        impl ListArcSafe<0> for GemEntry { untracked; }
    }

    impl_list_item! {
        impl ListItem<0> for GemEntry {
            using ListLinks { self.links };
        }
    }

    // SAFETY: It is safe to send a `GemEntry` to another thread because its
    // pointer is only dereferenced under the registry lock. The BO's free
    // hook takes that lock to unregister the BO while it is still valid. The
    // other fields are plain data.
    unsafe impl Send for GemEntry {}

    // SAFETY: It is safe to share a `GemEntry` between threads because its
    // pointer is only dereferenced under the registry lock and `Bo` is `Sync`.
    // The other fields are plain data.
    unsafe impl Sync for GemEntry {}

    /// Device-wide registry of live BOs backing the `gems` debugfs file.
    ///
    /// BOs are listed in registration order.
    ///
    /// The registry holds no reference to its BOs. A BO registers after it
    /// is created. It unregisters from its free hook, while it is still
    /// valid. Both the dump and unregistration take the registry lock, so a
    /// listed BO stays valid for the duration of the dump.
    ///
    /// Entries are allocated before the lock is taken, so the lock never
    /// covers an allocation. The free hook can run in a dma-fence signalling
    /// section or in memory reclaim, where an allocation under the lock would
    /// be a lockdep cycle.
    ///
    /// The registry lock is acquired before a BO's label lock, never the
    /// reverse.
    #[pin_data]
    pub(crate) struct GemRegistry {
        #[pin]
        bos: Mutex<List<GemEntry>>,
    }

    impl GemRegistry {
        pub(crate) fn new() -> impl PinInit<Self> {
            pin_init!(Self {
                bos <- kernel::new_mutex!(List::new()),
            })
        }

        fn unregister(&self, bo: &Bo) {
            let gem = NonNull::from(bo);
            let mut bos = self.bos.lock();
            let mut cursor = bos.cursor_front();
            while let Some(entry) = cursor.peek_next() {
                if entry.gem == gem {
                    entry.remove();
                    return;
                }
                cursor.move_next();
            }
        }

        fn print_bos(&self, m: &SeqFile) {
            seq_print!(
                m,
                "GEM state flags: imported (0x1), exported (0x2), evicted (0x4)\n"
            );
            seq_print!(m, "GEM usage flags: kernel (0x1), fw-mapped (0x2)\n\n");
            seq_print!(m, "created-by                      global-name     refcount   evictions  size            resident-size   file-offset       state      usage       label\n");
            seq_print!(m, "----------------------------------------------------------------------------------------------------------------------------------------------------\n");

            let mut total_size = 0usize;
            let mut total_resident = 0usize;
            let mut total_reclaimable = 0usize;

            {
                let bos = self.bos.lock();
                for entry in bos.iter() {
                    // SAFETY: `entry.gem` points to a live object, because
                    // every BO unregisters under this lock while it is still
                    // valid.
                    let bo = unsafe { entry.gem.as_ref() };

                    let refcount = bo.refcount();
                    // Skip BOs being destroyed.
                    if refcount == 0 {
                        continue;
                    }

                    let evictions = bo.evictions();
                    let size = bo.size();
                    let resident = if bo.pages_present() || bo.is_imported() {
                        size
                    } else {
                        0
                    };

                    let mut buf = [0u8; 48];
                    let mut f = Formatter::new(&mut buf);
                    let _ = f.write_fmt(fmt!("{}/{}", entry.creator_comm, entry.creator_tgid));
                    let n = min(f.bytes_written(), buf.len());
                    let creator = core::str::from_utf8(&buf[..n]).unwrap_or("");

                    let mut state = 0u32;
                    if bo.is_imported() {
                        state |= GEM_STATE_IMPORTED;
                    } else if resident == 0 && evictions != 0 {
                        state |= GEM_STATE_EVICTED;
                    }
                    if bo.has_dma_buf() {
                        state |= GEM_STATE_EXPORTED;
                    }

                    seq_print!(
                        m,
                        "{:<32.31}{:<16}{:<11}{:<11}{:<16}{:<16}0x{:<16x}0x{:<8x} 0x{:<10x}",
                        creator,
                        bo.global_name().unwrap_or(0),
                        refcount,
                        evictions,
                        size,
                        resident,
                        bo.vma_node_start(),
                        state,
                        entry.usage_flags
                    );
                    bo.with_label(|label| match label {
                        Some(l) => seq_print!(m, "{}\n", l),
                        None => seq_print!(m, "\n"),
                    });

                    total_size += size;
                    total_resident += resident;
                    if bo.reclaim_state() != ReclaimState::Unreclaimable {
                        total_reclaimable += resident;
                    }
                }
            }

            seq_print!(m, "====================================================================================================================================================\n");
            seq_print!(
                m,
                "Total size: {}, Total resident: {}, Total reclaimable: {}\n",
                total_size,
                total_resident,
                total_reclaimable
            );
        }
    }

    /// A BO's link to the device-wide `gems` registry.
    ///
    /// Holds the registry so the free hook can unregister without reaching
    /// the device data, and records whether the BO is listed so the hook can
    /// skip the registry lock otherwise.
    pub(crate) struct GemLink {
        registry: Arc<GemRegistry>,
        listed: Atomic<bool>,
    }

    impl GemLink {
        pub(crate) fn new(registry: &Arc<GemRegistry>) -> Self {
            Self {
                registry: registry.clone(),
                listed: Atomic::new(false),
            }
        }

        /// Registers `bo`, the owner of this link, with the given usage flags,
        /// capturing the creating task.
        ///
        /// A failed allocation drops the BO from the dump but is otherwise
        /// harmless.
        pub(crate) fn register(&self, bo: &Bo, usage_flags: u32) {
            let current = kernel::current!();
            let leader = current.group_leader();
            let entry = ListArc::pin_init(
                try_pin_init!(GemEntry {
                    gem: bo.into(),
                    creator_comm: leader.comm(),
                    creator_tgid: leader.pid(),
                    usage_flags,
                    links <- ListLinks::new(),
                }? Error),
                GFP_KERNEL,
            );
            match entry {
                Ok(entry) => {
                    self.registry.bos.lock().push_back(entry);
                    self.listed.store(true, Relaxed);
                }
                Err(_) => {
                    pr_warn_once!("gems debugfs registration failed under memory pressure\n")
                }
            }
        }

        /// Removes `bo`, the owner of this link, from the registry. A no-op if
        /// the BO is not listed.
        pub(crate) fn unregister(&self, bo: &Bo) {
            if self.listed.load(Relaxed) {
                self.registry.unregister(bo);
            }
        }
    }

    /// The `gems` debugfs file, a device-wide dump of every tracked BO.
    pub(crate) struct GemsShow;

    impl SeqShow<TyrDrmRegistrationData<'_>> for GemsShow {
        fn show(reg_data: &TyrDrmRegistrationData<'_>, m: &SeqFile) -> Result {
            reg_data.gem_registry.print_bos(m);
            Ok(())
        }
    }

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

        fn print_gpuvas(&self, m: &SeqFile) -> Result {
            let vms = self.vms.lock();
            for entry in vms.iter() {
                // SAFETY: `entry.vm` points to a live VM, because every VM
                // unregisters under this lock before its owner drops it.
                let vm = unsafe { entry.vm.as_ref() };
                vm.show_gpuvas(m)?;
                seq_print!(m, "\n");
            }
            Ok(())
        }
    }

    /// The `gpuvas` debugfs file, a device-wide dump of every VM's GPU VA space.
    pub(crate) struct GpuvasShow;

    impl SeqShow<TyrDrmRegistrationData<'_>> for GpuvasShow {
        fn show(reg_data: &TyrDrmRegistrationData<'_>, m: &SeqFile) -> Result {
            reg_data.vm_registry.print_gpuvas(m)
        }
    }

    /// The `shrink` debugfs file. Reading it returns the number of pages that
    /// the last scan reclaimed. Writing `n` scans `n` pages.
    pub(crate) struct ShrinkAttr;

    impl Attribute<TyrDrmRegistrationData<'_>> for ShrinkAttr {
        const FORMAT: &'static CStr = c"0x%08llx\n";

        fn get(reg_data: &TyrDrmRegistrationData<'_>) -> Result<u64> {
            Ok(reg_data.reclaim.last_scan_pages() as u64)
        }

        fn set(reg_data: &TyrDrmRegistrationData<'_>, val: u64) -> Result {
            reg_data
                .reclaim
                .shrink(usize::try_from(val).unwrap_or(usize::MAX));
            Ok(())
        }
    }
}

#[cfg(not(CONFIG_DEBUG_FS))]
mod disabled {
    use kernel::{
        prelude::*,
        sync::Arc, //
    };

    use crate::{
        gem::Bo,
        vm::Vm, //
    };

    /// Stand-in for the BO registry that tracks nothing.
    pub(crate) struct GemRegistry;

    impl GemRegistry {
        pub(crate) fn new() -> impl PinInit<Self> {
            Self
        }
    }

    /// Stand-in for a BO's link to the BO registry.
    pub(crate) struct GemLink;

    impl GemLink {
        pub(crate) fn new(_registry: &Arc<GemRegistry>) -> Self {
            Self
        }

        pub(crate) fn register(&self, _bo: &Bo, _usage_flags: u32) {}

        pub(crate) fn unregister(&self, _bo: &Bo) {}
    }

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
