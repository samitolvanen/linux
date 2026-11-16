// SPDX-License-Identifier: GPL-2.0 or MIT

//! Device-wide object registries and their debugfs files, and the
//! `sched_groups` file.
//!
//! Each registry tracks live objects without referencing them, so a debugfs
//! file can dump them without walking per-file state. Without
//! `CONFIG_DEBUG_FS` the registries do nothing.

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
    SchedGroupsShow,
    VmRegistry, //
};

/// BO is used only by the kernel driver.
pub(crate) const GEM_USAGE_KERNEL: u32 = 1 << 0;
/// BO is mapped into the firmware VM.
pub(crate) const GEM_USAGE_FW_MAPPED: u32 = 1 << 1;

#[cfg(CONFIG_DEBUG_FS)]
mod enabled {
    use core::{
        cmp::min,
        fmt::Write,
        ptr::NonNull, //
    };

    use kernel::{
        debugfs::SeqShow,
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
            Arc,
            Mutex,
            SetOnce, //
        },
        task::{
            Pid,
            TaskComm, //
        },
    };

    use crate::{
        driver::TyrDrmRegistrationData,
        fw::global::csg::Priority,
        gem::Bo,
        vm::Vm, //
    };

    const GEM_STATE_IMPORTED: u32 = 1 << 0;
    const GEM_STATE_EXPORTED: u32 = 1 << 1;

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
    /// covers an allocation and the free hook never waits behind one.
    ///
    /// The registry lock is acquired before a BO's label lock, never the
    /// reverse.
    #[pin_data]
    pub(crate) struct GemRegistry {
        #[pin]
        bos: Mutex<List<GemEntry>>,
    }

    impl GemRegistry {
        /// Creates an empty registry.
        pub(crate) fn new() -> impl PinInit<Self> {
            pin_init!(Self {
                bos <- kernel::new_mutex!(List::new()),
            })
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

            {
                let bos = self.bos.lock();
                for entry in bos.iter() {
                    // SAFETY: `entry.gem` points to a live object, because
                    // every BO unregisters under this lock while it is still
                    // valid.
                    let bo = unsafe { entry.gem.as_ref() };

                    let refcount = bo.refcount();
                    if refcount == 0 {
                        continue;
                    }

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
                        0,
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

                    total_size = total_size.saturating_add(size);
                    total_resident = total_resident.saturating_add(resident);
                }
            }

            seq_print!(m, "====================================================================================================================================================\n");
            seq_print!(
                m,
                "Total size: {}, Total resident: {}, Total reclaimable: {}\n",
                total_size,
                total_resident,
                0
            );
        }
    }

    /// A BO's link to the device-wide `gems` registry.
    ///
    /// Holds the registry and the BO's entry once the BO is listed, so the
    /// free hook can unregister without reaching the device data or walking
    /// the list.
    pub(crate) struct GemLink {
        listing: SetOnce<(Arc<GemRegistry>, Arc<GemEntry>)>,
    }

    impl GemLink {
        /// Creates an unlisted link. It owns nothing, since an imported BO
        /// whose shmem init fails is freed with `kfree()` without being
        /// dropped.
        pub(crate) fn new() -> Self {
            Self {
                listing: SetOnce::new(),
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
                    let registry = &bo.dev().gem_registry;
                    if self.listing.populate((registry.clone(), entry.clone_arc())) {
                        registry.bos.lock().push_back(entry);
                    }
                }
                Err(_) => {
                    pr_warn_once!("gems debugfs registration failed under memory pressure\n")
                }
            }
        }

        /// Removes the owner of this link from the registry. A no-op if the
        /// BO is not listed.
        pub(crate) fn unregister(&self) {
            if let Some((registry, entry)) = self.listing.as_ref() {
                // SAFETY: `entry` is only ever added to the list of
                // `registry`.
                let _ = unsafe { registry.bos.lock().remove(entry) };
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
    /// VMs are listed in registration order without a reference. Each VM
    /// unregisters under the registry lock before its owner drops it, so a
    /// listed VM stays valid while the lock is held.
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

    fn priority_name(priority: Priority) -> &'static str {
        match priority {
            Priority::Low => "LOW",
            Priority::Medium => "MEDIUM",
            Priority::High => "HIGH",
            Priority::RealTime => "REAL-TIME",
        }
    }

    /// The `sched_groups` debugfs file, which lists the groups of every open
    /// file.
    pub(crate) struct SchedGroupsShow;

    impl SeqShow<TyrDrmRegistrationData<'_>> for SchedGroupsShow {
        fn show(reg_data: &TyrDrmRegistrationData<'_>, m: &SeqFile) -> Result {
            reg_data.tdev.for_each_file(|file| {
                let client_id = file.client_id();

                file.inner().group_pool().for_each(|handle, group| {
                    seq_print!(
                        m,
                        "client_id {:8} pid {:8} command {}: group {:2} priority {} queue count {}\n",
                        client_id,
                        group.task_pid(),
                        group.task_comm(),
                        handle,
                        priority_name(group.priority),
                        group.queue_count()
                    );
                    Ok(())
                })
            })
        }
    }
}

#[cfg(not(CONFIG_DEBUG_FS))]
mod disabled {
    use kernel::prelude::*;

    use crate::{
        gem::Bo,
        vm::Vm, //
    };

    /// Stand-in for the BO registry that tracks nothing.
    pub(crate) struct GemRegistry;

    impl GemRegistry {
        /// Creates the stand-in registry.
        pub(crate) fn new() -> impl PinInit<Self> {
            Self
        }
    }

    /// Stand-in for a BO's link to the BO registry.
    pub(crate) struct GemLink;

    impl GemLink {
        /// Creates the stand-in link.
        pub(crate) fn new() -> Self {
            Self
        }

        /// Does nothing without `CONFIG_DEBUG_FS`.
        pub(crate) fn register(&self, _bo: &Bo, _usage_flags: u32) {}

        /// Does nothing without `CONFIG_DEBUG_FS`.
        pub(crate) fn unregister(&self) {}
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
