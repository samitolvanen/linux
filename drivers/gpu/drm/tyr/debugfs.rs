// SPDX-License-Identifier: GPL-2.0 or MIT

//! Device-wide object registries and their debugfs files.
//!
//! Each registry tracks live objects, without referencing them, so a debugfs
//! file can dump them without walking per-file state.

use core::{
    cmp::min,
    fmt::Write,
    ptr::NonNull,
    sync::atomic::{
        AtomicUsize,
        Ordering, //
    },
};

use kernel::{
    drm::{
        debugfs::Info,
        gem::BaseObject, //
    },
    pr_warn_once,
    prelude::*,
    seq_file::{
        seq_print,
        SeqFile, //
    },
    str::Formatter,
    sync::Mutex,
    task::{
        Pid,
        TaskComm, //
    },
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDriver, //
    },
    gem::Bo,
    vm::Vm,
};

/// Sentinel `BoData` registry-slot value for a BO absent from the registry.
pub(crate) const NOT_REGISTERED: usize = usize::MAX;

const GEM_STATE_IMPORTED: u32 = 1 << 0;
const GEM_STATE_EXPORTED: u32 = 1 << 1;

/// BO is used only by the kernel driver.
pub(crate) const GEM_USAGE_KERNEL: u32 = 1 << 0;
/// BO is mapped into the firmware VM.
pub(crate) const GEM_USAGE_FW_MAPPED: u32 = 1 << 1;

/// One registry entry, holding a non-owning pointer to a live BO plus the
/// immutable creator and usage snapshot captured at registration.
struct GemEntry {
    gem: NonNull<Bo>,
    creator_comm: TaskComm,
    creator_tgid: Pid,
    usage_flags: u32,
}

// SAFETY: It is safe to send a `GemEntry` to another thread because the
// `NonNull<Bo>` it holds points to a GEM object, which is `Send` and `Sync`,
// and the registry only dereferences it while holding the registry lock, which
// blocks the object's free path before its backing is torn down. The remaining
// fields are plain data.
unsafe impl Send for GemEntry {}

/// Device-wide registry of live BOs backing the `gems` debugfs file.
///
/// The registry holds no reference to its BOs. A BO registers itself just after
/// creation and deregisters from its free path (the `BoData` `free` hook),
/// which runs before the object's backing is torn down. Both the dump and
/// deregistration take the registry lock, so while the dump holds it a listed
/// BO can neither be removed nor start teardown, keeping every entry valid.
///
/// Lock ordering: the registry lock is acquired before a BO's label lock, never
/// the reverse.
#[pin_data]
pub(crate) struct GemRegistry {
    #[pin]
    bos: Mutex<KVec<GemEntry>>,
}

impl GemRegistry {
    pub(crate) fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            bos <- kernel::new_mutex!(KVec::new()),
        })
    }

    /// Registers `bo` with the given usage flags, capturing the creating task.
    ///
    /// A failed allocation drops the BO from the dump but is otherwise harmless.
    pub(crate) fn register(&self, bo: &Bo, usage_flags: u32) {
        let current = kernel::current!();
        let leader = current.group_leader();
        let entry = GemEntry {
            gem: bo.into(),
            creator_comm: leader.comm(),
            creator_tgid: leader.pid(),
            usage_flags,
        };

        let mut bos = self.bos.lock();
        let index = bos.len();
        match bos.push(entry, GFP_KERNEL) {
            Ok(()) => bo.registry_slot().store(index, Ordering::Relaxed),
            Err(_) => {
                pr_warn_once!("tyr: gems debugfs registration failed under memory pressure\n")
            }
        }
    }

    /// Removes the BO owning `slot`. A no-op if the BO was never registered.
    pub(crate) fn unregister(&self, slot: &AtomicUsize) {
        let mut bos = self.bos.lock();
        let index = slot.swap(NOT_REGISTERED, Ordering::Relaxed);
        if index == NOT_REGISTERED {
            return;
        }

        let last = bos.len() - 1;
        if index != last {
            bos.swap(index, last);
        }
        bos.pop();
        if index != last {
            // The former last entry now sits at `index`. Fix up its slot.
            // SAFETY: `bos[index].gem` is still in the registry, so its object
            // is alive, and the registry lock is held for exclusive access.
            unsafe { bos[index].gem.as_ref() }
                .registry_slot()
                .store(index, Ordering::Relaxed);
        }
    }

    fn print_bos(&self, m: &SeqFile) {
        seq_print!(m, "GEM state flags: imported (0x1), exported (0x2)\n");
        seq_print!(m, "GEM usage flags: kernel (0x1), fw-mapped (0x2)\n\n");
        seq_print!(m, "created-by                      global-name     refcount        size            resident-size   file-offset       state      usage       label\n");
        seq_print!(m, "----------------------------------------------------------------------------------------------------------------------------------------------\n");

        let mut total_size = 0usize;
        let mut total_resident = 0usize;

        {
            let bos = self.bos.lock();
            for entry in bos.iter() {
                // SAFETY: `entry.gem` points to a live object. Deregistration
                // takes this lock and runs before the object's backing is torn
                // down, so holding the lock keeps every listed object valid.
                let bo = unsafe { entry.gem.as_ref() };

                let refcount = bo.refcount();
                // Skip BOs being destroyed.
                if refcount == 0 {
                    continue;
                }

                let size = bo.size();
                let resident = if bo.pages_present() { size } else { 0 };

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

                // The creator is left-justified in 32 columns, capped at 31.
                seq_print!(
                    m,
                    "{:<32.31}{:<16}{:<16}{:<16}{:<16}0x{:<16x}0x{:<8x} 0x{:<10x}",
                    creator,
                    bo.global_name(),
                    refcount,
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
            }
        }

        seq_print!(m, "==============================================================================================================================================\n");
        seq_print!(
            m,
            "Total size: {}, Total resident: {}, Total reclaimable: {}\n",
            total_size,
            total_resident,
            0
        );
    }
}

/// The `gems` debugfs file, a device-wide dump of every tracked BO.
pub(crate) struct GemsFile;

impl Info for GemsFile {
    type Driver = TyrDrmDriver;
    const NAME: &'static CStr = c"gems";

    fn show(device: &TyrDrmDevice, m: &SeqFile) -> Result {
        device.gem_registry().print_bos(m);
        Ok(())
    }
}

/// One registry entry, holding a non-owning pointer to a live VM.
struct VmEntry {
    vm: NonNull<Vm>,
}

// SAFETY: It is safe to send a `VmEntry` to another thread because the
// `NonNull<Vm>` it holds points to a `Vm`, which is `Send` and `Sync`, and the
// registry only dereferences it while holding the registry lock, during which
// an owning reference keeps the VM alive.
unsafe impl Send for VmEntry {}

/// Device-wide registry of live VMs backing the `gpuvas` debugfs file.
///
/// VMs are listed in registration order.
///
/// The registry holds no reference to its VMs. A user VM registers as it is
/// created and unregisters when its file pool destroys it. The firmware VM
/// registers at probe. While a VM is registered an owning reference keeps it
/// alive, so both the dump and unregistration take the registry lock and a
/// listed VM stays valid for the duration of the dump.
///
/// Lock ordering: the registry lock is acquired before a VM's `gpuvm_unique`
/// lock, never the reverse.
#[pin_data]
pub(crate) struct VmRegistry {
    #[pin]
    vms: Mutex<KVec<VmEntry>>,
}

impl VmRegistry {
    pub(crate) fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            vms <- kernel::new_mutex!(KVec::new()),
        })
    }

    /// Registers `vm` in the device-wide `gpuvas` registry.
    ///
    /// A failed allocation drops the VM from the dump but is otherwise harmless.
    pub(crate) fn register(&self, vm: &Vm) {
        let mut vms = self.vms.lock();
        let index = vms.len();
        match vms.push(VmEntry { vm: vm.into() }, GFP_KERNEL) {
            Ok(()) => vm.registry_slot().store(index, Ordering::Relaxed),
            Err(_) => {
                pr_warn_once!("tyr: gpuvas debugfs registration failed under memory pressure\n")
            }
        }
    }

    /// Removes the VM owning `slot`. A no-op if the VM was never registered.
    pub(crate) fn unregister(&self, slot: &AtomicUsize) {
        let mut vms = self.vms.lock();
        let index = slot.swap(NOT_REGISTERED, Ordering::Relaxed);
        if index == NOT_REGISTERED {
            return;
        }

        let _ = vms.remove(index);

        // Every entry after `index` moved down by one. Fix up their slots.
        for (i, entry) in vms.iter().enumerate().skip(index) {
            // SAFETY: `entry.vm` is still in the registry, so an owning
            // reference keeps its VM alive, and the registry lock is held.
            unsafe { entry.vm.as_ref() }
                .registry_slot()
                .store(i, Ordering::Relaxed);
        }
    }

    fn print_gpuvas(&self, m: &SeqFile) -> Result {
        let vms = self.vms.lock();
        for entry in vms.iter() {
            // SAFETY: `entry.vm` points to a live VM. While registered an
            // owning reference keeps it alive, and the registry lock blocks
            // unregistration, so holding it keeps every listed VM valid.
            let vm = unsafe { entry.vm.as_ref() };
            vm.show_gpuvas(m)?;
            seq_print!(m, "\n");
        }
        Ok(())
    }
}

/// The `gpuvas` debugfs file, a device-wide dump of every VM's GPU VA space.
pub(crate) struct GpuvasFile;

impl Info for GpuvasFile {
    type Driver = TyrDrmDriver;
    const NAME: &'static CStr = c"gpuvas";

    fn show(device: &TyrDrmDevice, m: &SeqFile) -> Result {
        device.vm_registry().print_gpuvas(m)
    }
}
