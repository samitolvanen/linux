// SPDX-License-Identifier: GPL-2.0 or MIT

//! Device-wide object registries, their debugfs files, the `shrink` debugfs
//! file, and the knobs for exercising the GPU reset machinery. The knobs are
//! a local debugging aid.
//!
//! Each registry tracks live objects, without referencing them, so a debugfs
//! file can dump them without walking per-file state.

use core::{
    cmp::min,
    fmt::Write,
    ptr::{
        self,
        NonNull, //
    },
    sync::atomic::Ordering, //
};

use kernel::{
    debugfs::{
        Dir,
        File, //
    },
    drm::{
        debugfs::{
            Attribute,
            Info, //
        },
        gem::BaseObject, //
    },
    fmt,
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
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        },
        Mutex, //
    },
    task::{
        Pid,
        TaskComm, //
    },
    uaccess::UserSliceReader, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDriver, //
    },
    gem::Bo,
    reclaim::{
        self,
        ReclaimState, //
    },
    vm::Vm,
};

/// Sentinel `Vm` registry-slot value for a VM absent from the `gpuvas` registry.
pub(crate) const NOT_REGISTERED: usize = usize::MAX;

const GEM_STATE_IMPORTED: u32 = 1 << 0;
const GEM_STATE_EXPORTED: u32 = 1 << 1;
const GEM_STATE_EVICTED: u32 = 1 << 2;

/// BO is used only by the kernel driver.
pub(crate) const GEM_USAGE_KERNEL: u32 = 1 << 0;
/// BO is mapped into the firmware VM.
pub(crate) const GEM_USAGE_FW_MAPPED: u32 = 1 << 1;

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

// SAFETY: It is safe to send a `GemEntry` to another thread because the
// `NonNull<Bo>` it holds points to a GEM object, which is `Send` and `Sync`,
// and the registry only dereferences it while holding the registry lock, which
// blocks the object's free path before its backing is torn down. The remaining
// fields are plain data.
unsafe impl Send for GemEntry {}

// SAFETY: It is safe to share a `GemEntry` between threads because its
// pointer is only dereferenced under the registry lock and `Bo` is `Sync`.
// The other fields are plain data.
unsafe impl Sync for GemEntry {}

/// A BO's entry in the `gems` registry, or null if the BO is not listed. Only
/// ever touched under the registry lock.
pub(crate) struct GemSlot(Atomic<*const GemEntry>);

impl GemSlot {
    pub(crate) fn new() -> Self {
        Self(Atomic::new(ptr::null()))
    }
}

/// Device-wide registry of live BOs backing the `gems` debugfs file.
///
/// The registry holds no reference to its BOs. A BO registers itself just after
/// creation and deregisters from its free path (the `BoData` `free` hook),
/// which runs before the object's backing is torn down. Both the dump and
/// deregistration take the registry lock, so while the dump holds it a listed
/// BO can neither be removed nor start teardown, keeping every entry valid.
///
/// The free hook can run in memory reclaim, so entries are allocated before
/// the registry lock is taken.
///
/// Lock ordering: the registry lock is acquired before a BO's label lock, never
/// the reverse.
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

    /// Registers `bo` with the given usage flags, capturing the creating task.
    ///
    /// A failed allocation drops the BO from the dump but is otherwise harmless.
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
        let Ok(entry) = entry else {
            pr_warn_once!("gems debugfs registration failed under memory pressure\n");
            return;
        };

        let mut bos = self.bos.lock();
        bo.registry_slot().0.store(ptr::from_ref(&*entry), Relaxed);
        bos.push_back(entry);
    }

    /// Removes the BO owning `slot`. A no-op if the BO was never registered.
    pub(crate) fn unregister(&self, slot: &GemSlot) {
        let mut bos = self.bos.lock();
        let entry = slot.0.xchg(ptr::null(), Relaxed);
        if entry.is_null() {
            return;
        }

        // SAFETY: A non-null slot points to the entry of its BO, which this
        // list owns until the BO unregisters, and no other list holds it.
        drop(unsafe { bos.remove(&*entry) });
    }

    fn print_bos(&self, m: &SeqFile) {
        seq_print!(
            m,
            "GEM state flags: imported (0x1), exported (0x2), evicted (0x4)\n"
        );
        seq_print!(m, "GEM usage flags: kernel (0x1), fw-mapped (0x2)\n\n");
        seq_print!(m, "created-by                      global-name     refcount   evictions  size            resident-size   file-offset       state      usage       label\n");
        seq_print!(m, "----------------------------------------------------------------------------------------------------------------------------------------------------\n");

        let mut total_size = 0u64;
        let mut total_resident = 0u64;
        let mut total_reclaimable = 0u64;

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

                // The creator is left-justified in 32 columns, capped at 31.
                seq_print!(
                    m,
                    "{:<32.31}{:<16}{:<11}{:<11}{:<16}{:<16}0x{:<16x}0x{:<8x} 0x{:<10x}",
                    creator,
                    bo.global_name(),
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

                total_size = total_size.saturating_add(size as u64);
                total_resident = total_resident.saturating_add(resident as u64);
                if bo.reclaim_state() != ReclaimState::Unreclaimable {
                    total_reclaimable = total_reclaimable.saturating_add(resident as u64);
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
            Ok(()) => vm.registry_slot().store(index, Relaxed),
            Err(_) => {
                pr_warn_once!("gpuvas debugfs registration failed under memory pressure\n")
            }
        }
    }

    /// Removes the VM owning `slot`. A no-op if the VM was never registered.
    pub(crate) fn unregister(&self, slot: &Atomic<usize>) {
        let mut vms = self.vms.lock();
        let index = slot.xchg(NOT_REGISTERED, Relaxed);
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
                .store(i, Relaxed);
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

/// The `shrink` debugfs file. Reading it returns the number of pages that
/// the last scan reclaimed. Writing `n` scans `n` pages.
pub(crate) struct ShrinkAttr;

impl Attribute<TyrDrmDevice> for ShrinkAttr {
    const FORMAT: &'static CStr = c"0x%08llx\n";

    fn get(device: &TyrDrmDevice) -> Result<u64> {
        let pages = reclaim::with_reclaim(device, |reclaim| reclaim.last_scan_pages());

        Ok(pages.unwrap_or(0) as u64)
    }

    fn set(device: &TyrDrmDevice, val: u64) -> Result {
        reclaim::with_reclaim(device, |reclaim| {
            reclaim.shrink(usize::try_from(val).unwrap_or(usize::MAX))
        });
        Ok(())
    }
}

/// Owns the debugfs entries. Dropped with the platform driver data at
/// unbind, which removes the files before the reset controller is torn
/// down.
pub(crate) struct TyrDebugfs {
    _reset: Pin<KBox<File<ARef<TyrDrmDevice>>>>,
    _fail_ping: Pin<KBox<File<ARef<TyrDrmDevice>>>>,
    _fw_va: Pin<KBox<File<ARef<TyrDrmDevice>>>>,
    _dir: Dir,
}

impl TyrDebugfs {
    /// Creates the `tyr` debugfs directory and its entries.
    pub(crate) fn new(tdev: ARef<TyrDrmDevice>) -> Result<Self> {
        let dir = Dir::new(c"tyr");
        let fail_ping = KBox::pin_init(
            dir.read_write_callback_file(
                c"fail_ping",
                tdev.clone(),
                &fail_ping_read,
                &fail_ping_write,
            ),
            GFP_KERNEL,
        )?;
        let fw_va = KBox::pin_init(
            dir.read_callback_file(c"fw_va", tdev.clone(), &fw_va_read),
            GFP_KERNEL,
        )?;
        let reset = KBox::pin_init(
            dir.write_callback_file(c"reset", tdev, &reset_write),
            GFP_KERNEL,
        )?;
        Ok(Self {
            _reset: reset,
            _fail_ping: fail_ping,
            _fw_va: fw_va,
            _dir: dir,
        })
    }
}

/// Schedules an asynchronous GPU reset on any write to `tyr/reset`.
fn reset_write(tdev: &ARef<TyrDrmDevice>, _reader: &mut UserSliceReader) -> Result {
    dev_info!(tdev.pdev.as_ref(), "debug: scheduling a GPU reset\n");
    tdev.reset.schedule();
    Ok(())
}

/// Reports the remaining number of armed ping failures.
fn fail_ping_read(tdev: &ARef<TyrDrmDevice>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(f, "{}", tdev.fail_ping_count.load(Ordering::Relaxed))
}

/// Arms ping fault injection for the next N watchdog pings.
fn fail_ping_write(tdev: &ARef<TyrDrmDevice>, reader: &mut UserSliceReader) -> Result {
    let mut buf = [0u8; 16];
    if reader.len() > buf.len() {
        return Err(EINVAL);
    }
    let n = reader.len();
    reader.read_slice(&mut buf[..n])?;
    let s = core::str::from_utf8(&buf[..n]).map_err(|_| EINVAL)?;
    let count = s.trim().parse::<u32>().map_err(|_| EINVAL)?;
    tdev.fail_ping_count.store(count, Ordering::Relaxed);
    Ok(())
}

/// Reports the firmware VM kernel-VA window as "<used> <total>" bytes,
/// for watching suspend-buffer VA growth across reset storms.
fn fw_va_read(tdev: &ARef<TyrDrmDevice>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (used, total) = tdev.fw.vm().kernel_va_occupancy();
    writeln!(f, "{} {}", used, total)
}
