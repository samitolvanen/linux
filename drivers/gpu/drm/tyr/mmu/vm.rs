// SPDX-License-Identifier: GPL-2.0 or MIT

//! VM management.
//!
//! VMs represent a given address space. It provides memory isolation and the
//! illusion of owning the entire VA range, much like CPU virtual memory.
//!
//! VMs can be placed into a hardware slots (i.e.: AS slots), which will make
//! them active. The number of AS's is limited, and one VM must evict an inactive
//! one if all slots are taken. In Panthor, this is implemented by keeping a LRU
//! list, but this is currently not implemented here.
//!
//! A VM is assigned an AS by means of a VM_BIND call if the request operation
//! is OP_MAP.
//!
//! If there is no unactive VM to evict, the call to VM_BIND should fail with
//! EBUSY, but note that slot management is somewhat WIP for now, as we have no
//! tests for that yet.
//!
//! AS0 is special, in the sense that it's the slot used by the firmware's VM.
//! No other VM can occupy AS0 at any time.

use core::ops::Range;

use gpuvm::LockedVm;
use gpuvm::StepContext;
use kernel::bindings::SZ_2M;
use kernel::c_str;
use kernel::devres::Devres;
use kernel::drm::gem::shmem;
use kernel::drm::gpuvm::ExecToken;
use kernel::drm::mm;
use kernel::io::mem::IoMem;
use kernel::io_pgtable::ARM64LPAES1;
use kernel::io_pgtable::{self};
use kernel::platform;
use kernel::prelude::*;
use kernel::sizes::SZ_4K;
use kernel::sync::Arc;
use kernel::types::ARef;

use crate::driver::TyrDevice;
use crate::gem;
use crate::gem::DriverObject;
use crate::gem::KernelVaPlacement;
use crate::gpu::GpuInfo;
use crate::mmu::Mmu;
use crate::regs;

mod gpuvm;
pub(crate) mod map_flags;
pub(crate) mod pool;

// TODO: we need *all* of these in kernel::bindings.
const SZ_4G: u64 = 4 * kernel::bindings::SZ_1G as u64;

pub(crate) struct Vm {
    /// A dummy object to serve as GPUVM's root. We need ownership of this.
    _dummy_obj: ARef<shmem::Object<DriverObject>>,

    pub(super) gpuvm: ARef<kernel::drm::gpuvm::GpuVm<LockedVm>>,

    /// The AS to which this VM is bound, if any.
    pub(super) address_space: Option<usize>,

    // binding: Option<SlotAllocation>,
    /// The memory attributes for this VM.
    pub(super) memattr: u64,

    /// The layout describing how the VM is split between user and kernel space.
    _layout: VmLayout,

    /// Whether this is the MCU VM.
    pub(super) for_mcu: bool,

    /// The range to automatically allocate kernel VAs from, if requested.
    auto_kernel_va: Range<u64>,

    /// Whether this VM was destroyed by userspace.
    ///
    /// Destroyed VMs are unmapped and cannot be the target of map operations
    /// anymore.
    pub(super) destroyed: bool,
}

impl Vm {
    pub(super) fn create(
        tdev: &TyrDevice,
        pdev: &platform::Device,
        for_mcu: bool,
        gpu_info: &GpuInfo,
        layout: VmLayout,
        auto_kernel_va: Range<u64>,
    ) -> Result<Self> {
        // We should ideally not allocate memory for this, but there is no way
        // to create dummy GPUVM GEM objects for now.
        //
        // This is being discussed on Zulip. For now we have to waste 4k on
        // this.
        let dummy_obj = gem::new_dummy_object(tdev)?;

        let va_bits = gpu_info.va_bits();
        let pa_bits = gpu_info.pa_bits();

        pr_info!(
            "Creating VM with VA bits: {}, PA bits: {}\n",
            va_bits,
            pa_bits
        );

        let full_va_range = 1u64 << va_bits;

        let va_range = if for_mcu { 0..SZ_4G } else { 0..full_va_range };

        let kernel_mm = mm::Allocator::new(
            layout.kernel.start,
            layout.kernel.end - layout.kernel.start,
            (),
        )?;

        let page_table = ARM64LPAES1::new(
            pdev.as_ref(),
            io_pgtable::Config {
                pgsize_bitmap: SZ_4K | SZ_2M as usize,
                ias: va_bits as usize,
                oas: pa_bits as usize,
                coherent_walk: false,
                quirks: 0,
            },
            (),
        )?;

        let memattr = mair_to_memattr(page_table.cfg().mair);

        Ok(Vm {
            _dummy_obj: dummy_obj.gem.clone(),
            gpuvm: kernel::drm::gpuvm::GpuVm::new(
                c_str!("Tyr::GpuVm"),
                tdev,
                &*(dummy_obj.gem),
                va_range.clone(),
                0..0,
                LockedVm::new(page_table, kernel_mm),
            )?,
            // binding: None,
            address_space: None,
            memattr,
            _layout: layout,
            for_mcu,
            auto_kernel_va,
            destroyed: false,
        })
    }

    /// Allocs a kernel range using the MM allocator.
    ///
    /// Kernel VAs are used for the FW, for synchronization objects, ring
    /// buffers and other kernel-only data structures.
    pub(crate) fn alloc_kernel_range(&mut self, va: KernelVaPlacement) -> Result<mm::Node<(), ()>> {
        // stack_pin_init!(let local_guard = new_mutex!(()));
        // let mut locked_vm = self.gpuvm.lock(&mut local_guard.lock());

        match va {
            KernelVaPlacement::Auto { size } => unsafe { self.gpuvm.as_inner_mut() }
                .kernel_mm
                .insert_node_in_range(
                    (),
                    size as u64,
                    4096,
                    0,
                    self.auto_kernel_va.start,
                    self.auto_kernel_va.end,
                    mm::InsertMode::Best,
                ),
            KernelVaPlacement::At(va) => unsafe { self.gpuvm.as_inner_mut() }
                .kernel_mm
                .reserve_node((), va.start, va.end - va.start, 0),
        }
    }

    /// Binds a GEM object to the VM, starting at `bo_offset`.
    ///
    /// `va_range` controls where in the VA space the BO will be mapped to.
    pub(crate) fn bind_gem(
        &mut self,
        iomem: Arc<Devres<IoMem>>,
        bo: &gem::Object,
        bo_offset: u64,
        va_range: Range<u64>,
        vm_map_flags: map_flags::Flags,
    ) -> Result {
        // XXX: do not rearrange this or it will deadlock.
        //
        // Sadly, `inner` will lock the reservation for `bo`, and we need
        // `inner` to produce `vm_bo`.
        //
        // In the natural drop order, the `ARef` for `vm_bo` will attempt to
        // lock the reservation to decrement the refcount, but it's already
        // locked by the call that produced `inner`.
        //
        // We can prove the above by just enabling lockdep.
        //
        // This means that it's trivially easy to deadlock when obtain_bo() is
        // called if the drop order is not inverted. A solution to this will
        // probably be beyond the scope of this driver. This problem also
        // apparently predates Rust4Linux, from what I could gather.
        //
        // Here we just move `vm_bo` into `ctx`, to make sure it gets dropped
        // after `inner`, on top of it also being needed in the `step_map`
        // callback.
        //
        // Note that sg_table() will also lock the reservation, so it too needs
        // to come before `inner`.
        let mut ctx: StepContext = StepContext {
            iomem,
            vm_bo: None,
            vm_map_flags: Some(vm_map_flags),
            vm_as_nr: self.address_space,
            preallocated_vas: StepContext::preallocate_vas()?,
        };

        // Things get tricky/nasty here as obtaining the gpuvm inner data requires
        // a guard. Even though access is already protected by VM lock,
        // this one cannot be used really, so ... there it is
        // ... untill smth better pops up
        // stack_pin_init!(let local_guard = new_mutex!(()));
        // let mut locked_vm = self.gpuvm.lock(&mut local_guard.lock());

        let vm_bo = self.gpuvm.obtain_bo(bo)?;

        ctx.vm_bo = Some(vm_bo);
        unsafe { self.gpuvm.as_inner_mut() }.map(&mut ctx, bo, va_range, bo_offset)
    }

    /// Unmap a given VA range.
    pub(crate) fn unmap_range(&mut self, iomem: Arc<Devres<IoMem>>, range: Range<u64>) -> Result {
        // stack_pin_init!(let local_guard = new_mutex!(()));
        // let mut locked_vm = self.gpuvm.lock(&mut local_guard.lock());

        let mut ctx = StepContext {
            iomem,
            vm_bo: None,
            vm_map_flags: None,
            vm_as_nr: None,
            preallocated_vas: StepContext::preallocate_vas()?,
        };

        unsafe { self.gpuvm.as_inner_mut() }.unmap(&mut ctx, range)
    }

    /// Flush L2 caches for the entirety of a VM's AS.
    pub(crate) fn flush(&self, tdev: &ARef<TyrDevice>) -> Result {
        let iomem = &tdev.iomem;

        let as_nr = self.address_space.ok_or(EINVAL)?;
        let range = self.gpuvm.va_range();
        Mmu::flush_range(iomem, as_nr, range)
    }

    /// Unmap the whole VM.
    pub(crate) fn unmap_all(&mut self, iomem: Arc<Devres<IoMem>>) -> Result {
        let range = self.gpuvm.va_range();

        self.unmap_range(iomem, range)?;
        self.address_space = None;

        Ok(())
    }

    pub(crate) fn address_space(&self) -> Option<usize> {
        self.address_space
    }

    /// Prepare our objecs, reserving a total of `num_slots` fence slots.
    pub(crate) fn with_prepared_vm(
        &self,
        num_slots: u32,
        f: impl FnOnce(PreparedVm<'_>) -> Result,
    ) -> Result {
        let exec_token = self.gpuvm.prepare(num_slots)?;
        let prepared_vm = PreparedVm {
            exec_token,
            num_slots,
        };

        f(prepared_vm)
    }
}

/// Indicates that all the reservations are locked for the objects in a given
/// VM, and that `num_slots` have been reserved for fences.
pub(crate) struct PreparedVm<'a> {
    exec_token: ExecToken<'a, LockedVm>,
    pub(crate) num_slots: u32,
}

/// 256M of every VM is reserved for kernel objects by default, i.e.: heap
/// chunks, heapcontext, ring buffers, kernel synchronization objects and etc.
///
/// The user VA space always start at 0x0, and the kernel VA space is always
/// placed after the user VA range.
const MIN_KERNEL_VA_SIZE: u64 = 0x10000000;

pub(crate) struct VmLayout {
    /// Section reserved for user objects.
    pub(crate) user: Range<u64>,

    /// Section reserved for kernel objects.
    pub(crate) kernel: Range<u64>,
}

impl VmLayout {
    /// Automatically manages a layout given the a `VmSize`
    pub(crate) fn from_user_sz(tdev: &TyrDevice, user_sz: VmUserSize) -> Self {
        let va_bits = tdev.gpu_info.va_bits();
        let max_va_range = 1u64 << va_bits;

        let user;
        let kernel;

        match user_sz {
            VmUserSize::Auto | VmUserSize::Custom(0) => {
                user = 0..max_va_range - MIN_KERNEL_VA_SIZE;
                kernel = user.end..user.end + MIN_KERNEL_VA_SIZE;
            }
            VmUserSize::Custom(user_sz) => {
                let user_sz = core::cmp::min(user_sz, max_va_range - MIN_KERNEL_VA_SIZE);
                user = 0..user_sz;
                kernel = user_sz..user_sz + MIN_KERNEL_VA_SIZE;
            }
        }

        Self { user, kernel }
    }
}

/// Controls the size of the user VA space.
pub(crate) enum VmUserSize {
    /// Lets the kernel decide the user/kernel split.
    Auto,
    /// Sets the user VA space to a custom size. Things will crash if not enough
    /// is left for kernel objects.
    Custom(u64),
}

fn as_memattr_aarch64_inner_alloc_expl(inner: bool, outer: bool) -> u8 {
    ((inner as u8) << 1) | (outer as u8)
}

fn mair_to_memattr(mair: u64) -> u64 {
    let mut memattr: u64 = 0;

    for i in 0..8 {
        let in_attr = (mair >> (8 * i)) as u8;
        let outer = in_attr >> 4;
        let inner = in_attr & 0xf;

        // For caching to be enabled, inner and outer caching policy
        // have to be both write-back, if one of them is write-through
        // or non-cacheable, we just choose non-cacheable. Device
        // memory is also translated to non-cacheable.
        let out_attr = if (outer & 3 == 0) || (outer & 4 == 0) || (inner & 4 == 0) {
            regs::AS_MEMATTR_AARCH64_INNER_OUTER_NC
                | regs::AS_MEMATTR_AARCH64_SH_MIDGARD_INNER
                | as_memattr_aarch64_inner_alloc_expl(false, false) as u32
        } else {
            // Use SH_CPU_INNER mode so SH_IS, which is used when
            // IOMMU_CACHE is set, actually maps to the standard
            // definition of inner-shareable and not Mali's
            // internal-shareable mode.
            regs::AS_MEMATTR_AARCH64_INNER_OUTER_WB
                | regs::AS_MEMATTR_AARCH64_SH_CPU_INNER
                | as_memattr_aarch64_inner_alloc_expl(inner & 1 != 0, inner & 2 != 0) as u32
        };

        memattr |= (out_attr as u64) << (8 * i);
    }

    memattr
}
