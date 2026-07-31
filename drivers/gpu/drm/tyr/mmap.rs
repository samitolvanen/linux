// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    bindings,
    error::code::EINVAL,
    mm::virt::{
        flags as vma_flags,
        VmaNew,
        VmaRef, //
    },
    page::{
        Page,
        PAGE_SHIFT,
        PAGE_SIZE, //
    },
    prelude::*,
};

use crate::driver::TyrDrmDevice;

pub(crate) const DRM_PANTHOR_USER_MMIO_OFFSET_64BIT: u64 = 1u64 << 56;
const DRM_PANTHOR_USER_FLUSH_ID_MMIO_OFFSET: u64 = DRM_PANTHOR_USER_MMIO_OFFSET_64BIT;
const CSF_GPU_LATEST_FLUSH_ID_OFFSET: u64 = 0x10000;

pub(crate) fn mmap(
    device: &TyrDrmDevice,
    _file: &crate::file::TyrDrmFileData,
    vma: &VmaNew,
) -> Option<Result> {
    let offset = (vma.pgoff() as u64) << PAGE_SHIFT;

    if offset < DRM_PANTHOR_USER_MMIO_OFFSET_64BIT {
        return None;
    }

    if offset != DRM_PANTHOR_USER_FLUSH_ID_MMIO_OFFSET {
        return Some(Err(EINVAL));
    }

    if (vma.flags() & vma_flags::SHARED) == 0 {
        return Some(Err(EINVAL));
    }

    if vma.end() - vma.start() != PAGE_SIZE {
        return Some(Err(EINVAL));
    }

    if (vma.flags() & (vma_flags::WRITE | vma_flags::EXEC)) != 0 {
        return Some(Err(EINVAL));
    }

    vma.try_clear_maywrite().ok();

    vma.set_io();
    vma.set_dontcopy();
    vma.set_dontexpand();
    vma.set_dontdump();

    // SAFETY: `vma` is a live VMA provided by the DRM mmap callback and we only
    // update fields that the C path initializes for driver-managed PFN mappings.
    unsafe {
        let vma_ptr = vma.as_ptr();
        let mut flags = (*vma_ptr).__bindgen_anon_2.vm_flags;
        flags |= vma_flags::PFNMAP | vma_flags::NORESERVE;
        (*vma_ptr).__bindgen_anon_2.vm_flags = flags;

        (*vma_ptr).vm_private_data = core::ptr::from_ref(device).cast_mut().cast();
        (*vma_ptr).vm_ops = core::ptr::from_ref(&VM_OPS).cast();
    }

    Some(Ok(()))
}

static VM_OPS: bindings::vm_operations_struct = bindings::vm_operations_struct {
    fault: Some(vm_fault_handler),
    // SAFETY: All zeros is valid for vm ops.
    ..unsafe { core::mem::zeroed() }
};

/// # Safety
///
/// `vmf` must be a valid fault pointer provided by the kernel VM fault path
/// for a VMA previously initialized by `mmap` above.
unsafe extern "C" fn vm_fault_handler(vmf: *mut bindings::vm_fault) -> bindings::vm_fault_t {
    const VM_FAULT_SIGBUS: bindings::vm_fault_t = 0x02;

    // SAFETY: `vmf` is provided by the VM subsystem for this fault callback.
    let vma = unsafe { (*vmf).__bindgen_anon_1.vma };
    // SAFETY: `vmf` is provided by the VM subsystem for this fault callback.
    let address = unsafe { (*vmf).__bindgen_anon_1.address };

    // SAFETY: `vma` came from the VM subsystem and `vm_private_data` was set in
    // `mmap` to either a valid `TyrDrmDevice` pointer or null.
    let tdev_ptr = unsafe { (*vma).vm_private_data as *const TyrDrmDevice };
    if tdev_ptr.is_null() {
        return VM_FAULT_SIGBUS;
    }

    // SAFETY: Null was checked above and the pointer was stored from a live
    // device reference in `mmap`.
    let tdev = unsafe { &*tdev_ptr };

    // SAFETY: `vma` came from the VM subsystem for this fault callback.
    let offset = (unsafe { (*vma).vm_pgoff } << PAGE_SHIFT) as u64;
    if offset != DRM_PANTHOR_USER_FLUSH_ID_MMIO_OFFSET {
        return VM_FAULT_SIGBUS;
    }

    // SAFETY: `vma` is the active VMA for this fault; the kernel holds the
    // mmap read lock for the duration of the callback.
    let vma_ref = unsafe { VmaRef::from_raw(vma) };

    // A read through a live PTE into unclocked MMIO is an external
    // abort, so a suspended device gets the dummy page. The `user_mmio`
    // lock orders the check and the PTE insert against the suspend
    // path's unmap.
    let user_mmio = tdev.user_mmio.lock();
    let (pfn, pgprot) = if user_mmio.powered {
        let phys_addr = tdev.mmio_phys_addr + CSF_GPU_LATEST_FLUSH_ID_OFFSET;
        (
            (phys_addr >> PAGE_SHIFT) as usize,
            vma_ref.vm_page_prot().noncached(),
        )
    } else {
        (user_mmio.dummy_latest_flush.pfn(), vma_ref.vm_page_prot())
    };

    vma_ref.vmf_insert_pfn_prot(address, pfn, pgprot)
}

/// State of the user `LATEST_FLUSH` mapping, shared under one lock by
/// the fault handler and the runtime PM callbacks so the mapping tracks
/// whether the GPU is powered.
pub(crate) struct UserMmio {
    /// Whether the GPU MMIO region is powered. The fault handler may
    /// insert the real `LATEST_FLUSH` PFN only while this is set.
    powered: bool,
    /// Stand-in page served by the fault handler while the GPU is
    /// suspended. It holds 1 so userspace skips the cache flush. Zero
    /// cannot be used because it means "always flush".
    dummy_latest_flush: Page,
}

impl UserMmio {
    /// Allocates and initializes the dummy page. Called once at probe,
    /// while the device is powered.
    pub(crate) fn new() -> Result<Self> {
        let dummy_latest_flush = Page::alloc_page(GFP_KERNEL | __GFP_ZERO)?;

        let init = 1u32.to_ne_bytes();
        // SAFETY: the page was just allocated and is not shared, so the
        // write cannot race, and the 4-byte write at offset 0 is in
        // bounds.
        unsafe { dummy_latest_flush.write_raw(init.as_ptr(), 0, init.len())? };

        Ok(Self {
            powered: true,
            dummy_latest_flush,
        })
    }

    /// Sets whether the GPU MMIO is powered and drops the user `LATEST_FLUSH`
    /// PTEs so the fault handler re-derives the mapping.
    #[expect(dead_code)]
    pub(crate) fn set_powered(&mut self, device: &TyrDrmDevice, powered: bool) {
        self.powered = powered;
        device.unmap_mapping_range(DRM_PANTHOR_USER_MMIO_OFFSET_64BIT, 0);
    }
}
