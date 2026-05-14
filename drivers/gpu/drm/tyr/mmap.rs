// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    bindings,
    error::code::EINVAL,
    mm::virt::{flags as vma_flags, VmaNew},
    page::{PAGE_SHIFT, PAGE_SIZE},
    prelude::*,
};

use crate::driver::TyrDrmDevice;

const DRM_PANTHOR_USER_MMIO_OFFSET_64BIT: u64 = 1u64 << 56;
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

    let phys_addr = tdev.mmio_phys_addr + CSF_GPU_LATEST_FLUSH_ID_OFFSET;
    let pfn = (phys_addr >> PAGE_SHIFT) as usize;

    // SAFETY: `vma` and `address` describe the active fault and `pfn` points to
    // the device MMIO page we expose through this special mapping.
    let ret = unsafe { bindings::vmf_insert_pfn(vma, address, pfn) };

    ret as bindings::vm_fault_t
}
