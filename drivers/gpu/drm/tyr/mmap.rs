// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::bindings;
use kernel::error::code::*;
use kernel::mm::virt::{flags as vma_flags, VmaNew};
use kernel::page::{PAGE_SHIFT, PAGE_SIZE};
use kernel::prelude::*;

use crate::driver::TyrDevice;
use crate::regs::CSF_GPU_LATEST_FLUSH_ID;

const DRM_PANTHOR_USER_MMIO_OFFSET_64BIT: u64 = 1u64 << 56;
const DRM_PANTHOR_USER_FLUSH_ID_MMIO_OFFSET: u64 = DRM_PANTHOR_USER_MMIO_OFFSET_64BIT;

pub(crate) fn mmap(device: &TyrDevice, _file: &crate::file::File, vma: &VmaNew) -> Option<Result> {
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

    unsafe {
        let vma_ptr = vma.as_ptr();
        let mut flags = (*vma_ptr).__bindgen_anon_2.__vm_flags;
        flags |= vma_flags::PFNMAP | vma_flags::NORESERVE;
        (*vma_ptr).__bindgen_anon_2.__vm_flags = flags;

        (*vma_ptr).vm_private_data = device as *const _ as *mut _;
        (*vma_ptr).vm_ops = &VM_OPS as *const _ as *const _;
    }

    Some(Ok(()))
}

static VM_OPS: bindings::vm_operations_struct = bindings::vm_operations_struct {
    fault: Some(vm_fault_handler),
    // SAFETY: All zeros is valid for vm ops.
    ..unsafe { core::mem::zeroed() }
};

unsafe extern "C" fn vm_fault_handler(vmf: *mut bindings::vm_fault) -> bindings::vm_fault_t {
    const VM_FAULT_SIGBUS: bindings::vm_fault_t = 0x02;

    let vma = unsafe { (*vmf).__bindgen_anon_1.vma };
    let address = unsafe { (*vmf).__bindgen_anon_1.address };

    let tdev_ptr = unsafe { (*vma).vm_private_data as *const TyrDevice };
    if tdev_ptr.is_null() {
        return VM_FAULT_SIGBUS;
    }

    let tdev = unsafe { &*tdev_ptr };

    let offset = (unsafe { (*vma).vm_pgoff } << PAGE_SHIFT) as u64;

    if offset != DRM_PANTHOR_USER_FLUSH_ID_MMIO_OFFSET {
        return VM_FAULT_SIGBUS;
    }

    let phys_addr = tdev.mmio_phys_addr + CSF_GPU_LATEST_FLUSH_ID as u64;
    let pfn = (phys_addr >> PAGE_SHIFT) as usize;

    let pgprot = unsafe { bindings::pgprot_noncached((*vma).vm_page_prot) };

    let ret = unsafe { bindings::vmf_insert_pfn_prot(vma, address, pfn, pgprot) };

    ret as bindings::vm_fault_t
}
