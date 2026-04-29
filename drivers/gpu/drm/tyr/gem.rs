// SPDX-License-Identifier: GPL-2.0 or MIT
//! GEM buffer object management for the Tyr driver.
//!
//! This module provides buffer object (BO) management functionality using
//! DRM's GEM subsystem with shmem backing.

use core::ops::Range;

use kernel::{
    device::{
        Bound,
        Device, //
    },
    drm::gem::{
        self,
        shmem,
        BaseObject, //
    },
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    }, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDriver, //
    },
    file::TyrDrmFile,
    vm::{
        range,
        Vm,
        VmMapFlags, //
    },
};

/// Tyr's DriverObject type for GEM objects.
#[pin_data]
pub(crate) struct BoData {
    flags: u32,
}

/// Provides a way to pass arguments when creating BoData
/// as required by the gem::DriverObject trait.
pub(crate) struct BoCreateArgs {
    flags: u32,
}

impl gem::DriverObject for BoData {
    type Driver = TyrDrmDriver;
    type Args = BoCreateArgs;

    fn new(_dev: &TyrDrmDevice, _size: usize, args: BoCreateArgs) -> impl PinInit<Self, Error> {
        try_pin_init!(Self { flags: args.flags })
    }

    fn create_imported(_dev: &TyrDrmDevice, _size: usize) -> impl PinInit<Self, Error> {
        try_pin_init!(Self { flags: 0 })
    }
}

/// Type alias for Tyr GEM buffer objects.
pub(crate) type Bo = gem::shmem::Object<BoData>;

#[expect(dead_code)]
/// A mapped kernel-owned buffer object with an always-valid kernel mapping.
pub(crate) struct MappedBo {
    kernel_bo: KernelBo,
    kernel_node: range::LiveRange,
    vmap: shmem::VMapOwned<BoData>,
}

impl MappedBo {
    pub(crate) fn new(kernel_bo: KernelBo, kernel_node: range::LiveRange) -> Result<Arc<Self>> {
        let vmap = kernel_bo.bo.owned_vmap::<0>()?;
        Ok(Arc::new(
            Self {
                kernel_bo,
                kernel_node,
                vmap,
            },
            GFP_KERNEL,
        )?)
    }

    pub(crate) fn vmap(&self) -> &shmem::VMapOwned<BoData> {
        &self.vmap
    }

    pub(crate) fn kernel_va(&self) -> Option<Range<u64>> {
        Some(self.kernel_node.range())
    }
}

impl core::ops::Deref for MappedBo {
    type Target = Bo;

    fn deref(&self) -> &Bo {
        self.vmap.owner()
    }
}

/// Creates a dummy GEM object to serve as the root of a GPUVM.
pub(crate) fn new_dummy_object(ddev: &TyrDrmDevice) -> Result<ARef<Bo>> {
    let bo = Bo::new(
        ddev,
        4096,
        shmem::ObjectConfig {
            map_wc: true,
            parent_resv_obj: None,
        },
        BoCreateArgs { flags: 0 },
    )?;

    Ok(bo)
}

pub(crate) fn new_bo(ddev: &TyrDrmDevice, size: usize, flags: u32) -> Result<ARef<Bo>> {
    let aligned_size = size.next_multiple_of(1 << 12);

    if size == 0 || size > aligned_size {
        return Err(EINVAL);
    }

    Bo::new(
        ddev,
        aligned_size,
        shmem::ObjectConfig {
            map_wc: true,
            parent_resv_obj: None,
        },
        BoCreateArgs { flags },
    )
}

pub(crate) fn lookup_handle(file: &TyrDrmFile, handle: u32) -> Result<ARef<Bo>> {
    shmem::Object::lookup_handle(file, handle)
}

/// Creates a kernel-owned GEM object mapped into the VM and vmapped for CPU access.
pub(crate) fn new_kernel_object(
    dev: &Device<Bound>,
    ddev: &TyrDrmDevice,
    vm: &Arc<Vm>,
    size: usize,
    flags: VmMapFlags,
) -> Result<Arc<MappedBo>> {
    let aligned_size = size.next_multiple_of(1 << 12);
    let node = vm.alloc_kernel_range(aligned_size)?;
    let va = node.start();

    let kernel_bo = KernelBo::new(
        dev,
        ddev,
        vm.clone(),
        aligned_size as u64,
        KernelBoVaAlloc::Explicit(va),
        flags,
    )?;

    MappedBo::new(kernel_bo, node)
}

/// Specifies how to choose a GPU virtual address for a [`KernelBo`].
/// An automatic VA allocation strategy will be added in the future.
pub(crate) enum KernelBoVaAlloc {
    /// Explicit VA address specified by the caller.
    Explicit(u64),
}

/// A kernel-owned buffer object with automatic GPU virtual address mapping.
///
/// This structure represents a buffer object that is created and managed entirely
/// by the kernel driver, as opposed to userspace-created GEM objects. It combines
/// a GEM object with automatic GPU virtual address (VA) space mapping and cleanup.
///
/// When dropped, the buffer is automatically unmapped from the GPU VA space.
pub(crate) struct KernelBo {
    /// The underlying GEM buffer object.
    bo: ARef<Bo>,
    /// The GPU VM this buffer is mapped into.
    vm: Arc<Vm>,
    /// The GPU VA range occupied by this buffer.
    va_range: Range<u64>,
}

impl KernelBo {
    /// Creates a new kernel-owned buffer object and maps it into GPU VA space.
    ///
    /// This function allocates a new shmem-backed GEM object and immediately maps
    /// it into the specified GPU virtual memory space. The mapping is automatically
    /// cleaned up when the [`KernelBo`] is dropped.
    pub(crate) fn new(
        dev: &Device<Bound>,
        ddev: &TyrDrmDevice,
        vm: Arc<Vm>,
        size: u64,
        va_alloc: KernelBoVaAlloc,
        flags: VmMapFlags,
    ) -> Result<Self> {
        if size == 0 {
            dev_err!(dev, "Cannot create KernelBo with size 0");
            return Err(EINVAL);
        }

        let KernelBoVaAlloc::Explicit(va) = va_alloc;

        let bo_size = usize::try_from(size).map_err(|_| EOVERFLOW)?;
        let va_end = va.checked_add(size).ok_or(EINVAL)?;

        let bo = Bo::new(
            ddev,
            bo_size,
            shmem::ObjectConfig {
                map_wc: true,
                parent_resv_obj: None,
            },
            BoCreateArgs { flags: 0 },
        )?;

        vm.map_bo_range(dev, &bo, 0, size, va, flags)?;

        Ok(KernelBo {
            bo,
            vm,
            va_range: va..va_end,
        })
    }

    pub(crate) fn bo(&self) -> &Bo {
        &self.bo
    }

    /// Returns the GPU virtual address range occupied by this buffer.
    pub(crate) fn va_range(&self) -> &Range<u64> {
        &self.va_range
    }
}

impl Drop for KernelBo {
    fn drop(&mut self) {
        let va = self.va_range.start;
        let size = self.va_range.end - self.va_range.start;

        if let Err(e) = self.vm.unmap_range(va, size) {
            // If unmap_range fails, it is still safe to drop the
            // KernelBo and its ARef to the GEM buffer object because
            // GPUVM also holds a reference to the GEM buffer object.
            // The physical pages won't be freed or reallocated.
            dev_err!(
                self.vm.dev(),
                "Failed to unmap KernelBo range {:#x}..{:#x}: {:?}",
                self.va_range.start,
                self.va_range.end,
                e
            );
        }
    }
}
