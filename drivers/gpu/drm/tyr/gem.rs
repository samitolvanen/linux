// SPDX-License-Identifier: GPL-2.0 or MIT
//! GEM buffer object management for the Tyr driver.
//!
//! This module provides buffer object (BO) management functionality using
//! DRM's GEM subsystem with shmem backing.

use core::ops::Range;

use kernel::{
    drm::{
        gem,
        gem::BaseObject,
        gem::shmem,
        DeviceContext, //
    },
    prelude::*,
    sync::{
        aref::ARef,
        Arc,
        ArcBorrow, //
    },
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

/// Driver-specific data for Tyr GEM buffer objects.
///
/// This structure contains Tyr-specific metadata associated with each GEM object.
/// It implements [`gem::DriverObject`] to provide driver-specific behavior for
/// buffer object creation and management.
#[pin_data]
pub(crate) struct BoData {
    /// Buffer object creation flags (currently unused).
    flags: u32,
}

/// Arguments for creating a [`BoData`] instance.
///
/// This structure is used to pass creation parameters when instantiating
/// a new buffer object, as required by the [`gem::DriverObject`] trait.
pub(crate) struct BoCreateArgs {
    /// Buffer object creation flags (currently unused).
    flags: u32,
}

impl gem::DriverObject for BoData {
    type Driver = TyrDrmDriver;
    type Args = BoCreateArgs;

    /// Constructs a new [`BoData`] instance for a GEM object.
    ///
    /// This function is called by the GEM subsystem when creating a new buffer
    /// object. It initializes the driver-specific data with the provided flags.
    /// The device and size parameters are currently unused but required by the
    /// [`gem::DriverObject`] trait.
    fn new<Ctx: DeviceContext>(
        _dev: &TyrDrmDevice<Ctx>,
        _size: usize,
        args: BoCreateArgs,
    ) -> impl PinInit<Self, Error> {
        try_pin_init!(Self { flags: args.flags })
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

#[expect(dead_code)]
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
pub(crate) fn new_dummy_object<Ctx: DeviceContext>(ddev: &TyrDrmDevice<Ctx>) -> Result<ARef<Bo>> {
    let bo = gem::shmem::Object::<BoData>::new(
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

pub(crate) fn new_bo<Ctx: DeviceContext>(
    ddev: &TyrDrmDevice<Ctx>,
    size: usize,
    flags: u32,
) -> Result<ARef<Bo>> {
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

#[expect(dead_code)]
/// Creates a kernel-owned GEM object mapped into the VM and vmapped for CPU access.
pub(crate) fn new_kernel_object<Ctx: DeviceContext>(
    dev: &TyrDrmDevice<Ctx>,
    vm: &Arc<Vm>,
    size: usize,
    flags: VmMapFlags,
) -> Result<Arc<MappedBo>> {
    let aligned_size = size.next_multiple_of(1 << 12);
    let node = vm.alloc_kernel_range(aligned_size)?;
    let va = node.start();

    let kernel_bo = KernelBo::new(
        dev,
        vm.as_arc_borrow(),
        aligned_size as u64,
        KernelBoVaAlloc::Explicit(va),
        flags,
    )?;

    MappedBo::new(kernel_bo, node)
}

/// VA allocation strategy for kernel buffer objects.
///
/// Specifies how the GPU virtual address should be determined when creating
/// a [`KernelBo`]. An automatic VA allocation strategy will be added in the future.
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
    pub(crate) bo: ARef<Bo>,
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
    pub(crate) fn new<Ctx: DeviceContext>(
        ddev: &TyrDrmDevice<Ctx>,
        vm: ArcBorrow<'_, Vm>,
        size: u64,
        va_alloc: KernelBoVaAlloc,
        flags: VmMapFlags,
    ) -> Result<Self> {
        if size == 0 {
            pr_err!("Cannot create KernelBo with size 0\n");
            return Err(EINVAL);
        }

        let KernelBoVaAlloc::Explicit(va) = va_alloc;

        let bo = gem::shmem::Object::<BoData>::new(
            ddev,
            size as usize,
            shmem::ObjectConfig {
                map_wc: true,
                parent_resv_obj: None,
            },
            BoCreateArgs { flags: 0 },
        )?;

        vm.map_bo_range(&bo, 0, size, va, flags)?;

        Ok(KernelBo {
            bo,
            vm: vm.into(),
            va_range: va..(va + size),
        })
    }

    /// Returns the GPU virtual address range occupied by this buffer.
    pub(crate) fn va_range(&self) -> Range<u64> {
        self.va_range.clone()
    }
}

impl Drop for KernelBo {
    fn drop(&mut self) {
        let va = self.va_range.start;
        let size = self.va_range.end - self.va_range.start;

        if let Err(e) = self.vm.unmap_range(va, size) {
            pr_err!(
                "Failed to unmap KernelBo range {:#x}..{:#x}: {:?}\n",
                self.va_range.start,
                self.va_range.end,
                e
            );
        }
    }
}
