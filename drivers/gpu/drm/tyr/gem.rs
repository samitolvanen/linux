// SPDX-License-Identifier: GPL-2.0 or MIT
//! GEM buffer object management for the Tyr driver.
//!
//! This module provides buffer object (BO) management functionality using
//! DRM's GEM subsystem with shmem backing.

use core::ops::Range;

use kernel::{
    drm::{
        gem,
        gem::shmem,
        gem::BaseObject,
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
    vm::LiveRange,
    vm::{
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
    /// Whether this is a kernel or user BO.
    ty: ObjectType,
    /// The flags received at BO creation time.
    pub(crate) flags: u32,
}

impl BoData {
    /// Returns the kernel VA range for kernel-owned BOs.
    pub(crate) fn kernel_va(&self) -> Option<Range<u64>> {
        match &self.ty {
            ObjectType::Kernel { node } => Some(node.range()),
            ObjectType::User => None,
        }
    }
}

enum ObjectType {
    // Kernel objects have their VA managed by the range allocator.
    // This node represents the allocation.
    Kernel { node: LiveRange },
    User,
}

/// Arguments for creating a [`BoData`] instance.
///
/// This structure is used to pass creation parameters when instantiating
/// a new buffer object, as required by the [`gem::DriverObject`] trait.
pub(crate) struct BoCreateArgs {
    ty: ObjectType,
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
        try_pin_init!(Self {
            ty: args.ty,
            flags: args.flags,
        })
    }
}

/// Type alias for Tyr GEM buffer objects.
pub(crate) type Bo = gem::shmem::Object<BoData>;

/// A mapped GEM buffer object with an always-valid kernel mapping.
///
/// This wraps a [`shmem::VMap`] that holds both the kernel mapping and a
/// reference to the underlying [`Bo`]. Use [`Deref`] to access the `Bo`
/// (via [`VMap::owner()`]).
pub(crate) struct MappedBo {
    vmap: shmem::VMap<BoData>,
}

impl MappedBo {
    /// Creates a new `MappedBo` by vmapping the given BO.
    pub(crate) fn new(bo: &Bo) -> Result<Arc<Self>> {
        let vmap = bo.vmap()?;
        Ok(Arc::new(MappedBo { vmap: vmap.into() }, GFP_KERNEL)?)
    }

    /// Returns a reference to the underlying VMap.
    pub(crate) fn vmap(&self) -> &shmem::VMap<BoData> {
        &self.vmap
    }
}

impl core::ops::Deref for MappedBo {
    type Target = Bo;

    fn deref(&self) -> &Bo {
        self.vmap.owner()
    }
}

pub(crate) fn new_bo<Ctx: DeviceContext>(
    dev: &TyrDrmDevice<Ctx>,
    size: usize,
    flags: u32,
) -> Result<ARef<Bo>> {
    let aligned_size = size.next_multiple_of(1 << 12);

    if size == 0 || size > aligned_size {
        return Err(EINVAL);
    }

    Bo::new(
        dev,
        aligned_size,
        shmem::ObjectConfig {
            map_wc: true,
            parent_resv_obj: None,
        },
        BoCreateArgs {
            ty: ObjectType::User,
            flags,
        },
    )
}

pub(crate) fn lookup_handle(file: &TyrDrmFile, handle: u32) -> Result<ARef<Bo>> {
    shmem::Object::lookup_handle(file, handle)
}

/// Creates a kernel-owned GEM object mapped into the VM.
///
/// Allocates a virtual address range from the VM's kernel VA allocator,
/// creates a GEM buffer object, maps it into the VM, and vmaps it for
/// CPU access. The returned `MappedBo` always has a valid kernel mapping.
pub(crate) fn new_kernel_object<Ctx: DeviceContext>(
    dev: &TyrDrmDevice<Ctx>,
    vm: &Vm,
    size: usize,
    flags: VmMapFlags,
) -> Result<Arc<MappedBo>> {
    let aligned_size = size.next_multiple_of(1 << 12);
    let node = vm.alloc_kernel_range(aligned_size)?;
    let va = node.start();

    let gem = Bo::new(
        dev,
        aligned_size,
        shmem::ObjectConfig {
            map_wc: true,
            parent_resv_obj: None,
        },
        BoCreateArgs {
            ty: ObjectType::Kernel { node },
            flags: 0,
        },
    )?;

    vm.map_bo_range(&gem, 0, aligned_size as u64, va, flags)?;
    MappedBo::new(&gem)
}

/// Creates a dummy GEM object to serve as the root of a GPUVM.
pub(crate) fn new_dummy_object<Ctx: DeviceContext>(ddev: &TyrDrmDevice<Ctx>) -> Result<ARef<Bo>> {
    Bo::new(
        ddev,
        4096,
        shmem::ObjectConfig {
            map_wc: true,
            parent_resv_obj: None,
        },
        BoCreateArgs {
            ty: ObjectType::User,
            flags: 0,
        },
    )
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

        let bo = Bo::new(
            ddev,
            size as usize,
            shmem::ObjectConfig {
                map_wc: true,
                parent_resv_obj: None,
            },
            BoCreateArgs {
                ty: ObjectType::User,
                flags: 0,
            },
        )?;

        vm.map_bo_range(&bo, 0, size, va, flags)?;

        Ok(KernelBo {
            bo,
            vm: vm.into(),
            va_range: va..(va + size),
        })
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
