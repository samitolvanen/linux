// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;

use crate::driver::IoMem;
use crate::driver::TyrDevice;
use crate::driver::TyrDriver;
use crate::file::DrmFile;
use crate::mmu::vm;
use crate::mmu::vm::{LiveRange, Vm};
use kernel::devres::Devres;
use kernel::drm::gem;
use kernel::drm::gem::shmem;
use kernel::drm::gem::BaseObject;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::types::ARef;

/// GEM Object inner driver data
#[pin_data]
pub(crate) struct TyrObject {
    /// Whether this is a kernel or user BO.
    ty: ObjectType,

    /// The flags received at BO creation time.
    flags: u32,
}

enum ObjectType {
    Kernel {
        // Kernel objects have their VA managed by the MM allocator. This node
        // represents the allocation.
        node: LiveRange,
    },

    User,
}

/// Type alias for the GEM object type for this driver.
pub(crate) type Object = gem::shmem::Object<TyrObject>;

pub(crate) struct GemArgs {
    ty: ObjectType,
    flags: u32,
}

impl gem::DriverObject for TyrObject {
    type Driver = TyrDriver;
    type Args = GemArgs;

    fn new(_dev: &TyrDevice, _size: usize, args: Self::Args) -> impl PinInit<Self, Error> {
        try_pin_init!(TyrObject {
            ty: args.ty,
            flags: args.flags,
        })
    }
}

// impl gem::shmem::DriverObject for TyrObject {
//     type Driver = TyrDriver;
// }

/// A shared reference to a GEM object for this driver.
pub(crate) struct ObjectRef {
    /// The underlying GEM object reference
    pub(crate) gem: ARef<shmem::Object<TyrObject>>,

    /// The kernel-side VMap of this object, if any.
    vmap: Option<shmem::VMap<TyrObject, u8>>,
}

impl ObjectRef {
    /// Create a new wrapper for a raw GEM object reference.
    pub(crate) fn new(gem: ARef<shmem::Object<TyrObject>>) -> ObjectRef {
        ObjectRef { gem, vmap: None }
    }

    /// Return the `VMap` for this object, creating it if necessary.
    pub(crate) fn vmap(&mut self) -> Result<&mut shmem::VMap<TyrObject, u8>> {
        if self.vmap.is_none() {
            self.vmap = Some(self.gem.vmap()?.into());
        }
        Ok(self.vmap.as_mut().unwrap())
    }

    /// Returns the size of an object in bytes
    pub(crate) fn size(&self) -> usize {
        self.gem.size()
    }

    /// Returns the range occupied by this object in the kernel VA space, if
    /// any.
    pub(crate) fn kernel_va(&self) -> Option<Range<u64>> {
        match &self.gem.ty {
            ObjectType::Kernel { node } => Some(node.range()),
            ObjectType::User => None,
        }
    }
}

type ObjectConfig<'a> = shmem::ObjectConfig<'a, TyrObject>;

/// Create a new DRM GEM object.
pub(crate) fn new_object(dev: &TyrDevice, size: usize, flags: u32) -> Result<ObjectRef> {
    let aligned_size = size.next_multiple_of(1 << 12);

    if size == 0 || size > aligned_size {
        return Err(EINVAL);
    }

    let gem = Object::new(
        dev,
        aligned_size,
        ObjectConfig {
            map_wc: true,
            parent_resv_obj: None,
        },
        GemArgs {
            ty: ObjectType::User,
            flags,
        },
    )?;

    // TODO: This is really bad but at this point seems to be the only way:
    // to be refactored
    // SAFETY: We are the only owners at this point
    let mut obj = ARef::<kernel::drm::gem::shmem::Object<TyrObject>>::into_raw(gem);
    unsafe { obj.as_mut().flags = flags };

    let gem = unsafe { ARef::<kernel::drm::gem::shmem::Object<TyrObject>>::from_raw(obj) };

    Ok(ObjectRef::new(gem))
}

/// Look up a GEM object handle for a `File` and return an `ObjectRef` for it.
pub(crate) fn lookup_handle(file: &DrmFile, handle: u32) -> Result<ObjectRef> {
    Ok(ObjectRef::new(shmem::Object::lookup_handle(file, handle)?))
}

/// Create a new kernel-owned GEM object.
pub(crate) fn new_kernel_object(
    tdev: &TyrDevice,
    iomem: Arc<Devres<IoMem>>,
    vm: &mut Vm,
    mut va: KernelVaPlacement,
    flags: vm::map_flags::Flags,
) -> Result<ObjectRef> {
    va.align()?;
    let sz = va.size();
    let node = vm.alloc_kernel_range(va)?;
    let range = node.range();

    let gem = Object::new(
        tdev,
        sz,
        ObjectConfig {
            map_wc: true,
            parent_resv_obj: None,
        },
        GemArgs {
            ty: ObjectType::Kernel { node },
            flags: 0,
        },
    )?;

    pr_info!(
        "Binding kernel GEM object at VA range {:#x}-{:#x} (size: {:#x}) for VM {}\n",
        range.start,
        range.end,
        sz,
        vm.address_space().map_or(-1, |as_nr| as_nr as i32)
    );
    vm.bind_gem(iomem, &gem, 0, range, flags)?;

    Ok(ObjectRef::new(gem))
}

/// Creates a dummy GEM object to serve as the root of a GPUVM.
pub(crate) fn new_dummy_object(tdev: &TyrDevice) -> Result<ObjectRef> {
    let gem = Object::new(
        tdev,
        4096,
        ObjectConfig {
            map_wc: true,
            parent_resv_obj: None,
        },
        GemArgs {
            ty: ObjectType::User,
            flags: 0,
        },
    )?;

    Ok(ObjectRef::new(gem))
}

/// Controls the VA range assigned to a kernel-owned GEM object.
pub(crate) enum KernelVaPlacement {
    /// Automatically place this object in a free spot in the kernel VA range.
    Auto { size: usize },
    /// Place this object at a given address.
    At(Range<u64>),
}

impl KernelVaPlacement {
    pub(crate) fn size(&self) -> usize {
        match self {
            KernelVaPlacement::Auto { size } => *size,
            KernelVaPlacement::At(range) => (range.end - range.start) as usize,
        }
    }

    pub(crate) fn align(&mut self) -> Result {
        match self {
            KernelVaPlacement::Auto { size } => {
                *size = size.next_multiple_of(1 << 12);
            }
            KernelVaPlacement::At(range) => {
                if range.start % (1 << 12) != 0 {
                    pr_err!(
                        "Invalid range for kernel VA placement: {:#x}..{:#x}",
                        range.start,
                        range.end
                    );
                    return Err(EINVAL);
                }
            }
        }

        Ok(())
    }
}
