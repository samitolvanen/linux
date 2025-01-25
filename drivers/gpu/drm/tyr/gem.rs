// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;

use crate::driver::TyrDevice;
use crate::driver::TyrDriver;
use crate::file::DrmFile;
use crate::mmu::vm;
use crate::mmu::vm::Vm;
use kernel::devres::Devres;
use kernel::drm::gem::shmem;
use kernel::drm::gem::BaseObject;
use kernel::drm::gem::{self};
use kernel::drm::mm;
use kernel::io::mem::IoMem;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::types::ARef;

/// GEM Object inner driver data
#[pin_data]
pub(crate) struct DriverObject {
    /// Whether this is a kernel or user BO.
    ty: ObjectType,

    /// The flags received at BO creation time.
    flags: u32,
}

enum ObjectType {
    Kernel {
        // Kernel objects have their VA managed by the MM allocator. This node
        // represents the allocation.
        node: mm::Node<(), ()>,
    },

    User,
}

/// Type alias for the GEM object type for this driver.
pub(crate) type Object = gem::shmem::Object<DriverObject>;

pub struct GemArgs {
    ty: ObjectType,
    flags: u32,
}

#[vtable]
impl gem::BaseDriverObject for DriverObject {
    type Driver = TyrDriver;
    type Object = gem::shmem::Object<Self>;
    type Args = GemArgs;

    fn new(dev: &TyrDevice, _size: usize, args: Self::Args) -> impl PinInit<Self, Error> {
        dev_dbg!(dev.as_ref(), "DriverObject::new\n");
        DriverObject {
            ty: args.ty,
            flags: args.flags,
        }
    }
}

// impl gem::shmem::DriverObject for DriverObject {
//     type Driver = TyrDriver;
// }

/// A shared reference to a GEM object for this driver.
pub(crate) struct ObjectRef {
    /// The underlying GEM object reference
    pub(crate) gem: ARef<shmem::Object<DriverObject>>,

    /// The kernel-side VMap of this object, if any.
    vmap: Option<shmem::VMap<DriverObject>>,
}

impl ObjectRef {
    /// Create a new wrapper for a raw GEM object reference.
    pub(crate) fn new(gem: ARef<shmem::Object<DriverObject>>) -> ObjectRef {
        ObjectRef { gem, vmap: None }
    }

    /// Return the `VMap` for this object, creating it if necessary.
    pub(crate) fn vmap(&mut self) -> Result<&mut shmem::VMap<DriverObject>> {
        if self.vmap.is_none() {
            self.vmap = Some(self.gem.vmap()?);
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
            ObjectType::Kernel { node } => Some(node.start()..node.start() + node.size()),
            ObjectType::User => None,
        }
    }
}

type ObjectConfig<'a> = shmem::ObjectConfig<'a, DriverObject>;

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
    let mut obj = ARef::<kernel::drm::gem::shmem::Object<DriverObject>>::into_raw(gem);
    unsafe { obj.as_mut().flags = flags };

    let gem = unsafe { ARef::<kernel::drm::gem::shmem::Object<DriverObject>>::from_raw(obj) };

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
    vm: Arc<Mutex<Vm>>,
    mut va: KernelVaPlacement,
    flags: vm::map_flags::Flags,
) -> Result<ObjectRef> {
    va.align()?;
    let sz = va.size();
    let node = vm.lock().alloc_kernel_range(va)?;
    let range = node.start()..node.start() + node.size();

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

    vm.lock().bind_gem(iomem, &gem, 0, range, flags)?;

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
