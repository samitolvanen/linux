// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    drm,
    prelude::*,
    sync::aref::ARef,
    uaccess::UserSlice,
    uapi, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmDriver, //
    },
    vm,
};

#[pin_data(PinnedDrop)]
pub(crate) struct TyrDrmFileData {
    vm_pool: vm::Pool,
}

/// Convenience type alias for our DRM `File` type
pub(crate) type TyrDrmFile = drm::file::File<TyrDrmFileData>;

impl drm::file::DriverFile for TyrDrmFileData {
    type Driver = TyrDrmDriver;

    fn open(_dev: &drm::Device<Self::Driver>) -> Result<Pin<KBox<Self>>> {
        KBox::try_pin_init(
            try_pin_init!(Self {
                vm_pool: vm::Pool::create()?,
            }),
            GFP_KERNEL,
        )
    }
}

#[pinned_drop]
impl PinnedDrop for TyrDrmFileData {
    fn drop(self: Pin<&mut Self>) {
        if let Err(e) = self.as_ref().vm_pool().destroy_all() {
            pr_err!("Failed to destroy all VMs: {:?}\n", e);
        }
    }
}

impl TyrDrmFileData {
    pub(crate) fn vm_pool(self: Pin<&Self>) -> &vm::Pool {
        &self.get_ref().vm_pool
    }

    pub(crate) fn dev_query(
        ddev: &TyrDrmDevice,
        devquery: &mut uapi::drm_panthor_dev_query,
        _file: &TyrDrmFile,
    ) -> Result<u32> {
        if devquery.pointer == 0 {
            match devquery.type_ {
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GPU_INFO => {
                    devquery.size = core::mem::size_of_val(&ddev.gpu_info) as u32;
                    Ok(0)
                }
                _ => Err(EINVAL),
            }
        } else {
            match devquery.type_ {
                uapi::drm_panthor_dev_query_type_DRM_PANTHOR_DEV_QUERY_GPU_INFO => {
                    let mut writer = UserSlice::new(
                        UserPtr::from_addr(devquery.pointer as usize),
                        devquery.size as usize,
                    )
                    .writer();

                    writer.write(&ddev.gpu_info)?;

                    Ok(0)
                }
                _ => Err(EINVAL),
            }
        }
    }

    pub(crate) fn vm_create(
        ddev: &TyrDrmDevice,
        vmcreate: &mut uapi::drm_panthor_vm_create,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if vmcreate.flags != 0 {
            return Err(EINVAL);
        }

        let (id, user_va_range) = file
            .inner()
            .vm_pool()
            .create_vm(&ARef::from(ddev), vmcreate.user_va_range)?;

        vmcreate.id = id as u32;
        vmcreate.user_va_range = user_va_range;
        Ok(0)
    }

    pub(crate) fn vm_destroy(
        _ddev: &TyrDrmDevice,
        vmdestroy: &mut uapi::drm_panthor_vm_destroy,
        file: &TyrDrmFile,
    ) -> Result<u32> {
        if vmdestroy.pad != 0 {
            return Err(EINVAL);
        }

        file.inner().vm_pool().destroy_vm(vmdestroy.id as usize)?;
        Ok(0)
    }
}
