// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DRM debugfs support.
//!
//! C header: [`include/drm/drm_debugfs.h`](srctree/include/drm/drm_debugfs.h)

use crate::{
    bindings,
    drm,
    drm::device::{
        Device,
        Registered, //
    },
    error::from_result,
    prelude::*,
    seq_file::SeqFile, //
};
use core::ptr;

/// A debugfs file that dumps device state.
///
/// Implement this on a marker type for each file and register it with
/// [`Device::debugfs_add_file`]. The DRM core owns the file for the lifetime of
/// the device and removes it when the device is unregistered, so there is no
/// matching removal step.
pub trait Info {
    /// The [`drm::Driver`] this file belongs to.
    type Driver: drm::Driver;

    /// The file's name in the device's debugfs directory.
    const NAME: &'static CStr;

    /// Writes the file's contents to `m`.
    ///
    /// Called when userspace reads the file. Driver state is reached through
    /// `device`.
    fn show(device: &Device<Self::Driver>, m: &SeqFile) -> Result;
}

/// The `show` trampoline the DRM core installs for an [`Info`].
///
/// # Safety
///
/// `seq` must point at a valid `struct seq_file` whose `private` field is the
/// `struct drm_debugfs_entry` registered for `F`, as guaranteed by the DRM core
/// when it invokes this callback. The second argument is the seq iterator and
/// is unused.
unsafe extern "C" fn show_callback<F: Info>(
    seq: *mut bindings::seq_file,
    _data: *mut c_void,
) -> c_int {
    from_result(|| {
        // SAFETY: The caller guarantees `seq` is valid, and the DRM core sets
        // `private` to the `drm_debugfs_entry` for this file.
        let entry = unsafe { (*seq).private }.cast::<bindings::drm_debugfs_entry>();

        // SAFETY: `entry` is a valid `drm_debugfs_entry` whose `dev` is the
        // `drm_device` embedded in a `Device<F::Driver>`.
        let raw_device = unsafe { (*entry).dev };

        // SAFETY: The device is registered and outlives its debugfs files, so it
        // is valid for this call.
        let device = unsafe { Device::<F::Driver>::from_raw(raw_device) };

        // SAFETY: `seq` is valid and accessed only from this thread.
        let m = unsafe { SeqFile::from_raw(seq) };

        F::show(device, m)?;
        Ok(0)
    })
}

impl<T: drm::Driver> Device<T, Registered> {
    /// Registers a debugfs file that dumps device state.
    ///
    /// The file appears in the device's debugfs directory under `F::NAME` and is
    /// removed by the DRM core when the device is unregistered. This is a no-op
    /// when `CONFIG_DEBUG_FS` is disabled.
    #[inline]
    pub fn debugfs_add_file<F>(&self)
    where
        F: Info<Driver = T>,
    {
        // SAFETY: `self.as_raw()` is a valid `drm_device` by the type invariant,
        // `F::NAME` is a `'static` C string, and `show_callback::<F>` has the
        // signature the DRM core expects. The callback recovers its state from
        // the `drm_debugfs_entry`, so no cookie is needed.
        unsafe {
            bindings::drm_debugfs_add_file(
                self.as_raw(),
                F::NAME.as_char_ptr(),
                Some(show_callback::<F>),
                ptr::null_mut(),
            );
        }
    }
}
