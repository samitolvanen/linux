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
    module::{
        this_module,
        ModuleMetadata, //
    },
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

/// Reads and writes a `u64` attribute of `data` as text.
///
/// Reading the file formats the value that [`Attribute::get`] returns with [`Attribute::FORMAT`].
/// Writing a number to the file passes it to [`Attribute::set`]. The number is decimal, octal or
/// hexadecimal, as its prefix selects. The file does not support seeking.
pub trait Attribute<T> {
    /// The `printf` format of the value, with one conversion of an `unsigned long long`, for
    /// example `c"%llu\n"`. A file with another format does not compile.
    const FORMAT: &'static CStr;

    /// Returns the value of the attribute.
    fn get(data: &T) -> Result<u64>;

    /// Sets the value of the attribute.
    fn set(data: &T, val: u64) -> Result;
}

/// Returns whether `format` has one conversion of an `unsigned long long`, and no other.
const fn is_attribute_format(format: &CStr) -> bool {
    let bytes = format.to_bytes();
    let mut conversions = 0;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }

        i += 1;
        if i < bytes.len() && bytes[i] == b'%' {
            i += 1;
            continue;
        }

        while i < bytes.len() && matches!(bytes[i], b'#' | b'0' | b'-' | b' ' | b'+') {
            i += 1;
        }

        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }

        if i + 2 >= bytes.len() || bytes[i] != b'l' || bytes[i + 1] != b'l' {
            return false;
        }

        if !matches!(bytes[i + 2], b'd' | b'i' | b'o' | b'u' | b'x' | b'X') {
            return false;
        }

        i += 3;
        conversions += 1;
    }

    conversions == 1
}

/// Reads the value of an [`Attribute`] for `simple_attr_read()`.
///
/// # Safety
///
/// `data` must point to a valid `T`, and `val` must be valid for writes.
unsafe extern "C" fn attribute_get<A: Attribute<T>, T: Sync>(
    data: *mut c_void,
    val: *mut u64,
) -> c_int {
    // SAFETY: Per the safety requirements, `data` points to a valid `T`.
    let data = unsafe { &*data.cast::<T>() };

    match A::get(data) {
        Ok(value) => {
            // SAFETY: Per the safety requirements, `val` is valid for writes.
            unsafe { *val = value };
            0
        }
        Err(e) => e.to_errno(),
    }
}

/// Writes the value of an [`Attribute`] for `simple_attr_write()`.
///
/// # Safety
///
/// `data` must point to a valid `T`.
unsafe extern "C" fn attribute_set<A: Attribute<T>, T: Sync>(data: *mut c_void, val: u64) -> c_int {
    // SAFETY: Per the safety requirements, `data` points to a valid `T`.
    let data = unsafe { &*data.cast::<T>() };

    from_result(|| A::set(data, val).map(|()| 0))
}

/// Opens an [`Attribute`] file.
///
/// # Safety
///
/// `inode` must be valid with `i_private` pointing to a valid `T` while the open, read and write
/// operations of the file run, and `file` must point to a live, uninitialized file object.
unsafe extern "C" fn attribute_open<A: Attribute<T>, T: Sync>(
    inode: *mut bindings::inode,
    file: *mut bindings::file,
) -> c_int {
    // SAFETY: `inode` and `file` are valid per the safety requirements. `simple_attr_open()`
    // passes `i_private`, a valid `T`, to the callbacks. `A::FORMAT` has one conversion of an
    // `unsigned long long`, as `AttributeFile::FILE_OPS` checks.
    unsafe {
        bindings::simple_attr_open(
            inode,
            file,
            Some(attribute_get::<A, T>),
            Some(attribute_set::<A, T>),
            A::FORMAT.as_char_ptr(),
        )
    }
}

trait AttributeFile<M, T> {
    const FILE_OPS: bindings::file_operations;
}

impl<M: ModuleMetadata, A: Attribute<T>, T: Sync> AttributeFile<M, T> for A {
    const FILE_OPS: bindings::file_operations = {
        assert!(
            is_attribute_format(A::FORMAT),
            "the format must have one conversion of an unsigned long long"
        );

        bindings::file_operations {
            owner: this_module::<M>().as_ptr(),
            open: Some(attribute_open::<Self, T>),
            release: Some(bindings::simple_attr_release),
            read: Some(bindings::simple_attr_read),
            write: Some(bindings::simple_attr_write),
            ..pin_init::zeroed()
        }
    };
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

    /// Creates a debugfs file named `name` that reads and writes a `u64` of the device with `A`.
    ///
    /// The file appears in the device's debugfs directory and is removed by the DRM core when the
    /// device is unregistered. This is a no-op when `CONFIG_DEBUG_FS` is disabled or the device
    /// is unplugged.
    pub fn debugfs_add_attribute<A: Attribute<Self>>(&self, name: &CStr) {
        let fops = &<A as AttributeFile<T::OwnerModule, Self>>::FILE_OPS;

        #[cfg(CONFIG_DEBUG_FS)]
        if let Some(_guard) = self.registration_guard() {
            // SAFETY: `_guard` keeps the device registered, so `debugfs_root` is the valid debugfs
            // directory of the device. The DRM core removes the directory, and waits for the
            // operations of the file, before it releases the device, so `self` is valid while
            // `attribute_open::<A, Self>` and the callbacks run.
            unsafe {
                bindings::debugfs_create_file_full(
                    name.as_char_ptr(),
                    0o600,
                    (*self.as_raw()).debugfs_root,
                    ptr::from_ref(self).cast_mut().cast(),
                    ptr::null(),
                    fops,
                )
            };
        }

        #[cfg(not(CONFIG_DEBUG_FS))]
        let _ = (name, fops);
    }
}

#[kunit_tests(rust_drm_debugfs_attribute)]
mod tests {
    use super::*;
    use crate::{
        sync::atomic::{
            Atomic,
            Relaxed, //
        },
        LocalModule, //
    };

    struct Counter;

    impl Attribute<Atomic<u64>> for Counter {
        const FORMAT: &'static CStr = c"0x%08llx\n";

        fn get(data: &Atomic<u64>) -> Result<u64> {
            Ok(data.load(Relaxed))
        }

        fn set(data: &Atomic<u64>, val: u64) -> Result {
            if val == u64::MAX {
                return Err(EINVAL);
            }

            data.store(val, Relaxed);
            Ok(())
        }
    }

    #[test]
    fn attribute_formats() {
        assert!(is_attribute_format(c"%llu\n"));
        assert!(is_attribute_format(c"0x%08llx\n"));
        assert!(is_attribute_format(c"100%% %lld\n"));

        assert!(!is_attribute_format(c"none\n"));
        assert!(!is_attribute_format(c"%llu %llu\n"));
        assert!(!is_attribute_format(c"%s\n"));
        assert!(!is_attribute_format(c"%lu\n"));
        assert!(!is_attribute_format(c"%ll"));
    }

    #[test]
    fn attribute_callbacks() {
        let _ops = &<Counter as AttributeFile<LocalModule, Atomic<u64>>>::FILE_OPS;

        let counter = Atomic::new(0u64);
        let data = core::ptr::from_ref(&counter).cast_mut().cast::<c_void>();
        let mut val = 0;

        // SAFETY: `data` points to a valid `Atomic<u64>`.
        assert_eq!(unsafe { attribute_set::<Counter, _>(data, 42) }, 0);
        // SAFETY: `data` points to a valid `Atomic<u64>`, and `val` is valid for writes.
        assert_eq!(unsafe { attribute_get::<Counter, _>(data, &mut val) }, 0);
        assert_eq!(val, 42);

        // SAFETY: `data` points to a valid `Atomic<u64>`.
        let ret = unsafe { attribute_set::<Counter, _>(data, u64::MAX) };
        assert_eq!(ret, EINVAL.to_errno());
        assert_eq!(counter.load(Relaxed), 42);
    }
}
