// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DRM printer.
//!
//! C header: [`include/drm/drm_print.h`](srctree/include/drm/drm_print.h)

use crate::{
    bindings,
    ffi,
    fmt,
    prelude::*,
    types::Opaque, //
};

/// A print target for the DRM core, wrapping `struct drm_printer`.
///
/// The DRM core constructs the printer and passes a pointer to driver
/// callbacks such as `show_fdinfo`. Drivers borrow it through
/// [`Printer::from_raw`] and never build one themselves.
///
/// # Invariants
///
/// `self.0` wraps a valid `struct drm_printer`.
#[repr(transparent)]
pub struct Printer(Opaque<bindings::drm_printer>);

impl Printer {
    /// Borrows a [`Printer`] from a raw pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that for the duration of `'a` the pointer points
    /// at a valid `struct drm_printer`.
    pub unsafe fn from_raw<'a>(ptr: *mut bindings::drm_printer) -> &'a Self {
        // SAFETY: The caller ensures that the reference is valid for `'a`.
        //
        // CAST: The layout of `struct drm_printer` and `Printer` is compatible.
        unsafe { &*ptr.cast() }
    }

    /// Returns a raw pointer to the wrapped `struct drm_printer`.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::drm_printer {
        self.0.get()
    }

    /// Prints a formatted string.
    #[inline]
    pub fn printf(&self, args: fmt::Arguments<'_>) {
        // SAFETY: By the type invariant `self.as_raw()` points at a valid
        // `struct drm_printer`. Passing a void pointer to `Arguments` is valid
        // for the `%pA` format extension.
        unsafe {
            bindings::drm_printf(
                self.as_raw(),
                c"%pA".as_char_ptr(),
                core::ptr::from_ref(&args).cast::<ffi::c_void>(),
            );
        }
    }

    /// Prints a memory size as an fdinfo `prefix-stat-region` line.
    #[inline]
    pub fn fdinfo_print_size(&self, prefix: &CStr, stat: &CStr, region: &CStr, sz: u64) {
        // SAFETY: By the type invariant `self.as_raw()` points at a valid
        // `struct drm_printer`. The three string arguments are valid C strings.
        unsafe {
            bindings::drm_fdinfo_print_size(
                self.as_raw(),
                prefix.as_char_ptr(),
                stat.as_char_ptr(),
                region.as_char_ptr(),
                sz,
            );
        }
    }
}

/// Writes to a [`Printer`] with the ordinary Rust formatting syntax.
#[macro_export]
macro_rules! drm_printf {
    ($p:expr, $($arg:tt)+) => (
        $p.printf($crate::prelude::fmt!($($arg)+))
    );
}
pub use drm_printf;
