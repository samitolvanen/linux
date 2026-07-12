// SPDX-License-Identifier: GPL-2.0

//! NVMEM consumer abstraction.
//!
//! C header: [`include/linux/nvmem-consumer.h`](srctree/include/linux/nvmem-consumer.h)

use crate::{
    bindings,
    device::{
        Bound,
        Device, //
    },
    error::{
        from_err_ptr,
        Result, //
    },
    prelude::*,
};

/// An NVMEM cell obtained from a consumer device's provider.
///
/// # Invariants
///
/// `self.0` points to a valid `nvmem_cell` owned by this handle.
pub struct Cell(*mut bindings::nvmem_cell);

impl Cell {
    /// Looks up the NVMEM cell named `id` declared for `dev`.
    ///
    /// Returns [`ENOENT`] when the device declares no cell of that name, and
    /// [`EPROBE_DEFER`] when the backing provider has not registered yet.
    pub fn get(dev: &Device<Bound>, id: &CStr) -> Result<Self> {
        // SAFETY: `dev` is bound, so `as_raw()` yields a valid `struct device`
        // pointer for the call, and `id` is a valid NUL-terminated C string.
        let cell =
            from_err_ptr(unsafe { bindings::nvmem_cell_get(dev.as_raw(), id.as_char_ptr()) })?;

        // INVARIANT: `nvmem_cell_get()` returned a valid owned cell pointer.
        Ok(Self(cell))
    }

    /// Reads the cell contents into an owned buffer.
    ///
    /// The buffer length is the cell size reported by the provider.
    pub fn read(&self) -> Result<KVec<u8>> {
        let mut len = 0usize;
        // SAFETY: By the type invariant `self.0` is a valid cell pointer, and
        // `len` is a valid place for the returned byte count.
        let buf = from_err_ptr(unsafe { bindings::nvmem_cell_read(self.0, &mut len) })?;

        // SAFETY: On success `nvmem_cell_read()` returns a kzalloc-allocated
        // buffer holding `len` valid bytes whose ownership passes to the caller.
        let src = unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), len) };
        let out = KVec::with_capacity(len, GFP_KERNEL).and_then(|mut v| {
            v.extend_from_slice(src, GFP_KERNEL)?;
            Ok(v)
        });

        // SAFETY: `buf` was allocated by the NVMEM core with kzalloc and is
        // owned here. Free it now that its bytes have been copied out.
        unsafe { bindings::kfree(buf) };

        out.map_err(Into::into)
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        // SAFETY: By the type invariant `self.0` is a valid owned cell pointer.
        unsafe { bindings::nvmem_cell_put(self.0) };
    }
}
