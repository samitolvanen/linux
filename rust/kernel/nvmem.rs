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
    error::to_result,
    prelude::*,
};

/// Reads the NVMEM cell named `id` declared for `dev` as a little-endian number.
///
/// This API is identical to `nvmem_cell_read_variable_le_u64()`. The cell is
/// looked up, read, and released in one step. When the cell declares a bit
/// width, only the bytes covering it are used. A cell wider than 64 bits fails
/// with [`ERANGE`]. Returns [`ENOENT`] when the device declares no cell of that
/// name, [`EPROBE_DEFER`] when the backing provider has not registered yet, and
/// [`EOPNOTSUPP`] under `CONFIG_NVMEM=n`.
#[inline]
pub fn read_variable_le_u64(dev: &Device<Bound>, id: &CStr) -> Result<u64> {
    let mut val = 0u64;
    // SAFETY: `dev` is a valid and bound device, `id` is a valid NUL-terminated
    // C string, and `val` is a valid place for the result.
    to_result(unsafe {
        bindings::nvmem_cell_read_variable_le_u64(dev.as_raw(), id.as_char_ptr(), &mut val)
    })?;
    Ok(val)
}
