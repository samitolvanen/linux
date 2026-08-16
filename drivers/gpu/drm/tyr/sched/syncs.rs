// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU synchronization objects.
//!
//! Groups allocate firmware sync objects per queue, and later scheduler-side
//! dependency handling needs typed accessors for those shared slots.

use kernel::{
    io::Io,
    prelude::*, //
};

use crate::gem;

/// Minimal 32-bit firmware sync object layout.
#[repr(C)]
pub(crate) struct SyncObj32b {
    seqno: u32,
    status: u32,
}

impl SyncObj32b {
    const SEQNO: usize = core::mem::offset_of!(Self, seqno);

    pub(super) fn read_seqno(mem: &gem::BoVmap, offset: usize) -> Result<u32> {
        mem.check_offset::<Self>(offset)?;

        mem.vmap().try_read32(offset + Self::SEQNO)
    }
}

/// Minimal 64-bit firmware sync object layout.
#[repr(C)]
pub(crate) struct SyncObj64b {
    pub(crate) seqno: u64,
    pub(crate) status: u32,
    pub(crate) pad: u32,
}

impl SyncObj64b {
    const SEQNO: usize = core::mem::offset_of!(Self, seqno);
    const STATUS: usize = core::mem::offset_of!(Self, status);
    const PAD: usize = core::mem::offset_of!(Self, pad);

    pub(super) fn read_seqno(mem: &gem::BoVmap, offset: usize) -> Result<u64> {
        mem.check_offset::<Self>(offset)?;

        mem.vmap().try_read64(offset + Self::SEQNO)
    }

    pub(super) fn write(mem: &gem::BoVmap, offset: usize, value: Self) -> Result {
        mem.check_offset::<Self>(offset)?;
        let vmap = mem.vmap();

        vmap.try_write32(value.pad, offset + Self::PAD)?;
        vmap.try_write32(value.status, offset + Self::STATUS)?;
        vmap.try_write64(value.seqno, offset + Self::SEQNO)
    }
}
