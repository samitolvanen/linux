// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU synchronization objects.
//!
//! Groups allocate firmware sync objects per queue, and later scheduler-side
//! dependency handling needs typed accessors for those shared slots.

#![expect(dead_code)]

use kernel::{
    io::Io,
    prelude::*,
    sync::Arc, //
};

use crate::gem;

#[repr(C)]
pub(crate) struct SyncObj32b {
    pub(crate) seqno: u32,
    pub(crate) status: u32,
}

#[repr(C)]
pub(crate) struct SyncObj64b {
    pub(crate) seqno: u64,
    pub(crate) status: u32,
    pub(crate) pad: u32,
}

pub(crate) enum SyncObj {
    SyncObj32(SyncObj32b),
    SyncObj64(SyncObj64b),
}

pub(crate) struct SyncRef {
    mem: Arc<gem::MappedBo>,
    mem_offset: usize,
    is_sync64: bool,
    pub(super) greater_than: bool,
    pub(super) reference_value: u64,
}

impl SyncRef {
    pub(super) fn read(&self) -> Result<SyncObj> {
        if self.is_sync64 {
            let sync_obj = SyncObj64b::read(&self.mem, self.mem_offset)?;
            Ok(SyncObj::SyncObj64(sync_obj))
        } else {
            let sync_obj = SyncObj32b::read(&self.mem, self.mem_offset)?;
            Ok(SyncObj::SyncObj32(sync_obj))
        }
    }

    pub(super) fn new(
        mem: Arc<gem::MappedBo>,
        mem_offset: usize,
        is_sync64: bool,
        greater_than: bool,
        reference_value: u64,
    ) -> Self {
        Self {
            mem,
            mem_offset,
            is_sync64,
            greater_than,
            reference_value,
        }
    }
}

macro_rules! impl_sync_rw {
    ($type:ty) => {
        impl $type {
            pub(super) fn read(mem: &gem::MappedBo, offset: usize) -> Result<Self> {
                mem.check_offset::<Self>(offset)?;

                let vmap = mem.vmap();
                // SAFETY: `check_offset` verified bounds and alignment for `Self` at `offset`.
                let ptr = unsafe { (vmap.addr() as *mut u8).add(offset).cast::<Self>() };

                // SAFETY: `ptr` is aligned, in-bounds (see above), and shared with the GPU.
                Ok(unsafe { core::ptr::read_volatile(ptr) })
            }

            pub(super) fn write(mem: &gem::MappedBo, offset: usize, value: Self) -> Result {
                mem.check_offset::<Self>(offset)?;

                let vmap = mem.vmap();
                // SAFETY: `check_offset` verified bounds and alignment for `Self` at `offset`.
                let ptr = unsafe { (vmap.addr() as *mut u8).add(offset).cast::<Self>() };

                // SAFETY: `ptr` is aligned, in-bounds (see above), and shared with the GPU.
                unsafe { core::ptr::write_volatile(ptr, value) };

                Ok(())
            }
        }
    };
}

impl_sync_rw!(SyncObj32b);
impl_sync_rw!(SyncObj64b);
