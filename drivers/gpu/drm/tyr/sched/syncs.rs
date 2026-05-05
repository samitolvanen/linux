// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU synchronization objects.
//!
//! Groups allocate firmware sync objects per queue, and later scheduler-side
//! dependency handling needs typed accessors for those shared slots.

#![expect(dead_code)]

use kernel::{
    drm::gem::BaseObject,
    io::IoBase,
    prelude::*, //
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

macro_rules! impl_sync_rw {
    ($type:ty) => {
        impl $type {
            pub(super) fn read(mem: &gem::MappedBo, offset: usize) -> Result<Self> {
                let end = offset
                    .checked_add(core::mem::size_of::<Self>())
                    .ok_or(EINVAL)?;

                if end > mem.size() {
                    return Err(EINVAL);
                }

                let vmap = mem.vmap();
                // SAFETY: `offset..end` was bounds-checked against the mapped object size,
                // so the computed pointer is valid for a single sync-object read.
                let ptr = unsafe {
                    vmap.as_view()
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<Self>()
                };

                // SAFETY: `ptr` points into the mapped sync-object storage and is valid
                // for one volatile read of `Self`.
                Ok(unsafe { core::ptr::read_volatile(ptr) })
            }

            pub(super) fn write(mem: &gem::MappedBo, offset: usize, value: Self) -> Result {
                let end = offset
                    .checked_add(core::mem::size_of::<Self>())
                    .ok_or(EINVAL)?;

                if end > mem.size() {
                    return Err(EINVAL);
                }

                let vmap = mem.vmap();
                // SAFETY: `offset..end` was bounds-checked against the mapped object size,
                // so the computed pointer is valid for a single sync-object write.
                let ptr = unsafe {
                    vmap.as_view()
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<Self>()
                };

                // SAFETY: `ptr` points into the mapped sync-object storage and is valid
                // for one volatile write of `Self`.
                unsafe { core::ptr::write_volatile(ptr, value) };

                Ok(())
            }
        }
    };
}

impl_sync_rw!(SyncObj32b);
impl_sync_rw!(SyncObj64b);
