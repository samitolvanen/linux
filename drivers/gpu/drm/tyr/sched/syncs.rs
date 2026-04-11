// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU synchronization objects.
//!
//! Synchronization objects allows for general synchronization between command
//! streams and any other actor (e.g. host CPU, other command streams or other
//! hardware devices).

#![expect(dead_code)]

use kernel::{
    drm::gem::BaseObject,
    io::Io,
    prelude::*,
    sync::Arc, //
};

use crate::gem;

/// Represents a 32-bit firmware synchronization object.
#[repr(C)]
pub(crate) struct SyncObj32b {
    /// Sequence number.
    pub(crate) seqno: u32,

    /// Status.
    ///
    /// Non-zero on failure.
    pub(crate) status: u32,
}

/// Represents a 64-bit firmware synchronization object.
#[repr(C)]
pub(crate) struct SyncObj64b {
    /// Sequence number.
    pub(crate) seqno: u64,

    /// Status.
    ///
    /// Non-zero on failure.
    pub(crate) status: u32,

    /// Padding (must be zero).
    pub(crate) pad: u32,
}

pub(crate) enum SyncObj {
    /// 32-bit sync object.
    SyncObj32(SyncObj32b),

    /// 64-bit sync object.
    SyncObj64(SyncObj64b),
}

pub(crate) struct SyncRef {
    /// The memory where the synchronization object is stored.
    mem: Arc<gem::MappedBo>,

    /// The offset in the memory where the synchronization object is stored.
    mem_offset: usize,

    /// Whether this is a sync64 object.
    is_sync64: bool,

    /// Whether this is a greater than comparison against the reference value.
    pub(super) greater_than: bool,

    /// The reference value to compare against.
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
}

macro_rules! impl_sync_rw {
    ($type:ty) => {
        impl $type {
            /// Reads a synchronization object at a given offset.
            ///
            /// Note that the area pointed to by `ptr` is shared with the GPU, so we
            /// cannot simply parse it or cast it to &Self.
            ///
            /// Merely taking a reference to it would be UB, as the GPU can change the
            /// underlying memory at any time, as it is a core running on its own.
            pub(super) fn read(mem: &gem::MappedBo, offset: usize) -> Result<Self> {
                if offset > mem.size() {
                    return Err(EINVAL);
                }

                let vmap = mem.vmap();
                let ptr = unsafe { (vmap.addr() as *mut u8).add(offset).cast::<Self>() };
                // SAFETY: we know that this pointer is aligned and valid for reads for
                // at least size_of::<Self>() bytes.
                Ok(unsafe { core::ptr::read_volatile(ptr) })
            }

            /// Writes a synchronization object at a given offset.
            ///
            /// Note that the area pointed to by `ptr` is shared with the GPU, so we
            /// cannot simply parse it or cast it to &Self.
            ///
            /// Merely taking a reference to it would be UB, as the GPU can change the
            /// underlying memory at any time, as it is a core running on its own.
            pub(super) fn write(mem: &gem::MappedBo, offset: usize, value: Self) -> Result {
                if offset > mem.size() {
                    return Err(EINVAL);
                }

                let vmap = mem.vmap();
                let ptr = unsafe { (vmap.addr() as *mut u8).add(offset).cast::<Self>() };
                // SAFETY: we know that this pointer is aligned and valid for writes for
                // at least size_of::<Self>() bytes.
                unsafe { core::ptr::write_volatile(ptr, value) };

                Ok(())
            }
        }
    };
}

impl_sync_rw!(SyncObj32b);
impl_sync_rw!(SyncObj64b);
