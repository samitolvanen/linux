// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU synchronization objects.
//!
//! Groups allocate firmware sync objects per queue, and later scheduler-side
//! dependency handling needs typed accessors for those shared slots.

#![expect(dead_code)]

use kernel::{
    device::{
        Bound,
        Device, //
    },
    drm::gem::{
        shmem,
        BaseObject, //
    },
    io::Io,
    prelude::*,
    sync::Arc,
    uapi, //
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

/// Common surface that the `SyncObj32b` / `SyncObj64b` readers and
/// writers need from a mapped GPU buffer object: a CPU `shmem::VMap`
/// onto the BO and a bounds/alignment check for `T` at a given offset.
///
/// Implemented for both kernel-owned (`gem::MappedBo`) and user-owned
/// (`gem::MappedUserBo`) BO wrappers so the same macro-generated
/// `read` / `write` accessors work against either.
pub(super) trait BoMapping {
    fn vmap(&self) -> &shmem::VMapOwned<gem::BoData>;
    fn check_offset<T>(&self, offset: usize) -> Result;
}

impl BoMapping for gem::MappedBo {
    fn vmap(&self) -> &shmem::VMapOwned<gem::BoData> {
        gem::MappedBo::vmap(self)
    }

    fn check_offset<T>(&self, offset: usize) -> Result {
        gem::MappedBo::check_offset::<T>(self, offset)
    }
}

impl BoMapping for gem::MappedUserBo {
    fn vmap(&self) -> &shmem::VMapOwned<gem::BoData> {
        gem::MappedUserBo::vmap(self)
    }

    fn check_offset<T>(&self, offset: usize) -> Result {
        gem::MappedUserBo::check_offset::<T>(self, offset)
    }
}

impl<T: BoMapping> BoMapping for Arc<T> {
    fn vmap(&self) -> &shmem::VMapOwned<gem::BoData> {
        T::vmap(self)
    }

    fn check_offset<U>(&self, offset: usize) -> Result {
        T::check_offset::<U>(self, offset)
    }
}

macro_rules! impl_sync_rw {
    ($type:ty, $seqno_ty:ty) => {
        impl $type {
            pub(super) fn read<M: BoMapping>(mem: &M, offset: usize) -> Result<Self> {
                mem.check_offset::<Self>(offset)?;

                let vmap = mem.vmap();
                // SAFETY: `check_offset` verified bounds and alignment for `Self` at `offset`.
                let ptr = unsafe { (vmap.addr() as *mut u8).add(offset).cast::<Self>() };

                // SAFETY: `ptr` is aligned, in-bounds (see above), and shared with the GPU.
                Ok(unsafe { core::ptr::read_volatile(ptr) })
            }

            pub(super) fn read_seqno<M: BoMapping>(mem: &M, offset: usize) -> Result<$seqno_ty> {
                let offset = offset + core::mem::offset_of!(Self, seqno);
                mem.check_offset::<$seqno_ty>(offset)?;

                let vmap = mem.vmap();
                // SAFETY: `check_offset` verified bounds and alignment for the seqno at `offset`.
                let ptr = unsafe { (vmap.addr() as *mut u8).add(offset).cast::<$seqno_ty>() };

                // SAFETY: `ptr` is aligned, in-bounds (see above), and shared with the GPU.
                Ok(unsafe { core::ptr::read_volatile(ptr) })
            }

            pub(super) fn write<M: BoMapping>(mem: &M, offset: usize, value: Self) -> Result {
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

impl_sync_rw!(SyncObj32b, u32);
impl_sync_rw!(SyncObj64b, u64);

/// Makes the GPU's last write to the seqno of the sync object at `offset`
/// visible to a CPU read through a cached mapping of `mem`.
/// Does nothing for an imported BO.
pub(super) fn sync_seqno_for_cpu(
    dev: &Device<Bound>,
    mem: &gem::MappedUserBo,
    offset: usize,
    sync64: bool,
) -> Result {
    let bo = mem.vmap().owner();

    if bo.is_imported() {
        return Ok(());
    }

    let (seqno, size) = if sync64 {
        (
            core::mem::offset_of!(SyncObj64b, seqno),
            core::mem::size_of::<u64>(),
        )
    } else {
        (
            core::mem::offset_of!(SyncObj32b, seqno),
            core::mem::size_of::<u32>(),
        )
    };

    gem::sync(
        bo,
        dev,
        uapi::drm_panthor_bo_sync_op_type_DRM_PANTHOR_BO_SYNC_CPU_CACHE_FLUSH_AND_INVALIDATE,
        (offset + seqno) as u64,
        size as u64,
    )
}
