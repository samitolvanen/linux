// SPDX-License-Identifier: GPL-2.0 or MIT

//! Scheduler-owned synchronization operation types.
//!
//! Group submission consumes parsed sync operations as scheduler input, so the
//! internal sync handle and operation vocabulary lives here instead of in the
//! UAPI parsing layer.

use kernel::{
	alloc::KVec,
    dma_buf::dma_fence::PublicDmaFence,
	drm::syncobj::SyncObj,
	prelude::*,
    sync::aref::ARef,
	transmute::FromBytes,
	uaccess::UserSlice,
	uapi,
};

use crate::{driver::TyrDrmDriver, file::TyrDrmFile};

#[repr(transparent)]
struct RawSyncOp(uapi::drm_panthor_sync_op);

// SAFETY: This wrapper is layout-identical to the UAPI sync-op record read
// from userspace.
unsafe impl FromBytes for RawSyncOp {}

#[repr(i32)]
pub(crate) enum SyncOpType {
    Wait = kernel::uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_WAIT,
    Signal = kernel::uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_SIGNAL,
}

pub(crate) enum SyncHandle {
    Binary { handle: u32 },
    Timeline { handle: u32, timeline_value: u64 },
}

impl SyncHandle {
    pub(crate) fn handle(&self) -> u32 {
        match self {
            Self::Binary { handle } | Self::Timeline { handle, .. } => *handle,
        }
    }

    pub(crate) fn timeline_value(&self) -> u64 {
        match self {
            Self::Binary { .. } => 0,
            Self::Timeline { timeline_value, .. } => *timeline_value,
        }
    }
}

pub(crate) struct SyncOp {
    pub(crate) ty: SyncOpType,
    pub(crate) handle: SyncHandle,
}

impl SyncOp {
    pub(crate) fn is_signal(&self) -> bool {
        matches!(self.ty, SyncOpType::Signal)
    }

    pub(crate) fn is_wait(&self) -> bool {
        matches!(self.ty, SyncOpType::Wait)
    }
}

impl TryFrom<&uapi::drm_panthor_sync_op> for SyncOp {
    type Error = Error;

    fn try_from(uapi_sync: &uapi::drm_panthor_sync_op) -> Result<Self> {
        let valid_flags = (uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_SIGNAL
            | uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_WAIT
            | uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK)
            as u32;

        if uapi_sync.flags & !valid_flags != 0 {
            return Err(EINVAL);
        }

        let handle_type = uapi_sync.flags
            & uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK as u32;

        if handle_type
            != uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ as u32
            && handle_type
                != uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ
                    as u32
        {
            return Err(EINVAL);
        }

        let ty = if uapi_sync.flags
            & uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_SIGNAL as u32
            != 0
        {
            SyncOpType::Signal
        } else {
            SyncOpType::Wait
        };

        let handle = if handle_type
            == uapi::drm_panthor_sync_op_flags_DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ
                as u32
        {
            SyncHandle::Timeline {
                handle: uapi_sync.handle,
                timeline_value: uapi_sync.timeline_value,
            }
        } else {
            if uapi_sync.timeline_value != 0 {
                return Err(EINVAL);
            }

            SyncHandle::Binary {
                handle: uapi_sync.handle,
            }
        };

        Ok(Self { ty, handle })
    }
}

pub(crate) fn wait_for_syncops(file: &TyrDrmFile, syncops: &[SyncOp]) -> Result {
    if syncops.iter().any(SyncOp::is_signal) {
        return Err(ENOTSUPP);
    }

    for fence in wait_fences(file, syncops)?.iter() {
        fence.wait()?;
    }

    Ok(())
}

pub(crate) fn wait_fences(
    file: &TyrDrmFile,
    syncops: &[SyncOp],
) -> Result<KVec<ARef<PublicDmaFence>>> {
    let mut fences = KVec::new();

    for sync in syncops.iter().filter(|sync| sync.is_wait()) {
        let fence = SyncObj::<TyrDrmDriver>::find_fence(
            file,
            sync.handle.handle(),
            sync.handle.timeline_value(),
            0,
        )?
        .ok_or(EINVAL)?;
        fences.push(fence, GFP_KERNEL)?;
    }

    Ok(fences)
}

pub(crate) fn append_syncops(
	syncops: &mut KVec<SyncOp>,
	array: u64,
	count: u32,
	stride: u32,
) -> Result {
	if stride as usize != core::mem::size_of::<uapi::drm_panthor_sync_op>() {
		return Err(ENOTSUPP);
	}

	let mut reader =
		UserSlice::new(UserPtr::from_addr(array as usize), stride as usize * count as usize)
			.reader();

	for _ in 0..count {
		let sync: RawSyncOp = reader.read()?;
		syncops.push(SyncOp::try_from(&sync.0)?, GFP_KERNEL)?;
	}

	Ok(())
}
