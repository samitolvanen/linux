// SPDX-License-Identifier: GPL-2.0 or MIT

/// Minimal 64-bit firmware sync object layout.
///
/// Groups allocate one of these per queue so later submit and event handling
/// changes have stable storage for firmware completion state.
#[repr(C)]
pub(crate) struct SyncObj64b {
    _seqno: u64,
    _status: u32,
    _pad: u32,
}