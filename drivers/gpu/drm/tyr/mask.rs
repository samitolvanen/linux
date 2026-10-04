// SPDX-License-Identifier: GPL-2.0 or MIT

//! Bit positions in `u32` masks.

use kernel::{
    num::Bounded,
    prelude::*, //
};

/// An index below `1 << BITS`, usable as a bit position in a `u32` mask.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct MaskIdx<const BITS: u32>(Bounded<u32, BITS>);

impl<const BITS: u32> MaskIdx<BITS> {
    /// Returns `idx` as an index, or `None` if it is out of range.
    pub(crate) fn new(idx: usize) -> Option<Self> {
        const_assert!(1 << BITS <= u32::BITS);
        u32::try_from(idx).ok().and_then(Bounded::try_new).map(Self)
    }

    /// Returns every index in increasing order.
    pub(crate) fn all() -> impl Iterator<Item = Self> {
        (0..1usize << BITS).map_while(Self::new)
    }

    /// Returns the indices of the bits set in `mask` in increasing order.
    pub(crate) fn iter_mask(mask: u32) -> impl Iterator<Item = Self> {
        Self::all().filter(move |idx| mask & idx.bit() != 0)
    }

    /// Returns the mask of the indices below `count`.
    pub(crate) fn mask_below(count: usize) -> u32 {
        Self::all()
            .take(count)
            .fold(0, |mask, idx| mask | idx.bit())
    }

    /// Returns the index as a `usize`.
    pub(crate) fn get(self) -> usize {
        *self.0 as usize
    }

    /// Returns the bit of this index in a mask.
    pub(crate) fn bit(self) -> u32 {
        1 << *self.0
    }
}
