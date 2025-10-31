// SPDX-License-Identifier: GPL-2.0 or MIT

//! A bare-bones std::io::Cursor<[u8]> clone to keep track of the current
//! position in the firmware binary.

use core::ops::Range;

use kernel::prelude::*;

use crate::driver::TyrDevice;

pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(super) fn len(&self) -> usize {
        self.data.len()
    }

    pub(super) fn pos(&self) -> usize {
        self.pos
    }

    pub(super) fn advance(&mut self, nbytes: usize) -> Result {
        if self.pos + nbytes > self.data.len() {
            return Err(EINVAL);
        }

        self.pos += nbytes;
        Ok(())
    }

    /// Returns a view into the cursor's data.
    ///
    /// This spawns a new cursor, leaving the current cursor unchanged.
    pub(super) fn view(&self, range: Range<usize>) -> Result<Cursor<'_>> {
        if range.start < self.pos || range.end > self.data.len() {
            pr_err!(
                "Invalid cursor range {:?} for data of length {}",
                range,
                self.data.len()
            );

            Err(EINVAL)
        } else {
            Ok(Self {
                data: &self.data[range],
                pos: 0,
            })
        }
    }

    pub(super) fn read(&mut self, tdev: &TyrDevice, nbytes: usize) -> Result<&[u8]> {
        let start = self.pos;
        let end = start + nbytes;

        if end > self.data.len() {
            dev_err!(
                tdev.as_ref(),
                "Invalid firmware file: read of size {} at position {} is out of bounds",
                nbytes,
                start,
            );
            return Err(EINVAL);
        }

        self.pos += nbytes;
        Ok(&self.data[start..end])
    }

    pub(super) fn read_u8(&mut self, tdev: &TyrDevice) -> Result<u8> {
        let bytes = self.read(tdev, 1)?;
        Ok(bytes[0])
    }

    pub(super) fn read_u16(&mut self, tdev: &TyrDevice) -> Result<u16> {
        let bytes = self.read(tdev, 2)?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub(super) fn read_u32(&mut self, tdev: &TyrDevice) -> Result<u32> {
        let bytes = self.read(tdev, 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }
}
