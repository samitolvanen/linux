use kernel::bits::bit_u32;
use kernel::io_pgtable;
use kernel::prelude::*;

use crate::impl_flags;

impl_flags!(Flags, Flag, u32);

impl Flags {
    /// Convert the flags to `io_pgtable::prot`.
    pub(super) fn to_prot(&self) -> u32 {
        let mut prot = 0;

        if self.contains(READONLY) {
            prot |= io_pgtable::prot::READ;
        } else {
            prot |= io_pgtable::prot::READ | io_pgtable::prot::WRITE;
        }

        if self.contains(NOEXEC) {
            prot |= io_pgtable::prot::NOEXEC;
        }

        if !self.contains(UNCACHED) {
            prot |= io_pgtable::prot::CACHE;
        }

        prot
    }
}

pub(crate) const READONLY: Flag = Flag(bit_u32(1));
pub(crate) const NOEXEC: Flag = Flag(bit_u32(2));
pub(crate) const UNCACHED: Flag = Flag(bit_u32(3));

impl core::fmt::Display for Flags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.contains(READONLY) {
            write!(f, "| READONLY")?;
        }
        if self.contains(NOEXEC) {
            write!(f, " | NOEXEC")?;
        }

        if self.contains(UNCACHED) {
            write!(f, " | UNCACHED")?;
        }

        Ok(())
    }
}

impl TryFrom<u32> for Flags {
    type Error = Error;

    fn try_from(value: u32) -> core::result::Result<Self, Self::Error> {
        let valid = Flags::from(READONLY) | Flags::from(NOEXEC) | Flags::from(UNCACHED);

        if value & !valid.0 != 0 {
            pr_err!("Invalid VM map flags: {:#x}\n", value);
            Err(EINVAL)
        } else {
            Ok(Self(value << 1))
        }
    }
}
