// SPDX-License-Identifier: GPL-2.0 or MIT

//! A general flags type adapted from the WIP work from Felipe Xavier.
//!
//! This will be replaced by his patch once it's ready.

#[macro_export]
/// Creates a new flags type.
macro_rules! impl_flags {
    ($flags:ident, $flag:ident, $ty:ty) => {
        #[allow(missing_docs)]
        #[repr(transparent)]
        #[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
        pub struct $flags($ty);

        #[allow(missing_docs)]
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub struct $flag($ty);

        impl From<$flag> for $flags {
            #[inline]
            fn from(value: $flag) -> Self {
                Self(value.0)
            }
        }

        impl From<$flags> for $ty {
            #[inline]
            fn from(value: $flags) -> Self {
                value.0
            }
        }

        impl core::ops::BitOr for $flags {
            type Output = Self;

            #[inline]
            fn bitor(self, rhs: Self) -> Self::Output {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $flags {
            #[inline]
            fn bitor_assign(&mut self, rhs: Self) {
                *self = *self | rhs;
            }
        }

        impl core::ops::BitAnd for $flags {
            type Output = Self;

            #[inline]
            fn bitand(self, rhs: Self) -> Self::Output {
                Self(self.0 & rhs.0)
            }
        }

        impl core::ops::BitAndAssign for $flags {
            #[inline]
            fn bitand_assign(&mut self, rhs: Self) {
                *self = *self & rhs;
            }
        }

        impl core::ops::BitOr<$flag> for $flags {
            type Output = Self;

            #[inline]
            fn bitor(self, rhs: $flag) -> Self::Output {
                self | Self::from(rhs)
            }
        }

        impl core::ops::BitOrAssign<$flag> for $flags {
            #[inline]
            fn bitor_assign(&mut self, rhs: $flag) {
                *self = *self | rhs;
            }
        }

        impl core::ops::BitAnd<$flag> for $flags {
            type Output = Self;

            #[inline]
            fn bitand(self, rhs: $flag) -> Self::Output {
                self & Self::from(rhs)
            }
        }

        impl core::ops::BitAndAssign<$flag> for $flags {
            #[inline]
            fn bitand_assign(&mut self, rhs: $flag) {
                *self = *self & rhs;
            }
        }

        impl core::ops::BitXor for $flags {
            type Output = Self;

            #[inline]
            fn bitxor(self, rhs: Self) -> Self::Output {
                Self(self.0 ^ rhs.0)
            }
        }

        impl core::ops::BitXorAssign for $flags {
            #[inline]
            fn bitxor_assign(&mut self, rhs: Self) {
                *self = *self ^ rhs;
            }
        }

        impl core::ops::Neg for $flags {
            type Output = Self;

            #[inline]
            fn neg(self) -> Self::Output {
                Self(!self.0)
            }
        }

        impl $flags {
            /// Returns an empty instance of <type> where no flags are set.
            #[inline]
            pub const fn empty() -> Self {
                Self(0)
            }

            /// Checks if a specific flag is set.
            #[inline]
            pub fn contains(self, flag: $flag) -> bool {
                (self.0 & flag.0) == flag.0
            }
        }
    };
}
