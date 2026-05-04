// SPDX-License-Identifier: GPL-2.0 or MIT

//! Public entry point for the CSF firmware global interface.
//!
//! The global interface controls firmware state shared across all command
//! stream groups. Keeping this module boundary stable lets later commits split
//! the concrete GLB/CSG/CS implementation out of the older monolithic helper
//! file without changing callers again.

pub(crate) use super::interfaces::GlobalInterface;