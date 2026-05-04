// SPDX-License-Identifier: GPL-2.0 or MIT

//! Public entry point for the CSF firmware global interface.
//!
//! The global interface controls firmware state shared across all command
//! stream groups. This module now provides the stable wrapper type that fw.rs
//! uses, which lets later commits move GLB-specific implementation out of the
//! older monolithic helper file without changing those callers again.

use crate::{
	driver::IoMem,
	fw::Section,
	gpu::GpuInfo,
	wait::Wait,
};
use kernel::{
	clk::Clk,
	devres::Devres,
	platform,
	prelude::*,
};

/// Stable module boundary for the firmware global interface implementation.
pub(crate) struct GlobalInterface(super::interfaces::GlobalInterface);

impl GlobalInterface {
	pub(crate) fn new() -> Result<Self> {
		Ok(Self(super::interfaces::GlobalInterface::new()?))
	}

	pub(crate) fn enable(
		&mut self,
		pdev: &platform::Device,
		iomem: &Devres<IoMem>,
		shared_section: &Section,
		gpu_info: &GpuInfo,
		core_clk: &Clk,
		event_wait: &Wait,
	) -> Result {
		self.0
			.enable(pdev, iomem, shared_section, gpu_info, core_clk, event_wait)
	}

	pub(crate) fn csif_info_counts(&self) -> Result<(u32, u32, u32, u32)> {
		self.0.csif_info_counts()
	}

	pub(crate) fn group_suspend_buf_sizes(&self) -> Result<(u32, u32)> {
		self.0.group_suspend_buf_sizes()
	}
}