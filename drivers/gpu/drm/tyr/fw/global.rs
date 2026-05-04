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
	bindings::SZ_1K,
	clk::Clk,
	devres::Devres,
	num::Bounded,
	platform,
	prelude::*,
	time::arch_timer_get_rate,
};

/// Encodes a GLB timer timeout and selects the backing time source.
pub(super) fn conv_timeout(core_clk: &Clk, timeout_us: u32) -> Result<(u32, Bounded<u32, 1>)> {
	// The max timeout is determined by the 31 bit size of the timeout field.
	let max_timeout = (1u32 << 31) - 1;
	let core_rate = core_clk.rate().as_hz() as u64;

	let (timer_rate, timer_source) = match arch_timer_get_rate() {
		Some(rate) => (u64::from(rate), Bounded::try_new(0).unwrap()),
		_ if core_rate != 0 => (core_rate, Bounded::try_new(1).unwrap()),
		_ => return Err(EINVAL),
	};

	let timeout_in_cycles = u64::from(timeout_us) * timer_rate;

	// The hardware stores the represented timeout value with a shr(10) to save space.
	let timeout_shift = u64::from(SZ_1K);
	let us_per_second = 1_000_000u64;

	let timeout_val = timeout_in_cycles.div_ceil(us_per_second * timeout_shift);
	let timeout_val = timeout_val.min(u64::from(max_timeout)) as u32;

	Ok((timeout_val, timer_source))
}

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