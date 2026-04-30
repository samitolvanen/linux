// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::prelude::*;

use crate::driver::TyrDrmDevice;

pub(crate) mod group;
pub(crate) mod queue;
pub(crate) mod syncs;

/// The scheduler object.
pub(crate) enum SchedulerState {
	/// The scheduler has not been initialized yet.
	Disabled,
	/// The scheduler is ready to accept work.
	Enabled(Scheduler),
}

impl SchedulerState {
	pub(crate) fn init(&mut self, tdev: &TyrDrmDevice) -> Result {
		let scheduler = Scheduler::init(tdev)?;
		*self = Self::Enabled(scheduler);
		Ok(())
	}

	pub(crate) fn enabled_mut(&mut self) -> Result<&mut Scheduler> {
		match self {
			Self::Enabled(scheduler) => Ok(scheduler),
			Self::Disabled => Err(EINVAL),
		}
	}
}

/// Minimal scheduler shell.
pub(crate) struct Scheduler;

impl Scheduler {
	pub(crate) fn init(_tdev: &TyrDrmDevice) -> Result<Self> {
		Ok(Self)
	}
}