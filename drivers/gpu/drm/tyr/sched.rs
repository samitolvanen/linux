// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
	alloc::KVec,
	prelude::*,
	sync::Arc,
};

use crate::{
	driver::TyrDrmDevice,
	file::{
		QueueSubmit,
		SyncOp,
		TyrDrmFile,
	},
};

use group::Group;

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

	pub(crate) fn bind(&mut self, _tdev: &TyrDrmDevice, _group: Arc<Group>) -> Result {
		Ok(())
	}

	pub(crate) fn submit(
		&mut self,
		_syncs: KVec<SyncOp>,
		_group: Arc<Group>,
		_queue_submits: KVec<QueueSubmit>,
		_file: &TyrDrmFile,
	) -> Result {
		Err(ENOTSUPP)
	}
}