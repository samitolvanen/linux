// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
	alloc::KVec,
	prelude::*,
	sync::Arc,
	uapi,
};

use crate::{
	driver::TyrDrmDevice,
	file::{
		QueueSubmit,
		TyrDrmFile,
	},
};

use deps::SyncOp;
use group::Group;

const GROUP_PRIORITY_COUNT: usize =
	uapi::drm_panthor_group_priority_PANTHOR_GROUP_PRIORITY_REALTIME as usize + 1;

pub(crate) mod group;
pub(crate) mod deps;
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

struct CommandStreamGroupSlot {
	group: Arc<Group>,
}

/// Minimal scheduler shell.
pub(crate) struct Scheduler {
	idle_groups: [KVec<Arc<Group>>; GROUP_PRIORITY_COUNT],
	csg_slots: KVec<Option<CommandStreamGroupSlot>>,
}

impl Scheduler {
	pub(crate) fn init(tdev: &TyrDrmDevice) -> Result<Self> {
		let (csg_slot_count, cs_slot_count, cs_reg_count, scoreboard_slot_count) =
			tdev.fw.csif_info_counts()?;
		let mut csg_slots = KVec::with_capacity(csg_slot_count as usize, GFP_KERNEL)?;

		for _ in 0..csg_slot_count {
			csg_slots.push(None, GFP_KERNEL)?;
		}

		{
			let mut csif = tdev.csif_info.lock();
			csif.csg_slot_count = csg_slot_count;
			csif.cs_slot_count = cs_slot_count;
			csif.cs_reg_count = cs_reg_count;
			csif.scoreboard_slot_count = scoreboard_slot_count;
		}

		Ok(Self {
			idle_groups: [const { KVec::new() }; GROUP_PRIORITY_COUNT],
			csg_slots,
		})
	}

	pub(crate) fn bind(&mut self, _tdev: &TyrDrmDevice, group: Arc<Group>) -> Result {
		if group.csg_id().is_some() {
			return Ok(());
		}

		let csg_slot = self
			.csg_slots
			.iter_mut()
			.position(|slot| slot.is_none())
			.ok_or(ENOSPC)?;
		let idle_groups = self
			.idle_groups
			.get_mut(group.priority as usize)
			.ok_or(EINVAL)?;
		let idle_pos = idle_groups
			.iter()
			.position(|other| Arc::ptr_eq(other, &group))
			.ok_or(EINVAL)?;
		let group = idle_groups.remove(idle_pos)?;
		group.vm.activate()?;
		let slot = self.csg_slots.get_mut(csg_slot).ok_or(EINVAL)?;
		group.set_csg_id(Some(csg_slot));
		for queue in group.queues.iter() {
			queue.set_doorbell_id(Some(csg_slot + 1));
		}
		*slot = Some(CommandStreamGroupSlot { group });

		Ok(())
	}

	pub(crate) fn add_group(&mut self, group: Arc<Group>) -> Result {
		let groups = self
			.idle_groups
			.get_mut(group.priority as usize)
			.ok_or(EINVAL)?;

		groups.push(group, GFP_KERNEL).map_err(|_| ENOMEM)
	}

	pub(crate) fn remove_group(&mut self, group: Arc<Group>) -> Result {
		if let Some(csg_id) = group.csg_id() {
			let csg_slot = self.csg_slots.get_mut(csg_id).ok_or(EINVAL)?;
			let slot = csg_slot.as_mut().ok_or(EINVAL)?;
			slot.group.vm.deactivate()?;
			for queue in slot.group.queues.iter() {
				queue.set_doorbell_id(None);
			}
			slot.group.set_csg_id(None);
			*csg_slot = None;
			return Ok(());
		}

		let groups = self
			.idle_groups
			.get_mut(group.priority as usize)
			.ok_or(EINVAL)?;
		let pos = groups
			.iter()
			.position(|other| Arc::ptr_eq(other, &group))
			.ok_or(EINVAL)?;

		groups.remove(pos)?;

		Ok(())
	}

	pub(crate) fn submit(
		&mut self,
		syncs: KVec<SyncOp>,
		group: Arc<Group>,
		queue_submits: KVec<QueueSubmit>,
		file: &TyrDrmFile,
	) -> Result {
		group.submit(syncs, queue_submits, file)
	}
}