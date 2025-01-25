// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::impl_has_work;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::workqueue::WorkItem;

use crate::driver::TyrData;
use crate::sched::group::Group;

use super::Scheduler;

pub(super) struct Tick {
    groups: KVec<Arc<Group>>,
    idle_group_count: usize,
}

impl Tick {
    fn full(&self, sched: &Scheduler) -> bool {
        self.groups.len() as u32 == sched.csg_slot_count
    }
}

impl_has_work! {
    impl HasWork<Self, 1> for TyrData {
        self.tick_work
    }
}

impl WorkItem<1> for TyrData {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        let _ = this.with_locked_scheduler(|sched| Ok(()));
    }
}
