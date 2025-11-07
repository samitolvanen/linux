// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::impl_has_work;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::workqueue::WorkItem;

use crate::driver::TyrData;
use crate::fw::global::csg::Priority;
use crate::sched::group::Group;
use crate::sched::group::State;
use crate::sched::CommandStreamGroupSlot;

use super::Scheduler;

#[expect(dead_code)]
pub(super) struct Tick {
    groups: KVec<Arc<Group>>,
    idle_group_count: usize,
}

#[expect(dead_code)]
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
        // the world's simplest scheduler.
        // all this does is evict any idle group and fill any empty csg slot with
        // groups from runnable_groups. any destroyed groups are removed from idle groups
        let _ = this.with_locked_scheduler(|sched| {
            let sg = kernel::types::ScopeGuard::new(|| pr_err!("an error occured in tick\n"));
            let mut old_groups: [Option<CommandStreamGroupSlot>; 31] = [const { None }; 31];

            let slot_count = sched.csg_slot_count as usize;

            // sync group state for all queued groups
            for i in 0..slot_count {
                if let Some(slot) = &sched.csg_slots[i] {
                    sched.sync_group_state(&this, i)?;
                }
            }

            // keep any task that is not idle in the same slot
            for i in 0..slot_count {
                if let Some(slot) = &sched.csg_slots[i] {
                    if slot.idle {
                        old_groups[i] = Some(sched.unbind_group(&this, i)?);
                    }
                }
            }

            let priorities = [
                Priority::RealTime,
                Priority::High,
                Priority::Medium,
                Priority::Low,
            ];
            let mut index = 0;
            // fill empty slots with runnable groups
            'outer: for priority in priorities {
                for i in 0..sched.runnable_groups[priority as usize].len() {
                    while let Some(_) = sched.csg_slots[index] {
                        index += 1;
                        if index >= slot_count {
                            break 'outer;
                        }
                    }
                    let group = &sched.runnable_groups[priority as usize][i];
                    let state = group.with_locked_inner(|inner| Ok(inner.state))?;
                    if state == State::Active {
                        continue;
                    }
                    sched.bind_group(&this, group.clone(), index)?;
                    sched.program_csg_slot(&this, index, priority)?;
                    sched.sync_group_state(&this, index)?;

                    index += 1;
                    if index >= slot_count {
                        break 'outer;
                    }
                }
            }

            // drop destroyed groups
            for priority in priorities {
                sched.idle_groups[priority as usize].retain(|group| {
                    group.with_locked_inner(|inner| Ok(inner.destroyed)) != Ok(true)
                });
            }
            sched.resched_target = None;
            sg.dismiss();

            Ok(())
        });
    }
}
