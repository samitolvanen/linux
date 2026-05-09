// SPDX-License-Identifier: GPL-2.0 or MIT

//! Slot management abstraction for limited hardware resources.
//!
//! This module provides a generic [`SlotManager`] that assigns limited hardware
//! slots to logical "seats". A seat represents an entity (such as a virtual memory
//! (VM) address space) that needs access to a hardware slot.
//!
//! The [`SlotManager`] tracks slot allocation using sequence numbers (seqno) to detect
//! when a seat's binding has been invalidated. When a seat requests activation,
//! the manager will either reuse the seat's existing slot (if still valid),
//! allocate a free slot (if any are available), or evict the oldest idle slot if any
//! slots are idle.
//!
//! Hardware-specific behavior is customized by implementing the [`SlotOperations`]
//! trait, which allows callbacks when slots are activated or evicted.
//!
//! This is currently used for managing address space slots in the GPU, and it will
//! also be used to manage Command Stream Group (CSG) interface slots in the future.
//!
//! [SlotOperations]: crate::slot::SlotOperations
//! [SlotManager]: crate::slot::SlotManager

use core::{
    mem::take,
    ops::{
        Deref,
        DerefMut, //
    }, //
};

use kernel::{
    prelude::*,
    sync::LockedBy, //
};

/// Seat information.
///
/// This can't be accessed directly by the element embedding a `Seat`,
/// but is used by the generic slot manager logic to control residency
/// of a certain object on a hardware slot.
pub(crate) struct SeatInfo {
    /// Slot used by this seat.
    ///
    /// This index is only valid if the slot pointed to by this index
    /// has its `SlotInfo::seqno` match `SeatInfo::seqno`. Otherwise,
    /// it means the object has been evicted from the hardware slot,
    /// and a new slot needs to be acquired to make this object
    /// resident again.
    slot: u8,

    /// Sequence number encoding the last time this seat was active.
    /// We also use it to check if a slot is still bound to a seat.
    seqno: u64,
}

/// Seat state.
///
/// This is meant to be embedded in the object that wants to acquire
/// hardware slots. It also starts in the `Seat::NoSeat` state, and
/// the slot manager will change the object value when an active/evict
/// request is issued.
#[derive(Default)]
pub(crate) enum Seat {
    #[expect(clippy::enum_variant_names)]
    /// Resource is not resident.
    ///
    /// All objects start with a seat in the `Seat::NoSeat` state. The seat also
    /// gets back to that state if the user requests eviction. It
    /// can also end up in that state next time an operation is done
    /// on a `Seat::Idle` seat and the slot manager finds out this
    /// object has been evicted from the slot.
    #[default]
    NoSeat,

    /// Resource is actively used and resident.
    ///
    /// When a seat is in the `Seat::Active` state, it can't be evicted, and the
    /// slot pointed to by `SeatInfo::slot` is guaranteed to be reserved
    /// for this object as long as the seat stays active.
    Active(SeatInfo),

    /// Resource is idle and might or might not be resident.
    ///
    /// When a seat is in the`Seat::Idle` state, we can't know for sure if the
    /// object is resident or evicted until the next request we issue
    /// to the slot manager. This tells the slot manager it can
    /// reclaim the underlying slot if needed.
    /// In order for the hardware to use this object again, the seat
    /// needs to be turned into an `Seat::Active` state again
    /// with a `SlotManager::activate()` call.
    Idle(SeatInfo),
}

impl Seat {
    /// Get the slot index this seat is pointing to.
    ///
    /// If the seat is not `Seat::Active` we can't trust the
    /// `SeatInfo`. In that case `None` is returned, otherwise
    /// `Some(SeatInfo::slot)` is returned.
    pub(super) fn slot(&self) -> Option<u8> {
        match self {
            Self::Active(info) => Some(info.slot),
            _ => None,
        }
    }
}

/// Trait describing the slot-related operations.
pub(crate) trait SlotOperations {
    /// Implementation-specific data associated with each slot.
    type SlotData;

    /// Caller-provided context threaded through [`SlotManager::activate`]
    /// and [`SlotManager::evict`] into the callbacks.
    ///
    /// Implementations that don't need a context should set this to `()`.
    type Context;

    /// Called when a slot is being activated for a seat.
    ///
    /// This callback allows hardware-specific actions to be performed when a slot
    /// becomes active, such as updating hardware registers or invalidating caches.
    fn activate(
        &mut self,
        _slot_idx: usize,
        _slot_data: &Self::SlotData,
        _ctx: &mut Self::Context,
    ) -> Result {
        Ok(())
    }

    /// Called when a slot is being evicted and freed.
    ///
    /// This callback allows hardware-specific cleanup when a slot is being
    /// completely freed, either explicitly or when an idle slot is being
    /// reused for a different seat. Any hardware state should be invalidated.
    fn evict(
        &mut self,
        _slot_idx: usize,
        _slot_data: &Self::SlotData,
        _ctx: &mut Self::Context,
    ) -> Result {
        Ok(())
    }
}

/// Data attached to a slot.
///
/// Contains data and the sequence number used to check
/// whether a seat's binding to this slot is still valid.
struct SlotInfo<T> {
    /// Type specific data attached to a slot
    slot_data: T,

    /// Sequence number from when this slot was last activated
    seqno: u64,
}

/// Slot state.
///
/// Tracks whether a hardware slot is free, actively in use, or idle and available
/// for eviction.
#[derive(Default)]
enum Slot<T> {
    /// Slot is free.
    ///
    /// All slots start in the `Slot::Free` state when the slot manager is created.
    #[default]
    Free,

    /// Slot is active.
    ///
    /// When in the `Slot::Active` state, the slot is guaranteed to stay active
    /// for as long as the resource bound to it has its seat in the
    /// `Seat::Active` state. No new resource can be bound to it.
    Active(SlotInfo<T>),

    /// Slot is idle.
    ///
    /// Happens when the underlying resource has been flagged
    /// `Seat::Idle`. When in the `Slot::Idle` state, the slot manager is allowed
    /// to evict the resource and re-assign the slot to someone else.
    /// This process involves updating the `SlotInfo::seqno` which
    /// will be checked against the `SeatInfo::seqno` in case the idle
    /// resource wants to become active again.
    Idle(SlotInfo<T>),
}

/// Generic slot manager object.
///
/// It abstracts away all the churn around activeness/idleness tracking
/// and lets the implementer of the SlotOperations trait focus on how to
/// make a resource active or evict it.
///
/// This structure must be protected by a lock.
/// Seats that want to use this manager must be wrapped with
/// `LockedBy<Seat, SlotManager<T, MAX_SLOTS>>` to ensure they are protected by the same lock.
/// All operations on seats and slots are synchronized through this shared lock.
pub(crate) struct SlotManager<T: SlotOperations, const MAX_SLOTS: usize> {
    /// Manager specific data
    manager: T,

    /// Number of slots actually available
    slot_count: usize,

    /// Slots
    slots: [Slot<T::SlotData>; MAX_SLOTS],

    /// Sequence number incremented each time a Seat is successfully activated
    use_seqno: u64,
}

/// A `Seat` protected by the same lock that is used to wrap the `SlotManager`.
type LockedSeat<T, const MAX_SLOTS: usize> = LockedBy<Seat, SlotManager<T, MAX_SLOTS>>;

impl<T: SlotOperations, const MAX_SLOTS: usize> SlotManager<T, MAX_SLOTS> {
    /// Creates a new slot manager.
    ///
    /// Returns [`EINVAL`] if the slot count is zero or exceeds the maximum number of slots.
    pub(crate) fn new(manager: T, slot_count: usize) -> Result<Self> {
        if slot_count == 0 {
            return Err(EINVAL);
        }
        if slot_count > MAX_SLOTS {
            return Err(EINVAL);
        }
        Ok(Self {
            manager,
            slot_count,
            slots: [const { Slot::Free }; MAX_SLOTS],
            use_seqno: 1,
        })
    }

    /// Updates the active slot count.
    ///
    /// Lets callers that don't know the hardware slot count at
    /// [`SlotManager::new`] time (e.g. because firmware boot has to
    /// happen first) resize the manager once that information becomes
    /// available. The new count must be in `1..=MAX_SLOTS` and is
    /// only safe to call before any seat has been activated, which the
    /// caller is responsible for ensuring.
    ///
    /// Returns [`EINVAL`] if `slot_count` is zero or exceeds
    /// `MAX_SLOTS`.
    pub(crate) fn set_slot_count(&mut self, slot_count: usize) -> Result {
        if slot_count == 0 || slot_count > MAX_SLOTS {
            return Err(EINVAL);
        }
        self.slot_count = slot_count;
        Ok(())
    }

    /// Returns the number of slots currently exposed by the manager.
    ///
    /// Always in `1..=MAX_SLOTS`. Callers that walk slot indices should
    /// bound their iteration by this value rather than `MAX_SLOTS` to
    /// avoid touching slots the hardware does not report.
    pub(crate) fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Records a slot as active for the given seat.
    ///
    /// Updates both the seat state and the slot state to reflect the active binding,
    /// using the current sequence number. Increments the sequence number for the next
    /// activation.
    fn record_active_slot(
        &mut self,
        slot_idx: usize,
        locked_seat: &LockedSeat<T, MAX_SLOTS>,
        slot_data: T::SlotData,
    ) -> Result {
        let cur_seqno = self.use_seqno;

        *locked_seat.access_mut(self) = Seat::Active(SeatInfo {
            slot: slot_idx as u8,
            seqno: cur_seqno,
        });

        self.slots[slot_idx] = Slot::Active(SlotInfo {
            slot_data,
            seqno: cur_seqno,
        });

        self.use_seqno += 1;
        Ok(())
    }

    /// Activates a slot for the given seat.
    ///
    /// Calls the activation callback and then records the slot as active.
    fn activate_slot(
        &mut self,
        slot_idx: usize,
        locked_seat: &LockedSeat<T, MAX_SLOTS>,
        slot_data: T::SlotData,
        ctx: &mut T::Context,
    ) -> Result {
        self.manager.activate(slot_idx, &slot_data, ctx)?;
        self.record_active_slot(slot_idx, locked_seat, slot_data)
    }

    /// Allocates a slot for the given seat.
    ///
    /// Searches for a free slot first. If none are available, finds the oldest idle
    /// slot (by sequence number) and evicts it. Returns [`EBUSY`] if all slots are
    /// active and none can be evicted.
    fn allocate_slot(
        &mut self,
        locked_seat: &LockedSeat<T, MAX_SLOTS>,
        slot_data: T::SlotData,
        ctx: &mut T::Context,
    ) -> Result {
        let slots = &self.slots[..self.slot_count];

        let mut idle_slot_idx = None;
        let mut idle_slot_seqno: u64 = 0;

        for (slot_idx, slot) in slots.iter().enumerate() {
            match slot {
                Slot::Free => {
                    return self.activate_slot(slot_idx, locked_seat, slot_data, ctx);
                }
                Slot::Idle(slot_info) => {
                    if idle_slot_idx.is_none() || slot_info.seqno < idle_slot_seqno {
                        idle_slot_idx = Some(slot_idx);
                        idle_slot_seqno = slot_info.seqno;
                    }
                }
                Slot::Active(_) => (),
            }
        }

        match idle_slot_idx {
            Some(slot_idx) => {
                // Lazily evict idle slot just before it is reused
                if let Slot::Idle(slot_info) = &self.slots[slot_idx] {
                    self.manager.evict(slot_idx, &slot_info.slot_data, ctx)?;
                }
                self.activate_slot(slot_idx, locked_seat, slot_data, ctx)
            }
            None => {
                pr_err!(
                    "Slot allocation failed: all {} slots in use\n",
                    self.slot_count
                );
                Err(EBUSY)
            }
        }
    }

    /// Transitions a slot from active to idle state.
    ///
    /// Updates both the slot and seat to idle state, making the slot eligible for
    /// eviction if needed by another seat.
    fn idle_slot(&mut self, slot_idx: usize, locked_seat: &LockedSeat<T, MAX_SLOTS>) -> Result {
        let slot = take(&mut self.slots[slot_idx]);

        if let Slot::Active(slot_info) = slot {
            self.slots[slot_idx] = Slot::Idle(SlotInfo {
                slot_data: slot_info.slot_data,
                seqno: slot_info.seqno,
            })
        };

        *locked_seat.access_mut(self) = match locked_seat.access(self) {
            Seat::Active(seat_info) | Seat::Idle(seat_info) => Seat::Idle(SeatInfo {
                slot: seat_info.slot,
                seqno: seat_info.seqno,
            }),
            Seat::NoSeat => Seat::NoSeat,
        };
        Ok(())
    }

    /// Evicts a seat from its slot and marks the slot as free.
    ///
    /// Calls the eviction callback then frees the slot and resets the seat to `NoSeat`.
    fn evict_slot(
        &mut self,
        slot_idx: usize,
        locked_seat: &LockedSeat<T, MAX_SLOTS>,
        ctx: &mut T::Context,
    ) -> Result {
        match &self.slots[slot_idx] {
            Slot::Active(slot_info) | Slot::Idle(slot_info) => {
                self.manager.evict(slot_idx, &slot_info.slot_data, ctx)?;
                take(&mut self.slots[slot_idx]);
            }
            _ => (),
        }

        *locked_seat.access_mut(self) = Seat::NoSeat;
        Ok(())
    }

    /// Checks and updates the seat state based on the slot it points to.
    ///
    /// Validates that the seat's sequence number matches the slot's sequence number.
    /// If they don't match, the seat has been evicted and is reset to `NoSeat`.
    fn check_seat(&mut self, locked_seat: &LockedSeat<T, MAX_SLOTS>) {
        let (slot_idx, seqno, is_active) = match locked_seat.access(self) {
            Seat::Active(info) => (info.slot as usize, info.seqno, true),
            Seat::Idle(info) => (info.slot as usize, info.seqno, false),
            _ => return,
        };

        let valid = if is_active {
            !kernel::warn_on!(!matches!(&self.slots[slot_idx], Slot::Active(s) if s.seqno == seqno))
        } else {
            matches!(&self.slots[slot_idx], Slot::Idle(s) if s.seqno == seqno)
        };

        if !valid {
            *locked_seat.access_mut(self) = Seat::NoSeat;
        }
    }

    /// Make a resource active on any available/reclaimable slot.
    ///
    /// Returns [`EBUSY`] if all slots are in use and none can be reclaimed
    /// or the reclaim failed. May also return errors from the callbacks.
    pub(crate) fn activate(
        &mut self,
        locked_seat: &LockedSeat<T, MAX_SLOTS>,
        slot_data: T::SlotData,
        ctx: &mut T::Context,
    ) -> Result {
        self.check_seat(locked_seat);
        match locked_seat.access(self) {
            Seat::Active(seat_info) | Seat::Idle(seat_info) => {
                // With lazy eviction, if seqno matches, the hardware state is still
                // valid for both Active and Idle slots, so just update our records
                self.record_active_slot(seat_info.slot as usize, locked_seat, slot_data)
            }
            _ => self.allocate_slot(locked_seat, slot_data, ctx),
        }
    }

    /// Flag a resource idle.
    ///
    /// The slot manager can decide to reclaim the slot this resource
    /// was bound to at any point after function returns.
    // The idle() method will be used when we start adding support for user VMs.
    #[expect(dead_code)]
    pub(crate) fn idle(&mut self, locked_seat: &LockedSeat<T, MAX_SLOTS>) -> Result {
        self.check_seat(locked_seat);
        if let Seat::Active(seat_info) = locked_seat.access(self) {
            self.idle_slot(seat_info.slot as usize, locked_seat)?;
        }
        Ok(())
    }

    /// Evict a resource from its slot, and make this slot free again
    /// for other users.
    ///
    /// May return errors from the eviction callback.
    pub(crate) fn evict(
        &mut self,
        locked_seat: &LockedSeat<T, MAX_SLOTS>,
        ctx: &mut T::Context,
    ) -> Result {
        self.check_seat(locked_seat);

        match locked_seat.access(self) {
            Seat::Active(seat_info) | Seat::Idle(seat_info) => {
                let slot_idx = seat_info.slot as usize;

                self.evict_slot(slot_idx, locked_seat, ctx)?;
            }
            _ => (),
        }

        Ok(())
    }

    /// Returns the per-slot driver data for `slot_idx`.
    ///
    /// Returns `Some(&data)` when the slot is allocated to a group
    /// (states [`Slot::Active`] and [`Slot::Idle`]), and `None` when
    /// the index is out of range or the slot has no group assigned.
    pub(crate) fn slot_data(&self, slot_idx: usize) -> Option<&T::SlotData> {
        if slot_idx >= self.slot_count {
            return None;
        }
        match &self.slots[slot_idx] {
            Slot::Active(info) | Slot::Idle(info) => Some(&info.slot_data),
            _ => None,
        }
    }

    /// Returns the per-slot driver data for `slot_idx`.
    ///
    /// Same semantics as [`SlotManager::slot_data`] but yields a `&mut`
    /// reference.
    pub(crate) fn slot_data_mut(&mut self, slot_idx: usize) -> Option<&mut T::SlotData> {
        if slot_idx >= self.slot_count {
            return None;
        }
        match &mut self.slots[slot_idx] {
            Slot::Active(info) | Slot::Idle(info) => Some(&mut info.slot_data),
            _ => None,
        }
    }
}

impl<T: SlotOperations, const MAX_SLOTS: usize> Deref for SlotManager<T, MAX_SLOTS> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.manager
    }
}

impl<T: SlotOperations, const MAX_SLOTS: usize> DerefMut for SlotManager<T, MAX_SLOTS> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.manager
    }
}
