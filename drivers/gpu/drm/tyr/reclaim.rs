// SPDX-License-Identifier: GPL-2.0 or MIT

//! Reclaim of BO pages.
//!
//! A BO whose pages can be reclaimed is on the LRU of its reclaim state. The
//! GEM LRU mutex of the device protects every LRU.

use core::ptr;

use kernel::{
    drm::{
        gem::{
            lru::{
                self,
                Lru, //
            },
            ResvGuard, //
        },
        gpuvm::GemGpuvaGuard, //
    },
    prelude::*,
    sync::atomic::AtomicType, //
};

use crate::{
    driver::TyrDrmDevice,
    gem::Bo,
    vm::GpuVmData, //
};

/// Reclaim state of a BO, from the most to the least reclaimable.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub(crate) enum ReclaimState {
    /// The BO has pages, and nothing maps or pins them.
    Unused = 0,
    /// Only userspace maps the pages.
    Mmapped = 1,
    /// One VM maps the pages.
    GpuMappedSingleVm = 2,
    /// Several VMs map the pages.
    GpuMappedMultiVm = 3,
    /// The BO has no pages, or they are pinned.
    Unreclaimable = 4,
}

// SAFETY: `ReclaimState` and `i32` have the same size and alignment, and `ReclaimState` is
// round-trip transmutable to `i32`.
unsafe impl AtomicType for ReclaimState {
    type Repr = i32;
}

/// The LRUs of the BOs of a device that no VM maps.
#[pin_data]
pub(crate) struct Reclaim {
    /// BOs that nothing maps.
    #[pin]
    unused: Lru<Bo>,
    /// BOs that only userspace maps.
    #[pin]
    mmapped: Lru<Bo>,
}

impl Reclaim {
    pub(crate) fn new(dev: &TyrDrmDevice) -> impl PinInit<Self> {
        let unused = Lru::new(dev);
        let mmapped = Lru::new(dev);

        pin_init!(Self {
            unused <- unused,
            mmapped <- mmapped,
        })
    }
}

/// Runs `f` with the reclaim state of `dev`, unless the device is unbound or
/// not yet registered.
fn with_reclaim<R>(dev: &TyrDrmDevice, f: impl FnOnce(&Reclaim) -> R) -> Option<R> {
    let reg = dev.registration_guard()?;
    let data = dev.data()?;
    // SAFETY: The parent device stays bound while `reg` is held.
    let bound = unsafe { reg.as_ref().as_bound() };
    let reclaim = data.reclaim.as_ref()?.access(bound).ok()?;

    Some(f(reclaim))
}

/// Reclaim state of a VM.
#[pin_data]
pub(crate) struct VmReclaim {
    /// BOs that only this VM maps.
    #[pin]
    lru: Lru<Bo>,
}

impl VmReclaim {
    pub(crate) fn new(dev: &TyrDrmDevice) -> impl PinInit<Self> {
        let lru = Lru::new(dev);

        pin_init!(Self {
            lru <- lru,
        })
    }
}

/// Updates the reclaim state of the BO whose reservation lock `resv` holds, and moves the BO to
/// the LRU of the new state. Returns the previous state and the new state.
///
/// `gpuva` holds the gpuva lock of the BO. If it is `None`, the lock is taken when the state
/// depends on the GPU mappings of the BO.
pub(crate) fn update_state(
    resv: &ResvGuard<'_, Bo>,
    gpuva: Option<&GemGpuvaGuard<'_, GpuVmData>>,
) -> (ReclaimState, ReclaimState) {
    if !resv.is_resident() || resv.is_pinned() {
        return set_state(resv.obj(), ReclaimState::Unreclaimable, None);
    }

    match gpuva {
        Some(gpuva) => update_resident(resv, gpuva),
        None => update_resident(resv, &GemGpuvaGuard::lock(resv.obj())),
    }
}

/// Updates the reclaim state of a resident BO that nothing pins.
fn update_resident(
    resv: &ResvGuard<'_, Bo>,
    gpuva: &GemGpuvaGuard<'_, GpuVmData>,
) -> (ReclaimState, ReclaimState) {
    let bo = resv.obj();
    let mut vm_bos = gpuva.vm_bos();

    match (vm_bos.next(), vm_bos.next()) {
        (None, _) if resv.is_mmapped() => set_state(bo, ReclaimState::Mmapped, None),
        (None, _) => set_state(bo, ReclaimState::Unused, None),
        (Some(vm_bo), None) => set_state(
            bo,
            ReclaimState::GpuMappedSingleVm,
            vm_bo.data().vm().map(|vm| &**vm),
        ),
        (Some(_), Some(_)) => set_state(bo, ReclaimState::GpuMappedMultiVm, None),
    }
}

/// Stores `state` as the reclaim state of `bo`, and moves `bo` to the LRU of `state` if the
/// state or its VM changed.
///
/// `vm` is the VM that maps a BO in the single-VM state.
fn set_state(bo: &Bo, state: ReclaimState, vm: Option<&VmReclaim>) -> (ReclaimState, ReclaimState) {
    let vm_ptr = vm.map_or(ptr::null(), ptr::from_ref);
    let (old, old_vm) = bo.replace_reclaim_state(state, vm_ptr);
    if old == state && old_vm == vm_ptr {
        return (old, state);
    }

    match (state, vm) {
        (ReclaimState::Unused | ReclaimState::Mmapped, _) => move_to_device_lru(bo, state),
        (ReclaimState::GpuMappedSingleVm, Some(vm)) => {
            let _ = vm.lru.move_tail(bo);
        }
        _ => lru::remove(bo),
    }

    (old, state)
}

/// Moves `bo` to the device LRU of `state`, or removes it from its LRU once the device is
/// unbound.
fn move_to_device_lru(bo: &Bo, state: ReclaimState) {
    let moved = with_reclaim(bo.dev(), |reclaim| {
        let lru = match state {
            ReclaimState::Mmapped => &reclaim.mmapped,
            _ => &reclaim.unused,
        };

        lru.move_tail(bo).is_ok()
    });

    if moved != Some(true) {
        lru::remove(bo);
    }
}
