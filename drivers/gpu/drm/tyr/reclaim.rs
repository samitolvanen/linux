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
                Lru,
                Shrink, //
            },
            BaseObject,
            ResvGuard, //
        },
        gpuvm::{
            GemGpuvaGuard,
            GpuVmBo, //
        }, //
    },
    list::{
        impl_list_arc_safe,
        impl_list_item,
        List,
        ListArc,
        ListLinks, //
    },
    mm::reclaim::{
        nr_swap_pages,
        FsReclaimGuard, //
    },
    prelude::*,
    shrinker::{
        CountObjects,
        ScanObjects,
        ShrinkControl,
        Shrinker,
        ShrinkerBuilder,
        ShrinkerRegistration, //
    },
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            AtomicType,
            Relaxed, //
        },
        new_mutex,
        new_spinlock,
        Arc,
        ArcBorrow,
        LockedBy,
        Mutex,
        SpinLock, //
    },
    time::Jiffies,
};

use crate::{
    driver::TyrDrmDevice,
    gem::Bo,
    vm::{
        GpuVmData,
        VmExec, //
    },
};

/// Reclaim state of a BO, from the most to the least reclaimable. The states ignore the mappings
/// of evicted `GpuVmBo`s.
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

/// How long a scan waits for a VM to finish its jobs before it skips the BOs of the VM.
const IDLE_TIMEOUT: Jiffies = 10;

/// The LRUs of the BOs and the VMs of a device.
#[pin_data]
pub(crate) struct Reclaim {
    /// BOs that nothing maps.
    #[pin]
    unused: Lru<Bo>,
    /// BOs that only userspace maps.
    #[pin]
    mmapped: Lru<Bo>,
    /// User VMs, from the least to the most recently active. A scan moves each VM that it is done
    /// with to the tail.
    vms: LockedBy<List<VmReclaim>, ()>,
    /// Generation of the last scan of the VMs, held while the VMs are scanned.
    #[pin]
    vm_scan: Mutex<u32>,
    /// Number of scans in a row that freed nothing while BOs remained.
    retry_count: Atomic<u32>,
    /// Number of pages that the last scan reclaimed.
    #[cfg(CONFIG_DEBUG_FS)]
    last_scan_pages: Atomic<usize>,
    /// Device whose GEM LRU mutex protects the LRUs.
    dev: ARef<TyrDrmDevice>,
}

impl Reclaim {
    pub(crate) fn new(dev: &TyrDrmDevice) -> impl PinInit<Self> {
        let unused = Lru::new(dev);
        let mmapped = Lru::new(dev);
        let vms = LockedBy::new(dev.gem_lru_mutex(), List::new());
        let dev = dev.into();

        pin_init!(Self {
            unused <- unused,
            mmapped <- mmapped,
            vms,
            vm_scan <- new_mutex!(0),
            retry_count: Atomic::new(0),
            #[cfg(CONFIG_DEBUG_FS)]
            last_scan_pages: Atomic::new(0),
            dev,
        })
    }

    /// Returns the number of pages on the LRUs that a scan reaches.
    fn count(&self, can_block: bool) -> usize {
        let guard = self.dev.gem_lru_mutex().lock();

        let mut count = [&self.unused, &self.mmapped]
            .iter()
            .map(|lru| lru.count(&guard).unwrap_or(0))
            .sum();

        if can_block {
            for vm in self.vms.access_with_guard(&guard).iter() {
                count += vm.lru.count(&guard).unwrap_or(0);
            }
        }

        count
    }

    /// Reclaims up to `nr_to_scan` pages. The BOs that a VM maps are only reclaimed if
    /// `can_block` allows waiting for the VM to finish its jobs.
    fn scan(&self, nr_to_scan: usize, can_block: bool) -> ScanObjects {
        let mut freed = 0;
        let mut remaining = 0;

        if can_swap() {
            for lru in [&self.unused, &self.mmapped] {
                if freed >= nr_to_scan {
                    break;
                }

                freed += lru.scan::<EvictNoWait>(nr_to_scan - freed, &mut remaining);
            }

            if can_block && freed < nr_to_scan {
                freed += self.scan_vms(nr_to_scan - freed, &mut remaining);
            }
        }

        #[cfg(CONFIG_DEBUG_FS)]
        self.last_scan_pages.store(freed, Relaxed);

        if freed == 0 && remaining > 0 && self.retry_count.fetch_add(1, Relaxed) < 1 {
            return ScanObjects::from_count(0);
        }

        self.retry_count.store(0, Relaxed);

        if freed > 0 {
            ScanObjects::from_count(freed)
        } else {
            ScanObjects::STOP
        }
    }

    /// Returns the number of pages that the last scan reclaimed.
    #[cfg(CONFIG_DEBUG_FS)]
    pub(crate) fn last_scan_pages(&self) -> usize {
        self.last_scan_pages.load(Relaxed)
    }

    /// Reclaims up to `nr_to_scan` pages, as memory reclaim would.
    #[cfg(CONFIG_DEBUG_FS)]
    pub(crate) fn shrink(&self, nr_to_scan: usize) {
        let _scope = FsReclaimGuard::new(GFP_KERNEL);
        self.scan(nr_to_scan, true);
    }

    /// Reclaims up to `nr_to_scan` pages of the BOs that one VM maps, starting with the least
    /// recently active VM.
    fn scan_vms(&self, nr_to_scan: usize, remaining: &mut usize) -> usize {
        // Concurrent scans would overwrite each other's marks and could revisit the VMs forever.
        let Some(mut scan_gen) = self.vm_scan.try_lock() else {
            return 0;
        };
        *scan_gen = scan_gen.wrapping_add(1);

        let mut freed = 0;
        let mut done = None;
        while freed < nr_to_scan {
            let Some(vm) = self.next_vm(*scan_gen, done.as_deref()) else {
                break;
            };

            freed += vm.lru.scan::<EvictIdle>(nr_to_scan - freed, remaining);
            done = Some(vm);
        }

        freed
    }

    /// Returns the first VM that has BOs to reclaim and that scan `scan_gen` has not visited.
    /// Moves `done` and the skipped VMs to the tail, as the scan is done with them.
    fn next_vm(&self, scan_gen: u32, mut done: Option<&VmReclaim>) -> Option<Arc<VmReclaim>> {
        let mut guard = self.dev.gem_lru_mutex().lock();

        loop {
            let vm = self.vms.access_with_guard(&guard).iter().next()?;

            if vm.scan_gen.xchg(scan_gen, Relaxed) == scan_gen {
                if !done.take().is_some_and(|done| ptr::eq(done, &*vm)) {
                    return None;
                }
            } else if vm.lru.count(&guard).is_ok_and(|count| count > 0) {
                return Some(vm.into());
            }

            let vms = self.vms.access_with_guard_mut(&mut guard);
            if let Some(vm) = vms.pop_front() {
                vms.push_back(vm);
            }
        }
    }
}

/// Runs `f` with the reclaim state of `dev`, unless the device is unbound or
/// not yet registered.
pub(crate) fn with_reclaim<R>(dev: &TyrDrmDevice, f: impl FnOnce(&Reclaim) -> R) -> Option<R> {
    let reg = dev.registration_guard()?;
    let data = dev.data()?;
    // SAFETY: The parent device stays bound while `reg` is held.
    let bound = unsafe { reg.as_ref().as_bound() };
    let reclaim = data.reclaim.as_ref()?.access(bound).ok()?;

    Some(f(reclaim))
}

/// Adds the reclaim state of a new user VM to the VMs of the device.
pub(crate) fn add_vm(vm: ListArc<VmReclaim>) {
    let dev = ARef::from(vm.root_gem.dev());

    with_reclaim(&dev, |reclaim| {
        let mut guard = reclaim.dev.gem_lru_mutex().lock();
        reclaim.vms.access_with_guard_mut(&mut guard).push_back(vm);
    });
}

/// Registers the shrinker of the BOs of a device.
pub(crate) fn register_shrinker(
    reclaim: Arc<Reclaim>,
) -> Result<ShrinkerRegistration<GemShrinker>> {
    {
        let _scope = FsReclaimGuard::new(GFP_KERNEL);
        reclaim.dev.gem_lru_mutex().might_lock();
    }

    Ok(ShrinkerBuilder::new(c"drm-tyr-gem")?.register::<GemShrinker>(reclaim))
}

/// The shrinker of the BOs of a device.
pub(crate) struct GemShrinker;

impl Shrinker for GemShrinker {
    type Ptr = Arc<Reclaim>;

    fn count_objects(reclaim: ArcBorrow<'_, Reclaim>, sc: ShrinkControl<'_>) -> CountObjects {
        if !can_swap() {
            return CountObjects::new(0);
        }

        match reclaim.count(sc.can_block()) {
            0 => CountObjects::EMPTY,
            count => CountObjects::new(count),
        }
    }

    fn scan_objects(reclaim: ArcBorrow<'_, Reclaim>, sc: ShrinkControl<'_>) -> ScanObjects {
        reclaim.scan(sc.nr_to_scan(), sc.can_block())
    }
}

/// Returns whether reclaimed pages can be written to swap.
fn can_swap() -> bool {
    nr_swap_pages() > 0
}

/// Reclaims the pages of the BOs on the LRUs of the device, without waiting for fences.
struct EvictNoWait;

impl Shrink<Bo> for EvictNoWait {
    fn shrink(resv: &mut ResvGuard<'_, Bo>) -> bool {
        evict(resv, ReclaimState::Mmapped, None).is_ok()
    }
}

/// Reclaims the pages of the BOs that one VM maps, once the VM has finished its jobs.
struct EvictIdle;

impl Shrink<Bo> for EvictIdle {
    fn shrink(resv: &mut ResvGuard<'_, Bo>) -> bool {
        evict_idle(resv).is_ok()
    }
}

/// Reclaims the pages of the BO whose reservation lock `resv` holds, once the only VM that maps
/// the BO has finished its jobs.
fn evict_idle(resv: &mut ResvGuard<'_, Bo>) -> Result {
    let vm = mapping_vm(resv)?;
    let exec = vm.exec().ok_or(EBUSY)?;

    if vm.shares_resv(resv.obj()) {
        vm.wait_idle_in_scan(&exec, resv)?;
        return evict(resv, ReclaimState::GpuMappedSingleVm, None);
    }

    let vm_resv = vm.root_gem.try_lock_resv().ok_or(EBUSY)?;
    vm.wait_idle_in_scan(&exec, &vm_resv)?;

    evict(resv, ReclaimState::GpuMappedSingleVm, Some(&vm))
}

/// Returns the only VM that maps the BO whose reservation lock `resv` holds.
fn mapping_vm(resv: &ResvGuard<'_, Bo>) -> Result<Arc<VmReclaim>> {
    let gpuva = GemGpuvaGuard::try_lock(resv.obj()).ok_or(EBUSY)?;
    let mut vm_bos = mapped_vm_bos(resv, &gpuva);

    if let (Some(vm_bo), None) = (vm_bos.next(), vm_bos.next()) {
        return vm_bo.data().vm().cloned().ok_or(EBUSY);
    }

    update_state(resv, Some(&gpuva));
    Err(EAGAIN)
}

/// Reclaims the pages of the BO whose reservation lock `resv` holds.
///
/// Fails with `EAGAIN` if the BO is now harder to reclaim than its state says, or than `max`.
/// The caller holds the reservation lock of `held`.
fn evict(resv: &mut ResvGuard<'_, Bo>, max: ReclaimState, held: Option<&VmReclaim>) -> Result {
    {
        let gpuva = GemGpuvaGuard::try_lock(resv.obj()).ok_or(EBUSY)?;
        let (old, new) = update_state(resv, Some(&gpuva));
        if new > old || new > max {
            return Err(EAGAIN);
        }

        for vm_bo in gpuva.vm_bos() {
            if is_fully_evicted(vm_bo, resv, &gpuva) {
                continue;
            }

            let vm = vm_bo.data().vm().ok_or(EBUSY)?;
            let exec = vm.exec().ok_or(EBUSY)?;
            let locked = held.is_some_and(|held| ptr::eq(held, &**vm));
            let _vm_resv = if locked || vm.shares_resv(resv.obj()) {
                None
            } else {
                Some(vm.root_gem.try_lock_resv().ok_or(EBUSY)?)
            };

            exec.evict_mappings(vm_bo, resv, &gpuva)?;
        }
    }

    // SAFETY: Every GPU mapping of the BO is evicted. A new mapping pins the BO, which takes the
    // reservation lock that `resv` holds.
    unsafe { resv.evict() }
}

/// Reclaim state of a VM.
#[pin_data]
pub(crate) struct VmReclaim {
    /// BOs that only this VM maps.
    #[pin]
    lru: Lru<Bo>,
    /// Links in the VMs of the device.
    #[pin]
    links: ListLinks,
    /// Generation of the last scan that visited this VM.
    scan_gen: Atomic<u32>,
    /// Value of `scan_gen` when a wait for this VM to finish its jobs last timed out.
    busy_gen: Atomic<u32>,
    /// Execution state of the VM until the VM drops. `VmExec` holds this reclaim state, so
    /// `Vm::drop` clears the field to break the cycle.
    #[pin]
    exec: SpinLock<Option<Arc<VmExec>>>,
    /// GEM object whose reservation lock protects the VM.
    root_gem: ARef<Bo>,
    /// Declared last, so the device outlives the drop of every other field.
    ddev: ARef<TyrDrmDevice>,
}

impl VmReclaim {
    pub(crate) fn new(dev: &TyrDrmDevice, root_gem: &Bo) -> impl PinInit<Self> {
        let lru = Lru::new(dev);
        let root_gem = root_gem.into();
        let ddev = dev.into();

        pin_init!(Self {
            lru <- lru,
            links <- ListLinks::new(),
            scan_gen: Atomic::new(0),
            busy_gen: Atomic::new(0),
            exec <- new_spinlock!(None),
            root_gem,
            ddev,
        })
    }

    /// Moves the VM to the tail of the VMs of the device, as the most recently active one.
    pub(crate) fn activate(&self) {
        with_reclaim(self.root_gem.dev(), |reclaim| {
            let mut guard = reclaim.dev.gem_lru_mutex().lock();
            let vms = reclaim.vms.access_with_guard_mut(&mut guard);

            // SAFETY: The reclaim state of a VM is only added to the VMs of its own device.
            if let Some(vm) = unsafe { vms.remove(self) } {
                vms.push_back(vm);
            }
        });
    }

    /// Removes the VM from the VMs of the device.
    pub(crate) fn remove(&self) -> Option<ListArc<Self>> {
        with_reclaim(self.root_gem.dev(), |reclaim| {
            let mut guard = reclaim.dev.gem_lru_mutex().lock();

            // SAFETY: The reclaim state of a VM is only added to the VMs of its own device.
            unsafe { reclaim.vms.access_with_guard_mut(&mut guard).remove(self) }
        })
        .flatten()
    }

    /// Sets the execution state of the VM.
    pub(crate) fn attach(&self, exec: Arc<VmExec>) {
        *self.exec.lock() = Some(exec);
    }

    /// Clears the execution state of the VM, and returns it.
    pub(crate) fn detach(&self) -> Option<Arc<VmExec>> {
        self.exec.lock().take()
    }

    fn exec(&self) -> Option<Arc<VmExec>> {
        self.exec.lock().clone()
    }

    /// Waits up to `IDLE_TIMEOUT` for the VM to finish its jobs. Fails with `EBUSY` without
    /// waiting if a wait timed out since a scan last visited the VM.
    fn wait_idle_in_scan(&self, exec: &VmExec, resv: &ResvGuard<'_, Bo>) -> Result {
        // Both generations only change with `vm_scan` held, so no other scan changes them while
        // this one runs.
        let scan_gen = self.scan_gen.load(Relaxed);
        if self.busy_gen.load(Relaxed) == scan_gen {
            return Err(EBUSY);
        }

        if !exec.wait_idle(resv, IDLE_TIMEOUT) {
            self.busy_gen.store(scan_gen, Relaxed);
            return Err(EBUSY);
        }

        Ok(())
    }

    /// Returns whether `bo` uses the reservation lock of the VM.
    pub(crate) fn shares_resv(&self, bo: &Bo) -> bool {
        let root_gem = &*self.root_gem;

        ptr::eq(bo, root_gem)
            || bo
                .exclusive_vm_root_gem()
                .is_some_and(|root| ptr::eq(root, root_gem))
    }
}

impl_list_arc_safe! {
    impl ListArcSafe<0> for VmReclaim { untracked; }
}

impl_list_item! {
    impl ListItem<0> for VmReclaim {
        using ListLinks { self.links };
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
    let mut vm_bos = mapped_vm_bos(resv, gpuva);

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

/// Returns the `GpuVmBo`s of a BO that are not evicted.
fn mapped_vm_bos<'a>(
    resv: &'a ResvGuard<'_, Bo>,
    gpuva: &'a GemGpuvaGuard<'_, GpuVmData>,
) -> impl Iterator<Item = &'a GpuVmBo<GpuVmData>> {
    gpuva
        .vm_bos()
        .filter(|vm_bo| matches!(vm_bo.is_evicted(resv), Ok(false)))
}

/// Returns whether `vm_bo` and all its mappings are evicted. A map on an evicted `GpuVmBo` adds a
/// mapping that is not evicted.
fn is_fully_evicted(
    vm_bo: &GpuVmBo<GpuVmData>,
    resv: &ResvGuard<'_, Bo>,
    gpuva: &GemGpuvaGuard<'_, GpuVmData>,
) -> bool {
    matches!(vm_bo.is_evicted(resv), Ok(true))
        && vm_bo
            .vas(gpuva)
            .is_ok_and(|mut vas| vas.all(|va| va.data_ref().is_evicted()))
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
