// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::{
    AtomicBool,
    AtomicU32,
    Ordering, //
};

use kernel::{
    bindings,
    clk::{
        Clk,
        OptionalClk, //
    },
    devfreq::Registration as DevfreqRegistration,
    device::Core,
    devres::Devres,
    dma::{
        Device as DmaDevice,
        DmaMask, //
    },
    dma_buf::dma_fence::{
        impl_has_dma_fence_work,
        new_dma_fence_work,
        DmaFenceWork,
        DmaFenceWorkItem,
        DmaFenceWorkqueue, //
    },
    drm,
    drm::{
        driver::Registration,
        ioctl,
        UnregisteredDevice, //
    },
    new_mutex,
    of,
    opp::ConfigToken,
    platform,
    pm::{
        self,
        PMConfig,
        PMContext,
        PMProfile,
        RuntimePMState, //
    },
    prelude::*,
    regulator,
    regulator::Regulator,
    sizes::SZ_2M,
    sync::{
        aref::ARef,
        atomic::Atomic,
        Arc,
        Mutex,
        SetOnce, //
    },
    time::{
        msecs_to_jiffies,
        Jiffies, //
    },
    types::ScopeGuard,
    workqueue::{
        self,
        impl_has_delayed_work,
        DelayedWork,
        OwnedQueue,
        Queue,
        Work,
        WorkItem, //
    }, //
};

use crate::{
    devfreq::{
        self,
        TyrDevfreqCallbacks,
        TyrDevfreqData, //
    },
    file::TyrDrmFileData,
    fw::{
        irq::{
            job_irq_enable,
            job_irq_init,
            JobIrq, //
        },
        Firmware, //
    },
    gem::BoData,
    gpu,
    gpu::{
        irq::GpuIrq,
        GpuInfo, //
    },
    irq::IrqSlot,
    mmap,
    mmu::{
        irq::{
            mmu_irq_enable,
            mmu_irq_init,
            MmuIrq, //
        },
        Mmu, //
    },
    pm::{
        TyrPmOps,
        AUTOSUSPEND_DELAY_MS, //
    },
    regs::gpu_control::*,
    reset, //
    sched::{
        CsgSlotManager,
        CsgSlotOps,
        Scheduler,
        SchedulerState,
        MAX_CSGS, //
    },
    slot::SlotManager,
};

pub(crate) type IoMem = kernel::io::mem::IoMem<SZ_2M>;

pub(crate) struct TyrDrmDriver;

/// Convenience type alias for the DRM device type for this driver.
pub(crate) type TyrDrmDevice<Ctx = drm::Registered> = drm::Device<TyrDrmDriver, Ctx>;

/// Interval between firmware liveness pings.
const PING_INTERVAL_MS: u32 = 12_000;

/// Time the firmware is given to acknowledge a ping before the watchdog
/// triggers a GPU reset.
const PING_TIMEOUT_MS: u32 = 100;

/// Per-device work-slot identifiers used as the `WORK_ID` const
/// generic on this device's work-item fields and their `HasWork` /
/// `HasDelayedWork` impls.
pub(crate) mod work_id {
    /// Scheduler tick worker.
    pub(crate) const TICK: u64 = 1;
    /// Firmware-event drain worker.
    pub(crate) const FW_EVENTS: u64 = 2;
    /// Group sync-update worker.
    pub(crate) const SYNC_UPD: u64 = 3;
    /// Periodic re-arming of the scheduler tick.
    pub(crate) const PERIODIC_TICK: u64 = 4;
    /// Firmware liveness ping watchdog.
    pub(crate) const FW_PING: u64 = 5;
}

/// `Send + Sync` newtype around `OwnedQueue` so the cleanup
/// workqueue can be shared as `Arc<CleanupQueue>` between the device
/// and the `KernelBo`s that enqueue deferred
/// drops on it. The wrapped `Queue` is
/// already `Send + Sync`; this mirrors the equivalent wrapper that
/// `DmaFenceWorkqueue` applies.
#[repr(transparent)]
pub(crate) struct CleanupQueue(OwnedQueue);

// SAFETY: The wrapped `OwnedQueue` exposes a `Queue` which is itself
// `Send`, and `destroy_workqueue` (run from `OwnedQueue::drop`) is
// safe to invoke from any thread.
unsafe impl Send for CleanupQueue {}
// SAFETY: As for `Send`; `Queue`'s operations are documented as
// thread-safe by the C workqueue API.
unsafe impl Sync for CleanupQueue {}

impl core::ops::Deref for CleanupQueue {
    type Target = OwnedQueue;
    fn deref(&self) -> &OwnedQueue {
        &self.0
    }
}

pub(crate) struct TyrPlatformDriverData {
    /// Devfreq registration, `None` on devices without an OPP table.
    devfreq_registration: Arc<Mutex<Option<DevfreqRegistration<TyrDevfreqCallbacks>>>>,

    /// Runtime PM registration. Owns the callback payload and disables
    /// runtime PM on unbind. Held only for its `Drop`.
    #[expect(dead_code)]
    pm: pm::Registration<TyrPmOps>,

    pub(crate) device: ARef<TyrDrmDevice>,
}

#[pin_data]
pub(crate) struct TyrDrmDeviceData {
    // A clone reachable through the MMU outlives this field, so dropping it
    // here does not bound the worker.
    pub(crate) reset: reset::ResetHandle,

    pub(crate) pdev: ARef<platform::Device>,

    pub(crate) mmu: Arc<Mmu>,

    /// MMU IRQ registration slot, set during probe and revoked by devres at unbind.
    #[pin]
    pub(crate) mmu_irq: IrqSlot<MmuIrq>,

    /// Job IRQ registration slot, set during probe and revoked by devres at unbind.
    #[pin]
    pub(crate) job_irq: IrqSlot<JobIrq>,

    /// GPU IRQ registration slot, set during probe and revoked by devres at unbind.
    #[pin]
    pub(crate) gpu_irq: IrqSlot<GpuIrq>,

    pub(crate) iomem: Arc<Devres<IoMem>>,

    pub(crate) mmio_phys_addr: u64,

    /// Whether the device is reported as DMA-coherent by firmware.
    ///
    /// Cached at probe via `device_get_dma_attr()`. Drives the BO
    /// cacheability policy in `crate::gem::should_map_wc`.
    pub(crate) coherent: bool,

    pub(crate) fw: Arc<Firmware>,

    pub(crate) wq: Arc<DmaFenceWorkqueue>,

    /// Dedicated DMA-fence-constrained workqueue for the scheduler
    /// bottom half. Created `WQ_HIGHPRI` (`MEM_RECLAIM` is added by
    /// `DmaFenceWorkqueue::new_highpri`) so the scheduler can keep up
    /// with firmware acks under memory pressure.
    pub(crate) sched_wq: Arc<DmaFenceWorkqueue>,

    /// Per-device cleanup workqueue.
    ///
    /// Carries deferred drops from objects whose `Drop` would
    /// otherwise run inside a dma-fence signalling section. The queue
    /// is deliberately **not** a `DmaFenceWorkqueue`: its purpose
    /// is to provide an execution context that does not hold the
    /// `dma_fence_map` lockdep token, so the cleanup work is free to
    /// take `dma_resv_lock`, the per-VM gpuvm mutex, and allocate
    /// with `GFP_KERNEL`.
    ///
    /// Declared before `clks` so the drop-time drain still runs with the
    /// clocks up. Probe failure takes the same drop order. After unbind the
    /// drained unmaps reach no hardware, since devres has revoked the
    /// mapping.
    pub(crate) cleanup_wq: Arc<CleanupQueue>,

    /// Dedicated unbound workqueue for the per-group tiler OOM workers.
    /// Heap growth allocates with `GFP_KERNEL` and can block in reclaim,
    /// so these workers get their own queue rather than sharing the
    /// system workqueues. Declared before `clks` for the same drop-order
    /// reason as `cleanup_wq`.
    pub(crate) heap_alloc_wq: OwnedQueue,

    #[pin]
    pub(crate) clks: Mutex<Clocks>,

    #[pin]
    regulators: Mutex<Regulators>,

    /// Some information on the GPU.
    ///
    /// This is mainly queried by userspace, i.e.: Mesa.
    pub(crate) gpu_info: GpuInfo,

    #[pin]
    pub(crate) csif_info: Mutex<gpu::CsifInfo>,

    /// The scheduler logic.
    #[pin]
    sched: Mutex<SchedulerState>,

    /// Set while the scheduler-level runtime suspend is in effect, from the
    /// start of the tick suspend until resume. Written under the scheduler
    /// mutex, so tick paths re-check it there. Also read without the lock
    /// in the tick re-arm gate, where a stale value only costs a redundant
    /// tick.
    pub(crate) sched_suspended: Atomic<bool>,

    /// Slot manager for the firmware-visible CSG slots.
    ///
    /// Pinned at probe time with `MAX_CSGS` as an upper bound so the
    /// per-group `Seat` field
    /// (`LockedBy<Seat, CsgSlotManager>`) has a stable owner address
    /// from the moment the device data is initialised. The actual
    /// hardware slot count, which is only known after firmware boot,
    /// is applied by `Scheduler::init` via
    /// `SlotManager::set_slot_count`.
    ///
    /// The lock ordering is `sched > csg_slot_manager`: callers that
    /// hold `sched` may acquire this mutex, but not the
    /// other way round.
    #[pin]
    pub(crate) csg_slot_manager: Mutex<CsgSlotManager>,

    /// Outstanding firmware-events bits accumulated by IRQ handlers.
    ///
    /// Producers OR new status bits in via `fw_events_or` from any
    /// context; the consumer reads-and-clears with `fw_events_take`.
    /// This keeps scheduler-mutex work off the threaded IRQ handler.
    fw_events: AtomicU32,

    /// Worker that drains `fw_events` under the
    /// scheduler mutex. Enqueued on `sched_wq`.
    ///
    /// Typed as `DmaFenceWork` so it can ride on `sched_wq` (a
    /// `DmaFenceWorkqueue`), not because the body signals dma-fences:
    /// it only ACKs CSG events. Sharing the queue with the tick worker
    /// keeps it on `WQ_HIGHPRI` without a second workqueue.
    #[pin]
    fw_events_work: DmaFenceWork<TyrDrmDevice, { work_id::FW_EVENTS }>,

    /// Scheduler tick worker. Enqueued on `sched_wq`.
    #[pin]
    tick_work: DmaFenceWork<TyrDrmDevice, { work_id::TICK }>,

    /// Group sync-update worker on `system_unbound()`: unblocks queues
    /// whose syncwait is satisfied.
    ///
    /// Plain Work, not DmaFenceWork: re-evaluating a foreign-BO syncwait
    /// takes dma_resv_lock and allocates, both forbidden on the signalling path.
    #[pin]
    sync_upd_work: Work<TyrDrmDevice, { work_id::SYNC_UPD }>,

    /// Dedup gate paired with `sync_upd_work`. The IRQ side flips it
    /// false -> true under cmpxchg before enqueuing the worker, and
    /// the worker flips it back to false at the start of its run.
    /// Coalesces a burst of CSG SYNC_UPDATE acks into a single
    /// re-evaluation pass while leaving any IRQ that races the
    /// snapshot free to schedule the next one.
    sync_upd_pending: AtomicBool,

    /// Periodic re-arm worker for `tick_work`.
    ///
    /// Enqueued on `system_unbound()` rather than `sched_wq`
    /// so a long-delay timer expiry does not hold a scheduler worker.
    #[pin]
    periodic_tick_work: DelayedWork<TyrDrmDevice, { work_id::PERIODIC_TICK }>,

    /// Firmware liveness ping watchdog on `system_unbound()`.
    #[pin]
    fw_ping_work: DelayedWork<TyrDrmDevice, { work_id::FW_PING }>,

    /// State the devfreq callbacks reach through their `data` argument,
    /// shared with the devfreq registration via the `Arc`.
    pub(crate) devfreq_data: Arc<TyrDevfreqData>,

    /// Runtime PM context, `None` until the end of probe.
    pub(crate) pm: SetOnce<PMContext<TyrPmOps>>,

    /// Set once runtime suspend can no longer fail and cleared when resume
    /// brings the hardware back, a different window from the mmap `powered`
    /// state. Written by the runtime PM callbacks and by unbind, and read
    /// without a lock from dma-fence signalling paths. The clearing store
    /// releases so a reader that sees the device powered also sees the
    /// hardware bring-up, and the load acquires to match. `sched_suspended`
    /// cannot be used instead, since the reset worker clears it.
    pub(crate) pm_powered_down: Atomic<bool>,

    /// Set when unbind takes over the device power state, and never
    /// cleared. Runtime resume refuses while it is set. `pm_powered_down`
    /// cannot serve instead, since resume clears it.
    pub(crate) unbinding: Atomic<bool>,

    #[pin]
    pub(crate) user_mmio: Mutex<mmap::UserMmio>,

    #[pin]
    pub(crate) opp_config: Mutex<Option<ConfigToken>>,
}

impl TyrDrmDeviceData {
    pub(crate) fn with_locked_core_clk<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Clk) -> R,
    {
        let clks = self.clks.lock();
        f(&clks.core)
    }

    pub(crate) fn with_locked_scheduler<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Scheduler) -> Result<R>,
    {
        let mut sched = self.sched.lock();
        f(sched.enabled_mut()?)
    }

    /// Accumulates `bits` into the firmware-events word.
    ///
    /// Safe to call from any context, including threaded IRQ handlers.
    /// `Release` pairs with the `Acquire` in `fw_events_take` so the
    /// drain side observes any state the producer wrote before raising
    /// the bit.
    pub(crate) fn fw_events_or(&self, bits: u32) {
        self.fw_events.fetch_or(bits, Ordering::Release);
    }

    /// Atomically reads and clears the firmware-events word, returning
    /// the bits that were set.
    pub(crate) fn fw_events_take(&self) -> u32 {
        self.fw_events.swap(0, Ordering::Acquire)
    }

    /// Returns whether any firmware-events bits are pending, a hint for
    /// rescheduling the drain worker. The drain itself synchronizes through
    /// `fw_events_take`.
    pub(crate) fn fw_events_pending(&self) -> bool {
        self.fw_events.load(Ordering::Relaxed) != 0
    }

    /// Schedules the fw-events worker on the scheduler workqueue.
    ///
    /// Safe to call from any context including the threaded IRQ
    /// handler. Repeated calls coalesce in the workqueue.
    pub(crate) fn schedule_fw_events(tdev: &ARef<TyrDrmDevice>) {
        let _ = tdev
            .sched_wq
            .enqueue::<ARef<TyrDrmDevice>, { work_id::FW_EVENTS }>(tdev.clone());
    }

    /// Schedules the sync-update worker. Safe from any context.
    ///
    /// `sync_upd_pending` short-circuits a SYNC_UPDATE storm before it
    /// reaches `queue_work`'s per-pool spinlock, coalescing the burst into
    /// one re-evaluation pass.
    pub(crate) fn schedule_sync_upd(tdev: &ARef<TyrDrmDevice>) {
        if tdev
            .sync_upd_pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let _ = workqueue::system_unbound()
            .enqueue::<ARef<TyrDrmDevice>, { work_id::SYNC_UPD }>(tdev.clone());
    }

    /// Schedules an immediate scheduler tick on
    /// `sched_wq`.
    ///
    /// Safe to call from any context including the threaded IRQ
    /// handler. Repeated calls coalesce in the workqueue: a second
    /// `schedule_tick` while a tick is already pending is a no-op.
    pub(crate) fn schedule_tick(tdev: &ARef<TyrDrmDevice>) {
        let _ = tdev
            .sched_wq
            .enqueue::<ARef<TyrDrmDevice>, { work_id::TICK }>(tdev.clone());
    }

    /// Waits for any in-flight scheduler tick to finish.
    ///
    /// Must not be called while holding the scheduler mutex: the tick
    /// worker takes it, so flushing under the lock would deadlock.
    pub(crate) fn flush_tick(&self) {
        let _ = workqueue::flush_work::<TyrDrmDevice, TyrDrmDeviceData, { work_id::TICK }>(self);
    }

    /// Waits for the tick and firmware-events workers to finish.
    ///
    /// Both block bounded. Not callable under the scheduler or CSG
    /// slot-manager mutexes, nor in a dma-fence signalling section. The
    /// per-group tiler OOM workers are not flushed. They re-check slot
    /// ownership and read the acknowledgment from the live interface
    /// under the scheduler mutex before writing to the firmware. A
    /// failed heap growth can still queue a fresh tick after this
    /// returns, so callers gate the tick first.
    pub(crate) fn drain_sched_work(&self) {
        let _ = workqueue::flush_work::<TyrDrmDevice, TyrDrmDeviceData, { work_id::TICK }>(self);
        let _ =
            workqueue::flush_work::<TyrDrmDevice, TyrDrmDeviceData, { work_id::FW_EVENTS }>(self);
    }

    /// Re-arms the scheduler tick `delay` jiffies from now.
    ///
    /// If a periodic tick is already pending, `delay` is ignored:
    /// `queue_delayed_work_on` will not shorten an in-flight delay.
    /// To force an earlier tick, call `schedule_tick`
    /// directly.
    pub(crate) fn schedule_periodic_tick(tdev: &ARef<TyrDrmDevice>, delay: Jiffies) {
        let _ = workqueue::system_unbound()
            .enqueue_delayed::<ARef<TyrDrmDevice>, { work_id::PERIODIC_TICK }>(tdev.clone(), delay);
    }

    /// Arms the firmware ping watchdog `PING_INTERVAL_MS` from now.
    ///
    /// Called at global-interface enable and re-arm, so the watchdog only
    /// runs while the firmware interface is live.
    pub(crate) fn arm_fw_ping(tdev: &ARef<TyrDrmDevice>) {
        let _ = workqueue::system_unbound()
            .enqueue_delayed::<ARef<TyrDrmDevice>, { work_id::FW_PING }>(
                tdev.clone(),
                msecs_to_jiffies(PING_INTERVAL_MS),
            );
    }

    /// Cancels the firmware ping watchdog and waits for an in-flight ping.
    ///
    /// Called before the firmware is halted for a suspend or reset so no
    /// ping reaches a stopped MCU. Must run in process context.
    pub(crate) fn cancel_fw_ping(&self) {
        let _ = self.fw_ping_work.cancel_sync();
    }
}

impl_has_dma_fence_work! {
    impl HasDmaFenceWork<TyrDrmDevice, { work_id::FW_EVENTS }> for TyrDrmDeviceData { self.fw_events_work }
}

impl_has_dma_fence_work! {
    impl HasDmaFenceWork<TyrDrmDevice, { work_id::TICK }> for TyrDrmDeviceData { self.tick_work }
}

kernel::impl_has_work! {
    impl HasWork<TyrDrmDevice, { work_id::SYNC_UPD }> for TyrDrmDeviceData { self.sync_upd_work }
}

impl_has_delayed_work! {
    impl HasDelayedWork<TyrDrmDevice, { work_id::PERIODIC_TICK }> for TyrDrmDeviceData { self.periodic_tick_work }
}

impl_has_delayed_work! {
    impl HasDelayedWork<TyrDrmDevice, { work_id::FW_PING }> for TyrDrmDeviceData { self.fw_ping_work }
}

impl DmaFenceWorkItem<{ work_id::FW_EVENTS }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    fn run(this: Self::Pointer) {
        let tdev = &*this;

        // Processing events ACKs them through CSG doorbells. If the
        // device is runtime suspended, leave the events latched in
        // `fw_events`. The resume path reschedules this worker.
        let Some(_active) = tdev.pm_get_if_active() else {
            return;
        };

        // Skip while a reset owns the firmware interface. The reset worker
        // reissues this work when the reset completes.
        if tdev.reset.in_progress() {
            return;
        }

        let events = tdev.fw_events_take();
        if events == 0 {
            return;
        }

        let _ = tdev
            .with_locked_scheduler(|sched| sched.process_csg_irqs(events, tdev))
            .inspect_err(|err| {
                pr_err!(
                    "fw_events_work: failed to process firmware CSG IRQs: {:?}\n",
                    err
                );
            });

        // A CSG IRQ that the firmware raised for any of the slots we
        // own is by definition an observable state change from the
        // scheduler's point of view: a CSG_REQ ack might have flipped,
        // or a CS in the slot might have hit a fault or run out of
        // tiler heap. Arm the periodic tick so it re-evaluates
        // residency and applies any pending state transitions.
        crate::sched::Scheduler::request_tick(&this);
    }
}

impl DmaFenceWorkItem<{ work_id::TICK }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    fn run(this: Self::Pointer) {
        if let Err(err) = crate::sched::tick::tick_step(&this) {
            pr_err!("tick_step failed: {:?}\n", err);
        }
    }
}

impl WorkItem<{ work_id::SYNC_UPD }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    /// After draining completions, re-evaluate the wait list in three
    /// phases: snapshot under the scheduler mutex, evaluate without it (so
    /// gpuvm_unique and dma_resv_lock stay outside the mutex), then apply,
    /// re-validating against the live wait list before promoting groups.
    fn run(this: Self::Pointer) {
        let tdev = &*this;

        // Reset the dedup gate before reading any state so a
        // SYNC_UPDATE that fires after the snapshot re-arms the worker
        // for the next pass; clearing at the end would silently drop
        // IRQs racing the snapshot.
        tdev.sync_upd_pending.store(false, Ordering::Release);

        Scheduler::drain_resident_queue_completions(tdev);

        let snapshot = tdev
            .with_locked_scheduler(|sched| Ok(sched.collect_syncwait_candidates()))
            .unwrap_or_default();

        let results = Scheduler::evaluate_syncwait_candidates(snapshot);

        let immediate_tick = tdev
            .with_locked_scheduler(|sched| Ok(sched.apply_syncwait_results(&results)))
            .unwrap_or(false);
        drop(results);

        if immediate_tick {
            Self::schedule_tick(&this);
        }
    }
}

impl WorkItem<{ work_id::PERIODIC_TICK }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    fn run(this: Self::Pointer) {
        Self::schedule_tick(&this);
    }
}

impl WorkItem<{ work_id::FW_PING }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    fn run(this: Self::Pointer) {
        let tdev = &*this;

        // A reset is in progress and owns the firmware interface, so skip
        // the ping and the re-arm. The reset path re-arms the watchdog
        // when it re-enables the global interface.
        if tdev.reset.in_progress() {
            return;
        }

        // The device is runtime suspended (or a transition is in flight),
        // so the clocks are gated and the firmware MMIO is unreachable.
        // The resume path, or an aborted suspend, re-arms the watchdog.
        if !tdev.pm_active() {
            return;
        }

        if tdev.fw.ping(PING_TIMEOUT_MS).is_err() {
            dev_err!(tdev.pdev.as_ref(), "FW ping timeout, scheduling a reset\n");
            tdev.reset.schedule();
            return;
        }

        Self::arm_fw_ping(&this);
    }
}

kernel::of_device_table!(
    OF_TABLE,
    MODULE_OF_TABLE,
    <TyrPlatformDriverData as platform::Driver>::IdInfo,
    [
        (of::DeviceId::new(c"rockchip,rk3588-mali"), ()),
        (of::DeviceId::new(c"arm,mali-valhall-csf"), ())
    ]
);

impl platform::Driver for TyrPlatformDriverData {
    type IdInfo = ();
    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);
    const PM_OPS: Option<&'static bindings::dev_pm_ops> = Some(&PMContext::<TyrPmOps>::PM_OPS);

    fn probe(
        pdev: &platform::Device<Core>,
        _info: Option<&Self::IdInfo>,
    ) -> impl PinInit<Self, Error> {
        let core_clk = Clk::get(pdev.as_ref(), Some(c"core"))?;
        let stacks_clk = OptionalClk::get(pdev.as_ref(), Some(c"stacks"))?;
        let coregroup_clk = OptionalClk::get(pdev.as_ref(), Some(c"coregroup"))?;

        core_clk.prepare_enable()?;
        stacks_clk.prepare_enable()?;
        coregroup_clk.prepare_enable()?;

        let mali_regulator = Regulator::<regulator::Enabled>::get(pdev.as_ref(), c"mali")?;

        let request = pdev.io_request_by_index(0).ok_or(ENODEV)?;
        let mmio_phys_addr = request.start();
        let iomem = Arc::pin_init(request.iomap_sized::<SZ_2M>(), GFP_KERNEL)?;

        gpu::reset(pdev.as_ref(), &iomem)?;

        let gpu_info = GpuInfo::new(pdev.as_ref(), &iomem)?;
        gpu_info.log(pdev.as_ref());

        let pa_bits = MMU_FEATURES::from_raw(gpu_info.mmu_features)
            .pa_bits()
            .get();
        // SAFETY: No concurrent DMA allocations or mappings can be made because
        // the device is still being probed and therefore isn't being used by
        // other threads of execution.
        unsafe {
            pdev.dma_set_max_seg_size(u32::MAX);
            pdev.dma_set_mask_and_coherent(DmaMask::try_new(pa_bits)?)?;
        }

        let coherent = pdev.as_ref().dma_coherent();

        let uninit_ddev = UnregisteredDevice::<TyrDrmDriver>::new(pdev.as_ref())?;

        let platform: ARef<platform::Device> = pdev.into();
        let reset = reset::ResetHandle::new(platform.clone(), iomem.clone())?;

        let mmu = Mmu::new(pdev, iomem.as_arc_borrow(), &gpu_info, reset.clone())?;

        let cleanup_wq = Arc::new(
            CleanupQueue(Queue::new_unbound().build(c"tyr-cleanup")?),
            GFP_KERNEL,
        )?;

        let firmware = Firmware::new(
            pdev,
            iomem.clone(),
            &uninit_ddev,
            mmu.as_arc_borrow(),
            &gpu_info,
            coherent,
            cleanup_wq.clone(),
        )?;

        let wq = Arc::new(
            DmaFenceWorkqueue::new_unbound(c"tyr-dma-fence")?,
            GFP_KERNEL,
        )?;

        let sched_wq = Arc::new(DmaFenceWorkqueue::new_highpri(c"tyr-sched")?, GFP_KERNEL)?;

        let heap_alloc_wq = Queue::new_unbound().build(c"tyr-heap-alloc")?;

        let csg_slot_ops = CsgSlotOps::new(firmware.clone());
        let csg_slot_manager = SlotManager::<CsgSlotOps, MAX_CSGS>::new(csg_slot_ops, MAX_CSGS)?;

        let devfreq_data = Arc::pin_init(TyrDevfreqData::new(), GFP_KERNEL)?;

        let data = try_pin_init!(TyrDrmDeviceData {
                pdev: platform.clone(),
                mmu,
                mmu_irq <- IrqSlot::new(),
                job_irq <- IrqSlot::new(),
                gpu_irq <- IrqSlot::new(),
                iomem: iomem.clone(),
                mmio_phys_addr,
                coherent,
                fw: firmware,
                wq,
                sched_wq,
                cleanup_wq,
                heap_alloc_wq,
                clks <- new_mutex!(Clocks {
                    core: core_clk,
                    stacks: stacks_clk,
                    coregroup: coregroup_clk,
                    gated: false,
                }),
                regulators <- new_mutex!(Regulators {
                    _mali: mali_regulator,
                }),
                reset,
                gpu_info,
                csif_info <- new_mutex!(gpu::CsifInfo::default()),
                sched <- new_mutex!(SchedulerState::Disabled),
                sched_suspended: Atomic::new(false),
                csg_slot_manager <- new_mutex!(csg_slot_manager),
                fw_events: AtomicU32::new(0),
                fw_events_work <- new_dma_fence_work!("TyrDrmDeviceData::fw_events_work"),
                tick_work <- new_dma_fence_work!("TyrDrmDeviceData::tick_work"),
                sync_upd_work <- kernel::new_work!("TyrDrmDeviceData::sync_upd_work"),
                sync_upd_pending: AtomicBool::new(false),
                periodic_tick_work <- kernel::new_delayed_work!("TyrDrmDeviceData::periodic_tick_work"),
                fw_ping_work <- kernel::new_delayed_work!("TyrDrmDeviceData::fw_ping_work"),
                devfreq_data,
                pm: SetOnce::new(),
                pm_powered_down: Atomic::new(false),
                unbinding: Atomic::new(false),
                user_mmio <- new_mutex!(mmap::UserMmio::new()?),
                opp_config <- new_mutex!(None),
        });

        if cfg!(CONFIG_TRANSPARENT_HUGEPAGE) {
            match uninit_ddev.create_huge_mnt(c"within_size") {
                Ok(()) => dev_info!(pdev, "Using transparent huge pages.\n"),
                Err(e) => dev_warn!(pdev, "Can't use transparent huge pages: {:?}\n", e),
            }
        }

        let ddev = Registration::new_foreign_owned(uninit_ddev, pdev.as_ref(), data, 0)?;
        let tdev: ARef<TyrDrmDevice> = ddev.into();

        tdev.reset
            .set_device(Devres::new(pdev.as_ref(), tdev.clone())?);

        let gpu_irq = Arc::pin_init(
            gpu::irq::gpu_irq_init(tdev.clone(), pdev, tdev.iomem.clone())?,
            GFP_KERNEL,
        )?;
        tdev.gpu_irq.publish(Devres::new(pdev.as_ref(), gpu_irq)?);
        tdev.gpu_irq
            .reset_resume(&tdev.iomem, gpu::irq::gpu_irq_enable);

        let mmu_irq = Arc::pin_init(
            mmu_irq_init(tdev.clone(), pdev, tdev.iomem.clone())?,
            GFP_KERNEL,
        )?;
        tdev.mmu_irq.publish(Devres::new(pdev.as_ref(), mmu_irq)?);
        tdev.mmu_irq.reset_resume(&tdev.iomem, mmu_irq_enable);

        let job_irq = Arc::pin_init(
            job_irq_init(tdev.clone(), pdev, tdev.iomem.clone(), tdev.fw.irq_state())?,
            GFP_KERNEL,
        )?;
        tdev.job_irq.publish(Devres::new(pdev.as_ref(), job_irq)?);
        tdev.job_irq.reset_resume(&tdev.iomem, job_irq_enable);

        let devfreq_registration = devfreq::init(&tdev, pdev.as_ref())?;
        let devfreq_registration = Arc::pin_init(new_mutex!(devfreq_registration), GFP_KERNEL)?;

        tdev.fw.boot()?;
        tdev.fw
            .wait_ready(1000)
            .inspect_err(|_| pr_err!("Timed out waiting for firmware to be ready.\n"))?;
        tdev.fw.enable_global_interface(&tdev)?;

        // enable_global_interface armed the firmware watchdog. Cancel it if
        // probe fails past this point so no ping outlives a failed bring-up.
        let ping_guard = ScopeGuard::new(|| tdev.cancel_fw_ping());

        let scheduler = Scheduler::init(&tdev)?;
        tdev.sched.lock().enable(scheduler);

        let mut pm_configs = KVec::<PMConfig>::with_capacity(1, GFP_KERNEL)?;
        pm_configs.push(PMConfig::AutoSuspendDelay(AUTOSUSPEND_DELAY_MS), GFP_KERNEL)?;

        let pm_registration = pm::Registration::<TyrPmOps>::new(
            pdev.as_ref(),
            None,
            Some(pm_configs),
            Some(devfreq_registration.clone()),
        )?;
        let pm = pm_registration.ctx().clone();

        // The device is already powered, so runtime PM starts resumed.
        pm.enable(RuntimePMState::RESUMED)?;

        drop(pm.get(PMProfile::new().auto())?);

        let populated = tdev.pm.populate(pm);
        debug_assert!(populated);

        tdev.reset.set_ready();

        TyrDrmDeviceData::schedule_tick(&tdev);

        // We need this to be dev_info!() because dev_dbg!() does not work at
        // all in Rust for now, and we need to see whether probe succeeded.
        dev_info!(pdev, "Tyr initialized correctly.\n");
        ping_guard.dismiss();
        Ok(TyrPlatformDriverData {
            devfreq_registration,
            pm: pm_registration,
            device: tdev,
        })
    }

    fn unbind(pdev: &platform::Device<Core>, this: Pin<&Self>) {
        // Runtime PM outlives unbind, so refuse resumes before any teardown
        // starts.
        this.device.set_unbinding();
        this.device.reset.unbind();
        drop(this.devfreq_registration.lock().take());
        Self::suspend_at_unbind(pdev, this);
        // The workers that enqueue tiler OOM works are drained and their
        // gates reject later runs, so the queue stays empty from here.
        this.device.heap_alloc_wq.flush();
        // Cancel the watchdog last. Both the reset worker and a resume that
        // was already in flight when `unbinding` was set re-arm it.
        this.device.cancel_fw_ping();
    }
}

// We need to retain the name "panthor" to achieve drop-in compatibility with
// the C driver in the userspace stack.
//
// Version history:
// - 1.0 - initial interface
// - 1.1 - adds DEV_QUERY_TIMESTAMP_INFO query
// - 1.2 - adds DEV_QUERY_GROUP_PRIORITIES_INFO query
//       - adds PANTHOR_GROUP_PRIORITY_REALTIME priority
// - 1.3 - adds DRM_PANTHOR_GROUP_STATE_INNOCENT flag
// - 1.4 - adds DRM_IOCTL_PANTHOR_BO_SET_LABEL ioctl
// - 1.5 - adds DRM_PANTHOR_SET_USER_MMIO_OFFSET ioctl
const INFO: drm::DriverInfo = drm::DriverInfo {
    major: 1,
    minor: 5,
    patchlevel: 0,
    name: c"panthor",
    desc: c"ARM Mali Tyr DRM driver",
};

#[vtable]
impl drm::Driver for TyrDrmDriver {
    type Data = TyrDrmDeviceData;
    type File = TyrDrmFileData;
    type Object<R: drm::DeviceContext> = drm::gem::shmem::Object<BoData>;

    const INFO: drm::DriverInfo = INFO;

    kernel::declare_drm_ioctls! {
        (PANTHOR_DEV_QUERY, drm_panthor_dev_query, ioctl::RENDER_ALLOW, TyrDrmFileData::dev_query),
        (PANTHOR_VM_CREATE, drm_panthor_vm_create, ioctl::RENDER_ALLOW, TyrDrmFileData::vm_create),
        (PANTHOR_VM_DESTROY, drm_panthor_vm_destroy, ioctl::RENDER_ALLOW, TyrDrmFileData::vm_destroy),
        (PANTHOR_VM_BIND, drm_panthor_vm_bind, ioctl::RENDER_ALLOW, TyrDrmFileData::vm_bind),
        (PANTHOR_VM_GET_STATE, drm_panthor_vm_get_state, ioctl::RENDER_ALLOW, TyrDrmFileData::vm_get_state),
        (PANTHOR_BO_CREATE, drm_panthor_bo_create, ioctl::RENDER_ALLOW, TyrDrmFileData::bo_create),
        (PANTHOR_BO_MMAP_OFFSET, drm_panthor_bo_mmap_offset, ioctl::RENDER_ALLOW, TyrDrmFileData::bo_mmap_offset),
        (PANTHOR_GROUP_CREATE, drm_panthor_group_create, ioctl::RENDER_ALLOW, TyrDrmFileData::group_create),
        (PANTHOR_GROUP_DESTROY, drm_panthor_group_destroy, ioctl::RENDER_ALLOW, TyrDrmFileData::group_destroy),
        (PANTHOR_GROUP_SUBMIT, drm_panthor_group_submit, ioctl::RENDER_ALLOW, TyrDrmFileData::group_submit),
        (PANTHOR_GROUP_GET_STATE, drm_panthor_group_get_state, ioctl::RENDER_ALLOW, TyrDrmFileData::group_get_state),
        (PANTHOR_TILER_HEAP_CREATE, drm_panthor_tiler_heap_create, ioctl::RENDER_ALLOW, TyrDrmFileData::heap_create),
        (PANTHOR_TILER_HEAP_DESTROY, drm_panthor_tiler_heap_destroy, ioctl::RENDER_ALLOW, TyrDrmFileData::heap_destroy),
        (PANTHOR_BO_SET_LABEL, drm_panthor_bo_set_label, ioctl::RENDER_ALLOW, TyrDrmFileData::bo_set_label),
        (PANTHOR_SET_USER_MMIO_OFFSET, drm_panthor_set_user_mmio_offset, ioctl::RENDER_ALLOW, TyrDrmFileData::set_user_mmio_offset),
        (PANTHOR_BO_SYNC, drm_panthor_bo_sync, ioctl::RENDER_ALLOW, TyrDrmFileData::bo_sync),
        (PANTHOR_BO_QUERY_INFO, drm_panthor_bo_query_info, ioctl::RENDER_ALLOW, TyrDrmFileData::bo_query_info),
    }

    fn mmap(
        device: &TyrDrmDevice,
        file: &drm::File<TyrDrmFileData>,
        vma: &kernel::mm::virt::VmaNew,
    ) -> Option<Result>
    where
        Self: Sized,
    {
        crate::mmap::mmap(device, &file.inner(), vma)
    }
}

pub(crate) struct Clocks {
    pub(crate) core: Clk,
    stacks: OptionalClk,
    coregroup: OptionalClk,
    /// Whether the clocks are currently gated by runtime suspend.
    gated: bool,
}

impl Clocks {
    /// Disables and unprepares the clocks for runtime suspend.
    pub(crate) fn gate(&mut self) {
        if self.gated {
            return;
        }
        self.coregroup.disable_unprepare();
        self.stacks.disable_unprepare();
        self.core.disable_unprepare();
        self.gated = true;
    }

    /// Re-enables the clocks on runtime resume.
    pub(crate) fn ungate(&mut self) -> Result {
        if !self.gated {
            return Ok(());
        }
        let clks: [&Clk; 3] = [&self.core, &self.stacks, &self.coregroup];
        for (i, clk) in clks.iter().enumerate() {
            if let Err(e) = clk.prepare_enable() {
                for prev in clks[..i].iter().rev() {
                    prev.disable_unprepare();
                }
                return Err(e);
            }
        }
        self.gated = false;
        Ok(())
    }
}

impl Drop for Clocks {
    fn drop(&mut self) {
        if !self.gated {
            self.coregroup.disable_unprepare();
            self.stacks.disable_unprepare();
            self.core.disable_unprepare();
        }
    }
}

struct Regulators {
    _mali: Regulator<regulator::Enabled>,
}
