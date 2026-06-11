// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    clk::{
        Clk,
        OptionalClk, //
    },
    devfreq::Registration as DevfreqRegistration,
    device::{
        self,
        Bound,
        Core,
        Device,
        DeviceContext, //
    },
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
    drm::ioctl,
    io::{
        mem::DevresIoMem,
        poll,
        Io, //
    },
    irq::ThreadedRegistration,
    mm::virt::VmaNew,
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
        atomic::{
            Acquire,
            Atomic,
            AtomicFlag,
            Full,
            Relaxed,
            Release, //
        },
        Arc,
        Mutex,
        SetOnce, //
    },
    time::{
        self,
        Jiffies, //
    },
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
    gem::Bo,
    gpu::{
        self,
        irq::{
            gpu_irq_enable,
            gpu_irq_init,
            GpuIrq, //
        },
        GpuInfo, //
    },
    irq::TyrIrq,
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
    sched::{
        tick,
        CsgSlotManager,
        CsgSlotOps,
        Scheduler,
        SchedulerState,
        MAX_CSGS, //
    },
    slot::SlotManager, //
};

pub(crate) type IoMem<'a> = kernel::io::mem::IoMem<'a, SZ_2M>;
pub(crate) type TyrRegisters = kernel::io::Region<SZ_2M>;

pub(crate) struct TyrDrmDriver;

/// Convenience type alias for the DRM device type for this driver.
pub(crate) type TyrDrmDevice<Ctx = drm::Normal> = drm::Device<TyrDrmDriver, Ctx>;

/// Returns the parent device of a Tyr DRM device.
pub(crate) fn parent_dev(tdev: &TyrDrmDevice) -> &device::Device {
    tdev.as_ref().as_ref()
}

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
}

/// Data owned by the DRM device.
///
/// Driver callbacks that cannot take a registration guard, such as the mmap hook, reach the
/// state they need through here.
#[pin_data]
pub(crate) struct TyrDrmDeviceData {
    /// Physical address of the GPU MMIO window.
    pub(crate) mmio_phys_addr: u64,

    /// Whether the device is reported as DMA-coherent by firmware.
    ///
    /// Cached at probe via `device_get_dma_attr()`. Drives the BO
    /// cacheability policy in `crate::gem::should_map_wc`.
    pub(crate) coherent: bool,

    /// Dedicated unbound workqueue for the per-group `term_work`, whose
    /// worker waits on in-flight hardware fences. Flushed at unbind.
    /// It sits on the device because a file release can terminate
    /// groups after unbind, with no registration data left to hold it.
    pub(crate) term_wq: DmaFenceWorkqueue,

    /// The scheduler logic.
    #[pin]
    sched: Mutex<SchedulerState>,

    /// Set while the scheduler-level runtime suspend is in effect, from the
    /// start of the tick suspend until resume. Written under the scheduler
    /// mutex, so tick paths re-check it there. Read locklessly by the
    /// hardware-access gate, which runs in dma-fence signalling sections and
    /// must not sleep.
    pub(crate) sched_suspended: Atomic<bool>,

    /// Slot manager for the firmware-visible CSG slots.
    ///
    /// Pinned at probe time with `MAX_CSGS` as an upper bound so the
    /// per-group `LockedBy<Seat, CsgSlotManager>` has a stable owner
    /// address from the moment the device data is initialized.
    /// `Scheduler::init` narrows it to the real slot count once the
    /// firmware has reported one.
    ///
    /// Lock ordering is `sched > csg_slot_manager`. Callers holding
    /// `sched` may take this mutex, never the other way round.
    #[pin]
    pub(crate) csg_slot_manager: Mutex<CsgSlotManager>,

    /// Outstanding firmware-events bits accumulated by IRQ handlers.
    ///
    /// Producers OR new status bits in via `fw_events_or` from any
    /// context. The consumer reads-and-clears with `fw_events_take`.
    /// This keeps scheduler-mutex work off the threaded IRQ handler.
    fw_events: Atomic<u32>,

    /// Worker that drains `fw_events` under the
    /// scheduler mutex. Enqueued on `sched_wq`.
    ///
    /// Typed as `DmaFenceWork` so it can ride on `sched_wq` (a
    /// `DmaFenceWorkqueue`), not because the body signals dma-fences.
    /// It only ACKs CSG events. Sharing the queue with the tick worker
    /// keeps it on `WQ_HIGHPRI` without a second workqueue.
    #[pin]
    fw_events_work: DmaFenceWork<TyrDrmDevice, { work_id::FW_EVENTS }>,

    /// Scheduler tick worker. Enqueued on `sched_wq`.
    #[pin]
    tick_work: DmaFenceWork<TyrDrmDevice, { work_id::TICK }>,

    /// Group sync-update worker on `system_dfl()`. Unblocks queues
    /// whose syncwait is satisfied.
    ///
    /// Plain Work, not DmaFenceWork. Re-evaluating a foreign-BO syncwait
    /// takes dma_resv_lock and allocates, both forbidden on the signalling path.
    #[pin]
    sync_upd_work: Work<TyrDrmDevice, { work_id::SYNC_UPD }>,

    /// Dedup gate paired with `sync_upd_work`. The IRQ side claims it
    /// with xchg and enqueues the worker only if it was false, and the
    /// worker flips it back to false at the start of its run.
    /// Coalesces a burst of CSG SYNC_UPDATE acks into a single
    /// re-evaluation pass while leaving any IRQ that races the
    /// snapshot free to schedule the next one.
    sync_upd_pending: AtomicFlag,

    /// Periodic re-arm worker for `tick_work`.
    ///
    /// Enqueued on `system_dfl()` rather than `sched_wq`
    /// so a long-delay timer expiry does not hold a scheduler worker.
    #[pin]
    periodic_tick_work: DelayedWork<TyrDrmDevice, { work_id::PERIODIC_TICK }>,

    /// State the devfreq callbacks reach through their `data` argument,
    /// shared with the devfreq registration via the `Arc`.
    pub(crate) devfreq_data: Arc<TyrDevfreqData>,

    /// Runtime PM context, `None` until the end of probe.
    pub(crate) pm: SetOnce<PMContext<platform::Adapter<TyrPlatformDriver>, TyrPmOps>>,

    #[pin]
    pub(crate) opp_config: Mutex<Option<ConfigToken>>,
}

impl TyrDrmDeviceData {
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
        let mut old = self.fw_events.load(Relaxed);

        while let Err(current) = self.fw_events.cmpxchg(old, old | bits, Release) {
            old = current;
        }
    }

    /// Atomically reads and clears the firmware-events word, returning
    /// the bits that were set.
    pub(crate) fn fw_events_take(&self) -> u32 {
        self.fw_events.xchg(0, Acquire)
    }

    /// Returns whether any firmware-events bits are pending, a hint for
    /// rescheduling the drain worker. The drain itself synchronizes through
    /// `fw_events_take`.
    #[expect(dead_code)]
    pub(crate) fn fw_events_pending(&self) -> bool {
        self.fw_events.load(Relaxed) != 0
    }

    /// Schedules the fw-events worker on the scheduler workqueue.
    ///
    /// Safe to call from any context including the threaded IRQ
    /// handler. Repeated calls coalesce in the workqueue.
    pub(crate) fn schedule_fw_events(tdev: &ARef<TyrDrmDevice>) {
        let Some(guard) = tdev.registration_guard() else {
            return;
        };

        guard.registration_data_with(|reg_data| {
            let _ = reg_data
                .sched_wq
                .enqueue::<ARef<TyrDrmDevice>, { work_id::FW_EVENTS }>(tdev.clone());
        });
    }

    /// Schedules an immediate scheduler tick on
    /// `sched_wq`.
    ///
    /// Safe to call from any context including the threaded IRQ
    /// handler. Repeated calls coalesce in the workqueue.
    pub(crate) fn schedule_tick(tdev: &ARef<TyrDrmDevice>) {
        let Some(guard) = tdev.registration_guard() else {
            return;
        };

        guard.registration_data_with(|reg_data| {
            let _ = reg_data
                .sched_wq
                .enqueue::<ARef<TyrDrmDevice>, { work_id::TICK }>(tdev.clone());
        });
    }

    /// Schedules the sync-update worker. Safe from any context.
    ///
    /// `sync_upd_pending` short-circuits a SYNC_UPDATE storm before it
    /// reaches `queue_work`'s per-pool spinlock, coalescing the burst into
    /// one re-evaluation pass.
    pub(crate) fn schedule_sync_upd(tdev: &ARef<TyrDrmDevice>) {
        if tdev.sync_upd_pending.xchg(true, Full) {
            return;
        }
        let _ = workqueue::system_dfl()
            .enqueue::<ARef<TyrDrmDevice>, { work_id::SYNC_UPD }>(tdev.clone());
    }

    /// Waits for any in-flight scheduler tick to finish.
    ///
    /// Must not be called while holding the scheduler mutex. The tick
    /// worker takes it, so flushing under the lock would deadlock.
    pub(crate) fn flush_tick(&self) {
        self.tick_work.inner.flush();
    }

    /// Re-arms the scheduler tick `delay` jiffies from now.
    ///
    /// If a periodic tick is already pending, `delay` is ignored.
    /// `queue_delayed_work_on` will not shorten an in-flight delay.
    /// To force an earlier tick, call `schedule_tick`
    /// directly.
    pub(crate) fn schedule_periodic_tick(tdev: &ARef<TyrDrmDevice>, delay: Jiffies) {
        let _ = workqueue::system_dfl()
            .enqueue_delayed::<ARef<TyrDrmDevice>, { work_id::PERIODIC_TICK }>(tdev.clone(), delay);
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

impl DmaFenceWorkItem<{ work_id::FW_EVENTS }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    fn run(this: Self::Pointer) {
        let tdev = &*this;

        let events = tdev.fw_events_take();
        if events == 0 {
            return;
        }

        let Some(guard) = tdev.registration_guard() else {
            return;
        };

        guard.registration_data_with(|reg_data| {
            let _ = tdev
                .with_locked_scheduler(|sched| sched.process_csg_irqs(tdev, &reg_data.fw, events))
                .inspect_err(|err| {
                    dev_err!(
                        reg_data.pdev,
                        "fw_events_work: failed to process firmware CSG IRQs: {:?}\n",
                        err
                    );
                });
        });

        // A CSG IRQ means firmware state changed on a slot we own. A
        // CSG_REQ ack may have flipped, or a CS may have faulted or run
        // out of tiler heap. Arm the periodic tick to re-evaluate
        // residency and apply any pending transitions.
        Scheduler::request_tick(&this);
    }
}

impl DmaFenceWorkItem<{ work_id::TICK }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    fn run(this: Self::Pointer) {
        let Some(guard) = this.registration_guard() else {
            return;
        };

        guard.registration_data_with(|reg_data| {
            if let Err(err) = tick::tick_step(&this, &reg_data.fw) {
                dev_err!(reg_data.pdev, "tick_step failed: {:?}\n", err);
            }
        });
    }
}

impl WorkItem<{ work_id::SYNC_UPD }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    /// After draining completions, re-evaluate the wait list in three
    /// phases: snapshot under the scheduler mutex, evaluate without it (so
    /// gpuvm_unique and dma_resv_lock stay outside the mutex), then apply,
    /// re-validating against the live wait list before promoting groups.
    fn run(this: Self::Pointer) {
        // Reset the dedup gate before reading any state so a
        // SYNC_UPDATE that fires after the snapshot re-arms the worker
        // for the next pass. Clearing at the end would silently drop
        // IRQs racing the snapshot.
        this.sync_upd_pending.store(false, Release);

        // The drain runs before the guard so an unplug racing this worker
        // cannot strand pending submit fences. It touches no
        // registration-owned state.
        Scheduler::drain_resident_queue_completions(&this);

        let Some(guard) = this.registration_guard() else {
            return;
        };

        guard.registration_data_with(|reg_data| {
            let snapshot = this
                .with_locked_scheduler(|sched| Ok(sched.collect_syncwait_candidates(&this)))
                .unwrap_or_default();

            let results = Scheduler::evaluate_syncwait_candidates(&this, &reg_data.fw, snapshot);

            let immediate_tick = this
                .with_locked_scheduler(|sched| Ok(sched.apply_syncwait_results(&results)))
                .unwrap_or(false);
            drop(results);

            if immediate_tick {
                Self::schedule_tick(&this);
            }
        });
    }
}

impl WorkItem<{ work_id::PERIODIC_TICK }> for TyrDrmDeviceData {
    type Pointer = ARef<TyrDrmDevice>;

    fn run(this: Self::Pointer) {
        Self::schedule_tick(&this);
    }
}

pub(crate) struct TyrPlatformDriver;

#[pin_data(PinnedDrop)]
pub(crate) struct TyrPlatformDriverData<'bound> {
    /// Devfreq registration, `None` on devices without an OPP table.
    devfreq_registration: Arc<Mutex<Option<DevfreqRegistration<TyrDevfreqCallbacks>>>>,

    /// Runtime PM registration. Owns the callback payload and disables
    /// runtime PM on unbind. Held only for its `Drop`.
    pm: pm::Registration<'bound, platform::Adapter<TyrPlatformDriver>, TyrPmOps>,

    reg: drm::Registration<'bound, TyrDrmDriver>,
}

/// Data owned by the DRM [`Registration`].
///
/// This data can have references tied to the parent platform device binding scope
/// and is accessible only while the DRM device is registered with userspace.
#[pin_data]
pub(crate) struct TyrDrmRegistrationData<'drm> {
    /// Parent platform device.
    pub(crate) pdev: &'drm platform::Device<Bound>,

    /// MMU manager backing every VM on this device.
    pub(crate) mmu: Arc<Mmu>,

    /// Firmware sections.
    pub(crate) fw: Firmware<'drm>,

    /// Job IRQ registration. Freed after `fw`, so the handler is still armed while the MCU
    /// stops.
    _job_irq: Pin<KBox<ThreadedRegistration<'drm, TyrIrq<'drm, JobIrq<'drm>>>>>,

    /// MMU IRQ registration. Freed after `mmu`, so faults raised during teardown are still
    /// reported.
    _mmu_irq: Pin<KBox<ThreadedRegistration<'drm, TyrIrq<'drm, MmuIrq>>>>,

    /// GPU IRQ registration. Freed after the job and MMU registrations, so the GPU fault
    /// handler outlives them.
    _gpu_irq: Pin<KBox<ThreadedRegistration<'drm, TyrIrq<'drm, GpuIrq>>>>,

    /// Workqueue for work items that may signal DMA fences.
    pub(crate) wq: Arc<DmaFenceWorkqueue>,

    /// Dedicated DMA-fence-constrained workqueue for the scheduler bottom half.
    /// `DmaFenceWorkqueue::new_highpri` builds it as a per-cpu, high-priority, mem-reclaim
    /// queue so the scheduler can keep up with firmware acks under memory pressure.
    pub(crate) sched_wq: Arc<DmaFenceWorkqueue>,

    /// Workqueue for deferred tiler heap growth.
    ///
    /// Freed after the IRQ registrations, so no handler can queue work into it by then.
    pub(crate) heap_wq: OwnedQueue,

    #[pin]
    clks: Mutex<Clocks>,

    #[pin]
    regulators: Mutex<Regulators>,

    /// Device-managed handle to the GPU MMIO register mapping.
    pub(crate) iomem: Arc<DevresIoMem<SZ_2M>>,

    /// GPU information read from hardware during probe.
    pub(crate) gpu_info: GpuInfo,

    /// Command stream interface information reported to userspace.
    pub(crate) csif_info: gpu::CsifInfo,
}

fn issue_soft_reset(dev: &Device, iomem: &IoMem<'_>) -> Result {
    iomem.write_reg(GPU_COMMAND::reset(ResetMode::SoftReset));

    poll::read_poll_timeout(
        || Ok(iomem.read(GPU_IRQ_RAWSTAT)),
        |status| status.reset_completed(),
        time::Delta::from_millis(1),
        time::Delta::from_millis(100),
    )
    .inspect_err(|_| dev_err!(dev, "GPU reset failed."))?;

    Ok(())
}

kernel::of_device_table!(
    OF_TABLE,
    <TyrPlatformDriver as platform::Driver>::IdInfo,
    [
        (of::DeviceId::new(c"rockchip,rk3588-mali"), ()),
        (of::DeviceId::new(c"arm,mali-valhall-csf"), ())
    ]
);

impl platform::Driver for TyrPlatformDriver {
    type IdInfo = ();
    type Data<'bound> = TyrPlatformDriverData<'bound>;
    type PmOps = TyrPmOps;
    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);

    fn dev_pm_ops() -> Option<pm::DevPMOps<platform::Adapter<Self>, Self::PmOps>> {
        Some(pm::DevPMOps::for_driver())
    }

    fn probe<'bound>(
        pdev: &'bound platform::Device<Core<'_>>,
        _info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound {
        let core_clk = Clk::get(pdev.as_ref(), Some(c"core"))?;
        let stacks_clk = OptionalClk::get(pdev.as_ref(), Some(c"stacks"))?;
        let coregroup_clk = OptionalClk::get(pdev.as_ref(), Some(c"coregroup"))?;

        core_clk.prepare_enable()?;
        stacks_clk.prepare_enable()?;
        coregroup_clk.prepare_enable()?;

        let mali_regulator = Regulator::<regulator::Enabled>::get(pdev.as_ref(), c"mali")?;

        let request = pdev.io_request_by_index(0).ok_or(ENODEV)?;
        let mmio_phys_addr = request.start();

        let iomem = Arc::new(request.iomap_sized::<SZ_2M>()?.into_devres()?, GFP_KERNEL)?;
        let io = iomem.access(pdev.as_ref())?;

        issue_soft_reset(pdev.as_ref(), io)?;
        gpu::l2_power_on(pdev.as_ref(), io)?;

        let gpu_info = GpuInfo::new(io);
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

        let term_wq = DmaFenceWorkqueue::new_unbound(c"tyr-group-term")?;

        let csg_slot_manager = SlotManager::<CsgSlotOps, MAX_CSGS>::new(CsgSlotOps, MAX_CSGS)?;

        let devfreq_data = Arc::pin_init(TyrDevfreqData::new(), GFP_KERNEL)?;

        let unreg_dev = drm::UnregisteredDevice::<TyrDrmDriver>::new(
            pdev,
            try_pin_init!(TyrDrmDeviceData {
                mmio_phys_addr,
                coherent,
                term_wq,
                sched <- new_mutex!(SchedulerState::Disabled),
                sched_suspended: Atomic::new(false),
                csg_slot_manager <- new_mutex!(csg_slot_manager),
                fw_events: Atomic::new(0),
                fw_events_work <- new_dma_fence_work!("TyrDrmDeviceData::fw_events_work"),
                tick_work <- new_dma_fence_work!("TyrDrmDeviceData::tick_work"),
                sync_upd_work <- kernel::new_work!("TyrDrmDeviceData::sync_upd_work"),
                sync_upd_pending: AtomicFlag::new(false),
                periodic_tick_work <- kernel::new_delayed_work!("TyrDrmDeviceData::periodic_tick_work"),
                devfreq_data,
                pm: SetOnce::new(),
                opp_config <- new_mutex!(None),
            }? Error),
        )?;

        let mmu = Mmu::new(pdev, iomem.clone(), &gpu_info)?;

        let firmware = Firmware::new(
            pdev,
            iomem.clone(),
            &unreg_dev,
            mmu.as_arc_borrow(),
            &gpu_info,
            coherent,
        )?;

        // SAFETY: The registration is owned by `gpu_irq` and then by
        // `TyrDrmRegistrationData`. Every exit from `probe()` drops one or the other, so it
        // is never forgotten.
        let gpu_irq = KBox::pin_init(
            unsafe { gpu_irq_init(pdev, ARef::from(&*unreg_dev), iomem.clone()) }?,
            GFP_KERNEL,
        )?;
        gpu_irq_enable(io);

        // SAFETY: The registration is owned by `mmu_irq` and then by
        // `TyrDrmRegistrationData`. Every exit from `probe()` drops one or the other, so it
        // is never forgotten.
        let mmu_irq = KBox::pin_init(
            unsafe { mmu_irq_init(pdev, ARef::from(&*unreg_dev), iomem.clone()) }?,
            GFP_KERNEL,
        )?;
        mmu_irq_enable(io);

        // SAFETY: The registration is owned by `job_irq` and then by
        // `TyrDrmRegistrationData`. Every exit from `probe()` drops one or the other, so it
        // is never forgotten.
        let job_irq = KBox::pin_init(
            unsafe {
                job_irq_init(
                    pdev,
                    ARef::from(&*unreg_dev),
                    iomem.clone(),
                    firmware.irq_state(),
                    firmware.global_iface(),
                )
            }?,
            GFP_KERNEL,
        )?;
        job_irq_enable(io);

        let devfreq_registration = devfreq::init(&unreg_dev, pdev.as_ref(), &core_clk)?;
        let devfreq_registration = Arc::pin_init(new_mutex!(devfreq_registration), GFP_KERNEL)?;

        firmware.boot(io)?;

        firmware
            .wait_ready(1000)
            .inspect_err(|_| dev_err!(pdev, "Timed out waiting for firmware to be ready."))?;

        firmware.enable_global_interface(core_clk.rate().as_hz() as u64, io)?;

        let (scheduler, csif_info) = Scheduler::init(&unreg_dev, &firmware)?;
        unreg_dev.sched.lock().enable(scheduler);

        let wq = Arc::new(
            DmaFenceWorkqueue::new_unbound(c"tyr-dma-fence")?,
            GFP_KERNEL,
        )?;

        let sched_wq = Arc::new(DmaFenceWorkqueue::new_highpri(c"tyr-sched")?, GFP_KERNEL)?;

        let heap_wq = Queue::new_unbound().build(c"tyr-heap")?;

        let reg_data = pin_init!(TyrDrmRegistrationData {
                pdev,
                mmu,
                fw: firmware,
                _job_irq: job_irq,
                _mmu_irq: mmu_irq,
                _gpu_irq: gpu_irq,
                wq,
                sched_wq,
                heap_wq,
                clks <- new_mutex!(Clocks {
                    core: core_clk,
                    stacks: stacks_clk,
                    coregroup: coregroup_clk,
                }),
                regulators <- new_mutex!(Regulators {
                    _mali: mali_regulator,
                }),
                iomem,
                gpu_info,
                csif_info,
        });

        if cfg!(CONFIG_TRANSPARENT_HUGEPAGE) {
            match unreg_dev.create_huge_mnt(c"within_size") {
                Ok(()) => dev_info!(pdev, "Using transparent huge pages.\n"),
                Err(e) => dev_warn!(pdev, "Can't use transparent huge pages: {:?}\n", e),
            }
        }

        let mut pm_configs = KVec::<PMConfig>::with_capacity(1, GFP_KERNEL)?;
        pm_configs.push(PMConfig::AutoSuspendDelay(AUTOSUSPEND_DELAY_MS), GFP_KERNEL)?;

        let pm_registration = pm::Registration::<platform::Adapter<Self>, TyrPmOps>::new(
            pdev.as_ref(),
            pm::DevPMOps::for_driver(),
            None,
            Some(pm_configs),
            Some(devfreq_registration.clone()),
        )?;
        let pm = pm_registration.ctx().clone();

        // The device is already powered, so runtime PM starts resumed.
        pm.enable(RuntimePMState::Resumed)?;

        drop(pm.get(PMProfile::new().auto())?);

        let populated = unreg_dev.pm.populate(pm);
        debug_assert!(populated);

        // SAFETY: `reg` is stored in `TyrPlatformDriverData` and dropped when the driver is
        // unbound; it is never forgotten.
        let reg = unsafe { drm::Registration::new(pdev.as_ref(), unreg_dev, reg_data, 0)? };

        let driver = TyrPlatformDriverData {
            devfreq_registration,
            pm: pm_registration,
            reg,
        };

        dev_dbg!(pdev, "Tyr initialized correctly.");
        Ok(driver)
    }
}

#[pinned_drop]
impl PinnedDrop for TyrPlatformDriverData<'_> {
    fn drop(self: Pin<&mut Self>) {
        drop(self.devfreq_registration.lock().take());
        // Let the queued terminations hand their groups to the cleanup
        // workqueue before the module can exit.
        self.reg.device().term_wq.flush();
    }
}

// We need to retain the name "panthor" to achieve drop-in compatibility with
// the C driver in the userspace stack.
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
    type RegistrationData<'drm> = TyrDrmRegistrationData<'drm>;
    type File = TyrDrmFileData;
    type Object = Bo;
    type ParentDevice<Ctx: DeviceContext> = platform::Device<Ctx>;

    const INFO: drm::DriverInfo = INFO;
    const FEAT_RENDER: bool = true;

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

    fn mmap(device: &TyrDrmDevice, file: &drm::File<TyrDrmFileData>, vma: &VmaNew) -> Option<Result>
    where
        Self: Sized,
    {
        mmap::mmap(device, &file.inner(), vma)
    }
}

struct Clocks {
    core: Clk,
    stacks: OptionalClk,
    coregroup: OptionalClk,
}

impl Drop for Clocks {
    fn drop(&mut self) {
        self.core.disable_unprepare();
        self.stacks.disable_unprepare();
        self.coregroup.disable_unprepare();
    }
}

struct Regulators {
    _mali: Regulator<regulator::Enabled>,
}
