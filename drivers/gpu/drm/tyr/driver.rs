// SPDX-License-Identifier: GPL-2.0 or MIT

use core::sync::atomic::{
    AtomicU32,
    Ordering, //
};

use kernel::{
    clk::{
        Clk,
        OptionalClk, //
    },
    device::{
        Bound,
        Core,
        Device, //
    },
    devres,
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
    io::{
        poll,
        Io, //
    },
    new_mutex,
    of,
    platform, //
    prelude::*,
    regulator,
    regulator::Regulator,
    sizes::SZ_2M,
    sync::{
        aref::ARef,
        Arc,
        Mutex, //
    },
    time::{
        self,
        Jiffies, //
    },
    workqueue::{
        self,
        impl_has_delayed_work,
        DelayedWork,
        Work,
        WorkItem,
        WqFlags, //
    },
};

use crate::{
    file::TyrDrmFileData,
    fw::{
        irq::job_irq_init,
        Firmware, //
    },
    gem::BoData,
    gpu,
    gpu::GpuInfo,
    mmu::{
        irq::mmu_irq_init,
        Mmu, //
    },
    new_wait,
    regs::gpu_control::*, //
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
    /// Tiler heap out-of-memory growth worker.
    pub(crate) const TILER_OOM: u64 = 5;
}

#[pin_data(PinnedDrop)]
pub(crate) struct TyrPlatformDriverData;

#[pin_data]
pub(crate) struct TyrDrmDeviceData {
    pub(crate) pdev: ARef<platform::Device>,

    pub(crate) mmu: Arc<Mmu>,

    pub(crate) iomem: Arc<Devres<IoMem>>,

    pub(crate) mmio_phys_addr: u64,

    /// Whether the device is reported as DMA-coherent by firmware.
    ///
    /// Cached at probe via `device_get_dma_attr()`. Drives the BO
    /// cacheability policy in [`crate::gem::should_map_wc`].
    pub(crate) coherent: bool,

    pub(crate) fw: Arc<Firmware>,

    pub(crate) wq: Arc<DmaFenceWorkqueue>,

    /// Dedicated DMA-fence-constrained workqueue for the scheduler
    /// bottom half. Created `WQ_HIGHPRI` (`MEM_RECLAIM` is added by
    /// [`DmaFenceWorkqueue::new`]) so the scheduler can keep up with
    /// firmware acks under memory pressure.
    pub(crate) sched_wq: Arc<DmaFenceWorkqueue>,

    #[pin]
    clks: Mutex<Clocks>,

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

    /// Slot manager for the firmware-visible CSG slots.
    ///
    /// Pinned at probe time with [`MAX_CSGS`] as an upper bound so the
    /// per-group [`Seat`](crate::slot::Seat) field
    /// (`LockedBy<Seat, CsgSlotManager>`) has a stable owner address
    /// from the moment the device data is initialised. The actual
    /// hardware slot count, which is only known after firmware boot,
    /// is applied by [`Scheduler::init`] via
    /// [`SlotManager::set_slot_count`].
    ///
    /// The lock ordering is `sched > csg_slot_manager`: callers that
    /// hold [`sched`](Self::sched) may acquire this mutex, but not the
    /// other way round.
    #[pin]
    pub(crate) csg_slot_manager: Mutex<CsgSlotManager>,

    /// Outstanding firmware-events bits accumulated by IRQ handlers.
    ///
    /// Producers OR new status bits in via [`fw_events_or`] from any
    /// context; the consumer reads-and-clears with [`fw_events_take`].
    /// This keeps scheduler-mutex work off the threaded IRQ handler.
    ///
    /// [`fw_events_or`]: TyrDrmDeviceData::fw_events_or
    /// [`fw_events_take`]: TyrDrmDeviceData::fw_events_take
    fw_events: AtomicU32,

    /// Worker that drains [`fw_events`](Self::fw_events) under the
    /// scheduler mutex. Enqueued on [`sched_wq`](Self::sched_wq).
    ///
    /// Typed as [`DmaFenceWork`] so it can ride on `sched_wq` (a
    /// [`DmaFenceWorkqueue`]), not because the body signals dma-fences:
    /// it only ACKs CSG events and kicks the scheduler tick. Sharing
    /// the queue with the tick worker keeps the IRQ -> ACK -> tick
    /// path on `WQ_HIGHPRI` without a second workqueue.
    #[pin]
    fw_events_work: DmaFenceWork<TyrDrmDevice, { work_id::FW_EVENTS }>,

    /// Scheduler tick worker. Enqueued on [`sched_wq`](Self::sched_wq).
    #[pin]
    tick_work: DmaFenceWork<TyrDrmDevice, { work_id::TICK }>,

    /// Group sync-update worker.
    ///
    /// Enqueued via [`schedule_sync_upd`](Self::schedule_sync_upd) onto
    /// the global `system_unbound()` queue. Scans groups whose queues
    /// reported a `SYNC_UPDATE` event and unblocks any whose syncwait
    /// has now been satisfied.
    ///
    /// Plain [`Work`], not [`DmaFenceWork`]: re-evaluating a foreign-BO
    /// syncwait requires `drm_gem_shmem_vmap`, which acquires
    /// `dma_resv_lock` and allocates with `GFP_KERNEL`. Both are
    /// forbidden on the DMA fence signalling path, so the worker stays
    /// outside it.
    #[pin]
    sync_upd_work: Work<TyrDrmDevice, { work_id::SYNC_UPD }>,

    /// Periodic re-arm worker for [`tick_work`](Self::tick_work).
    ///
    /// Enqueued on `system_unbound()` rather than [`sched_wq`](Self::sched_wq)
    /// so a long-delay timer expiry does not hold a scheduler worker.
    #[pin]
    periodic_tick_work: DelayedWork<TyrDrmDevice, { work_id::PERIODIC_TICK }>,

    #[pin]
    pub(crate) tiler_oom_work: Work<TyrDrmDevice, { work_id::TILER_OOM }>,
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
    /// `Release` pairs with the `Acquire` in [`fw_events_take`] so the
    /// drain side observes any state the producer wrote before raising
    /// the bit.
    ///
    /// [`fw_events_take`]: TyrDrmDeviceData::fw_events_take
    pub(crate) fn fw_events_or(&self, bits: u32) {
        self.fw_events.fetch_or(bits, Ordering::Release);
    }

    /// Atomically reads and clears the firmware-events word, returning
    /// the bits that were set.
    pub(crate) fn fw_events_take(&self) -> u32 {
        self.fw_events.swap(0, Ordering::Acquire)
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

    /// Schedules the group sync-update worker on the global
    /// `system_unbound()` queue.
    ///
    /// Safe to call from any context including the threaded IRQ
    /// handler. Repeated calls coalesce in the workqueue.
    pub(crate) fn schedule_sync_upd(tdev: &ARef<TyrDrmDevice>) {
        let _ = workqueue::system_unbound()
            .enqueue::<ARef<TyrDrmDevice>, { work_id::SYNC_UPD }>(tdev.clone());
    }

    /// Schedules an immediate scheduler tick on
    /// [`sched_wq`](Self::sched_wq).
    ///
    /// Safe to call from any context including the threaded IRQ
    /// handler. Repeated calls coalesce in the workqueue: a second
    /// `schedule_tick` while a tick is already pending is a no-op.
    pub(crate) fn schedule_tick(tdev: &ARef<TyrDrmDevice>) {
        let _ = tdev
            .sched_wq
            .enqueue::<ARef<TyrDrmDevice>, { work_id::TICK }>(tdev.clone());
    }

    /// Re-arms the scheduler tick `delay` jiffies from now.
    ///
    /// If a periodic tick is already pending, `delay` is ignored:
    /// `queue_delayed_work_on` will not shorten an in-flight delay.
    /// To force an earlier tick, call [`schedule_tick`](Self::schedule_tick)
    /// directly.
    pub(crate) fn schedule_periodic_tick(tdev: &ARef<TyrDrmDevice>, delay: Jiffies) {
        let _ = workqueue::system_unbound()
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

        let queued_tiler_oom = tdev
            .with_locked_scheduler(|sched| sched.process_csg_irqs(events, tdev))
            .inspect_err(|err| {
                pr_err!(
                    "fw_events_work: failed to process firmware CSG IRQs: {:?}\n",
                    err
                );
            })
            .unwrap_or(false);

        // A CSG IRQ that the firmware raised for any of the slots we
        // own is by definition an observable state change from the
        // scheduler's point of view: a CSG_REQ ack might have flipped,
        // or a CS in the slot might have hit a fault or run out of
        // tiler heap. Kick the tick so it can re-evaluate residency
        // and apply any pending state transitions.
        crate::sched::Scheduler::request_tick(&this);

        if queued_tiler_oom {
            let _ = kernel::workqueue::system()
                .enqueue::<ARef<TyrDrmDevice>, { work_id::TILER_OOM }>(this);
        }
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

    /// The submit-fence drain runs outside the scheduler mutex
    /// because fence signalling cannot nest inside a wide driver
    /// lock.
    fn run(this: Self::Pointer) {
        let tdev = &*this;
        Scheduler::drain_resident_queue_completions(tdev);
        let immediate_tick = tdev
            .with_locked_scheduler(|sched| Ok(sched.sync_upd_step()))
            .unwrap_or(false);

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

fn issue_soft_reset(dev: &Device<Bound>, iomem: &Devres<IoMem>) -> Result {
    let io = (*iomem).access(dev)?;
    io.write_reg(GPU_COMMAND::reset(ResetMode::SoftReset));

    poll::read_poll_timeout(
        || {
            let io = (*iomem).access(dev)?;
            Ok(io.read(GPU_IRQ_RAWSTAT))
        },
        |status| status.reset_completed(),
        time::Delta::from_millis(1),
        time::Delta::from_millis(100),
    )
    .inspect_err(|_| dev_err!(dev, "GPU reset failed."))?;

    Ok(())
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
        let sram_regulator = Regulator::<regulator::Enabled>::get(pdev.as_ref(), c"sram")?;

        let request = pdev.io_request_by_index(0).ok_or(ENODEV)?;
        let mmio_phys_addr = request.start();
        let iomem = Arc::pin_init(request.iomap_sized::<SZ_2M>(), GFP_KERNEL)?;

        issue_soft_reset(pdev.as_ref(), &iomem)?;
        gpu::l2_power_on(pdev.as_ref(), &iomem)?;

        let gpu_info = GpuInfo::new(pdev.as_ref(), &iomem)?;
        gpu_info.log(pdev.as_ref());

        let pa_bits = MMU_FEATURES::from_raw(gpu_info.mmu_features)
            .pa_bits()
            .get();
        // SAFETY: No concurrent DMA allocations or mappings can be made because
        // the device is still being probed and therefore isn't being used by
        // other threads of execution.
        unsafe { pdev.dma_set_mask_and_coherent(DmaMask::try_new(pa_bits)?)? };

        let coherent = pdev.as_ref().dma_coherent();

        let uninit_ddev = UnregisteredDevice::<TyrDrmDriver>::new(pdev.as_ref())?;
        let platform: ARef<platform::Device> = pdev.into();

        let mmu = Mmu::new(pdev, iomem.as_arc_borrow(), &gpu_info)?;

        let firmware = Firmware::new(
            pdev,
            iomem.clone(),
            &uninit_ddev,
            mmu.as_arc_borrow(),
            &gpu_info,
            coherent,
        )?;

        let wq = Arc::new(
            DmaFenceWorkqueue::new(c"tyr-dma-fence", WqFlags::UNBOUND, 0)?,
            GFP_KERNEL,
        )?;

        let sched_wq = Arc::new(
            DmaFenceWorkqueue::new(c"tyr-sched", WqFlags::HIGHPRI, 0)?,
            GFP_KERNEL,
        )?;

        let csg_slot_ops = CsgSlotOps::new(firmware.clone());
        let csg_slot_manager = SlotManager::<CsgSlotOps, MAX_CSGS>::new(csg_slot_ops, MAX_CSGS)?;

        let data = try_pin_init!(TyrDrmDeviceData {
                pdev: platform.clone(),
                mmu,
                iomem: iomem.clone(),
                mmio_phys_addr,
                coherent,
                fw: firmware,
                wq,
                sched_wq,
                clks <- new_mutex!(Clocks {
                    core: core_clk,
                    stacks: stacks_clk,
                    coregroup: coregroup_clk,
                }),
                regulators <- new_mutex!(Regulators {
                    _mali: mali_regulator,
                    _sram: sram_regulator,
                }),
                gpu_info,
                csif_info <- new_mutex!(gpu::CsifInfo::default()),
                sched <- new_mutex!(SchedulerState::Disabled),
                csg_slot_manager <- new_mutex!(csg_slot_manager),
                fw_events: AtomicU32::new(0),
                fw_events_work <- new_dma_fence_work!("TyrDrmDeviceData::fw_events_work"),
                tick_work <- new_dma_fence_work!("TyrDrmDeviceData::tick_work"),
                sync_upd_work <- kernel::new_work!("TyrDrmDeviceData::sync_upd_work"),
                periodic_tick_work <- kernel::new_delayed_work!("TyrDrmDeviceData::periodic_tick_work"),
                tiler_oom_work <- kernel::new_work!("TyrDrmDeviceData::tiler_oom_work"),
        });

        let ddev = Registration::new_foreign_owned(uninit_ddev, pdev.as_ref(), data, 0)?;
        let tdev: ARef<TyrDrmDevice> = ddev.into();

        let power_on_wait = new_wait!()?;

        let gpu_irq =
            gpu::irq::gpu_irq_init(tdev.clone(), pdev, tdev.iomem.clone(), power_on_wait)?;
        devres::register(pdev.as_ref(), gpu_irq, GFP_KERNEL)?;

        let mmu_irq = mmu_irq_init(tdev.clone(), pdev, tdev.iomem.clone())?;
        devres::register(pdev.as_ref(), mmu_irq, GFP_KERNEL)?;

        let job_irq = job_irq_init(tdev.clone(), pdev, tdev.iomem.clone(), tdev.fw.irq_state())?;
        devres::register(pdev.as_ref(), job_irq, GFP_KERNEL)?;

        tdev.fw.boot()?;
        tdev.fw
            .wait_ready(1000)
            .inspect_err(|_| pr_err!("Timed out waiting for firmware to be ready.\n"))?;
        tdev.fw.enable_global_interface(&tdev)?;

        let scheduler = Scheduler::init(&tdev)?;
        tdev.sched.lock().enable(scheduler);

        // We need this to be dev_info!() because dev_dbg!() does not work at
        // all in Rust for now, and we need to see whether probe succeeded.
        dev_info!(pdev, "Tyr initialized correctly.\n");
        Ok(TyrPlatformDriverData)
    }
}

#[pinned_drop]
impl PinnedDrop for TyrPlatformDriverData {
    fn drop(self: Pin<&mut Self>) {}
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
    _sram: Regulator<regulator::Enabled>,
}
