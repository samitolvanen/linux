// SPDX-License-Identifier: GPL-2.0 or MIT

use core::marker::PhantomPinned;
use core::sync::atomic::AtomicU32;

use kernel::{
    c_str,
    clk::{
        Clk,
        OptionalClk, //
    },
    device::{
        self,
        Bound,
        Core,
        Device, //
    },
    devres::{
        self,
        Devres, //
    },
    dma::{
        Device as DmaDevice,
        DmaMask, //
    },
    dma_fence::{
        DmaFenceWork,
        DmaFenceWorkqueue, //
    },
    drm::{
        self,
        driver::Registration,
        ioctl,
        UnregisteredDevice, //
    },
    io::{
        poll,
        Io, //
    },
    irq::{
        IrqReturn,
        ThreadedHandler,
        ThreadedIrqReturn,
        ThreadedRegistration, //
    },
    new_mutex,
    of,
    opp,
    platform,
    prelude::*,
    regulator::{
        self,
        Regulator, //
    },
    sizes::SZ_2M,
    sync::{
        aref::ARef,
        Arc,
        Mutex, //
    },
    time,
    workqueue, //
};

use crate::{
    file::TyrDrmFileData,
    fw::{
        self,
        Firmware, //
    },
    gem::BoData,
    gpu::{
        self,
        GpuInfo, //
    },
    mmu::{
        self,
        Mmu, //
    },
    new_wait,
    regs::gpu_control::*,
    sched::{
        CsgSlotManager, //
        Scheduler,
        SchedulerState,
    },
    slot::SlotManager,
};

pub(crate) type IoMem = kernel::io::mem::IoMem<SZ_2M>;

pub(crate) struct TyrDrmDriver;

/// Convenience type alias for the DRM device type for this driver.
pub(crate) type TyrDrmDevice<Ctx = drm::Registered> = drm::Device<TyrDrmDriver, Ctx>;

#[pin_data]
#[repr(transparent)]
pub(crate) struct TyrPlatformDriverData {
    pub(crate) tdev: ARef<TyrDrmDevice>,
}

/// Per-device DRM data for the Tyr driver.
///
/// # Lock ordering
///
/// When multiple Tyr-owned locks are acquired by the same code path, they
/// must be taken in this order (outer first):
///
/// 1. [`TyrDrmDeviceData::sched`] (the [`crate::sched::SchedulerState`]
///    mutex).
/// 2. [`TyrDrmDeviceData::csg_slot_manager`] (the CSG
///    [`crate::slot::SlotManager`] mutex).
/// 3. [`crate::sched::group::Group::inner`] (per-group state mutex).
/// 4. Per-queue state inside `GroupInner` (e.g. the
///    [`kernel::dma_fence::JobQueue`] held by each queue).
///
/// Locks at the same level may not be nested. The firmware global
/// interface lock (acquired through `Firmware::with_locked_global_iface`)
/// is leaf-level and may be taken under any of the above.
#[pin_data]
pub(crate) struct TyrDrmDeviceData {
    pub(crate) pdev: ARef<platform::Device>,

    pub(crate) max_freq: u64,

    pub(crate) fw: Arc<Firmware>,

    #[pin]
    pub(crate) clks: Mutex<Clocks>,

    #[pin]
    regulators: Mutex<Regulators>,

    /// Some information on the GPU.
    ///
    /// This is mainly queried by userspace, i.e.: Mesa.
    pub(crate) gpu_info: GpuInfo,

    /// CSIF information populated after firmware init.
    #[pin]
    pub(crate) csif_info: Mutex<gpu::CsifInfo>,

    /// The MMU, with internal locking.
    pub(crate) mmu: Arc<Mmu>,

    /// The MMIO region.
    pub(crate) iomem: Arc<Devres<IoMem>>,

    /// Physical address of the MMIO region.
    pub(crate) mmio_phys_addr: u64,

    /// The scheduler logic.
    #[pin]
    pub(crate) sched: Mutex<SchedulerState>,

    /// CSG slot manager.
    #[pin]
    pub(crate) csg_slot_manager: Mutex<CsgSlotManager>,

    pub(crate) reset_wq: &'static workqueue::Queue,
    /// Single-threaded scheduler workqueue.
    ///
    /// Owned by the device data; carries the bottom half of the
    /// scheduler (tick, fw_events, sync_upd, periodic_tick).  Held
    /// inline (rather than behind an `Arc`) because no other subsystem
    /// shares this queue.
    pub(crate) sched_wq: DmaFenceWorkqueue,
    /// Job execution workqueue, shared with per-queue `JobQueue`s.
    ///
    /// Wrapped in `Arc` because every `JobQueue` holds an owning
    /// reference to it.  Marked `MEM_RECLAIM` so dma-fence callbacks
    /// can run during low-memory conditions.
    pub(crate) job_wq: Arc<DmaFenceWorkqueue>,

    /// Work item for the firmware ping.
    #[pin]
    pub(crate) ping_work: workqueue::DelayedWork<TyrDrmDevice, 0>,

    /// Work item for the scheduler tick.
    ///
    /// Slot [`work_id::TICK`].  Coalesces redundant `schedule_tick`
    /// requests via the workqueue.
    #[pin]
    pub(crate) tick_work: DmaFenceWork<crate::driver::TyrDrmDevice, { work_id::TICK }>,

    /// Work item for processing firmware events.
    ///
    /// Slot [`work_id::FW_EVENTS`].  Drains [`fw_events`](Self::fw_events)
    /// when scheduled.
    #[pin]
    pub(crate) fw_events_work: DmaFenceWork<crate::driver::TyrDrmDevice, { work_id::FW_EVENTS }>,

    /// Outstanding firmware events accumulated by IRQ handlers.
    pub(crate) fw_events: AtomicU32,

    /// The work to process group status updates.
    ///
    /// Slot [`work_id::SYNC_UPD`].
    #[pin]
    pub(crate) sync_upd_work: DmaFenceWork<crate::driver::TyrDrmDevice, { work_id::SYNC_UPD }>,

    /// For scheduling periodic ticks.
    ///
    /// Slot [`work_id::PERIODIC_TICK`].
    #[pin]
    pub(crate) periodic_tick_work:
        workqueue::DelayedWork<crate::driver::TyrDrmDevice, { work_id::PERIODIC_TICK }>,

    /// Holds a temporary copy of `TyrPlatformDriverData` during probe to ensure
    /// `dev_get_drvdata` returns a valid pointer if called by `devfreq` before
    /// the platform driver framework sets the final pointer. This avoids a memory leak.
    #[pin]
    pub(crate) devfreq_temp_data: Mutex<Option<KBox<TyrPlatformDriverData>>>,

    #[pin]
    pub(crate) devfreq_registration:
        Mutex<Option<kernel::devfreq::Registration<crate::devfreq::TyrDevfreqCallbacks>>>,

    #[pin]
    pub(crate) devfreq_state: Mutex<crate::devfreq::DevfreqState>,

    #[pin]
    pub(crate) opp_table: Mutex<Option<kernel::opp::Table>>,

    #[pin]
    pub(crate) opp_config: Mutex<Option<kernel::opp::ConfigToken>>,

    pub(crate) current_frequency: core::sync::atomic::AtomicUsize,
}

/// Per-`TyrDrmDeviceData` work slot identifiers.
///
/// Used as the `WORK_ID` const generic on [`DmaFenceWork`] /
/// [`workqueue::DelayedWork`] and the matching
/// [`impl_has_dma_fence_work!`] / [`impl_has_delayed_work!`] impls.
///
/// [`impl_has_dma_fence_work!`]: kernel::impl_has_dma_fence_work
/// [`impl_has_delayed_work!`]: kernel::impl_has_delayed_work
pub(crate) mod work_id {
    /// Scheduler tick.
    pub(crate) const TICK: u64 = 1;
    /// Firmware-event drain.
    pub(crate) const FW_EVENTS: u64 = 2;
    /// Group sync-update worker.
    pub(crate) const SYNC_UPD: u64 = 3;
    /// Periodic re-arming of the scheduler tick.
    pub(crate) const PERIODIC_TICK: u64 = 4;
}

// Both `Clk` and `Regulator` do not implement `Send` or `Sync`, but they
// should. There are patches on the mailing list to address this, but they have
// not landed yet.
//
// For now, add this workaround so that this patch compiles with the promise
// that it will be removed in a future patch.
//
// SAFETY: This will be removed in a future patch.
unsafe impl Send for TyrDrmDeviceData {}
// SAFETY: This will be removed in a future patch.
unsafe impl Sync for TyrDrmDeviceData {}

impl TyrDrmDeviceData {
    /// Execute a function with the scheduler locked.
    pub(crate) fn with_locked_scheduler<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Scheduler) -> Result<R>,
    {
        let mut sched = self.sched.lock();
        f(sched.enabled_mut()?)
    }

    /// Enqueues a firmware-events drain on [`sched_wq`](Self::sched_wq).
    #[expect(dead_code)]
    pub(crate) fn schedule_fw_events(tdev: &ARef<crate::driver::TyrDrmDevice>) {
        let _ = tdev
            .sched_wq
            .enqueue::<_, { work_id::FW_EVENTS }>(tdev.clone());
    }

    /// Enqueues a group sync-update worker on [`sched_wq`](Self::sched_wq).
    pub(crate) fn schedule_sync_upd(tdev: &ARef<crate::driver::TyrDrmDevice>) {
        let _ = tdev
            .sched_wq
            .enqueue::<_, { work_id::SYNC_UPD }>(tdev.clone());
    }

    /// Enqueues a scheduler tick on [`sched_wq`](Self::sched_wq).
    pub(crate) fn schedule_tick(tdev: &ARef<crate::driver::TyrDrmDevice>) {
        let _ = tdev.sched_wq.enqueue::<_, { work_id::TICK }>(tdev.clone());
    }

    /// Re-arms the periodic tick after `delay` jiffies.
    pub(crate) fn schedule_periodic_tick(
        tdev: &ARef<crate::driver::TyrDrmDevice>,
        delay: kernel::time::Jiffies,
    ) {
        let _ = workqueue::system_unbound()
            .enqueue_delayed::<_, { work_id::PERIODIC_TICK }>(tdev.clone(), delay);
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
        let max_freq = get_max_freq(pdev, &core_clk)?;

        let request = pdev.io_request_by_index(0).ok_or(ENODEV)?;
        let mmio_phys_addr = request.start();
        let iomem = Arc::pin_init(request.iomap_sized::<SZ_2M>(), GFP_KERNEL)?;

        issue_soft_reset(pdev.as_ref(), &iomem)?;
        gpu::l2_power_on(pdev.as_ref(), &iomem)?;

        let gpu_info = GpuInfo::new(pdev.as_ref(), &iomem)?;
        gpu_info.log(pdev.as_ref());

        let io = (*iomem).access(pdev.as_ref())?;
        let pa_bits = io.read(MMU_FEATURES).pa_bits().get();
        // SAFETY: No concurrent DMA allocations or mappings can be made because
        // the device is still being probed and therefore isn't being used by
        // other threads of execution.
        unsafe {
            pdev.dma_set_max_seg_size(u32::MAX);
            pdev.dma_set_mask_and_coherent(DmaMask::try_new(pa_bits)?)?;
        }

        let uninit_ddev = UnregisteredDevice::<TyrDrmDriver>::new(pdev.as_ref())?;
        let platform: ARef<platform::Device> = pdev.into();

        let mmu = Mmu::new(pdev, iomem.as_arc_borrow())?;

        let firmware = Firmware::new(pdev, iomem.clone(), &uninit_ddev, mmu.as_arc_borrow())?;

        firmware.boot()?;

        // Save wait handles before firmware is moved into DRM device data
        let fw_event_wait = firmware.event_wait.clone();
        let irq_iomem = iomem.clone();

        let topology = firmware.with_locked_global_iface(|glb_iface| glb_iface.read_topology())?;

        let gpu_as_count = gpu_info.as_present & kernel::bits::genmask_u32(1..=31);
        let gpu_as_count = gpu_as_count.count_ones();
        let csg_count = core::cmp::min(topology.group_num, gpu_as_count) as usize;

        let sched_wq = DmaFenceWorkqueue::new(c_str!("tyr-sched"), workqueue::WqFlags::HIGHPRI, 0)?;

        let job_wq = Arc::new(
            DmaFenceWorkqueue::new(
                c_str!("tyr-job"),
                workqueue::WqFlags::HIGHPRI | workqueue::WqFlags::MEM_RECLAIM,
                0,
            )?,
            GFP_KERNEL,
        )?;

        let data = try_pin_init!(TyrDrmDeviceData {
                pdev: platform.clone(),
                max_freq,
                fw: firmware,
                clks <- new_mutex!(Clocks {
                    core: core_clk,
                    stacks: stacks_clk,
                    coregroup: coregroup_clk,
                }),
                regulators <- new_mutex!(Regulators {
                    _mali: mali_regulator,
                }),
                gpu_info,
                csif_info <- new_mutex!(gpu::CsifInfo::default()),
                mmu,
                iomem: iomem.clone(),
                mmio_phys_addr,
                sched <- new_mutex!(SchedulerState::Disabled),
                csg_slot_manager <- new_mutex!(SlotManager::new(crate::sched::CsgSlotOperations, csg_count)?),
                reset_wq: workqueue::system_unbound(),
                sched_wq,
                job_wq,
                ping_work <- kernel::new_delayed_work!("tyr_ping_work"),
                tick_work <- kernel::new_dma_fence_work!("tyr_tick"),
                fw_events_work <- kernel::new_dma_fence_work!("tyr-fw-events"),
                fw_events: AtomicU32::new(0),
                sync_upd_work <- kernel::new_dma_fence_work!("tyr-sync-upd"),
                periodic_tick_work <- kernel::new_delayed_work!("tyr_periodic_tick"),
                devfreq_temp_data <- new_mutex!(None),
                devfreq_registration <- new_mutex!(None),
                devfreq_state <- new_mutex!(crate::devfreq::DevfreqState::new()),
                opp_table <- new_mutex!(None),
                opp_config <- new_mutex!(None),
                current_frequency: core::sync::atomic::AtomicUsize::new(0),
        });

        let ddev = Registration::new_foreign_owned(uninit_ddev, pdev.as_ref(), data, 0)?;

        let dev_bound: &Device<Bound> = pdev.as_ref();
        let pdev_bound: &platform::Device<Bound> = pdev;
        let tdev: ARef<TyrDrmDevice> = ddev.into();

        let power_on_wait = new_wait!(false)?;
        let boot_wait = new_wait!()?;

        let gpu_irq =
            gpu::irq::gpu_irq_init(tdev.clone(), pdev_bound, irq_iomem.clone(), power_on_wait)?;
        devres::register(dev_bound, gpu_irq, GFP_KERNEL)?;
        gpu::irq::GpuIrq::enable_hardware(dev_bound, &irq_iomem)?;

        let mmu_irq = mmu::irq::mmu_irq_init(tdev.clone(), pdev_bound, irq_iomem.clone())?;
        devres::register(dev_bound, mmu_irq, GFP_KERNEL)?;
        mmu::irq::MmuIrq::enable_hardware(dev_bound, &irq_iomem)?;

        let job_irq = fw::irq::job_irq_init(
            tdev.clone(),
            pdev_bound,
            irq_iomem.clone(),
            fw_event_wait,
            boot_wait,
        )?;
        devres::register(dev_bound, job_irq, GFP_KERNEL)?;
        fw::irq::JobIrq::enable_hardware(dev_bound, &irq_iomem)?;

        // Reuse the topology read earlier (above csg_count) to size the
        // CSG / stream preallocations the firmware enable path will
        // consume under the shared-section mutex.
        let prealloc_csgs = KVec::with_capacity(topology.group_num as usize, GFP_KERNEL)?;
        let mut prealloc_streams = KVec::with_capacity(topology.group_num as usize, GFP_KERNEL)?;
        for _ in 0..topology.group_num {
            prealloc_streams.push(
                KVec::with_capacity(topology.stream_num as usize, GFP_KERNEL)?,
                GFP_KERNEL,
            )?;
        }

        // Enable the global interface now that the MCU has booted and IRQs are
        // registered. This reads the control structures from the shared section,
        // sets up CSG slots, configures timers, and starts the ping watchdog.
        let core_clk_rate = {
            let clks = tdev.clks.lock();
            clks.core.rate().as_hz() as u64
        };

        tdev.fw.enable_global_iface(
            &tdev,
            &tdev.gpu_info,
            core_clk_rate,
            prealloc_csgs,
            prealloc_streams,
        )?;

        // Initialize the scheduler now that the global interface is enabled.
        // This reads CSG/CS slot counts from the firmware and prepares the
        // scheduler for accepting group submissions.
        let scheduler = Scheduler::init(&tdev)?;
        *tdev.sched.lock() = SchedulerState::Enabled(scheduler);

        let temp_data = KBox::new(TyrPlatformDriverData { tdev: tdev.clone() }, GFP_KERNEL)?;
        // HACK: `devfreq::init` requires `drvdata` to be set because it may immediately
        // call `get_dev_status` which relies on it. However, the platform driver
        // framework only sets `drvdata` *after* `probe` returns.
        // We set it manually here to a temporary heap structure to bridge the gap,
        // and store it in `devfreq_temp_data` to avoid leaking it.
        //
        // SAFETY: `temp_data` is stored in `devfreq_temp_data` and remains valid
        // as long as the device exists.
        unsafe {
            kernel::bindings::dev_set_drvdata(
                core::ptr::from_ref(pdev.as_ref()).cast_mut().cast(),
                core::ptr::from_ref(&*temp_data).cast_mut().cast(),
            );
        }
        *tdev.devfreq_temp_data.lock() = Some(temp_data);

        crate::devfreq::init(&tdev, pdev.as_ref())?;

        // We need this to be dev_info!() because dev_dbg!() does not work at
        // all in Rust for now, and we need to see whether probe succeeded.
        dev_info!(pdev, "Tyr initialized correctly.\n");
        Ok(TyrPlatformDriverData { tdev })
    }
}

fn get_max_freq(pdev: &platform::Device, core_clk: &kernel::clk::Clk) -> Result<u64> {
    match opp::Table::from_of(&pdev.as_ref().into(), 0) {
        Ok(table) => match table.opp_from_freq(
            kernel::clk::Hertz(kernel::ffi::c_ulong::MAX),
            Some(true), // Only consider available (enabled) OPPs
            None,       // Use default clock index (0)
            opp::SearchType::Floor,
        ) {
            Ok(opp) => {
                let freq = opp.freq(None);
                let voltage = opp.voltage();

                dev_info!(
                    pdev.as_ref(),
                    "Max performance: {} Hz @ {} uV\n",
                    kernel::ffi::c_ulong::from(freq),
                    kernel::ffi::c_ulong::from(voltage)
                );

                Ok(freq.as_hz() as u64)
            }
            Err(e) => {
                dev_info!(
                    pdev.as_ref(),
                    "Failed to get max OPP: {:?}, using current clock\n",
                    e
                );
                Ok(core_clk.rate().as_hz() as u64)
            }
        },
        Err(e) => {
            dev_info!(
                pdev.as_ref(),
                "No OPP table in device tree: {:?}, using current clock\n",
                e
            );
            Ok(core_clk.rate().as_hz() as u64)
        }
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
        crate::mmap::mmap(device, &*file.inner(), vma)
    }
}

pub(crate) struct Clocks {
    pub(crate) core: Clk,
    pub(crate) stacks: OptionalClk,
    pub(crate) coregroup: OptionalClk,
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

pub(crate) trait TyrIrqTrait: Sync {
    /// Reads the interrupt status register.
    fn read_status(&self, dev: &Device<Bound>) -> u32;

    /// Disable all device interrupts for this interrupt line.
    fn disable_all(&self, dev: &Device<Bound>);

    /// Reenable the interrupts after the threaded handler has run.
    fn reenable(&self, dev: &Device<Bound>);

    /// Reads the raw interrupt status register.
    fn read_raw_status(&self, dev: &Device<Bound>) -> u32;

    /// Clears the interrupt status.
    fn clear_status(&self, dev: &Device<Bound>, status: u32);

    /// Returns the mask for the enabled interrupts.
    fn mask(&self) -> u32;

    /// Handles the interrupt in the threaded context.
    fn handle(&self, tdev: &TyrDrmDevice, status: u32);
}

#[pin_data]
pub(crate) struct TyrIrq<T: TyrIrqTrait> {
    tdev: ARef<TyrDrmDevice>,
    irq: T,
    #[pin]
    _pin: PhantomPinned,
}

impl<T: TyrIrqTrait + 'static> TyrIrq<T> {
    pub(crate) fn request<'a>(
        pdev: &'a platform::Device<device::Bound>,
        tdev: ARef<TyrDrmDevice>,
        name: &'static CStr,
        irq_type: T,
    ) -> Result<impl PinInit<ThreadedRegistration<Self>, Error> + 'a> {
        let handler = try_pin_init!(Self {
            tdev,
            irq: irq_type,
            _pin: PhantomPinned,
        });

        Ok(pdev.request_threaded_irq_by_name(kernel::irq::Flags::SHARED, name, name, handler))
    }
}

impl<T: TyrIrqTrait> ThreadedHandler for TyrIrq<T> {
    fn handle(&self, _dev: &Device<Bound>) -> ThreadedIrqReturn {
        let int_stat = self.irq.read_status(_dev);

        if int_stat == 0 {
            return ThreadedIrqReturn::None;
        }

        self.irq.disable_all(_dev);
        ThreadedIrqReturn::WakeThread
    }

    fn handle_threaded(&self, _dev: &Device<Bound>) -> IrqReturn {
        let mut ret = IrqReturn::None;

        loop {
            let int_stat = self.irq.read_raw_status(_dev) & self.irq.mask();

            if int_stat == 0 {
                break;
            }

            self.irq.clear_status(_dev, int_stat);
            self.irq.handle(&self.tdev, int_stat);
            ret = IrqReturn::Handled;
        }

        self.irq.reenable(_dev);
        ret
    }
}
