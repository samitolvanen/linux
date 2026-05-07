// SPDX-License-Identifier: GPL-2.0 or MIT

use core::marker::PhantomPinned;

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
    devres,
    devres::Devres,
    dma::{
        Device as DmaDevice,
        DmaMask, //
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
    irq::IrqReturn,
    irq::ThreadedHandler,
    irq::ThreadedIrqReturn,
    irq::ThreadedRegistration,
    new_mutex,
    of,
    opp,
    platform,
    prelude::*,
    regulator,
    regulator::Regulator,
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
    fw,
    fw::irq::JobIrq,
    fw::Firmware,
    gem::BoData,
    gpu,
    gpu::irq::GpuIrq,
    gpu::GpuInfo,
    mmu,
    mmu::irq::MmuIrq,
    mmu::Mmu,
    new_wait,
    regs,
    regs::gpu_control::*,
    sched::Scheduler,
    sched::SchedulerState,
    wait::Wait,
    wait::WaitResult, //
};

pub(crate) type IoMem = kernel::io::mem::IoMem<SZ_2M>;

pub(crate) struct TyrDrmDriver;

/// Convenience type alias for the DRM device type for this driver.
pub(crate) type TyrDrmDevice<Ctx = drm::Registered> = drm::Device<TyrDrmDriver, Ctx>;

#[pin_data(PinnedDrop)]
pub(crate) struct TyrPlatformDriverData;

#[pin_data]
pub(crate) struct TyrDrmDeviceData {
    pub(crate) pdev: ARef<platform::Device>,

    pub(crate) fw: Arc<Firmware>,

    #[pin]
    clks: Mutex<Clocks>,

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
    sched: Mutex<SchedulerState>,

    pub(crate) reset_wq: &'static workqueue::Queue,

    /// Work item for the firmware ping.
    #[pin]
    pub(crate) ping_work: workqueue::DelayedWork<TyrDrmDevice, 0>,

    /// Work item for the scheduler tick.
    #[pin]
    pub(crate) tick_work: workqueue::Work<TyrDrmDevice, 1>,

    /// Work item for processing firmware events.
    #[pin]
    pub(crate) fw_events_work: workqueue::Work<TyrDrmDevice, 2>,

    /// Work item for group updates.
    #[pin]
    pub(crate) group_upd_work: workqueue::Work<TyrDrmDevice, 3>,
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

        // Set GPU to maximum performance operating point
        set_maximum_opp(&platform);

        let mmu = Mmu::new(pdev, iomem.as_arc_borrow())?;

        let firmware = Firmware::new(pdev, iomem.clone(), &uninit_ddev, mmu.as_arc_borrow())?;

        firmware.boot()?;

        // Save wait handles before firmware is moved into DRM device data
        let fw_event_wait = firmware.event_wait.clone();
        let irq_iomem = iomem.clone();

        let data = try_pin_init!(TyrDrmDeviceData {
                pdev: platform.clone(),
                fw: firmware,
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
                mmu,
                iomem: iomem.clone(),
                mmio_phys_addr,
                sched <- new_mutex!(SchedulerState::Disabled),
                reset_wq: workqueue::system_unbound(),
                ping_work <- kernel::new_delayed_work!("tyr_ping_work"),
                tick_work <- kernel::new_work!("tyr_tick_work"),
                fw_events_work <- kernel::new_work!("tyr_fw_events_work"),
                group_upd_work <- kernel::new_work!("tyr_group_upd_work"),
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

        // Enable the global interface now that the MCU has booted and IRQs are
        // registered. This reads the control structures from the shared section,
        // sets up CSG slots, configures timers, and starts the ping watchdog.
        {
            let clks = tdev.clks.lock();
            tdev.fw
                .enable_global_iface(&tdev, &tdev.gpu_info, &clks.core)?;
        }

        // Initialize the scheduler now that the global interface is enabled.
        // This reads CSG/CS slot counts from the firmware and prepares the
        // scheduler for accepting group submissions.
        let scheduler = Scheduler::init(&tdev)?;
        *tdev.sched.lock() = SchedulerState::Enabled(scheduler);

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

fn set_maximum_opp(pdev: &ARef<platform::Device>) {
    match opp::Table::from_of(&pdev.as_ref().into(), 0) {
        Ok(table) => {
            match table.opp_from_freq(
                kernel::clk::Hertz(kernel::ffi::c_ulong::MAX),
                Some(true),
                None,
                opp::SearchType::Floor,
            ) {
                Ok(max_opp) => {
                    let freq = max_opp.freq(None);
                    let voltage = max_opp.voltage();

                    dev_info!(
                        pdev.as_ref(),
                        "Setting GPU to max performance: {} Hz @ {} uV\n",
                        kernel::ffi::c_ulong::from(freq),
                        kernel::ffi::c_ulong::from(voltage)
                    );

                    if let Err(e) = table.set_opp(&max_opp) {
                        dev_warn!(
                            pdev.as_ref(),
                            "Failed to set max OPP: {:?}, continuing anyway\n",
                            e
                        );
                    }
                }
                Err(e) => {
                    dev_info!(
                        pdev.as_ref(),
                        "Failed to get max OPP: {:?}, using default clocks\n",
                        e
                    );
                }
            }
        }
        Err(e) => {
            dev_info!(
                pdev.as_ref(),
                "No OPP table in device tree: {:?}, using default clocks\n",
                e
            );
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
