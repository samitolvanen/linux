// SPDX-License-Identifier: GPL-2.0 or MIT

use core::marker::PhantomPinned;

use kernel::{
    clk::{
        Clk,
        OptionalClk, //
    },
    device::{
        Bound,
        Core,
        Device,
        DeviceContext, //
    },
    dma::{
        Device as DmaDevice,
        DmaMask, //
    },
    drm,
    drm::ioctl,
    io::{
        mem::DevresIoMem,
        poll,
        Io, //
    },
    irq::{
        Flags,
        IrqReturn,
        ThreadedHandler,
        ThreadedIrqReturn,
        ThreadedRegistration, //
    },
    mm::virt::VmaNew,
    new_mutex,
    of,
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
    time, //
};

use crate::{
    file::TyrDrmFileData,
    fw::{
        irq::{
            job_irq_init,
            JobIrq, //
        },
        Firmware, //
    },
    gem::Bo,
    gpu,
    gpu::GpuInfo,
    mmap,
    mmu::{
        irq::{
            mmu_irq_init,
            MmuIrq, //
        },
        Mmu, //
    },
    regs::gpu_control::*,
    sched::{
        Scheduler,
        SchedulerState, //
    }, //
};

pub(crate) type IoMem<'a> = kernel::io::mem::IoMem<'a, SZ_2M>;
pub(crate) type TyrRegisters = kernel::io::Region<SZ_2M>;

pub(crate) struct TyrDrmDriver;

/// Convenience type alias for the DRM device type for this driver.
pub(crate) type TyrDrmDevice<Ctx = drm::Normal> = drm::Device<TyrDrmDriver, Ctx>;

/// Data owned by the DRM device.
///
/// `registration_guard()` exists only on `Device<T, Ioctl>`, so driver callbacks running in the
/// `Normal` context, such as the mmap hook, cannot reach `TyrDrmRegistrationData`. The data
/// they need lives here.
#[pin_data]
pub(crate) struct TyrDrmDeviceData {
    /// Physical address of the GPU MMIO window.
    pub(crate) mmio_phys_addr: u64,

    /// The scheduler logic.
    #[pin]
    sched: Mutex<SchedulerState>,
}

impl TyrDrmDeviceData {
    pub(crate) fn with_locked_scheduler<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Scheduler) -> Result<R>,
    {
        let mut sched = self.sched.lock();
        f(sched.enabled_mut()?)
    }
}

pub(crate) struct TyrPlatformDriver;

#[pin_data(PinnedDrop)]
pub(crate) struct TyrPlatformDriverData<'bound> {
    _reg: drm::Registration<'bound, TyrDrmDriver>,
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
    _job_irq: Pin<KBox<ThreadedRegistration<'drm, TyrIrq<'drm, JobIrq>>>>,

    /// MMU IRQ registration. Freed after `mmu`, so faults raised during teardown are still
    /// reported.
    _mmu_irq: Pin<KBox<ThreadedRegistration<'drm, TyrIrq<'drm, MmuIrq>>>>,

    #[pin]
    clks: Mutex<Clocks>,

    #[pin]
    regulators: Mutex<Regulators>,

    /// Device-managed handle to the GPU MMIO register mapping.
    pub(crate) iomem: Arc<DevresIoMem<SZ_2M>>,

    /// GPU information read from hardware during probe.
    pub(crate) gpu_info: GpuInfo,

    /// Command stream interface information reported to userspace.
    #[pin]
    pub(crate) csif_info: Mutex<gpu::CsifInfo>,
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
    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);

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
        let sram_regulator = Regulator::<regulator::Enabled>::get(pdev.as_ref(), c"sram")?;

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
        unsafe { pdev.dma_set_mask_and_coherent(DmaMask::try_new(pa_bits)?)? };

        let unreg_dev = drm::UnregisteredDevice::<TyrDrmDriver>::new(
            pdev,
            try_pin_init!(TyrDrmDeviceData {
                mmio_phys_addr,
                sched <- new_mutex!(SchedulerState::Disabled),
            }? Error),
        )?;

        let mmu = Mmu::new(pdev, iomem.clone(), &gpu_info)?;

        let firmware = Firmware::new(
            pdev,
            iomem.clone(),
            &unreg_dev,
            mmu.as_arc_borrow(),
            &gpu_info,
        )?;

        // SAFETY: The registration is owned by `mmu_irq` and then by
        // `TyrDrmRegistrationData`. Every exit from `probe()` drops one or the other, so it
        // is never forgotten.
        let mmu_irq = KBox::pin_init(
            unsafe { mmu_irq_init(pdev, ARef::from(&*unreg_dev), iomem.clone()) }?,
            GFP_KERNEL,
        )?;

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
                )
            }?,
            GFP_KERNEL,
        )?;

        firmware.boot(io)?;

        firmware
            .wait_ready(1000)
            .inspect_err(|_| dev_err!(pdev, "Timed out waiting for firmware to be ready."))?;

        firmware.enable_global_interface(&core_clk, io)?;

        let csif_info = unreg_dev.sched.lock().init(&unreg_dev, &firmware)?;

        let reg_data = pin_init!(TyrDrmRegistrationData {
                pdev,
                mmu,
                fw: firmware,
                _job_irq: job_irq,
                _mmu_irq: mmu_irq,
                clks <- new_mutex!(Clocks {
                    core: core_clk,
                    stacks: stacks_clk,
                    coregroup: coregroup_clk,
                }),
                regulators <- new_mutex!(Regulators {
                    _mali: mali_regulator,
                    _sram: sram_regulator,
                }),
                iomem,
                gpu_info,
                csif_info <- new_mutex!(csif_info),
        });

        // SAFETY: `reg` is stored in `TyrPlatformDriverData` and dropped when the driver is
        // unbound; it is never forgotten.
        let reg = unsafe { drm::Registration::new(pdev.as_ref(), unreg_dev, reg_data, 0)? };

        let driver = TyrPlatformDriverData { _reg: reg };

        dev_dbg!(pdev, "Tyr initialized correctly.");
        Ok(driver)
    }
}

#[pinned_drop]
impl PinnedDrop for TyrPlatformDriverData<'_> {
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
    _sram: Regulator<regulator::Enabled>,
}

pub(crate) trait TyrIrqTrait: Sync {
    fn read_status(&self, io: &IoMem<'_>) -> u32;
    fn disable_all(&self, io: &IoMem<'_>);
    fn reenable(&self, io: &IoMem<'_>);
    fn read_raw_status(&self, io: &IoMem<'_>) -> u32;
    fn clear_status(&self, io: &IoMem<'_>, status: u32);
    fn mask(&self) -> u32;
    fn handle(&self, tdev: &TyrDrmDevice, io: &IoMem<'_>, status: u32);
}

#[pin_data]
pub(crate) struct TyrIrq<'drm, T: TyrIrqTrait> {
    dev: &'drm Device<Bound>,
    tdev: ARef<TyrDrmDevice>,
    iomem: Arc<DevresIoMem<SZ_2M>>,
    irq: T,
    #[pin]
    _pin: PhantomPinned,
}

impl<'drm, T: TyrIrqTrait> TyrIrq<'drm, T> {
    /// Registers a threaded handler for the named IRQ line.
    ///
    /// # Safety
    ///
    /// Callers must not `mem::forget()` the resulting registration or otherwise prevent its
    /// `Drop` implementation from running.
    pub(crate) unsafe fn request(
        pdev: &'drm platform::Device<Bound>,
        tdev: ARef<TyrDrmDevice>,
        name: &'static CStr,
        iomem: Arc<DevresIoMem<SZ_2M>>,
        irq: T,
    ) -> impl PinInit<ThreadedRegistration<'drm, Self>, Error> + 'drm
    where
        T: 'drm,
    {
        let handler = try_pin_init!(Self {
            dev: pdev.as_ref(),
            tdev,
            iomem,
            irq,
            _pin: PhantomPinned,
        });

        // SAFETY: The caller guarantees that the registration is not leaked.
        unsafe { pdev.request_threaded_irq_by_name(Flags::SHARED, name, name, handler) }
    }
}

impl<T: TyrIrqTrait> ThreadedHandler for TyrIrq<'_, T> {
    fn handle(&self) -> ThreadedIrqReturn {
        let Ok(io) = self.iomem.access(self.dev) else {
            return ThreadedIrqReturn::None;
        };
        let masked_status = self.irq.read_status(io);

        if masked_status == 0 {
            return ThreadedIrqReturn::None;
        }
        self.irq.disable_all(io);
        ThreadedIrqReturn::WakeThread
    }

    fn handle_threaded(&self) -> IrqReturn {
        let Ok(io) = self.iomem.access(self.dev) else {
            return IrqReturn::None;
        };
        let mut ret = IrqReturn::None;

        loop {
            let raw_status = self.irq.read_raw_status(io) & self.irq.mask();
            if raw_status == 0 {
                break;
            }
            self.irq.clear_status(io, raw_status);
            self.irq.handle(&self.tdev, io, raw_status);
            ret = IrqReturn::Handled;
        }

        self.irq.reenable(io);
        ret
    }
}
