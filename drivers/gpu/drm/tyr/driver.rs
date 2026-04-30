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
    irq::{
        Flags,
        IrqReturn,
        ThreadedHandler,
        ThreadedIrqReturn,
        ThreadedRegistration, //
    },
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
        irq::job_irq_init,
        Firmware, //
    },
    gem::BoData,
    gpu,
    gpu::GpuInfo,
    mmu::Mmu,
    sched::Scheduler,
    sched::SchedulerState,
    regs::gpu_control::*, //
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

	pub(crate) mmu: Arc<Mmu>,

    pub(crate) iomem: Arc<Devres<IoMem>>,

	pub(crate) mmio_phys_addr: u64,

    pub(crate) fw: Arc<Firmware>,

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

        let uninit_ddev = UnregisteredDevice::<TyrDrmDriver>::new(pdev.as_ref())?;
        let platform: ARef<platform::Device> = pdev.into();

        let mmu = Mmu::new(pdev, iomem.as_arc_borrow(), &gpu_info)?;

        let firmware = Firmware::new(
            pdev,
            iomem.clone(),
            &uninit_ddev,
            mmu.as_arc_borrow(),
            &gpu_info,
        )?;

        let job_irq = job_irq_init(
            pdev,
            iomem.clone(),
            firmware.fw_ready.clone(),
            firmware.ready_wait.clone(),
        )?;
        devres::register(pdev.as_ref(), job_irq, GFP_KERNEL)?;

        firmware.boot()?;
        firmware
            .wait_ready(1000)
            .inspect_err(|_| pr_err!("Timed out waiting for firmware to be ready.\n"))?;
        firmware.enable_global_interface(&gpu_info, &core_clk)?;

        let data = try_pin_init!(TyrDrmDeviceData {
                pdev: platform.clone(),
				mmu,
				iomem: iomem.clone(),
				mmio_phys_addr,
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
                sched <- new_mutex!(SchedulerState::Disabled),
        });

        let ddev = Registration::new_foreign_owned(uninit_ddev, pdev.as_ref(), data, 0)?;
        let tdev: ARef<TyrDrmDevice> = ddev.into();

        tdev.sched.lock().init(&tdev)?;

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

pub(crate) trait TyrIrqTrait: Sync + 'static {
    fn read_status(&self, dev: &Device<Bound>) -> u32;
    fn clear_mask(&self, dev: &Device<Bound>);
    fn reenable_mask(&self, dev: &Device<Bound>);
    fn read_raw_status(&self, dev: &Device<Bound>) -> u32;
    fn clear_status(&self, dev: &Device<Bound>, status: u32);
    fn mask(&self) -> u32;
    fn handle(&self, status: u32);
}

#[pin_data]
pub(crate) struct TyrIrq<T: TyrIrqTrait> {
    irq: T,
    #[pin]
    _pin: PhantomPinned,
}

impl<T: TyrIrqTrait> TyrIrq<T> {
    pub(crate) fn request<'a>(
        pdev: &'a platform::Device<Bound>,
        name: &'static CStr,
        irq: T,
    ) -> Result<impl PinInit<ThreadedRegistration<Self>, Error> + 'a> {
        let handler = try_pin_init!(Self {
            irq,
            _pin: PhantomPinned,
        });

        Ok(pdev.request_threaded_irq_by_name(Flags::SHARED, name, name, handler))
    }
}

impl<T: TyrIrqTrait> ThreadedHandler for TyrIrq<T> {
    fn handle(&self, dev: &Device<Bound>) -> ThreadedIrqReturn {
        let masked_status = self.irq.read_status(dev);

        if masked_status == 0 {
            return ThreadedIrqReturn::None;
        }
        self.irq.clear_mask(dev);
        ThreadedIrqReturn::WakeThread
    }

    fn handle_threaded(&self, dev: &Device<Bound>) -> IrqReturn {
        let mut ret = IrqReturn::None;

        loop {
            let raw_status = self.irq.read_raw_status(dev) & self.irq.mask();
            if raw_status == 0 {
                break;
            }
            self.irq.handle(raw_status);
            self.irq.clear_status(dev, raw_status);
            ret = IrqReturn::Handled;
        }

        self.irq.reenable_mask(dev);
        ret
    }
}
