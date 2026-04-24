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
    fw::Firmware,
    gem::BoData,
    gpu,
    gpu::GpuInfo,
    mmu::Mmu,
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

    pub(crate) fw: Arc<Firmware>,

    #[pin]
    clks: Mutex<Clocks>,

    #[pin]
    regulators: Mutex<Regulators>,

    /// Some information on the GPU.
    ///
    /// This is mainly queried by userspace, i.e.: Mesa.
    pub(crate) gpu_info: GpuInfo,
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

        firmware.boot()?;

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
        });

        Registration::new_foreign_owned(uninit_ddev, pdev.as_ref(), data, 0)?;

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
