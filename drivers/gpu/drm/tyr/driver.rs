// SPDX-License-Identifier: GPL-2.0 or MIT

use core::marker::PhantomPinned;

use kernel::c_str;
use kernel::clk::Clk;
use kernel::clk::OptionalClk;
use kernel::device;
use kernel::device::Bound;
use kernel::device::Core;
use kernel::device::Device;
use kernel::devres::Devres;
use kernel::dma::{Device as DmaDevice, DmaMask};
use kernel::dma_fence::DmaFenceWork;
use kernel::dma_fence::DmaFenceWorkqueue;
use kernel::drm;
use kernel::drm::ioctl;
use kernel::irq::IrqReturn;
use kernel::irq::ThreadedHandler;
use kernel::irq::ThreadedIrqReturn;
use kernel::irq::ThreadedRegistration;
use kernel::new_delayed_work;
use kernel::new_dma_fence_work;
use kernel::new_mutex;
use kernel::of;
use kernel::opp;
use kernel::platform;
use kernel::prelude::*;
use kernel::regulator;
use kernel::regulator::Regulator;
use kernel::sizes::SZ_2M;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::time;
use kernel::types::ARef;
use kernel::workqueue::DelayedWork;
use kernel::workqueue::OwnedQueue;
use kernel::workqueue::WqFlags;
use pin_init::pin_init_from_closure;

use crate::file::File;
use crate::fw;
use crate::fw::irq::JobIrq;
use crate::fw::Firmware;
use crate::gem::TyrObject;
use crate::gpu;
use crate::gpu::irq::GpuIrq;
use crate::gpu::GpuInfo;
use crate::mmu;
use crate::mmu::irq::MmuIrq;
use crate::mmu::Mmu;
use crate::new_wait;
use crate::regs;
use crate::sched::Scheduler;
use crate::sched::SchedulerState;
use crate::wait::Wait;
use crate::wait::WaitResult;

pub(crate) type IoMem = kernel::io::mem::IoMem<SZ_2M>;

/// Convenience type alias for the DRM device type for this driver.
pub(crate) type TyrDevice = drm::Device<TyrDriver>;

#[pin_data(PinnedDrop)]
pub(crate) struct TyrDriver {
    device: ARef<TyrDevice>,

    #[pin]
    gpu_irq: ThreadedRegistration<TyrIrq<GpuIrq>>,

    #[pin]
    mmu_irq: ThreadedRegistration<TyrIrq<MmuIrq>>,

    #[pin]
    job_irq: ThreadedRegistration<TyrIrq<JobIrq>>,
}

#[pin_data(PinnedDrop)]
pub(crate) struct TyrData {
    pub(crate) pdev: ARef<platform::Device>,

    #[pin]
    clks: Mutex<Clocks>,

    #[pin]
    regulators: Mutex<Regulators>,

    /// Some information on the GPU.
    ///
    /// This is mainly queried by userspace, i.e.: Mesa.
    pub(crate) gpu_info: GpuInfo,

    /// CSIF information that gets populated after firmware initialization.
    /// Kept separate with a mutex since it's populated later.
    #[pin]
    pub(crate) csif_info: Mutex<gpu::CsifInfo>,

    /// The firmware running on the MCU.
    #[pin]
    pub(crate) fw: Firmware,

    /// True if the CPU/GPU are memory coherent.
    pub(crate) coherent: bool,

    /// MMU management.
    mmu: Pin<KBox<Mutex<Mmu>>>,

    /// The MMIO region.
    pub(crate) iomem: Arc<Devres<IoMem>>,

    /// Physical address of the MMIO region.
    pub(crate) mmio_phys_addr: u64,

    /// The firmware ping work.
    #[pin]
    pub(crate) ping_work: DelayedWork<Self, 0>,

    /// The scheduler logic.
    #[pin]
    sched: Mutex<SchedulerState>,

    #[pin]
    pub(crate) tick_work: DmaFenceWork<Self, 1>,

    #[pin]
    pub(crate) fw_events_work: DmaFenceWork<Self, 2>,

    /// The work to process group status updates.
    #[pin]
    pub(crate) group_upd_work: DmaFenceWork<Self, 3>,

    /// Workqueue shared by all job queues in this device.
    pub(crate) wq: Arc<DmaFenceWorkqueue>,

    pub(crate) reset_wq: OwnedQueue,
}

impl TyrData {
    /// Execute a function with the scheduler locked.
    ///
    /// This is implemented as a closure to reduce the scope of the scheduler
    /// lock.
    pub(crate) fn with_locked_scheduler<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Scheduler) -> Result<R>,
    {
        let mut sched = self.sched.lock();
        f(sched.enabled_mut()?)
    }

    /// Execute a function with the mmu locked.
    ///
    /// This is implemented as a closure to reduce the scope of the mmu
    /// lock.
    pub(crate) fn with_locked_mmu<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Mmu) -> Result<R>,
    {
        let mut mmu = self.mmu.lock();
        f(&mut mmu)
    }
}

// Both `Clk` and `Regulator` do not implement `Send` or `Sync`, but they
// should. There are patches on the mailing list to address this, but they have
// not landed yet.
//
// For now, add this workaround so that this patch compiles with the promise
// that it will be removed in a future patch.
//
// SAFETY: This will be removed in a future patch.
unsafe impl Send for TyrData {}
// SAFETY: This will be removed in a future patch.
unsafe impl Sync for TyrData {}

fn issue_soft_reset(dev: &Device<Bound>, iomem: &Devres<IoMem>) -> Result {
    regs::GPU_CMD.write(dev, iomem, regs::GPU_CMD_SOFT_RESET)?;

    // TODO: We cannot poll, as there is no support in Rust currently, so we
    // sleep. Change this when read_poll_timeout() is implemented in Rust.
    kernel::time::delay::fsleep(time::Delta::from_millis(100));

    if regs::GPU_IRQ_RAWSTAT.read(dev, iomem)? & regs::GPU_IRQ_RAWSTAT_RESET_COMPLETED == 0 {
        dev_err!(dev, "GPU reset failed with errno\n");
        dev_err!(
            dev,
            "GPU_INT_RAWSTAT is {}\n",
            regs::GPU_IRQ_RAWSTAT.read(dev, iomem)?
        );

        return Err(EIO);
    }

    Ok(())
}

fn set_maximum_opp(pdev: &ARef<platform::Device>) {
    match opp::Table::from_of(&pdev.as_ref().into(), 0) {
        Ok(table) => {
            match table.opp_from_freq(
                kernel::clk::Hertz(kernel::ffi::c_ulong::MAX),
                Some(true), // Only consider available (enabled) OPPs
                None,       // Use default clock index (0)
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

kernel::of_device_table!(
    OF_TABLE,
    MODULE_OF_TABLE,
    <TyrDriver as platform::Driver>::IdInfo,
    [
        (of::DeviceId::new(c_str!("rockchip,rk3588-mali")), ()),
        (of::DeviceId::new(c_str!("arm,mali-valhall-csf")), ())
    ]
);

impl platform::Driver for TyrDriver {
    type IdInfo = ();
    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);

    fn probe(
        pdev: &platform::Device<Core>,
        _info: Option<&Self::IdInfo>,
    ) -> Result<Pin<KBox<Self>>> {
        let core_clk = Clk::get(pdev.as_ref(), Some(c_str!("core")))?;
        let stacks_clk = OptionalClk::get(pdev.as_ref(), Some(c_str!("stacks")))?;
        let coregroup_clk = OptionalClk::get(pdev.as_ref(), Some(c_str!("coregroup")))?;

        core_clk.prepare_enable()?;
        stacks_clk.prepare_enable()?;
        coregroup_clk.prepare_enable()?;

        let mali_regulator = Regulator::<regulator::Enabled>::get(pdev.as_ref(), c_str!("mali"))?;
        let sram_regulator = Regulator::<regulator::Enabled>::get(pdev.as_ref(), c_str!("sram"))?;

        let io_resource = pdev.io_request_by_index(0).ok_or(EINVAL)?;
        let mmio_phys_addr = io_resource.start();

        let iomem = Arc::pin_init(IoMem::new(io_resource), GFP_KERNEL)?;

        issue_soft_reset(pdev.as_ref(), &iomem)?;
        gpu::l2_power_on(pdev.as_ref(), &iomem)?;

        let gpu_info = GpuInfo::new(pdev.as_ref(), &iomem)?;
        gpu_info.log(pdev);

        unsafe {
            pdev.dma_set_max_seg_size(u32::MAX);
            pdev.dma_set_mask_and_coherent(DmaMask::try_new(gpu_info.pa_bits())?)?;
        }
        let platform: ARef<platform::Device> = pdev.into();

        // Set GPU to maximum performance operating point
        // This ensures the GPU runs at the highest frequency for best
        // performance while we don't have any power management code in place.
        set_maximum_opp(&platform);

        // SAFETY: This should be safe as data is not touched by the driver
        // untill it gets fully initialised.
        // Additionally implementation of Drop trait is still pending
        // so no data will be accessed util proper init.
        let uninit =
            unsafe { pin_init_from_closure::<TyrData, kernel::error::Error>(|_slot| Ok(())) };
        let data = Arc::pin_init(uninit, GFP_KERNEL)?;
        let tdev: ARef<TyrDevice> = drm::Device::new(pdev.as_ref(), Ok(data.clone()))?;

        let mmu = KBox::pin_init(new_mutex!(Mmu::new()?), GFP_KERNEL)?;

        let fw_event_wait = Wait::new()?;
        let fw_boot_wait = new_wait!()?;
        let job_wq = Arc::new(
            DmaFenceWorkqueue::new(
                c_str!("tyr-job-queue"),
                WqFlags::UNBOUND | WqFlags::MEM_RECLAIM,
                0,
            )?,
            GFP_KERNEL,
        )?;
        let fw = Firmware::init(
            &tdev,
            pdev,
            &gpu_info,
            mmu.as_ref(),
            iomem.clone(),
            fw_event_wait.clone(),
            job_wq.clone(),
        )?;

        // Ideally we'd find a way around this useless clone too...
        let i = iomem.clone();
        let reset_wq = OwnedQueue::new(c_str!("tyr-reset"), WqFlags::UNBOUND, 0)?; // TODO: add WqFlags::ORDERED once it's available.
        let data_init = try_pin_init!(TyrData {
                pdev: platform.clone(),
                clks <- new_mutex!(Clocks {
                    core: core_clk,
                    stacks: stacks_clk,
                    coregroup: coregroup_clk,
                }),
                regulators <- new_mutex!(Regulators {
                    mali: mali_regulator,
                    sram: sram_regulator,
                }),
                gpu_info,
                csif_info <- new_mutex!(gpu::CsifInfo::default()),
                fw <- fw,
                coherent: false, // TODO. The GPU is not IO coherent on rk3588, which is what I am testing on.
                mmu,
                iomem: i,
                mmio_phys_addr,
                ping_work <- new_delayed_work!("tyr-ping-work"),
                sched <- new_mutex!(SchedulerState::Disabled),
                tick_work <- new_dma_fence_work!("tyr_tick"),
                fw_events_work <- new_dma_fence_work!("tyr-fw-events"),
                group_upd_work <- new_dma_fence_work!("tyr-group-upd"),
                wq: job_wq,
                reset_wq,
        });

        unsafe {
            data_init.__pinned_init(Arc::<TyrData>::as_ptr(&tdev) as *mut TyrData)?;
        }

        // We must find a way around this. It's being discussed on Zulip already.
        //
        // Note that this is a problem, because if we fail at probe, then the
        // drop code expects the data to be set, which leads to a crash.
        drm::driver::Registration::new_foreign_owned(&tdev, pdev.as_ref(), 0)?;

        let poweron_wait = Wait::new_with_data(false)?;
        let pow = poweron_wait.clone();

        let t = tdev.clone();
        let i = iomem.clone();
        let fwe = fw_event_wait.clone();
        let fbbw = fw_boot_wait.clone();
        let driver = KBox::pin_init(
            try_pin_init!(TyrDriver {
                device: t.clone(),
                gpu_irq <- gpu::irq::gpu_irq_init(t.clone(), pdev, i.clone(), pow)?,
                mmu_irq <- mmu::irq::mmu_irq_init(t.clone(), pdev, i.clone())?,
                job_irq <- fw::irq::job_irq_init(t.clone(), pdev, i.clone(), fwe.clone(), fbbw.clone())?,
            }),
            GFP_KERNEL,
        )?;

        poweron_wait.wait_interruptible_timeout(100, |powered_on| {
            if *powered_on {
                Ok(WaitResult::Ok)
            } else {
                Ok(WaitResult::Retry)
            }
        })?;

        regs::MCU_CONTROL.write(pdev.as_ref(), &tdev.iomem, regs::MCU_CONTROL_AUTO)?;

        let gpu_info = &tdev.gpu_info;
        let core_clk = &tdev.clks.lock().core;

        fw_boot_wait.clone().wait_interruptible_timeout(100, |()| {
            tdev.fw.with_locked_global_iface(|glb| {
                if glb.booted() {
                    glb.enable(&tdev, gpu_info, core_clk)?;
                    Ok(WaitResult::Ok)
                } else {
                    Ok(WaitResult::Retry)
                }
            })
        })?;

        tdev.sched.lock().init(&tdev.clone())?;

        // We need this to be dev_info!() because dev_dbg!() does not work at
        // all in Rust for now, and we need to see whether probe succeeded.
        dev_info!(pdev.as_ref(), "Tyr initialized correctly.\n");

        Ok(driver)
    }
}

#[pinned_drop]
impl PinnedDrop for TyrDriver {
    fn drop(self: Pin<&mut Self>) {
        // XXX: we will not have the `data` field here if we failed the
        // initialization, i.e.: if probe failed.
        //
        // We need to figure out with the community how to properly split the
        // creation of a DRM device from the place where the data is set and
        // from the place where it is registered to overcome this.
        //
        // The current solution, i.e.: `new_from_closure` is just a hack, and it
        // shows its shortcomings here, for example.
        //
        // dev_dbg!(self.device.data().pdev.as_ref(), "Removed Tyr.\n");
    }
}

#[pinned_drop]
impl PinnedDrop for TyrData {
    fn drop(self: Pin<&mut Self>) {
        // TODO: the type-state pattern for Clks will fix this.
        let clks = self.clks.lock();
        clks.core.disable_unprepare();
        clks.stacks.disable_unprepare();
        clks.coregroup.disable_unprepare();
    }
}

// We need to retain the name "panthor" to achieve drop-in compatibility with
// the C driver in the userspace stack.
const INFO: drm::DriverInfo = drm::DriverInfo {
    major: 1,
    minor: 5,
    patchlevel: 0,
    name: c_str!("panthor"),
    desc: c_str!("ARM Mali Tyr DRM driver"),
};

#[vtable]
impl drm::Driver for TyrDriver {
    type Data = Arc<TyrData>;
    type File = File;
    type Object = drm::gem::shmem::Object<TyrObject>;

    const INFO: drm::DriverInfo = INFO;

    kernel::declare_drm_ioctls! {
        (PANTHOR_DEV_QUERY, drm_panthor_dev_query, ioctl::RENDER_ALLOW, File::dev_query),
        (PANTHOR_VM_CREATE, drm_panthor_vm_create, ioctl::RENDER_ALLOW, File::vm_create),
        (PANTHOR_VM_DESTROY, drm_panthor_vm_destroy, ioctl::RENDER_ALLOW, File::vm_destroy),
        (PANTHOR_VM_BIND, drm_panthor_vm_bind, ioctl::RENDER_ALLOW, File::vm_bind),
        (PANTHOR_VM_GET_STATE, drm_panthor_vm_get_state, ioctl::RENDER_ALLOW, File::vm_get_state),
        (PANTHOR_BO_CREATE, drm_panthor_bo_create, ioctl::RENDER_ALLOW, File::bo_create),
        (PANTHOR_BO_MMAP_OFFSET, drm_panthor_bo_mmap_offset, ioctl::RENDER_ALLOW, File::bo_mmap_offset),
        (PANTHOR_GROUP_CREATE, drm_panthor_group_create, ioctl::RENDER_ALLOW, File::group_create),
        (PANTHOR_GROUP_DESTROY, drm_panthor_group_destroy, ioctl::RENDER_ALLOW, File::group_destroy),
        (PANTHOR_GROUP_SUBMIT, drm_panthor_group_submit, ioctl::RENDER_ALLOW, File::group_submit),
        (PANTHOR_GROUP_GET_STATE, drm_panthor_group_get_state, ioctl::RENDER_ALLOW, File::group_get_state),
        (PANTHOR_TILER_HEAP_CREATE, drm_panthor_tiler_heap_create, ioctl::RENDER_ALLOW, File::heap_create),
        (PANTHOR_TILER_HEAP_DESTROY, drm_panthor_tiler_heap_destroy, ioctl::RENDER_ALLOW, File::heap_destroy),
    }

    fn mmap(
        device: &TyrDevice,
        file: &drm::File<File>,
        vma: &kernel::mm::virt::VmaNew,
    ) -> Option<Result>
    where
        Self: Sized,
    {
        crate::mmap::mmap(device, &*file.inner(), vma)
    }
}

#[pin_data]
struct Clocks {
    core: Clk,
    stacks: OptionalClk,
    coregroup: OptionalClk,
}

#[pin_data]
struct Regulators {
    mali: Regulator<regulator::Enabled>,
    sram: Regulator<regulator::Enabled>,
}

pub(crate) trait TyrIrqTrait: Sync {
    /// Reads the interrupt status register.
    fn read_status(&self, dev: &Device<Bound>) -> u32;

    /// Disable all device interrupts for the interrupt line.
    ///
    /// Needed so we can disable the top part while the threaded handler runs.
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
    fn handle(&self, tdev: &TyrDevice, status: u32);
}

#[pin_data]
pub(crate) struct TyrIrq<T: TyrIrqTrait> {
    tdev: ARef<TyrDevice>,
    irq: T,
    #[pin]
    _pin: PhantomPinned,
}

impl<T: TyrIrqTrait + 'static> TyrIrq<T> {
    pub(crate) fn request<'a>(
        pdev: &'a platform::Device<device::Bound>,
        tdev: ARef<TyrDevice>,
        name: &'static CStr,
        irq_type: T,
    ) -> Result<impl PinInit<ThreadedRegistration<Self>, Error> + 'a> {
        let handler = try_pin_init!(Self {
            tdev,
            irq: irq_type,
            _pin: PhantomPinned,
        });

        pdev.request_threaded_irq_by_name(kernel::irq::Flags::SHARED, name, name, handler)
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
