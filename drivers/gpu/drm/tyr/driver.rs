// SPDX-License-Identifier: GPL-2.0 or MIT

use core::marker::PhantomPinned;
use core::pin::Pin;

use kernel::bits::bit_u32;
use kernel::c_str;
use kernel::clk::Clk;
use kernel::device;
use kernel::device::Core;
use kernel::devres::Devres;
use kernel::dma::{Device, DmaMask};
use kernel::drm;
use kernel::drm::ioctl;
use kernel::io;
use kernel::io::mem::IoMem;
use kernel::irq::request::IrqReturn;
use kernel::irq::request::ThreadedIrqReturn;
use kernel::irq::ThreadedHandler;
use kernel::irq::ThreadedRegistration;
use kernel::new_delayed_work;
use kernel::new_mutex;
use kernel::new_work;
use kernel::of;
use kernel::platform;
use kernel::prelude::*;
use kernel::regulator;
use kernel::regulator::Regulator;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::time;
use kernel::types::ARef;
use kernel::workqueue::DelayedWork;
use kernel::workqueue::OwnedQueue;
use kernel::workqueue::Work;
use kernel::workqueue::WqFlags;

use pin_init::pin_init_from_closure;

use crate::file::File;
use crate::fw;
use crate::fw::irq::JobIrq;
use crate::fw::Firmware;
use crate::gpu;
use crate::gpu::irq::GpuIrq;
use crate::gpu::GpuInfo;
use crate::mmu;
use crate::mmu::irq::MmuIrq;
use crate::mmu::Mmu;
use crate::regs::*;
use crate::sched::Scheduler;
use crate::sched::SchedulerState;
use crate::wait::Wait;
use crate::wait::WaitResult;

/// Convienence type alias for the DRM device type for this driver
pub(crate) type TyrDevice = drm::device::Device<TyrDriver>;

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

#[pin_data]
pub(crate) struct TyrData {
    pub(crate) pdev: ARef<platform::Device>,

    #[pin]
    clks: Mutex<Clocks>,

    #[pin]
    regulators: Mutex<Regulators>,

    // Some inforation on the GPU. This is mainly queried by userspace (mesa).
    pub(crate) gpu_info: GpuInfo,

    /// The firmware running on the MCU.
    #[pin]
    pub(crate) fw: Firmware,

    /// True if the CPU/GPU are memory coherent.
    pub(crate) coherent: bool,

    /// MMU management.
    mmu: Pin<KBox<Mutex<Mmu>>>,

    /// The MMIO region.
    pub(crate) iomem: Arc<Devres<IoMem>>,

    /// The firmware ping work.
    #[pin]
    pub(crate) ping_work: DelayedWork<Self, 0>,

    /// The scheduler logic.
    #[pin]
    sched: Mutex<SchedulerState>,

    #[pin]
    pub(crate) tick_work: Work<Self, 1>,

    #[pin]
    pub(crate) fw_events_work: Work<Self, 2>,

    /// The work to process group status updates.
    #[pin]
    pub(crate) group_upd_work: Work<Self, 3>,

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

unsafe impl Send for TyrData {}
unsafe impl Sync for TyrData {}

fn issue_soft_reset(iomem: &Devres<IoMem<0>>) -> Result<()> {
    let irq_enable_cmd = 1 | bit_u32(8);
    GPU_CMD.write(iomem, irq_enable_cmd)?;

    let op = || GPU_INT_RAWSTAT.read(iomem);
    let cond = |raw_stat: &u32| -> bool { (*raw_stat >> 8) & 1 == 1 };
    let res = io::poll::read_poll_timeout(
        op,
        cond,
        time::Delta::from_millis(100),
        time::Delta::from_micros(20000),
    );

    if let Err(e) = res {
        pr_err!("GPU reset failed with errno {}\n", e.to_errno());
        pr_err!("GPU_INT_RAWSTAT is {}\n", GPU_INT_RAWSTAT.read(iomem)?);
    }

    Ok(())
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
        dev_dbg!(pdev.as_ref(), "Probed Tyr\n");

        let core_clk = Clk::get(pdev.as_ref(), Some(c_str!("core")))?;
        let stacks_clk = Clk::get(pdev.as_ref(), Some(c_str!("stacks")))?;
        let coregroup_clk = Clk::get(pdev.as_ref(), Some(c_str!("coregroup")))?;

        core_clk.prepare_enable()?;
        stacks_clk.prepare_enable()?;
        coregroup_clk.prepare_enable()?;

        let mali_regulator = Regulator::<regulator::Enabled>::get(
            pdev.as_ref(),
            c_str!("mali"),
        )?;
        let sram_regulator = Regulator::<regulator::Enabled>::get(
            pdev.as_ref(),
            c_str!("sram"),
        )?;

        let iomem = Arc::pin_init(
            IoMem::new(pdev.io_request_by_index(0).ok_or(EINVAL)?),
            GFP_KERNEL,
        )?;

        issue_soft_reset(&iomem)?;
        gpu::l2_power_on(&iomem)?;

        let gpu_info = GpuInfo::new(&iomem)?;
        gpu_info.log(pdev);

        unsafe {
            pdev.dma_set_max_seg_size(u32::MAX);
            pdev.dma_set_mask_and_coherent(DmaMask::try_new(
                gpu_info.pa_bits(),
            )?)?;
        }
        let platform: ARef<platform::Device> = pdev.into();

        //TODO: This is very temporary
        // SAFETY: This should be safe as data is not touched by the driver
        // untill it gets fully initialised.
        // Additionally implementation of Drop trait is still pending
        // so no data will be accessed util proper init.
	let uninit = unsafe {
	    pin_init_from_closure::<TyrData, kernel::error::Error>(|_slot| Ok(()))
	};
	let data = Arc::pin_init(uninit, GFP_KERNEL)?;
	let tdev: ARef<TyrDevice> = drm::device::Device::new(pdev.as_ref(), Ok(data.clone()))?;

        let mmu = KBox::pin_init(new_mutex!(Mmu::new()?), GFP_KERNEL)?;

        let fw_event_wait = Wait::new()?;
        let fw_boot_wait = Wait::new()?;
        let fw = Firmware::init(
            &tdev,
            pdev,
            &gpu_info,
            mmu.as_ref(),
            iomem.clone(),
            fw_event_wait.clone(),
        )?;

        // Ideally we'd find a way around this useless clone too...
        let i = iomem.clone();
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
                fw <- fw,
                coherent: false, // TODO. The GPU is not IO coherent on rk3588, which is what I am testing on.
                mmu,
                iomem: i,
                ping_work <- new_delayed_work!("tyr-ping-work"),
                sched <- new_mutex!(SchedulerState::Disabled),
                tick_work <- new_work!("tyr_tick"),
                fw_events_work <- new_work!("tyr-fw-events"),
                group_upd_work <- new_work!("tyr-group-upd"),
                reset_wq: OwnedQueue::new(c_str!("tyr-reset"), WqFlags::UNBOUND, 0)? // TODO: add WqFlags::ORDERED once it's available.
        });

        unsafe {
            data_init
                .__pinned_init(Arc::<TyrData>::as_ptr(&tdev) as *mut TyrData)?;
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

        MCU_CONTROL.write(&iomem, MCU_CONTROL_AUTO)?;

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

const INFO: drm::driver::DriverInfo = drm::driver::DriverInfo {
    major: 0,
    minor: 0,
    patchlevel: 0,
    name: c_str!("tyr"),
    desc: c_str!("ARM Mali CSF-based GPU driver"),
};

#[vtable]
impl drm::driver::Driver for TyrDriver {
    type Data = Arc<TyrData>;
    type File = File;
    type Object = crate::gem::DriverObject;

    const INFO: drm::driver::DriverInfo = INFO;

    // TODO: missing feature SYNC_OBJ

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
    }
}

#[pin_data]
struct Clocks {
    core: Clk,
    stacks: Clk,
    coregroup: Clk,
}

#[pin_data]
struct Regulators {
    mali: Regulator<regulator::Enabled>,
    sram: Regulator<regulator::Enabled>,
}

pub(crate) trait TyrIrqTrait: Sync {
    /// Reads the interrupt status register.
    fn read_status(&self) -> u32;

    /// Disable all device interrupts for the interrupt line.
    ///
    /// Needed so we can disable the top part while the threaded handler runs.
    fn disable_all(&self);

    /// Reenable the interrupts after the threaded handler has run.
    fn reenable(&self);

    /// Reads the raw interrupt status register.
    fn read_raw_status(&self) -> u32;

    /// Clears the interrupt status.
    fn clear_status(&self, status: u32);

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

        pdev.request_threaded_irq_by_name(
            kernel::irq::Flags::SHARED,
            name,
            name,
            handler,
        )
    }
}

impl<T: TyrIrqTrait> ThreadedHandler for TyrIrq<T> {
    fn handle(&self) -> kernel::irq::request::ThreadedIrqReturn {
        let int_stat = self.irq.read_status();

        if int_stat == 0 {
            return ThreadedIrqReturn::None;
        }

        self.irq.disable_all();
        ThreadedIrqReturn::WakeThread
    }

    fn handle_threaded(&self) -> kernel::irq::request::IrqReturn {
        let mut ret = IrqReturn::None;

        loop {
            let int_stat = self.irq.read_raw_status() & self.irq.mask();

            if int_stat == 0 {
                break;
            }

            self.irq.clear_status(int_stat);
            self.irq.handle(&self.tdev, int_stat);
            ret = IrqReturn::Handled;
        }

        self.irq.reenable();
        ret
    }
}
