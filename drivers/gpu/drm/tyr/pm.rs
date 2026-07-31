// SPDX-License-Identifier: GPL-2.0 or MIT

//! Runtime PM integration.
//!
//! Runtime suspend powers the GPU down and resume brings it back. The
//! callbacks run from `pm_wq` and may sleep. Scheduler paths never run
//! them inline.

use kernel::{
    device::Bound,
    platform,
    pm::{
        AwakeScope,
        PMContext,
        PMOps,
        PMProfile, //
    },
    prelude::*,
    sync::{
        atomic::ordering,
        Arc, //
    },
};

use crate::{
    devfreq::{
        self,
        DevfreqSlot, //
    },
    driver::{
        TyrDrmDeviceData,
        TyrPlatformDriverData, //
    },
    gpu,
    mmu,
    sched, //
};

/// Autosuspend delay in milliseconds.
pub(crate) const AUTOSUSPEND_DELAY_MS: u32 = 50;

/// Asynchronous get/put with autosuspend for the scheduler's usage reference.
/// Both edges sit in dma-fence signalling sections, where only the
/// asynchronous variants are safe.
const SCHED_PROFILE: PMProfile = PMProfile::new().r#async().auto();

/// Marker type implementing the runtime PM callbacks.
pub(crate) struct TyrPmOps;

/// Return shape of the runtime PM callbacks. The payload travels back to
/// the PM context on both success and failure.
type PMCallbackResult = Result<Option<Arc<DevfreqSlot>>, (Option<Arc<DevfreqSlot>>, Error)>;

/// Powers the hardware components down for runtime suspend, the reverse
/// of `resume_hw_components`. Shared by runtime suspend and the
/// resume-failure unwind. The caller gates the clocks afterwards.
fn suspend_hw_components(dev: &platform::Device<Bound>, data: Pin<&TyrPlatformDriverData>) {
    let bound = dev.as_ref();
    let tdev = &data.device;

    tdev.fw.suspend(bound, &data.job_irq);

    // After fw.suspend() frees the firmware's AS slot, drain the idle
    // user slots while still clocked so teardown hits no gated MMIO.
    mmu::suspend(dev, data);

    gpu::suspend(dev, data);
}

/// Brings the hardware components up for runtime resume, the reverse of
/// `suspend_hw_components`.
fn resume_hw_components(
    dev: &platform::Device<Bound>,
    data: Pin<&TyrPlatformDriverData>,
) -> Result {
    let tdev = &data.device;

    gpu::resume(dev, data)?;
    mmu::resume(dev, data)?;
    tdev.fw.resume(dev.as_ref(), &data.job_irq, tdev)
}

/// Powers the GPU down for runtime suspend.
fn suspend(dev: &platform::Device<Bound>, slot: Option<&DevfreqSlot>) -> Result {
    let bound = dev.as_ref();
    let data = bound.drvdata::<TyrPlatformDriverData>()?;
    let tdev = &data.device;

    if let Err(e) = devfreq::suspend(slot) {
        sched::tick::resume_after_aborted_suspend(tdev);
        return Err(e);
    }

    tdev.pm_powered_down.store(true, ordering::Relaxed);

    // Nothing below fails. Once the governor is paused, the device
    // always reaches the suspended state.
    tdev.user_mmio.lock().set_powered(tdev, false);
    sched::tick::suspend(tdev);
    // Drain any worker that raced the gate before halting the hardware.
    tdev.drain_sched_work();
    suspend_hw_components(dev, data);
    tdev.clks.lock().gate();
    Ok(())
}

/// Runtime resume, the reverse of `suspend`.
fn resume(dev: &platform::Device<Bound>, slot: Option<&DevfreqSlot>) -> Result {
    let bound = dev.as_ref();
    let data = bound.drvdata::<TyrPlatformDriverData>()?;
    let tdev = &data.device;

    tdev.clks.lock().ungate()?;

    if let Err(e) = resume_hw_components(dev, data) {
        // The PM core latches the error in `power.runtime_error` and the
        // device stays suspended until unbind. Shut the hardware down first
        // so nothing touches the gated block.
        dev_err!(
            bound,
            "Runtime resume failed, device is unusable: {:?}\n",
            e
        );
        suspend_hw_components(dev, data);
        tdev.clks.lock().gate();
        return Err(e);
    }

    // The work reissued below tests this flag, so clear it first. A failed
    // resume leaves the flag set, since the device then stays unusable until
    // unbind.
    tdev.pm_powered_down.store(false, ordering::Relaxed);

    sched::tick::resume(tdev);

    if let Err(e) = devfreq::resume(slot) {
        dev_warn!(bound, "Failed to resume devfreq: {:?}\n", e);
    }

    tdev.user_mmio.lock().set_powered(tdev, true);

    Ok(())
}

#[vtable]
impl PMOps for TyrPmOps {
    type DeviceType = platform::Device<Bound>;
    type RuntimePayloadType = Arc<DevfreqSlot>;

    const SYSTEM_SLEEP: bool = true;

    fn runtime_suspend<'a>(
        dev: &'a Self::DeviceType,
        data: Option<Arc<DevfreqSlot>>,
    ) -> PMCallbackResult {
        match suspend(dev, data.as_deref()) {
            Ok(()) => Ok(data),
            Err(e) => Err((data, e)),
        }
    }

    fn runtime_resume<'a>(
        dev: &'a Self::DeviceType,
        data: Option<Arc<DevfreqSlot>>,
    ) -> PMCallbackResult {
        match resume(dev, data.as_deref()) {
            Ok(()) => Ok(data),
            Err(e) => Err((data, e)),
        }
    }

    fn system_resume_done(dev: &Self::DeviceType) {
        let Ok(data) = dev.as_ref().drvdata::<TyrPlatformDriverData>() else {
            return;
        };

        sched::tick::resume_after_system_sleep(&data.device);
    }
}

/// Permission token for scheduler hardware access.
///
/// The `AwakeScope`-backed variant holds a usage reference that keeps the
/// device runtime-active. The reference-less variant is granted when the
/// device is powered but runtime PM cannot hold a reference.
pub(crate) struct ActiveDevice {
    _scope: Option<AwakeScope>,
}

impl TyrDrmDeviceData {
    /// Returns the runtime PM context, `None` until the end of probe.
    pub(crate) fn pm_context(&self) -> Option<&PMContext<TyrPmOps>> {
        self.pm.as_ref()
    }

    /// Returns whether the recorded runtime PM state is suspended. `false`
    /// before the end of probe, when the device is still powered.
    pub(crate) fn pm_suspended(&self) -> bool {
        self.pm_context().is_some_and(|ctx| ctx.suspended())
    }

    /// Returns whether the runtime PM callbacks have the device powered down.
    pub(crate) fn pm_powered_down(&self) -> bool {
        self.pm_powered_down.load(ordering::Relaxed)
    }

    /// Takes an asynchronous runtime-PM usage reference for the scheduler.
    ///
    /// Returns `None` when runtime PM is unavailable, in which case the caller
    /// runs without a reference.
    pub(crate) fn sched_pm_get(&self) -> Option<AwakeScope> {
        self.pm_context()?.get(SCHED_PROFILE).ok()
    }

    /// Returns an `ActiveDevice` token if the device is powered, `None` if it
    /// is runtime suspended or a transition is in flight.
    ///
    /// Scheduler paths that program the hardware call this instead of resuming
    /// the device, since a resume in a dma-fence signalling section would run
    /// the heavyweight resume callback inline. On `None`, callers skip the
    /// hardware access and rely on the resume callback to reissue a tick.
    pub(crate) fn sched_pm_get_if_active(&self) -> Option<ActiveDevice> {
        let Some(ctx) = self.pm_context() else {
            // The device is powered for the whole probe window. The
            // window ends when probe publishes the PM context.
            return Some(ActiveDevice { _scope: None });
        };

        match ctx.get_if_active(SCHED_PROFILE) {
            Ok(scope @ Some(_)) => Some(ActiveDevice { _scope: scope }),
            Ok(None) => None,
            // `get_if_active` errors only when runtime PM is disabled, i.e.
            // under `CONFIG_PM=n` or inside the force-suspend window. A
            // disabled device reads as active, so the driver-owned
            // powered-down flag tells the two apart.
            Err(_) => (!self.pm_powered_down()).then_some(ActiveDevice { _scope: None }),
        }
    }
}
