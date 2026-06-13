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
    reset,
    sched, //
};

/// Autosuspend delay in milliseconds.
pub(crate) const AUTOSUSPEND_DELAY_MS: u32 = 50;

/// Asynchronous get/put with autosuspend. Some callers run inside
/// dma-fence signalling sections, where only the asynchronous variants
/// are safe.
const ASYNC_PROFILE: PMProfile = PMProfile::new().r#async().auto();

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
    reload: bool,
) -> Result {
    let tdev = &data.device;

    gpu::resume(dev, data)?;
    mmu::resume(dev, data)?;
    if reload {
        tdev.fw.reload(tdev)
    } else {
        tdev.fw.resume(dev.as_ref(), &data.job_irq, tdev)
    }
}

/// Failure path of `resume`. The PM core records the error in
/// `power.runtime_error` and the device stays suspended. Suspends the
/// hardware first so nothing touches the gated block.
fn fail_resume(
    dev: &platform::Device<Bound>,
    data: Pin<&TyrPlatformDriverData>,
    e: Error,
) -> Error {
    dev_err!(
        dev.as_ref(),
        "Runtime resume failed, device is unusable: {:?}\n",
        e
    );
    suspend_hw_components(dev, data);
    data.device.clks.lock().gate();
    e
}

/// Powers the GPU down for runtime suspend.
fn suspend(dev: &platform::Device<Bound>, slot: Option<&DevfreqSlot>) -> Result {
    let bound = dev.as_ref();
    let data = bound.drvdata::<TyrPlatformDriverData>()?;
    let tdev = &data.device;

    if let Err(e) = devfreq::suspend(slot) {
        sched::tick::resume_after_aborted_suspend(tdev);
        // Re-arm the ping watchdog that the aborted suspend may have left
        // disarmed.
        TyrDrmDeviceData::arm_fw_ping(tdev);
        return Err(e);
    }

    tdev.pm_powered_down.store(true, ordering::Relaxed);

    // Nothing below fails. Once the governor is paused, the device
    // always reaches the suspended state.
    tdev.user_mmio.lock().set_powered(tdev, false);

    tdev.reset.flush();

    tdev.cancel_fw_ping();

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

    // A reset recorded while the device was suspended means the firmware state
    // cannot be trusted, so complete the reset here with a full firmware
    // reload instead of the fast resident-section reboot.
    let pending_reset = tdev.reset.claim_pending();

    let hw = if pending_reset {
        resume_hw_components(dev, data, true)
    } else {
        resume_hw_components(dev, data, false).or_else(|e| {
            dev_err!(
                bound,
                "Resume failed, retrying with a full firmware reload: {:?}\n",
                e
            );
            resume_hw_components(dev, data, true)
        })
    };

    if pending_reset {
        tdev.reset.complete_claimed();
    }

    if let Err(e) = hw {
        return Err(fail_resume(dev, data, e));
    }

    // A request recorded during the reboot arrived after the earlier
    // claim, so no worker will pick it up. Complete it before the rebind.
    if tdev.reset.claim_pending() {
        let gate = tdev.reset.hw_gate();
        let reset_res = reset::run_hw_reset(tdev, bound, &tdev.iomem, &gate);
        tdev.reset.complete_claimed();

        if let Err(e) = reset_res {
            return Err(fail_resume(dev, data, e));
        }
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

/// Permission token for hardware access.
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

    /// Returns whether the recorded runtime PM state is active, i.e. the
    /// device is powered with no transition in flight. `true` before the
    /// end of probe, when the device is still powered.
    pub(crate) fn pm_active(&self) -> bool {
        self.pm_context().is_none_or(|ctx| ctx.active())
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
        self.pm_context()?.get(ASYNC_PROFILE).ok()
    }

    /// Returns an `ActiveDevice` token if the device is powered, `None` if it
    /// is runtime suspended or a transition is in flight. While runtime PM is
    /// disabled, the driver-owned powered-down flag decides the outcome, and
    /// a granted token holds no reference.
    ///
    /// Callers that program the hardware take this token instead of resuming
    /// the device. Some run in a dma-fence signalling section, where an
    /// inline resume would run the heavyweight resume callback. On `None`,
    /// callers skip the hardware access and rely on the resume path to
    /// reissue the work.
    pub(crate) fn pm_get_if_active(&self) -> Option<ActiveDevice> {
        let Some(ctx) = self.pm_context() else {
            // The device is powered for the whole probe window. The
            // window ends when probe publishes the PM context.
            return Some(ActiveDevice { _scope: None });
        };

        match ctx.get_if_active(ASYNC_PROFILE) {
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
