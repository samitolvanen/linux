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
        PMCallbackResult,
        PMContext,
        PMOps,
        PMProfile, //
    },
    prelude::*,
    sync::{
        aref::ARef,
        atomic::{
            Acquire,
            Relaxed,
            Release, //
        },
        Arc, //
    }, //
};

use crate::{
    devfreq::{
        self,
        DevfreqSlot, //
    },
    driver::{
        TyrDrmDevice,
        TyrDrmDeviceData,
        TyrDrmRegistrationData,
        TyrPlatformDriver, //
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

/// Payload owned by the runtime PM context. It holds the DRM device the
/// callbacks act on and the devfreq registration slot shared with
/// `TyrPlatformDriverData`.
pub(crate) struct TyrPmPayload {
    pub(crate) tdev: ARef<TyrDrmDevice>,
    pub(crate) devfreq: Arc<DevfreqSlot>,
}

/// Powers the hardware components down for runtime suspend, the reverse
/// of `resume_hw_components`. Shared by runtime suspend and the
/// resume-failure unwind. The caller gates the clocks afterwards.
fn suspend_hw_components(reg_data: &TyrDrmRegistrationData<'_>) {
    let Ok(io) = reg_data.iomem.access(reg_data.pdev.as_ref()) else {
        dev_err!(
            reg_data.pdev,
            "Skipped the hardware suspend, register access failed\n"
        );
        return;
    };

    reg_data.fw.suspend(&reg_data.job_irq, io);

    // After fw.suspend() frees the firmware's AS slot, drain the idle
    // user slots while still clocked so teardown hits no gated MMIO.
    mmu::suspend(reg_data, io);

    gpu::suspend(reg_data, io);
}

/// Brings the hardware components up for runtime resume, the reverse of
/// `suspend_hw_components`.
fn resume_hw_components(
    tdev: &TyrDrmDevice,
    reg_data: &TyrDrmRegistrationData<'_>,
    reload: bool,
) -> Result {
    let io = reg_data.iomem.access(reg_data.pdev.as_ref())?;

    gpu::resume(reg_data, io)?;
    mmu::resume(reg_data, io);
    let core_clk_rate = reg_data.clks.lock().core.rate().as_hz() as u64;
    if reload {
        reg_data
            .fw
            .reload(tdev, &reg_data.job_irq, core_clk_rate, io)
    } else {
        reg_data
            .fw
            .resume(tdev, &reg_data.job_irq, core_clk_rate, io)
    }
}

/// Latches a failed resume so the tick keeps asking for another resume,
/// logging only the first failure. The PM core does not latch the
/// failure itself.
fn latch_resume_failure(
    tdev: &ARef<TyrDrmDevice>,
    reg_data: &TyrDrmRegistrationData<'_>,
    e: Error,
) -> Error {
    if sched::tick::retry_after_failed_resume(tdev) {
        dev_err!(
            reg_data.pdev,
            "Runtime resume failed, device left in the suspended state: {:?}\n",
            e
        );
    }
    e
}

/// Failure path of `resume`. The device is returned to the suspended
/// state so a later resume retries from a known point. Suspends the
/// hardware first so nothing touches the gated block.
fn fail_resume(
    tdev: &ARef<TyrDrmDevice>,
    reg_data: &TyrDrmRegistrationData<'_>,
    e: Error,
) -> Error {
    let e = latch_resume_failure(tdev, reg_data, e);
    suspend_hw_components(reg_data);
    reg_data.clks.lock().gate();
    e
}

/// Stops every driver path that reaches the GPU, then powers the hardware
/// components down. Shared by runtime suspend and unbind. A second call is
/// a no-op, since the powered-down flag latches the halt.
fn quiesce_and_suspend(tdev: &ARef<TyrDrmDevice>, reg_data: &TyrDrmRegistrationData<'_>) {
    if tdev.pm_powered_down() {
        return;
    }
    tdev.pm_powered_down.store(true, Relaxed);

    tdev.user_mmio.lock().set_powered(tdev, false);
    tdev.reset.flush();
    tdev.cancel_fw_ping();
    sched::tick::suspend(tdev, reg_data);
    // Drain any worker that raced the gate before halting the hardware.
    tdev.drain_sched_work();
    suspend_hw_components(reg_data);
}

/// Powers the GPU down for runtime suspend.
fn suspend(data: Option<&TyrPmPayload>) -> Result {
    let Some(data) = data else {
        return Ok(());
    };
    let tdev = &data.tdev;

    // Probe arms autosuspend before it registers the DRM device. Fail
    // non-latching in that window instead of recording a suspend that
    // never touched the hardware.
    let Some(guard) = tdev.registration_guard() else {
        return Err(EAGAIN);
    };

    if let Err(e) = devfreq::suspend(Some(&data.devfreq)) {
        sched::tick::resume_after_aborted_suspend(tdev);
        // Re-arm the ping watchdog that the aborted suspend may have left
        // disarmed.
        TyrDrmDeviceData::arm_fw_ping(tdev);
        return Err(e);
    }

    // Nothing below fails. Once the governor is paused, the device
    // always reaches the suspended state.
    guard.registration_data_with(|reg_data| {
        quiesce_and_suspend(tdev, reg_data);
        reg_data.clks.lock().gate();
    });
    Ok(())
}

/// Runtime resume, the reverse of `suspend`.
fn resume(data: Option<&TyrPmPayload>) -> Result {
    let Some(data) = data else {
        return Ok(());
    };
    let tdev = &data.tdev;

    // Unbind stopped the hardware and the firmware memory is about to be
    // freed, so refuse before touching any of it.
    if tdev.unbinding() {
        return Err(ENODEV);
    }

    // Probe arms autosuspend before it registers the DRM device. The device
    // is still powered in that window, so there is nothing to resume.
    let Some(guard) = tdev.registration_guard() else {
        return Ok(());
    };
    guard.registration_data_with(|reg_data| {
        // Bound so the clock guard drops before the latch takes the scheduler
        // mutex. A failed `ungate` unwinds its own clocks, so this leg skips
        // the hardware suspend.
        let ungate_res = reg_data.clks.lock().ungate();
        if let Err(e) = ungate_res {
            return Err(latch_resume_failure(tdev, reg_data, e));
        }

        // A reset recorded while the device was suspended means the firmware state
        // cannot be trusted, so complete the reset here with a full firmware
        // reload instead of the fast resident-section reboot.
        let pending_reset = tdev.reset.claim_pending();

        let hw = if pending_reset || reg_data.fw.needs_reload() {
            resume_hw_components(tdev, reg_data, true)
        } else {
            resume_hw_components(tdev, reg_data, false).or_else(|e| {
                dev_err!(
                    reg_data.pdev,
                    "Resume failed, retrying with a full firmware reload: {:?}\n",
                    e
                );
                resume_hw_components(tdev, reg_data, true)
            })
        };

        if pending_reset {
            tdev.reset.complete_claimed();
        }

        if let Err(e) = hw {
            return Err(fail_resume(tdev, reg_data, e));
        }

        // A request recorded during the reboot arrived after the earlier
        // claim, so no worker will pick it up. Complete it before the rebind.
        if tdev.reset.claim_pending() {
            let gate = tdev.reset.hw_gate();
            let reset_res = reset::run_hw_reset(tdev, reg_data, &gate);
            tdev.reset.complete_claimed();

            if let Err(e) = reset_res {
                return Err(fail_resume(tdev, reg_data, e));
            }
        }

        // The work reissued below tests this flag, so clear it first. A failed
        // resume returns before this point, and the flag stays set until a
        // later resume succeeds.
        tdev.pm_powered_down.store(false, Release);

        sched::tick::resume(tdev);

        if let Err(e) = devfreq::resume(Some(&data.devfreq)) {
            dev_warn!(reg_data.pdev, "Failed to resume devfreq: {:?}\n", e);
        }

        Ok(())
    })?;

    tdev.user_mmio.lock().set_powered(tdev, true);

    Ok(())
}

#[vtable]
impl PMOps<platform::Adapter<TyrPlatformDriver>> for TyrPmOps {
    type DeviceType = platform::Device<Bound>;
    type RuntimePayloadType = TyrPmPayload;
    type SleepData = ARef<TyrDrmDevice>;

    const SYSTEM_SLEEP: bool = true;

    fn runtime_suspend<'a>(
        _dev: &'a Self::DeviceType,
        data: Option<TyrPmPayload>,
    ) -> PMCallbackResult<TyrPmPayload> {
        match suspend(data.as_ref()) {
            Ok(()) => Ok(data),
            Err(e) => Err((data, e)),
        }
    }

    fn runtime_resume<'a>(
        _dev: &'a Self::DeviceType,
        data: Option<TyrPmPayload>,
    ) -> PMCallbackResult<TyrPmPayload> {
        match resume(data.as_ref()) {
            Ok(()) => Ok(data),
            Err(e) => Err((data, e)),
        }
    }

    fn system_resume_done(_dev: &Self::DeviceType, data: Option<&ARef<TyrDrmDevice>>) {
        let Some(tdev) = data else {
            return;
        };

        sched::tick::resume_after_system_sleep(tdev);
    }
}

/// Runs the unbind halt on a powered device.
fn halt_at_unbind(tdev: &ARef<TyrDrmDevice>) {
    // `reg` drops after this runs, so the registration is still live.
    let Some(guard) = tdev.registration_guard() else {
        return;
    };

    // The last resume armed the ping watchdog and mapped the user MMIO
    // page, so run the software steps too, not only the hardware halt.
    guard.registration_data_with(|reg_data| quiesce_and_suspend(tdev, reg_data));
}

/// Halts the hardware at platform unbind and suspends the device.
///
/// Unbind is the last point at which the driver can reach the registers.
/// The registration data drop frees the firmware sections next, and
/// devres revokes the mapping after that. The caller sets `unbinding`
/// first, so no resume can restart what this stops.
pub(crate) fn suspend_at_unbind(tdev: &TyrDrmDevice) {
    // Unbind only follows a successful probe, which publishes the
    // context.
    let Some(ctx) = tdev.pm_context() else {
        return;
    };

    // The driver core dropped its usage reference before unbind, so take
    // one for the halt and wait out any transition in flight. A suspended
    // device fails here, since the resume it needs is refused.
    let awake = ctx.get(PMProfile::new()).ok();

    let tdev = ARef::from(tdev);

    // A sticky runtime error or disabled runtime PM fails the call even
    // on a powered device. The powered-down latch inside the halt covers
    // those. Neither state allows a runtime suspend, so nothing can race
    // the halt.
    if awake.is_some() || ctx.active() {
        halt_at_unbind(&tdev);
    }

    sched::tick::unbind(&tdev);
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
    pub(crate) fn pm_context(
        &self,
    ) -> Option<&PMContext<platform::Adapter<TyrPlatformDriver>, TyrPmOps>> {
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
        self.pm_powered_down.load(Acquire)
    }

    /// Returns whether unbind has taken over the device power state.
    pub(crate) fn unbinding(&self) -> bool {
        self.unbinding.load(Relaxed)
    }

    /// Records that unbind has taken over the device power state.
    pub(crate) fn set_unbinding(&self) {
        self.unbinding.store(true, Relaxed);
    }

    /// Takes an asynchronous runtime-PM usage reference for the scheduler.
    ///
    /// Returns `None` when runtime PM is unavailable, or once unbind has
    /// begun. The caller then runs without a reference.
    pub(crate) fn sched_pm_get(&self) -> Option<AwakeScope> {
        if self.unbinding() {
            return None;
        }
        self.pm_context()?.get(ASYNC_PROFILE).ok()
    }

    /// Returns an `ActiveDevice` token if the device is powered, `None` if it
    /// is runtime suspended or a transition is in flight. The driver-owned
    /// powered-down flag vetoes the token, since unbind halts the hardware
    /// without changing the PM core's recorded state. While runtime PM is
    /// disabled that flag decides on its own, and a granted token holds no
    /// reference.
    ///
    /// Callers that program the hardware take this token instead of resuming
    /// the device. Some run in a dma-fence signalling section, where an
    /// inline resume would run the heavyweight resume callback. On `None`,
    /// callers skip the hardware access and leave the work to any later
    /// resume.
    pub(crate) fn pm_get_if_active(&self) -> Option<ActiveDevice> {
        let Some(ctx) = self.pm_context() else {
            // The device is powered for the whole probe window. The
            // window ends when probe publishes the PM context.
            return Some(ActiveDevice { _scope: None });
        };

        match ctx.get_if_active(ASYNC_PROFILE) {
            Ok(Some(scope)) => (!self.pm_powered_down()).then_some(ActiveDevice {
                _scope: Some(scope),
            }),
            Ok(None) => None,
            // `get_if_active` errors only when runtime PM is disabled, i.e.
            // under `CONFIG_PM=n` or inside the force-suspend window. A
            // disabled device reads as active, so the driver-owned
            // powered-down flag tells the two apart.
            Err(_) => (!self.pm_powered_down()).then_some(ActiveDevice { _scope: None }),
        }
    }
}
