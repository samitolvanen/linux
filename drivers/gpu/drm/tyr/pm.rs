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
        atomic::Relaxed,
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
fn resume_hw_components(reg_data: &TyrDrmRegistrationData<'_>) -> Result {
    let io = reg_data.iomem.access(reg_data.pdev.as_ref())?;

    gpu::resume(reg_data, io)?;
    mmu::resume(reg_data, io);
    let core_clk_rate = reg_data.clks.lock().core.rate().as_hz() as u64;
    reg_data.fw.resume(&reg_data.job_irq, core_clk_rate, io)
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
        return Err(e);
    }

    // Nothing below fails. Once the governor is paused, the device
    // always reaches the suspended state.
    tdev.user_mmio.lock().set_powered(tdev, false);

    guard.registration_data_with(|reg_data| {
        sched::tick::suspend(tdev, reg_data);
        // Drain any worker that raced the gate before halting the hardware.
        tdev.drain_sched_work();
        suspend_hw_components(reg_data);
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

        if let Err(e) = resume_hw_components(reg_data) {
            // The unwind returns the hardware to the suspended state so a
            // later resume retries from a known point.
            let e = latch_resume_failure(tdev, reg_data, e);
            suspend_hw_components(reg_data);
            reg_data.clks.lock().gate();
            return Err(e);
        }

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
            // disabled device reads as active, so the driver-owned flag tells
            // the two apart.
            Err(_) => {
                (!self.sched_suspended.load(Relaxed)).then_some(ActiveDevice { _scope: None })
            }
        }
    }
}
