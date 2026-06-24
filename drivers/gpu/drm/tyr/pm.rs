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
    sched,
    trace, //
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

    tdev.fw.suspend(tdev, bound);
    trace::pm_hw(trace::PmHwStep::FwSuspend, 0);

    // After fw.suspend() frees the firmware's AS slot, drain the idle
    // user slots while still clocked so teardown hits no gated MMIO.
    mmu::suspend(dev, data);
    trace::pm_hw(trace::PmHwStep::MmuSuspend, 0);

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
    let fw_res = if reload {
        tdev.fw.reload(tdev)
    } else {
        tdev.fw.resume(tdev)
    };
    trace::pm_hw(
        trace::PmHwStep::FwResume,
        fw_res.as_ref().err().map_or(0, |e| e.to_errno()),
    );
    fw_res
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

/// Stops every driver path that reaches the GPU, then powers the hardware
/// components down. Shared by runtime suspend and unbind. A second call is
/// a no-op, since the powered-down flag latches the halt.
fn quiesce_and_suspend(dev: &platform::Device<Bound>, data: Pin<&TyrPlatformDriverData>) {
    let tdev = &data.device;

    // The halt below is not idempotent, so the powered-down flag doubles as
    // the latch.
    if tdev.pm_powered_down() {
        return;
    }
    tdev.pm_powered_down.store(true, ordering::Release);

    tdev.user_mmio.lock().set_powered(tdev, false);
    tdev.reset.flush();
    tdev.cancel_fw_ping();
    sched::tick::suspend(tdev);
    // Drain any worker that raced the gate before halting the hardware.
    tdev.drain_sched_work();
    suspend_hw_components(dev, data);
}

/// Powers the GPU down for runtime suspend.
fn suspend(dev: &platform::Device<Bound>, slot: Option<&DevfreqSlot>) -> Result {
    let bound = dev.as_ref();
    let data = bound.drvdata::<TyrPlatformDriverData>()?;
    let tdev = &data.device;

    trace::pm_runtime_suspend(trace::PmPhase::Begin, 0);

    let res = (|| -> Result {
        let devfreq_res = devfreq::suspend(slot);
        trace::pm_devfreq(
            trace::PmDevfreqOp::Suspend,
            devfreq_res.as_ref().err().map_or(0, |e| e.to_errno()),
        );
        if let Err(e) = devfreq_res {
            sched::tick::resume_after_aborted_suspend(tdev);
            // Re-arm the ping watchdog that the aborted suspend may have left
            // disarmed.
            TyrDrmDeviceData::arm_fw_ping(tdev);
            return Err(e);
        }

        // Nothing below fails. Once the governor is paused, the device
        // always reaches the suspended state.
        quiesce_and_suspend(dev, data);
        tdev.clks.lock().gate();
        Ok(())
    })();

    trace::pm_runtime_suspend(
        trace::PmPhase::End,
        res.as_ref().err().map_or(0, |e| e.to_errno()),
    );
    res
}

/// Runtime resume, the reverse of `suspend`.
fn resume(dev: &platform::Device<Bound>, slot: Option<&DevfreqSlot>) -> Result {
    let bound = dev.as_ref();
    let data = bound.drvdata::<TyrPlatformDriverData>()?;
    let tdev = &data.device;

    // Unbind stopped the hardware and the firmware memory is about to be
    // freed, so refuse before touching any of it.
    if tdev.unbinding() {
        return Err(ENODEV);
    }

    trace::pm_runtime_resume(trace::PmPhase::Begin, 0);

    let res = (|| -> Result {
        tdev.clks.lock().ungate()?;

        // A reset recorded while the device was suspended means the firmware
        // state cannot be trusted, so complete the reset here with a full
        // firmware reload instead of the fast resident-section reboot.
        let pending_reset = tdev.reset.claim_pending();
        if pending_reset {
            dev_info!(bound, "debug: completing latched GPU reset on resume\n");
        }

        let hw = if pending_reset || tdev.fw.needs_reload() {
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
            dev_info!(
                bound,
                "debug: completing GPU reset latched during firmware reboot\n"
            );
            let gate = tdev.reset.hw_gate();
            let reset_res = reset::run_hw_reset(tdev, bound, &tdev.iomem, &gate);
            tdev.reset.complete_claimed();

            if let Err(e) = reset_res {
                return Err(fail_resume(dev, data, e));
            }
        }

        // The work reissued below tests this flag, so clear it first. A failed
        // resume leaves the flag set, since the device then stays unusable
        // until unbind.
        tdev.pm_powered_down.store(false, ordering::Release);

        sched::tick::resume(tdev);

        let devfreq_res = devfreq::resume(slot);
        trace::pm_devfreq(
            trace::PmDevfreqOp::Resume,
            devfreq_res.as_ref().err().map_or(0, |e| e.to_errno()),
        );
        if let Err(e) = devfreq_res {
            dev_warn!(bound, "Failed to resume devfreq: {:?}\n", e);
        }

        tdev.user_mmio.lock().set_powered(tdev, true);

        Ok(())
    })();

    trace::pm_runtime_resume(
        trace::PmPhase::End,
        res.as_ref().err().map_or(0, |e| e.to_errno()),
    );
    res
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

impl TyrPlatformDriverData {
    /// Halts the hardware at platform unbind.
    ///
    /// Unbind is the last point at which the driver can reach the registers.
    /// Devres revokes the mapping right after, and the device data drop then
    /// frees the firmware sections. The caller sets `unbinding` first, so no
    /// resume can restart what this stops.
    pub(crate) fn suspend_at_unbind(dev: &platform::Device<Bound>, data: Pin<&Self>) {
        // Unbind only follows a successful probe, which publishes the
        // context.
        let Some(ctx) = data.device.pm_context() else {
            return;
        };

        // The driver core dropped its usage reference already, so pin the
        // count above zero for the rest of the function.
        let _hold = ctx.hold();

        // Wait out a transition already in flight. A suspended device fails
        // here, since the resume it needs is refused.
        let resumed = ctx.get(PMProfile::new()).is_ok();

        // A sticky runtime error or disabled runtime PM fails the call even
        // on a powered device. The powered-down latch inside the halt
        // covers those.
        if !resumed && !ctx.active() {
            return;
        }

        // A resume here re-arms the ping watchdog and remaps the user MMIO
        // page, so run the software steps too, not only the hardware halt.
        quiesce_and_suspend(dev, data);
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
        self.pm_powered_down.load(ordering::Acquire)
    }

    /// Returns whether unbind has taken over the device power state.
    pub(crate) fn unbinding(&self) -> bool {
        self.unbinding.load(ordering::Relaxed)
    }

    /// Records that unbind has taken over the device power state.
    pub(crate) fn set_unbinding(&self) {
        self.unbinding.store(true, ordering::Relaxed);
    }

    /// Takes an asynchronous runtime-PM usage reference for the scheduler.
    ///
    /// Returns `None` when runtime PM is unavailable, in which case the caller
    /// runs without a reference.
    pub(crate) fn sched_pm_get(&self) -> Option<AwakeScope> {
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
