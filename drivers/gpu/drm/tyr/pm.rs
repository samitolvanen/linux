// SPDX-License-Identifier: GPL-2.0 or MIT

//! Runtime PM integration.
//!
//! The runtime callbacks suspend and resume devfreq. Clock, regulator,
//! and MCU handling stays out of them.

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
    driver::TyrDrmDeviceData, //
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

#[vtable]
impl PMOps for TyrPmOps {
    type DeviceType = platform::Device<Bound>;
    type RuntimePayloadType = Arc<DevfreqSlot>;

    fn runtime_suspend<'a>(
        _dev: &'a Self::DeviceType,
        data: Option<Arc<DevfreqSlot>>,
    ) -> PMCallbackResult {
        match devfreq::suspend(data.as_deref()) {
            Ok(()) => Ok(data),
            Err(e) => Err((data, e)),
        }
    }

    fn runtime_resume<'a>(
        _dev: &'a Self::DeviceType,
        data: Option<Arc<DevfreqSlot>>,
    ) -> PMCallbackResult {
        match devfreq::resume(data.as_deref()) {
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
    pub(crate) fn pm_context(&self) -> Option<&PMContext<TyrPmOps>> {
        self.pm.as_ref()
    }

    /// Returns whether the recorded runtime PM state is suspended. `false`
    /// before the end of probe, when the device is still powered.
    #[expect(dead_code)]
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
    #[expect(dead_code)]
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
            Err(_) => (!self.sched_suspended.load(ordering::Relaxed))
                .then_some(ActiveDevice { _scope: None }),
        }
    }
}
