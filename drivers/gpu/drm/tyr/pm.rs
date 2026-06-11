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

impl TyrDrmDeviceData {
    /// Returns the runtime PM context, `None` until the end of probe.
    pub(crate) fn pm_context(&self) -> Option<&PMContext<TyrPmOps>> {
        self.pm.as_ref()
    }

    /// Takes an asynchronous runtime-PM usage reference for the scheduler.
    ///
    /// Returns `None` when runtime PM is unavailable, in which case the caller
    /// runs without a reference.
    pub(crate) fn sched_pm_get(&self) -> Option<AwakeScope> {
        self.pm_context()?.get(SCHED_PROFILE).ok()
    }
}
