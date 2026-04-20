// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::bindings;
use kernel::c_str;
use kernel::clk::Hertz;
use kernel::devfreq;
use kernel::device::Bound;
use kernel::device::Device;
use kernel::kvec;
use kernel::opp;
use kernel::prelude::*;
use kernel::regulator;
use kernel::str::CString;
use kernel::time::{Delta, Instant, Monotonic};
use kernel::types::{ARef, ForeignOwnable};

/// Tracks GPU utilization to inform devfreq scaling decisions.
pub(crate) struct DevfreqState {
    /// Accumulated time the GPU has spent executing workloads since the last status check.
    pub(crate) busy_time: Delta,
    /// Accumulated time the GPU has spent idle since the last status check.
    pub(crate) idle_time: Delta,
    /// Timestamp of the last state transition or status check.
    pub(crate) time_last_update: Instant<Monotonic>,
    /// Current execution state: true if the GPU has active workloads, false otherwise.
    pub(crate) last_busy_state: bool,
}

impl DevfreqState {
    pub(crate) fn new() -> Self {
        Self {
            busy_time: Delta::ZERO,
            idle_time: Delta::ZERO,
            time_last_update: Instant::now(),
            last_busy_state: false,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.busy_time = Delta::ZERO;
        self.idle_time = Delta::ZERO;
        self.time_last_update = Instant::now();
    }

    pub(crate) fn update_utilization(&mut self) {
        let now = Instant::now();
        let delta = now - self.time_last_update;

        if self.last_busy_state {
            self.busy_time += delta;
        } else {
            self.idle_time += delta;
        }

        self.time_last_update = now;
    }
}

pub(crate) struct TyrDevfreqCallbacks;

#[vtable]
impl devfreq::Callbacks for TyrDevfreqCallbacks {
    type Data = Pin<KBox<crate::driver::TyrDriver>>;

    fn target(
        dev: &Device,
        freq: &mut u64,
        flags: u32,
        driver: <Self::Data as ForeignOwnable>::Borrowed<'_>,
    ) -> Result {
        let (_opp, recommended_freq) = devfreq::recommended_opp(dev, *freq, flags)?;

        let table_guard = driver.device.opp_table.lock();

        if let Some(table) = table_guard.as_ref() {
            table.set_rate(Hertz(recommended_freq as kernel::ffi::c_ulong))?;
        } else {
            return Err(EINVAL);
        }

        *freq = recommended_freq;

        driver.device.current_frequency.store(
            recommended_freq as usize,
            core::sync::atomic::Ordering::Relaxed,
        );

        Ok(())
    }

    fn get_dev_status(
        dev: &Device,
        driver: <Self::Data as ForeignOwnable>::Borrowed<'_>,
    ) -> Result<devfreq::Status> {
        let current_frequency = driver
            .device
            .current_frequency
            .load(core::sync::atomic::Ordering::Relaxed);

        let mut state = driver.device.devfreq_state.lock();
        state.update_utilization();

        let total_time = (state.busy_time + state.idle_time).as_nanos() as usize;
        let busy_time = state.busy_time.as_nanos() as usize;

        state.reset();
        drop(state);

        let utilization = if total_time > 0 {
            (busy_time * 100) / total_time
        } else {
            0
        };

        dev_dbg!(
            dev,
            "busy {} total {} {} % freq {} MHz\n",
            busy_time,
            total_time,
            utilization,
            current_frequency / 1_000_000,
        );

        Ok(devfreq::Status {
            total_time,
            busy_time,
            current_frequency,
        })
    }
}

#[derive(Default)]
struct OppConfigOps;

#[vtable]
impl opp::ConfigOps for OppConfigOps {}

/// Initializes dynamic voltage and frequency scaling (DVFS) via the devfreq subsystem.
///
/// Configures Operating Performance Points (OPP), registers the simple_ondemand governor,
/// and sets up the cooling device for thermal management.
pub(crate) fn init(tdev: &crate::driver::TyrDevice, pdev: &Device<Bound>) -> Result {
    tdev.devfreq_state.lock().reset();

    // We enable the "sram" regulator manually here and let the coupling logic handle
    // voltage updates.
    match regulator::devm_enable_optional(pdev, c_str!("sram")) {
        Ok(()) => {}
        Err(e) if e == ENODEV => {}
        Err(e) => return Err(e),
    }

    let names = kvec![CString::try_from(c_str!("mali"))?]?;

    let config_token = opp::Config::<OppConfigOps>::new()
        .set_regulator_names(names)?
        .set(pdev)?;

    *tdev.opp_config.lock() = Some(config_token);

    let dev: ARef<Device> = tdev.pdev.as_ref().into();
    let table = match opp::Table::from_of(&dev, 0) {
        Ok(t) => t,
        Err(e) if e == ENODEV => return Ok(()),
        Err(e) => return Err(e),
    };
    *tdev.opp_table.lock() = Some(table);

    let cur_freq = tdev.clks.lock().core.rate().as_hz();
    let (opp, recommended_freq) = devfreq::recommended_opp(pdev, cur_freq as u64, 0)?;

    tdev.current_frequency.store(
        recommended_freq as usize,
        core::sync::atomic::Ordering::Relaxed,
    );

    if let Some(table) = tdev.opp_table.lock().as_ref() {
        table.set_opp(&opp)?;
    }

    let gov_data = bindings::devfreq_simple_ondemand_data {
        upthreshold: 45,
        downdifferential: 5,
    };

    // SAFETY: `tdev.pdev` has its driver data set to a type compatible with
    // `TyrDevfreqCallbacks::Data`.
    let mut registration = unsafe {
        devfreq::Registration::new::<devfreq::SimpleOndemand>(
            tdev.pdev.as_ref(),
            recommended_freq,
            50,
            Some(gov_data),
        )?
    };

    if let Err(e) = registration.register_em() {
        dev_info!(pdev, "Failed to register cooling device: {:?}", e);
    }

    let mut reg_guard = tdev.devfreq_registration.lock();
    *reg_guard = Some(registration);

    Ok(())
}

#[allow(dead_code)]
pub(crate) fn suspend(tdev: &crate::driver::TyrDevice) -> Result {
    // TODO: The `platform::Driver` trait doesn't expose PM callbacks yet, so
    // this is dead code for now.
    if let Some(reg) = tdev.devfreq_registration.lock().as_ref() {
        reg.devfreq().suspend_device()?;
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn resume(tdev: &crate::driver::TyrDevice) -> Result {
    // TODO: The `platform::Driver` trait doesn't expose PM callbacks yet, so
    // this is dead code for now.
    if let Some(reg) = tdev.devfreq_registration.lock().as_ref() {
        tdev.devfreq_state.lock().reset();
        reg.devfreq().resume_device()?;
    }
    Ok(())
}

/// Marks the GPU as active and updates the utilization tracking state.
pub(crate) fn record_busy(data: &crate::driver::TyrData) {
    let mut state = data.devfreq_state.lock();
    state.update_utilization();
    state.last_busy_state = true;
}

/// Marks the GPU as idle and updates the utilization tracking state.
pub(crate) fn record_idle(data: &crate::driver::TyrData) {
    let mut state = data.devfreq_state.lock();
    state.update_utilization();
    state.last_busy_state = false;
}
