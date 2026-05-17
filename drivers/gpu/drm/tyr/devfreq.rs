// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    bindings,
    c_str,
    clk::Hertz,
    devfreq,
    device::{
        Bound,
        Device, //
    },
    kvec,
    opp,
    prelude::*,
    regulator,
    str::CString,
    sync::aref::ARef,
    time::{
        Delta,
        Instant,
        Monotonic, //
    },
    types::ForeignOwnable, //
};

use crate::trace;

/// Tracks GPU utilization to inform devfreq scaling decisions.
pub(crate) struct DevfreqState {
    /// Busy time since the last `get_dev_status` call.
    pub(crate) busy_time: Delta,
    /// Idle time since the last `get_dev_status` call.
    pub(crate) idle_time: Delta,
    /// Timestamp of the last state transition or status check.
    pub(crate) time_last_update: Instant<Monotonic>,
    /// True if the GPU was busy at the last transition.
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

    pub(crate) fn mark_busy(&mut self) {
        let prev_busy_ns = self.busy_time.as_nanos() as u64;
        let prev_idle_ns = self.idle_time.as_nanos() as u64;
        self.update_utilization();
        self.last_busy_state = true;
        trace::devfreq_mark(true, prev_busy_ns, prev_idle_ns);
    }

    pub(crate) fn mark_idle(&mut self) {
        let prev_busy_ns = self.busy_time.as_nanos() as u64;
        let prev_idle_ns = self.idle_time.as_nanos() as u64;
        self.update_utilization();
        self.last_busy_state = false;
        trace::devfreq_mark(false, prev_busy_ns, prev_idle_ns);
    }
}

pub(crate) struct TyrDevfreqCallbacks;

// SAFETY: `TyrPlatformDriverData` is installed as drvdata on the parent
// platform device by the platform-bus probe before the devfreq
// `Registration` is constructed.
#[vtable]
unsafe impl devfreq::Callbacks for TyrDevfreqCallbacks {
    type Data = core::pin::Pin<kernel::alloc::KBox<crate::driver::TyrPlatformDriverData>>;

    fn target(
        dev: &Device,
        freq: &mut Hertz,
        flags: devfreq::DevfreqFlags,
        driver: <Self::Data as ForeignOwnable>::Borrowed<'_>,
    ) -> Result {
        let (_opp, recommended_freq) = devfreq::recommended_opp(dev, *freq, flags)?;

        let table_guard = driver.tdev.opp_table.lock();

        if let Some(table) = table_guard.as_ref() {
            table.set_rate(recommended_freq)?;
        } else {
            return Err(EINVAL);
        }

        *freq = recommended_freq;

        let prev_freq = driver.tdev.current_frequency.swap(
            recommended_freq.as_hz(),
            core::sync::atomic::Ordering::Relaxed,
        );
        trace::devfreq_target(prev_freq as u64, recommended_freq.as_hz() as u64);

        Ok(())
    }

    fn get_dev_status(
        dev: &Device,
        driver: <Self::Data as ForeignOwnable>::Borrowed<'_>,
    ) -> Result<devfreq::Status> {
        let current_frequency = Hertz(
            driver
                .tdev
                .current_frequency
                .load(core::sync::atomic::Ordering::Relaxed) as kernel::ffi::c_ulong,
        );

        let mut state = driver.tdev.devfreq_state.lock();
        state.update_utilization();

        let total_time = (state.busy_time + state.idle_time).as_nanos() as usize;
        let busy_time = state.busy_time.as_nanos() as usize;

        state.reset();
        drop(state);

        let utilization = (busy_time * 100).checked_div(total_time).unwrap_or(0);

        dev_dbg!(
            dev,
            "busy {} total {} {} % freq {} MHz\n",
            busy_time,
            total_time,
            utilization,
            current_frequency.as_hz() / 1_000_000,
        );

        trace::devfreq_status(
            busy_time as u64,
            total_time as u64,
            current_frequency.as_hz() as u64,
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

/// Brings up DVFS for the GPU.
///
/// The OPP table and the drvdata trampoline pointer must both be in
/// place before `devfreq_add_device` publishes sysfs and can dispatch
/// `get_dev_status` / `get_cur_freq`.
pub(crate) fn init(tdev: &crate::driver::TyrDrmDevice, pdev: &Device<Bound>) -> Result {
    tdev.devfreq_state.lock().reset();

    // The OPP core only tracks one regulator ("mali"); the "sram" rail
    // is wired up through the DT `regulator-coupled-with` binding so the
    // coupler keeps the two voltages in step, but the rail still has to
    // be enabled by us. Missing "sram" is not fatal on platforms that
    // do not split the supply.
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

    let cur_freq = tdev.clks.lock().core.rate();
    let (opp, recommended_freq) =
        devfreq::recommended_opp(pdev, cur_freq, devfreq::DevfreqFlags::empty())?;

    tdev.current_frequency.store(
        recommended_freq.as_hz(),
        core::sync::atomic::Ordering::Relaxed,
    );

    if let Some(table) = tdev.opp_table.lock().as_ref() {
        table.set_opp(&opp)?;
    }

    let gov_data = bindings::devfreq_simple_ondemand_data {
        upthreshold: 45,
        downdifferential: 5,
    };

    let registration = devfreq::Registration::new::<devfreq::SimpleOndemand>(
        tdev.pdev.as_ref(),
        recommended_freq,
        50,
        Some(gov_data),
        devfreq::RegistrationOptions {
            register_em: true,
            ..Default::default()
        },
    )?;

    if !registration.has_em() {
        dev_info!(pdev, "Energy Model cooling device not registered");
    }

    let mut reg_guard = tdev.devfreq_registration.lock();
    *reg_guard = Some(registration);

    Ok(())
}

#[expect(dead_code)]
pub(crate) fn suspend(tdev: &crate::driver::TyrDrmDevice) -> Result {
    // TODO: The `platform::Driver` trait doesn't expose PM callbacks yet, so
    // this is dead code.
    if let Some(reg) = tdev.devfreq_registration.lock().as_ref() {
        reg.devfreq().suspend_device()?;
    }
    Ok(())
}

#[expect(dead_code)]
pub(crate) fn resume(tdev: &crate::driver::TyrDrmDevice) -> Result {
    // TODO: The `platform::Driver` trait doesn't expose PM callbacks yet, so
    // this is dead code.
    if let Some(reg) = tdev.devfreq_registration.lock().as_ref() {
        tdev.devfreq_state.lock().reset();
        reg.devfreq().resume_device()?;
    }
    Ok(())
}
