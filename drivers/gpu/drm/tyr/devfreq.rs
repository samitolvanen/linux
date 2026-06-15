// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    clk::Hertz,
    devfreq::{
        self,
        Registration, //
    },
    device::{
        Bound,
        Device, //
    },
    kvec,
    opp,
    prelude::*,
    regulator,
    str::CString,
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        },
        new_mutex,
        Arc,
        ArcBorrow,
        Mutex, //
    },
    time::{
        Delta,
        Instant,
        Monotonic, //
    }, //
};

use crate::driver::TyrDrmDevice;

/// Tracks GPU utilization to inform devfreq scaling decisions.
pub(crate) struct DevfreqState {
    pub(crate) busy_time: Delta,
    pub(crate) idle_time: Delta,
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
        self.update_utilization();
        self.last_busy_state = true;
    }

    pub(crate) fn mark_idle(&mut self) {
        self.update_utilization();
        self.last_busy_state = false;
    }
}

/// State shared between the device and the devfreq registration.
///
/// The callbacks reach only these fields through their `data` argument.
#[pin_data]
pub(crate) struct TyrDevfreqData {
    #[pin]
    pub(crate) opp_table: Mutex<Option<opp::Table>>,

    pub(crate) current_frequency: Atomic<usize>,

    #[pin]
    pub(crate) devfreq_state: Mutex<DevfreqState>,
}

impl TyrDevfreqData {
    pub(crate) fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            opp_table <- new_mutex!(None),
            current_frequency: Atomic::new(0),
            devfreq_state <- new_mutex!(DevfreqState::new()),
        })
    }
}

pub(crate) struct TyrDevfreqCallbacks;

#[vtable]
impl devfreq::Callbacks for TyrDevfreqCallbacks {
    type Data = Arc<TyrDevfreqData>;

    fn target(
        dev: &Device,
        freq: &mut Hertz,
        flags: devfreq::DevfreqFlags,
        data: ArcBorrow<'_, TyrDevfreqData>,
    ) -> Result {
        let (_opp, recommended_freq) = devfreq::recommended_opp(dev, *freq, flags)?;

        let table_guard = data.opp_table.lock();

        if let Some(table) = table_guard.as_ref() {
            table.set_rate(recommended_freq)?;
        } else {
            return Err(EINVAL);
        }

        *freq = recommended_freq;

        data.current_frequency
            .store(recommended_freq.as_hz(), Relaxed);

        Ok(())
    }

    fn get_dev_status(
        _dev: &Device,
        data: ArcBorrow<'_, TyrDevfreqData>,
    ) -> Result<devfreq::Status> {
        let current_frequency = Hertz(data.current_frequency.load(Relaxed));

        let mut state = data.devfreq_state.lock();
        state.update_utilization();

        let total_time = (state.busy_time + state.idle_time).as_nanos() as usize;
        let busy_time = state.busy_time.as_nanos() as usize;

        state.reset();
        drop(state);

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

/// Sets up devfreq for the GPU. Returns `None` when the device node
/// declares no OPP table.
pub(crate) fn init(
    tdev: &TyrDrmDevice,
    pdev: &Device<Bound>,
) -> Result<Option<Registration<TyrDevfreqCallbacks>>> {
    tdev.devfreq_data.devfreq_state.lock().reset();

    // The "sram" rail must be enabled explicitly even where DT couples it to
    // "mali". A missing rail (ENODEV) is tolerated on non-split supplies.
    match regulator::devm_enable_optional(pdev, c"sram") {
        Ok(()) => {}
        Err(e) if e == ENODEV => {}
        Err(e) => return Err(e),
    }

    let names = kvec![CString::try_from(c"mali")?]?;

    let config_token = opp::Config::<OppConfigOps>::new()
        .set_regulator_names(names)?
        .set(pdev)?;

    *tdev.opp_config.lock() = Some(config_token);

    let dev: ARef<Device> = tdev.pdev.as_ref().into();
    let table = match opp::Table::from_of(&dev, 0) {
        Ok(t) => t,
        Err(e) if e == ENODEV => return Ok(None),
        Err(e) => return Err(e),
    };

    match table.opp_from_freq(
        Hertz(c_ulong::MAX),
        Some(true),
        None,
        opp::SearchType::Floor,
    ) {
        Ok(opp) => {
            tdev.set_max_freq(c_ulong::from(opp.freq(None)) as u64);
            dev_info!(
                pdev,
                "Max performance: {} Hz @ {} uV\n",
                c_ulong::from(opp.freq(None)),
                c_ulong::from(opp.voltage())
            );
        }
        Err(e) => dev_info!(pdev, "Failed to get max OPP: {:?}\n", e),
    }

    *tdev.devfreq_data.opp_table.lock() = Some(table);

    let cur_freq = tdev.clks.lock().core.rate();
    let (opp, recommended_freq) =
        devfreq::recommended_opp(pdev, cur_freq, devfreq::DevfreqFlags::empty())?;

    tdev.devfreq_data
        .current_frequency
        .store(recommended_freq.as_hz(), Relaxed);

    if let Some(table) = tdev.devfreq_data.opp_table.lock().as_ref() {
        table.set_opp(&opp)?;
    }

    let gov_data = devfreq::SimpleOndemandData {
        upthreshold: 45,
        downdifferential: 5,
    };

    let registration = Registration::<TyrDevfreqCallbacks>::new::<devfreq::SimpleOndemand>(
        pdev,
        recommended_freq,
        50,
        Some(gov_data),
        tdev.devfreq_data.clone(),
        devfreq::RegistrationOptions {
            register_em: true,
            ..Default::default()
        },
    )?;

    if !registration.has_em() {
        dev_info!(pdev, "Energy Model cooling device not registered");
    }

    Ok(Some(registration))
}

/// The runtime-PM payload is the devfreq registration slot, shared with
/// `TyrPlatformDriverData`. The inner `Option` is `None` on devices without
/// an OPP table and after `unbind`, making the devfreq steps no-ops.
pub(crate) type DevfreqSlot = Mutex<Option<Registration<TyrDevfreqCallbacks>>>;

/// Runs `f` against the registered devfreq device, if any.
fn with_devfreq(slot: Option<&DevfreqSlot>, f: impl FnOnce(&devfreq::Devfreq) -> Result) -> Result {
    match slot {
        Some(slot) => slot.lock().as_ref().map_or(Ok(()), |reg| f(reg.devfreq())),
        None => Ok(()),
    }
}

/// Pauses the devfreq governor for runtime suspend.
pub(crate) fn suspend(slot: Option<&DevfreqSlot>) -> Result {
    with_devfreq(slot, |devfreq| devfreq.suspend_device())
}

/// Resumes the devfreq governor after a runtime resume.
pub(crate) fn resume(slot: Option<&DevfreqSlot>) -> Result {
    with_devfreq(slot, |devfreq| devfreq.resume_device())
}
