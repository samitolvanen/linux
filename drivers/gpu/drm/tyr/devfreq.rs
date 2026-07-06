// SPDX-License-Identifier: GPL-2.0 or MIT

//! Example devfreq integration for the Tyr GPU.
//!
//! This registers the GPU with the devfreq simple_ondemand governor so the core
//! clock scales with the requested frequency through the OPP table. Busy time
//! tracking requires the job scheduler, which is not upstream, so the governor
//! always sees zero busy time.

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
    devres,
    kvec,
    opp,
    prelude::*,
    str::CString,
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc,
        ArcBorrow, //
    }, //
};

use crate::driver::TyrDrmDevice;

/// State the devfreq callbacks reach through their `data` argument.
pub(crate) struct TyrDevfreqData {
    opp_table: opp::Table,
    current_frequency: Atomic<usize>,
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

        data.opp_table.set_rate(recommended_freq)?;

        *freq = recommended_freq;
        data.current_frequency
            .store(recommended_freq.as_hz(), Relaxed);

        Ok(())
    }

    fn get_dev_status(
        _dev: &Device,
        data: ArcBorrow<'_, TyrDevfreqData>,
    ) -> Result<devfreq::Status> {
        // Report the last programmed core clock rate with zero busy time.
        Ok(devfreq::Status {
            total_time: 0,
            busy_time: 0,
            current_frequency: Hertz(data.current_frequency.load(Relaxed)),
        })
    }
}

#[derive(Default)]
struct OppConfigOps;

#[vtable]
impl opp::ConfigOps for OppConfigOps {}

/// Sets up devfreq for the GPU. Returns `None` when the device node declares no
/// OPP table.
pub(crate) fn init(
    tdev: &TyrDrmDevice,
    pdev: &Device<Bound>,
) -> Result<Option<Registration<TyrDevfreqCallbacks>>> {
    let names = kvec![CString::try_from(c"mali")?]?;
    let config_token = opp::Config::<OppConfigOps>::new()
        .set_regulator_names(names)?
        .set(pdev)?;
    devres::register(pdev, config_token, GFP_KERNEL)?;

    let dev: ARef<Device> = tdev.pdev.as_ref().into();
    let table = match opp::Table::from_of(&dev, 0) {
        Ok(t) => t,
        Err(e) if e == ENODEV => return Ok(None),
        Err(e) => return Err(e),
    };

    let cur_freq = tdev.clks.lock().core.rate();
    let (opp, recommended_freq) =
        devfreq::recommended_opp(pdev, cur_freq, devfreq::DevfreqFlags::empty())?;
    table.set_opp(&opp)?;

    let data = Arc::new(
        TyrDevfreqData {
            opp_table: table,
            current_frequency: Atomic::new(recommended_freq.as_hz()),
        },
        GFP_KERNEL,
    )?;

    let gov_data = devfreq::SimpleOndemandData {
        upthreshold: 45,
        downdifferential: 5,
    };

    Registration::<TyrDevfreqCallbacks>::new::<devfreq::SimpleOndemand>(
        pdev,
        recommended_freq,
        50,
        Some(gov_data),
        data,
        devfreq::RegistrationOptions {
            register_em: true,
            ..Default::default()
        },
    )
    .map(Some)
}
