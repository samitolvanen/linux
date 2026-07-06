// SPDX-License-Identifier: GPL-2.0

//! Rust devfreq driver sample.
//!
//! A minimal platform driver that registers a devfreq device with the
//! simple_ondemand governor. It adds a few synthetic operating points so it
//! runs without a device tree OPP table, then drives them with callbacks that
//! only track the last requested frequency. A real driver would program a clock
//! and read hardware busy counters instead.

use kernel::{
    clk::Hertz,
    devfreq::{
        Callbacks,
        DevfreqFlags,
        Registration,
        RegistrationOptions,
        SimpleOndemand,
        SimpleOndemandData,
        Status, //
    },
    device::{
        Core,
        Device, //
    },
    of,
    opp,
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        }, //
    }, //
};

/// Synthetic operating points, also used to seed the starting frequency.
const OPP_FREQS: [Hertz; 3] = [Hertz(200_000_000), Hertz(400_000_000), Hertz(800_000_000)];

/// Data the devfreq callbacks reach through their `data` argument.
struct SampleDevfreqData {
    current_frequency: Atomic<usize>,
}

struct SampleCallbacks;

#[vtable]
impl Callbacks for SampleCallbacks {
    type Data = KBox<SampleDevfreqData>;

    fn target(
        dev: &Device,
        freq: &mut Hertz,
        _flags: DevfreqFlags,
        data: &SampleDevfreqData,
    ) -> Result {
        // A real driver programs the clock to the new frequency here.
        data.current_frequency.store(freq.as_hz(), Relaxed);
        dev_dbg!(dev, "devfreq target: {} Hz\n", freq.as_hz());
        Ok(())
    }

    fn get_dev_status(_dev: &Device, data: &SampleDevfreqData) -> Result<Status> {
        // A real driver reads hardware busy counters here. Report a synthetic
        // moderate load so the governor scales the frequency instead of pinning
        // to the maximum.
        Ok(Status {
            total_time: 100,
            busy_time: 50,
            current_frequency: Hertz(data.current_frequency.load(Relaxed)),
        })
    }
}

struct SampleDriver {
    _registration: Registration<SampleCallbacks>,
    _opp_tokens: KVec<opp::Token>,
}

kernel::of_device_table!(
    OF_TABLE,
    MODULE_OF_TABLE,
    <SampleDriver as platform::Driver>::IdInfo,
    [(of::DeviceId::new(c"test,rust-devfreq"), ())]
);

impl platform::Driver for SampleDriver {
    type IdInfo = ();
    type Data<'bound> = Self;
    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);

    fn probe<'bound>(
        pdev: &'bound platform::Device<Core<'_>>,
        _info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self, Error> + 'bound {
        let dev: ARef<Device> = pdev.as_ref().into();

        // Add synthetic operating points so the sample runs without a device
        // tree OPP table. Each token removes its OPP when the driver unbinds.
        let mut opp_tokens = KVec::with_capacity(OPP_FREQS.len(), GFP_KERNEL)?;
        for freq in OPP_FREQS {
            let token = opp::Data::new(freq, opp::MicroVolt(0), 0, false).add_opp(&dev)?;
            opp_tokens.push(token, GFP_KERNEL)?;
        }

        let data = KBox::new(
            SampleDevfreqData {
                current_frequency: Atomic::new(OPP_FREQS[0].as_hz()),
            },
            GFP_KERNEL,
        )?;

        let gov_data = SimpleOndemandData {
            upthreshold: 90,
            downdifferential: 10,
        };

        let registration = Registration::<SampleCallbacks>::new::<SimpleOndemand>(
            pdev.as_ref(),
            OPP_FREQS[0],
            50,
            Some(gov_data),
            data,
            RegistrationOptions::default(),
        )?;

        Ok(Self {
            _registration: registration,
            _opp_tokens: opp_tokens,
        })
    }
}

kernel::module_platform_driver! {
    type: SampleDriver,
    name: "rust_driver_devfreq",
    authors: ["Sami Tolvanen"],
    description: "Rust devfreq driver sample",
    license: "GPL v2",
}
