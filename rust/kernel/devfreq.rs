// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Google LLC.

//! Generic Dynamic Voltage and Frequency Scaling (DVFS) Framework.
//!
//! C header: [`include/linux/devfreq.h`](srctree/include/linux/devfreq.h)
//!
//! # Data model
//!
//! The devfreq `driver_data` slot holds the [`Callbacks::Data`] value,
//! which the core passes to the profile callbacks. The embedded devfreq
//! device's drvdata holds the registration context. The chained release
//! function frees it when the last reference drops.
//!
//! # Examples
//!
//! ```
//! use kernel::{
//!     clk::Hertz,
//!     devfreq::{
//!         Callbacks,
//!         DevfreqFlags,
//!         Registration,
//!         RegistrationOptions,
//!         SimpleOndemand,
//!         SimpleOndemandData,
//!         Status, //
//!     },
//!     device::{
//!         Bound,
//!         Device, //
//!     },
//!     prelude::*, //
//! };
//!
//! struct MyDevfreqData {
//!     max_freq: Hertz,
//! }
//!
//! struct MyCallbacks;
//!
//! #[vtable]
//! impl Callbacks for MyCallbacks {
//!     type Data = KBox<MyDevfreqData>;
//!
//!     fn target(
//!         _dev: &Device,
//!         freq: &mut Hertz,
//!         _flags: DevfreqFlags,
//!         data: &MyDevfreqData,
//!     ) -> Result {
//!         if freq.as_hz() > data.max_freq.as_hz() {
//!             *freq = data.max_freq;
//!         }
//!         Ok(())
//!     }
//!
//!     fn get_dev_status(
//!         _dev: &Device,
//!         data: &MyDevfreqData,
//!     ) -> Result<Status> {
//!         Ok(Status {
//!             total_time: 100,
//!             busy_time: 50,
//!             current_frequency: data.max_freq,
//!         })
//!     }
//! }
//!
//! fn register_devfreq(
//!     dev: &Device<Bound>,
//!     data: KBox<MyDevfreqData>,
//! ) -> Result<Registration<MyCallbacks>> {
//!     let gov_data = SimpleOndemandData {
//!         upthreshold: 45,
//!         downdifferential: 5,
//!     };
//!     Registration::new::<SimpleOndemand>(
//!         dev,
//!         Hertz(800_000_000),
//!         50,
//!         Some(gov_data),
//!         data,
//!         RegistrationOptions::default(),
//!     )
//! }
//! ```

use crate::{
    bindings,
    clk::Hertz,
    device::{
        self,
        Device, //
    },
    error::{
        from_err_ptr,
        from_result,
        to_result,
        VTABLE_DEFAULT_ERROR, //
    },
    impl_flags,
    opp::OPP,
    prelude::*,
    sync::aref::ARef,
    types::{
        ForeignOwnable,
        Opaque, //
    }, //
};
use core::{
    marker::PhantomData,
    ptr,
    ptr::NonNull, //
};

/// A `devfreq` device.
#[repr(transparent)]
pub struct Devfreq(Opaque<bindings::devfreq>);

// SAFETY: `struct devfreq` serializes all mutable access internally, so it
// is safe to transfer a `Devfreq` to another thread.
unsafe impl Send for Devfreq {}
// SAFETY: All shared-reference access goes through kernel APIs that do their
// own locking, so concurrent use does not cause data races.
unsafe impl Sync for Devfreq {}

impl Devfreq {
    /// Creates a new `devfreq` device from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a valid `struct devfreq` that remains live for
    /// the duration of the lifetime `'a` the caller picks.
    #[inline]
    pub(crate) unsafe fn from_raw<'a>(ptr: *mut bindings::devfreq) -> &'a Self {
        // SAFETY: The caller ensures `ptr` is valid.
        unsafe { &*ptr.cast() }
    }

    /// Obtains the raw `struct devfreq *`.
    #[inline]
    pub fn as_raw(&self) -> *mut bindings::devfreq {
        self.0.get()
    }

    /// Suspends the `devfreq` device.
    ///
    /// # Note
    ///
    /// The core keeps a suspend counter, so each call must be paired with a
    /// later [`resume_device`](Self::resume_device). Nested suspends only
    /// raise the count. The device stays suspended until the counter returns
    /// to zero. An unbalanced resume is a driver bug. It drives the count
    /// negative and spuriously resumes a running device, but it is not unsafe.
    #[inline]
    pub fn suspend_device(&self) -> Result {
        // SAFETY: `self.as_raw()` is a valid pointer to a `struct devfreq`.
        to_result(unsafe { bindings::devfreq_suspend_device(self.as_raw()) })
    }

    /// Resumes the `devfreq` device.
    ///
    /// # Note
    ///
    /// This balances a previous [`suspend_device`](Self::suspend_device). See
    /// its note on the suspend counter.
    #[inline]
    pub fn resume_device(&self) -> Result {
        // SAFETY: `self.as_raw()` is a valid pointer to a `struct devfreq`.
        to_result(unsafe { bindings::devfreq_resume_device(self.as_raw()) })
    }
}

impl_flags!(
    /// Flags passed to devfreq governor callbacks.
    ///
    /// Mirrors the `flags` argument the devfreq core forwards to
    /// `devfreq_dev_profile::target` and to [`recommended_opp`].
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct DevfreqFlags(u32);

    /// An individual devfreq flag.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DevfreqFlag {
        /// Round the recommended frequency up to the next OPP rather than down.
        LeastUpperBound = bindings::DEVFREQ_FLAG_LEAST_UPPER_BOUND,
    }
);

impl DevfreqFlags {
    /// Wraps a raw flags word passed by the devfreq core.
    ///
    /// Unknown bits are kept as-is so callbacks can pass the
    /// kernel-supplied value back into [`recommended_opp`] without
    /// losing flags the C side knows about.
    #[inline]
    pub(crate) fn from_raw(value: u32) -> Self {
        Self(value)
    }
}

/// Finds a recommended OPP for `freq`, with `flags` selecting the rounding
/// direction.
///
/// Returns the matched OPP together with its frequency. That frequency is
/// the OPP's own rate, which may differ from the requested `freq`.
pub fn recommended_opp(
    dev: &Device,
    freq: Hertz,
    flags: DevfreqFlags,
) -> Result<(ARef<OPP>, Hertz)> {
    let mut c_freq: usize = freq.as_hz();

    // SAFETY: `dev.as_raw()` is valid. `c_freq` is a local variable.
    let opp_ptr = from_err_ptr(unsafe {
        bindings::devfreq_recommended_opp(dev.as_raw(), &mut c_freq, flags.into())
    })?;

    // SAFETY: `opp_ptr` is a valid `dev_pm_opp` pointer returned by
    // `devfreq_recommended_opp`. Ownership of the reference transfers to
    // the resulting `ARef<OPP>`.
    let opp = unsafe { OPP::from_raw_opp_owned(opp_ptr) }?;
    Ok((opp, Hertz(c_freq)))
}

/// Status of the devfreq device.
#[derive(Copy, Clone, Debug)]
pub struct Status {
    /// Total time since the last measure.
    pub total_time: usize,
    /// Time spent busy among the total time.
    pub busy_time: usize,
    /// Current operating frequency.
    pub current_frequency: Hertz,
}

/// Callbacks for a devfreq driver instance.
///
/// `Self::Data` is bounded `Send + Sync` because the core borrows the data
/// from several threads at once, and frees it on whichever thread drops the
/// last devfreq reference.
#[vtable]
pub trait Callbacks {
    /// The associated data type stored on the `struct devfreq`.
    ///
    /// `'static` because the value is freed only when the devfreq device is
    /// released, which a temporary reference can delay until after
    /// [`Registration`] is dropped.
    type Data: ForeignOwnable + Send + Sync + 'static;

    /// Sets the target frequency.
    fn target(
        dev: &Device,
        freq: &mut Hertz,
        flags: DevfreqFlags,
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
    ) -> Result;

    /// Gets the current device status.
    fn get_dev_status(
        dev: &Device,
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
    ) -> Result<Status>;

    /// Optional callback to get the current frequency.
    fn get_cur_freq(
        _dev: &Device,
        _data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
    ) -> Result<Hertz> {
        build_error!(VTABLE_DEFAULT_ERROR)
    }
}

/// A devfreq governor.
///
/// # Safety
///
/// Implementers must ensure that `NAME` is a valid null-terminated C string
/// naming a registered kernel governor and that the governor reads its
/// `data` argument as `Self::Raw`.
pub unsafe trait Governor {
    /// The data type expected by the governor.
    type Data;

    /// The representation the named kernel governor reads through its `data`
    /// argument.
    type Raw: Send + 'static;

    /// The name of the governor.
    const NAME: &'static CStr;

    /// Converts the governor's public data into [`Self::Raw`].
    fn raw_data(data: Self::Data) -> Self::Raw;
}

/// The `simple_ondemand` governor.
pub struct SimpleOndemand;

/// Tuning for the `simple_ondemand` governor.
///
/// A zero in either field selects the governor's default value.
pub struct SimpleOndemandData {
    /// Load percentage above which the frequency jumps. Valid values are
    /// 0 to 100.
    pub upthreshold: u32,
    /// If the load drops below `upthreshold - downdifferential`, the
    /// governor may lower the frequency. Must be less than `upthreshold`.
    /// Valid values are 0 to 100.
    pub downdifferential: u32,
}

// SAFETY: "simple_ondemand" names the kernel governor that reads its data
// argument as `struct devfreq_simple_ondemand_data`, which is `Self::Raw`.
unsafe impl Governor for SimpleOndemand {
    type Data = SimpleOndemandData;
    type Raw = bindings::devfreq_simple_ondemand_data;
    const NAME: &'static CStr = c"simple_ondemand";

    fn raw_data(data: SimpleOndemandData) -> Self::Raw {
        bindings::devfreq_simple_ondemand_data {
            upthreshold: data.upthreshold,
            downdifferential: data.downdifferential,
        }
    }
}

struct RegistrationContext<D: Send + 'static> {
    /// Held as [`Opaque`] because the devfreq core writes through the profile pointer.
    _profile: Pin<KBox<Opaque<bindings::devfreq_dev_profile>>>,
    _gov_data: Option<KBox<D>>,
    orig_release: Option<unsafe extern "C" fn(*mut bindings::device)>,
}

/// Optional registration knobs passed to [`Registration::new`].
///
/// `register_em` is applied best-effort. Failure leaves the registration
/// without cooling support, which [`Registration::has_em`] reports. An
/// `opp_notifier_dev` failure aborts the registration.
#[derive(Default)]
pub struct RegistrationOptions<'a> {
    /// Request Energy Model cooling-device registration.
    pub register_em: bool,
    /// If `Some`, register an OPP-change notifier on this device.
    pub opp_notifier_dev: Option<&'a Device<device::Bound>>,
}

/// A wrapper for the registration of a `devfreq` device.
pub struct Registration<T: Callbacks> {
    devfreq: NonNull<bindings::devfreq>,
    cooling_dev: Option<NonNull<bindings::thermal_cooling_device>>,
    opp_notifier_dev: Option<ARef<Device>>,
    _p: PhantomData<T>,
}

// SAFETY: It is safe to send a `Registration<T>` to another thread because
// the kernel objects it points to do their own locking, and none of its
// fields is tied to a thread.
unsafe impl<T: Callbacks> Send for Registration<T> {}
// SAFETY: It is safe to share a `&Registration<T>` between threads because
// `&self` methods only read immutable fields or return the `Sync` `&Devfreq`.
unsafe impl<T: Callbacks> Sync for Registration<T> {}

impl<T: Callbacks> Registration<T> {
    /// # Safety
    ///
    /// `dev` must be the embedded `struct device` of a `bindings::devfreq`
    /// instance registered through [`Registration::new`], with its drvdata
    /// set to a `RegistrationContext<G::Raw>` pointer allocated by that
    /// call and its devfreq `driver_data` slot holding the `T::Data`
    /// foreign value installed by that call.
    unsafe extern "C" fn release<G: Governor>(dev: *mut bindings::device) {
        // SAFETY: This device's drvdata is the `RegistrationContext` set at
        // registration, so the cast is sound.
        let context_ptr =
            unsafe { bindings::dev_get_drvdata(dev) }.cast::<RegistrationContext<G::Raw>>();
        // SAFETY: Release runs once, when the last reference is gone, so this
        // is the only place that frees the `KBox` allocated in `new`.
        let registration_context = unsafe { KBox::from_raw(context_ptr) };

        // SAFETY: `dev` is the embedded `struct device` of the matching
        // `struct devfreq`.
        let df = unsafe { kernel::container_of!(dev, bindings::devfreq, dev) };
        // SAFETY: `df` is valid until the original release below frees it.
        let driver_data_ptr = unsafe { (*df).driver_data };

        // The core's release still uses the profile, so it must run while
        // `registration_context` is alive.
        if let Some(orig_release) = registration_context.orig_release {
            // SAFETY: `orig_release` was installed by the devfreq core on
            // this same `dev`, so forwarding `dev` unchanged satisfies its
            // contract.
            unsafe { orig_release(dev) };
        }

        if !driver_data_ptr.is_null() {
            // SAFETY: The slot holds the `T::Data` foreign value installed by
            // `Registration::new`. Release runs once, after the core has shut
            // down every callback path, so this is the only place that frees
            // the value.
            drop(unsafe { <T::Data as ForeignOwnable>::from_foreign(driver_data_ptr) });
        }
    }

    /// Register a devfreq device with the given governor and driver data.
    pub fn new<G: Governor>(
        dev: &Device<device::Bound>,
        initial_freq: Hertz,
        polling_ms: u32,
        gov_data: Option<G::Data>,
        data: T::Data,
        options: RegistrationOptions<'_>,
    ) -> Result<Self> {
        let profile = KBox::new(
            Opaque::new(bindings::devfreq_dev_profile {
                initial_freq: initial_freq.as_hz(),
                polling_ms,
                timer: bindings::devfreq_timer_DEVFREQ_TIMER_DELAYED,
                target: Some(Self::target_callback),
                get_dev_status: Some(Self::get_dev_status_callback),
                get_cur_freq: if T::HAS_GET_CUR_FREQ {
                    Some(Self::get_cur_freq_callback)
                } else {
                    None
                },
                exit: None,
                freq_table: ptr::null_mut(),
                max_state: 0,
                is_cooling_device: false,
                dev_groups: ptr::null_mut(),
            }),
            GFP_KERNEL,
        )?;
        let profile: Pin<KBox<_>> = profile.into();
        let profile_ptr = profile.get();

        let (gov_data_box, gov_data_ptr) = if let Some(gov_data) = gov_data {
            let mut boxed = KBox::new(G::raw_data(gov_data), GFP_KERNEL)?;
            let gov_data_ptr = (&raw mut *boxed).cast::<c_void>();
            (Some(boxed), gov_data_ptr)
        } else {
            (None, ptr::null_mut())
        };

        let registration_context = KBox::new(
            RegistrationContext::<G::Raw> {
                _profile: profile,
                _gov_data: gov_data_box,
                orig_release: None,
            },
            GFP_KERNEL,
        )?;
        let context_ptr = KBox::into_raw(registration_context);

        let driver_data_ptr = <T::Data as ForeignOwnable>::into_foreign(data);

        // SAFETY: `dev.as_raw()` is valid. `profile_ptr` is pinned and valid.
        // `G::NAME` is null-terminated. `gov_data_ptr` is valid if present.
        // `driver_data_ptr` was produced by `into_foreign` immediately above.
        let devfreq_ptr = unsafe {
            bindings::devfreq_add_device(
                dev.as_raw(),
                profile_ptr,
                G::NAME.as_char_ptr(),
                gov_data_ptr,
                driver_data_ptr,
            )
        };

        let err_ptr = from_err_ptr(devfreq_ptr);
        let devfreq_nn = match err_ptr.and_then(|p| NonNull::new(p).ok_or(EINVAL)) {
            Ok(nn) => nn,
            Err(e) => {
                // The chained release is not installed yet, but the core's
                // release still uses the profile, so leak `context_ptr` to
                // keep it alive.
                //
                // devfreq_add_device failed, but the devfreq device object may
                // outlive this return if its release is deferred. PM QoS
                // notifiers are removed only in that release, so a callback
                // could still run and read driver_data. Leak it to keep it alive.
                return Err(e);
            }
        };

        // SAFETY: `devfreq_nn` is a non-null `*mut bindings::devfreq` whose
        // pointee was just initialized by `devfreq_add_device`.
        let devfreq_dev = unsafe { core::ptr::addr_of_mut!((*devfreq_nn.as_ptr()).dev) };

        // SAFETY: `devfreq_dev` points at the live `struct device` embedded in
        // the devfreq object just returned by the core.
        unsafe { bindings::dev_set_drvdata(devfreq_dev, context_ptr.cast::<c_void>()) };

        // Chain our release before the core's so `RegistrationContext`
        // outlives the core's release.
        // SAFETY: `devfreq_dev` is valid and `context_ptr` is uniquely owned
        // here. The release cannot fire until the last reference is gone,
        // which cannot happen before `devfreq_remove_device` runs in `Drop`,
        // so this install races no reader of `dev->release`.
        unsafe {
            (*context_ptr).orig_release = (*devfreq_dev).release;
            (*devfreq_dev).release = Some(Self::release::<G>);
        }

        let mut reg = Self {
            devfreq: devfreq_nn,
            cooling_dev: None,
            opp_notifier_dev: None,
            _p: PhantomData,
        };

        if options.register_em {
            // SAFETY: `reg.devfreq` is a valid pointer until `reg` drops.
            let cdev = unsafe {
                bindings::devfreq_cooling_em_register(reg.devfreq.as_ptr(), ptr::null_mut())
            };
            if let Ok(cdev) = from_err_ptr(cdev) {
                // A bare NULL return takes the same best-effort path as
                // an error.
                reg.cooling_dev = NonNull::new(cdev);
            }
        }

        if let Some(notifier_dev) = options.opp_notifier_dev {
            // SAFETY: `notifier_dev.as_raw()` and `reg.devfreq` are valid pointers.
            to_result(unsafe {
                bindings::devfreq_register_opp_notifier(notifier_dev.as_raw(), reg.devfreq.as_ptr())
            })?;
            // Keep a reference without the `Bound` device context for the
            // `Drop`-time unregister, which may run after the device is
            // unbound.
            reg.opp_notifier_dev = Some(notifier_dev.into());
        }

        Ok(reg)
    }

    /// Returns the `Devfreq` wrapper.
    #[inline]
    pub fn devfreq(&self) -> &Devfreq {
        // SAFETY: `self.devfreq` is a valid pointer.
        unsafe { Devfreq::from_raw(self.devfreq.as_ptr()) }
    }

    /// Returns true if the Energy Model cooling device was registered.
    #[inline]
    pub fn has_em(&self) -> bool {
        self.cooling_dev.is_some()
    }

    /// Borrows the driver data from a profile callback's `data` argument.
    ///
    /// Returns `Err` if the pointer is null.
    ///
    /// # Safety
    ///
    /// `data` must be the `driver_data` value forwarded by the devfreq
    /// core to a profile callback for a devfreq instance registered by
    /// [`Registration::new`]. The matching `struct devfreq` must remain
    /// live for the duration of the returned borrow.
    unsafe fn borrow_data<'a>(
        data: *mut c_void,
    ) -> Result<<T::Data as ForeignOwnable>::Borrowed<'a>> {
        if data.is_null() {
            return Err(ENODEV);
        }
        // SAFETY: The slot holds the `T::Data` foreign value installed by
        // `Registration::new`. The chained release cannot free it while a
        // callback is running.
        Ok(unsafe { <T::Data as ForeignOwnable>::borrow(data) })
    }

    /// # Safety
    ///
    /// `dev` is the parent device and `data` the `driver_data` the core
    /// forwards to a profile callback registered by [`Registration::new`].
    unsafe extern "C" fn target_callback(
        dev: *mut bindings::device,
        data: *mut c_void,
        freq: *mut usize,
        flags: u32,
    ) -> c_int {
        from_result(|| {
            // SAFETY: `dev` is the parent device, live for the duration of the callback.
            let dev_ref: &Device = unsafe { Device::from_raw(dev) };

            // SAFETY: `data` satisfies the `borrow_data` contract by the
            // C API guarantee on this callback.
            let inner = unsafe { Self::borrow_data(data) }?;

            // SAFETY: The core passes a valid out-parameter.
            let mut r_freq = Hertz(unsafe { *freq });
            T::target(dev_ref, &mut r_freq, DevfreqFlags::from_raw(flags), inner)?;

            // SAFETY: `freq` is the same valid out-parameter as above.
            unsafe { *freq = r_freq.as_hz() };
            Ok(0)
        })
    }

    /// # Safety
    ///
    /// `dev` is the parent device and `data` the `driver_data` the core
    /// forwards to a profile callback registered by [`Registration::new`].
    unsafe extern "C" fn get_dev_status_callback(
        dev: *mut bindings::device,
        data: *mut c_void,
        stat: *mut bindings::devfreq_dev_status,
    ) -> c_int {
        // SAFETY: `dev` is the parent device, live for the duration of the callback.
        let dev_ref: &Device = unsafe { Device::from_raw(dev) };

        // SAFETY: `data` satisfies the `borrow_data` contract by the
        // C API guarantee on this callback.
        let inner = match unsafe { Self::borrow_data(data) } {
            Ok(inner) => inner,
            Err(e) => return e.to_errno(),
        };

        match T::get_dev_status(dev_ref, inner) {
            Ok(status) => {
                // SAFETY: The core passes a valid out-parameter.
                unsafe {
                    (*stat).total_time = status.total_time;
                    (*stat).busy_time = status.busy_time;
                    (*stat).current_frequency = status.current_frequency.as_hz();
                    (*stat).private_data = ptr::null_mut();
                }
                0
            }
            Err(e) => e.to_errno(),
        }
    }

    /// # Safety
    ///
    /// `dev` is the parent device and `data` the `driver_data` the core
    /// forwards to a profile callback registered by [`Registration::new`].
    unsafe extern "C" fn get_cur_freq_callback(
        dev: *mut bindings::device,
        data: *mut c_void,
        freq: *mut usize,
    ) -> c_int {
        from_result(|| {
            // SAFETY: `dev` is the parent device, live for the duration of the callback.
            let dev_ref: &Device = unsafe { Device::from_raw(dev) };

            // SAFETY: `data` satisfies the `borrow_data` contract by the
            // C API guarantee on this callback.
            let inner = unsafe { Self::borrow_data(data) }?;

            let f = T::get_cur_freq(dev_ref, inner)?;

            // SAFETY: The core passes a valid out-parameter.
            unsafe { *freq = f.as_hz() };
            Ok(0)
        })
    }
}

impl<T: Callbacks> Drop for Registration<T> {
    fn drop(&mut self) {
        if let Some(cdev) = self.cooling_dev {
            // SAFETY: `cdev` was returned by `devfreq_cooling_em_register` in
            // `new` and remains live until this call.
            unsafe { bindings::devfreq_cooling_unregister(cdev.as_ptr()) };
        }

        if let Some(ref dev) = self.opp_notifier_dev {
            // SAFETY: `dev` is an owned `ARef<Device>` and `self.devfreq` was
            // registered with `devfreq_register_opp_notifier` in `new`.
            unsafe {
                bindings::devfreq_unregister_opp_notifier(dev.as_raw(), self.devfreq.as_ptr())
            };
        }

        // devfreq_remove_device drops our reference to the devfreq device. The
        // chained release frees the RegistrationContext and driver_data when
        // the last reference is gone.
        // SAFETY: `self.devfreq` is a valid pointer to a devfreq device registered by us.
        unsafe { bindings::devfreq_remove_device(self.devfreq.as_ptr()) };
    }
}
