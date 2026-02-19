// SPDX-License-Identifier: GPL-2.0

//! Generic Dynamic Voltage and Frequency Scaling (DVFS) Framework.
//!
//! This module provides Rust abstractions for the `devfreq` subsystem.
//!
//! C header: [`include/linux/devfreq.h`](srctree/include/linux/devfreq.h)

use crate::{
    bindings,
    device::Device,
    error::{from_err_ptr, from_result, to_result, Result},
    opp::OPP,
    prelude::*,
    str::CStr,
    types::{ARef, ForeignOwnable, Opaque},
};
use core::{ffi::c_void, marker::PhantomData, ptr};
use macros::vtable;

/// A reference-counted `devfreq` device.
///
/// This structure represents the Rust abstraction for a C `struct devfreq`.
///
/// # Invariants
///
/// The pointer stored in `Self` is non-null and valid for the lifetime of the [`Devfreq`].
#[repr(transparent)]
pub struct Devfreq(Opaque<bindings::devfreq>);

// SAFETY: `devfreq` objects are safe to send across threads.
unsafe impl Send for Devfreq {}
// SAFETY: `devfreq` objects are safe to share across threads.
unsafe impl Sync for Devfreq {}

impl Devfreq {
    /// Creates a new `devfreq` device from a raw pointer.
    ///
    /// # Safety
    ///
    /// Callers must ensure that `ptr` is valid and non-null.
    pub unsafe fn from_raw<'a>(ptr: *mut bindings::devfreq) -> &'a Self {
        // SAFETY: The caller ensures `ptr` is valid.
        unsafe { &*ptr.cast() }
    }

    /// Obtains the raw `struct devfreq *`.
    pub fn as_raw(&self) -> *mut bindings::devfreq {
        self.0.get()
    }

    /// Suspends the `devfreq` device.
    pub fn suspend_device(&self) -> Result {
        // SAFETY: `self.as_raw()` is a valid pointer to a `struct devfreq`.
        to_result(unsafe { bindings::devfreq_suspend_device(self.as_raw()) })
    }

    /// Resumes the `devfreq` device.
    pub fn resume_device(&self) -> Result {
        // SAFETY: `self.as_raw()` is a valid pointer to a `struct devfreq`.
        to_result(unsafe { bindings::devfreq_resume_device(self.as_raw()) })
    }
}

/// Helper to find a recommended OPP.
pub fn recommended_opp(dev: &Device, freq: u64, flags: u32) -> Result<(ARef<OPP>, u64)> {
    // Check for overflow on 32-bit architectures where usize is u32
    let mut c_freq: usize = freq.try_into().map_err(|_| ERANGE)?;

    // SAFETY: `dev.as_raw()` is valid. `c_freq` is a local variable.
    let ptr = unsafe { bindings::devfreq_recommended_opp(dev.as_raw(), &mut c_freq, flags) };

    // We transfer ownership to `ARef<OPP>`.
    // SAFETY: `ptr` is a valid `dev_pm_opp` pointer returned by `devfreq_recommended_opp`.
    let opp = unsafe { OPP::from_raw_opp_owned(from_err_ptr(ptr)?) }?;
    Ok((opp, c_freq as u64))
}

/// Status of the devfreq device.
#[derive(Copy, Clone, Debug, Default)]
pub struct Status {
    /// Total time since the last measure.
    pub total_time: usize,
    /// Time spent busy among the total time.
    pub busy_time: usize,
    /// Current operating frequency.
    pub current_frequency: usize,
}

/// Devfreq configuration callbacks.
///
/// Users should implement this trait to provide device-specific behavior.
#[vtable]
pub trait Callbacks {
    /// The associated data type stored in the `struct device` driver data.
    ///
    /// # Safety
    ///
    /// Drivers must ensure that `dev_get_drvdata` returns a valid pointer
    /// compatible with `<Self::Data as ForeignOwnable>::borrow`.
    type Data: ForeignOwnable + Send + Sync;

    /// Sets the target frequency.
    fn target(
        dev: &Device,
        freq: &mut u64,
        flags: u32,
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
    ) -> Result<u64> {
        Err(EINVAL)
    }
}

/// A devfreq governor.
///
/// # Safety
///
/// Implementers must ensure that `NAME` is a valid null-terminated C string
/// and that the governor expects data of type `Data`.
pub unsafe trait Governor {
    /// The data type expected by the governor.
    type Data: Send + Sync + 'static;

    /// The name of the governor.
    const NAME: &'static CStr;
}

/// The `simple_ondemand` governor.
pub struct SimpleOndemand;

// SAFETY: `NAME` is "simple_ondemand" and the kernel governor expects `SimpleOndemandData`.
unsafe impl Governor for SimpleOndemand {
    type Data = bindings::devfreq_simple_ondemand_data;
    const NAME: &'static CStr = crate::c_str!("simple_ondemand");
}

struct RegistrationContext<D: Send + Sync + 'static, T: Callbacks> {
    _profile: Pin<KBox<bindings::devfreq_dev_profile>>,
    _gov_data: Option<KBox<D>>,
    orig_release: Option<unsafe extern "C" fn(*mut bindings::device)>,
    _p: PhantomData<T>,
}

/// A wrapper for the registration of a `devfreq` device.
pub struct Registration<T: Callbacks> {
    devfreq: *mut bindings::devfreq,
    cooling_dev: Option<*mut bindings::thermal_cooling_device>,
    opp_notifier_dev: Option<ARef<Device>>,
    _p: PhantomData<T>,
}

// SAFETY: The registration owns the devfreq pointer and handles its lifecycle.
unsafe impl<T: Callbacks> Send for Registration<T> {}
// SAFETY: The registration owns the devfreq pointer and handles its lifecycle.
unsafe impl<T: Callbacks> Sync for Registration<T> {}

impl<T: Callbacks> Registration<T> {
    /// # Safety
    ///
    /// The caller must ensure that `dev` is a valid pointer to a `struct device`
    /// and that the driver data has been set to a valid pointer.
    unsafe extern "C" fn release<G: Governor>(dev: *mut bindings::device) {
        // SAFETY: `dev` is a valid pointer. The pointer we stored in `drvdata` is a valid
        // pointer to our `RegistrationContext` struct.
        let ptr =
            unsafe { bindings::dev_get_drvdata(dev) }.cast::<RegistrationContext<G::Data, T>>();
        // SAFETY: The pointer was allocated with `KBox` during `new` and passed to us.
        let registration_context = unsafe { KBox::from_raw(ptr) };

        // Call the original devfreq release callback, which may use `profile->exit`.
        if let Some(orig_release) = registration_context.orig_release {
            // When this returns, `dev` may have been freed, but our `registration_context`
            // is independently allocated and remains valid until dropped at the end of this scope.
            // SAFETY: `orig_release` is the original kernel release callback.
            unsafe { orig_release(dev) };
        }

        // `registration_context` drops here, freeing the `_profile`, `_gov_data`, and `_data` memory
        // after `orig_release` is finished with it.
    }

    /// Registers a new `devfreq` device.
    ///
    /// This uses `devfreq_add_device` internally. The device is automatically unregistered
    /// when this `Registration` is dropped.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `dev` has driver data set to a type compatible with `T::Data`.
    pub unsafe fn new<G: Governor>(
        dev: &Device,
        initial_freq: u64,
        polling_ms: u32,
        gov_data: Option<G::Data>,
    ) -> Result<Self> {
        let profile = KBox::new(
            bindings::devfreq_dev_profile {
                initial_freq: initial_freq.try_into().map_err(|_| ERANGE)?,
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
            },
            GFP_KERNEL,
        )?;
        let profile: Pin<KBox<_>> = profile.into();
        let profile_ptr = core::ptr::from_ref(&*profile).cast_mut();

        let (gov_data_box, gov_data_raw_ptr) = if let Some(gov_data) = gov_data {
            let mut boxed = KBox::new(gov_data, GFP_KERNEL)?;
            let raw_ptr = core::ptr::from_mut(&mut *boxed).cast::<c_void>();
            (Some(boxed), raw_ptr)
        } else {
            (None, ptr::null_mut())
        };

        let registration_context = KBox::new(
            RegistrationContext::<G::Data, T> {
                _profile: profile,
                _gov_data: gov_data_box,
                orig_release: None,
                _p: PhantomData,
            },
            GFP_KERNEL,
        )?;
        let raw_data = KBox::into_raw(registration_context);

        // SAFETY: `dev.as_raw()` is valid. `profile_ptr` is pinned and valid. `G::NAME` is
        // null-terminated. `gov_data_raw_ptr` is valid if present.
        let ptr = unsafe {
            bindings::devfreq_add_device(
                dev.as_raw(),
                profile_ptr,
                G::NAME.as_char_ptr(),
                gov_data_raw_ptr,
            )
        };

        if let Err(e) = from_err_ptr(ptr) {
            // INTENTIONAL LEAK:
            // `devfreq_add_device` may fail and return an error after the device has already
            // been registered. In this case, the `devfreq` object might be kept alive
            // asynchronously via sysfs references and `devfreq_dev_release()` will eventually
            // be called, accessing `devfreq->profile->exit`.
            // Tying the lifetime of this context to the parent device (e.g. via devres) is
            // unsafe because if `devfreq_add_device` fails during driver probe, the probe
            // can fail and devres will immediately free the context, again resulting in UAF.
            // We cannot determine if the object is still alive, so we must intentionally leak
            // the context.
            return Err(e);
        }

        // SAFETY: `ptr` is a valid devfreq pointer since `devfreq_add_device` succeeded.
        let devfreq_dev = unsafe { core::ptr::addr_of_mut!((*ptr).dev) };

        // We store the pointer to our allocated data inside the devfreq device
        // so we can access it during the release callback.
        // SAFETY: `devfreq_dev` is a valid pointer.
        unsafe { bindings::dev_set_drvdata(devfreq_dev, raw_data.cast::<c_void>()) };

        // Override the release function.
        // SAFETY: The kernel provides single-threaded access during initialization,
        // so it is safe to mutate `devfreq_dev` and `raw_data`.
        unsafe {
            (*raw_data).orig_release = (*devfreq_dev).release;
            (*devfreq_dev).release = Some(Self::release::<G>);
        }

        Ok(Self {
            devfreq: ptr,
            cooling_dev: None,
            opp_notifier_dev: None,
            _p: PhantomData,
        })
    }

    /// Returns the `Devfreq` wrapper.
    pub fn devfreq(&self) -> &Devfreq {
        // SAFETY: `self.devfreq` is a valid pointer.
        unsafe { Devfreq::from_raw(self.devfreq) }
    }

    /// Register a notifier for OPP changes.
    ///
    /// The notifier is automatically unregistered when the `Registration` is dropped.
    pub fn register_opp_notifier(&mut self, dev: ARef<Device>) -> Result<()> {
        if self.opp_notifier_dev.is_some() {
            return Err(EBUSY);
        }
        // SAFETY: `dev.as_raw()` and `self.devfreq` are valid pointers.
        to_result(unsafe { bindings::devfreq_register_opp_notifier(dev.as_raw(), self.devfreq) })?;
        self.opp_notifier_dev = Some(dev);
        Ok(())
    }

    /// Registers the device as a cooling device with the Energy Model.
    ///
    /// The cooling device is automatically unregistered when the `Registration` is dropped.
    pub fn register_em(&mut self) -> Result<()> {
        if self.cooling_dev.is_some() {
            return Err(EBUSY);
        }
        // SAFETY: `self.devfreq` is a valid pointer.
        let ptr = unsafe { bindings::devfreq_cooling_em_register(self.devfreq, ptr::null_mut()) };
        let ptr = from_err_ptr(ptr)?;
        self.cooling_dev = Some(ptr);
        Ok(())
    }

    /// # Safety
    ///
    /// The caller must ensure that `dev` is a valid pointer to a `struct device`
    /// and that the driver data has been set to a valid pointer.
    unsafe extern "C" fn target_callback(
        dev: *mut bindings::device,
        freq: *mut usize,
        flags: u32,
    ) -> core::ffi::c_int {
        from_result(|| {
            // SAFETY: By the C API contract, `dev` is guaranteed to be a valid pointer.
            let dev_ref: &Device = unsafe { Device::from_raw(dev) };

            // SAFETY: `dev_get_drvdata` returns the driver-provided data from the parent device.
            let ptr = unsafe { bindings::dev_get_drvdata(dev_ref.as_raw()) };
            if ptr.is_null() {
                return Err(ENODEV);
            }
            // SAFETY: By the safety requirements of the `Callbacks` trait, the driver data is of
            // type `T::Data`.
            let data = unsafe { T::Data::borrow(ptr) };

            // SAFETY: By the C API contract, `freq` is guaranteed to be a valid pointer.
            let mut r_freq = unsafe { *freq } as u64;
            T::target(dev_ref, &mut r_freq, flags, data)?;

            // SAFETY: By the C API contract, `freq` is guaranteed to be a valid pointer.
            unsafe { *freq = r_freq.try_into().map_err(|_| ERANGE)? };
            Ok(0)
        })
    }

    /// # Safety
    ///
    /// The caller must ensure that `dev` is a valid pointer to a `struct device`
    /// and that the driver data has been set to a valid pointer.
    unsafe extern "C" fn get_dev_status_callback(
        dev: *mut bindings::device,
        stat: *mut bindings::devfreq_dev_status,
    ) -> core::ffi::c_int {
        // SAFETY: By the C API contract, `dev` is guaranteed to be a valid pointer.
        let dev_ref: &Device = unsafe { Device::from_raw(dev) };

        // SAFETY: `dev_get_drvdata` returns the driver-provided data from the parent device.
        let ptr = unsafe { bindings::dev_get_drvdata(dev_ref.as_raw()) };
        if ptr.is_null() {
            return ENODEV.to_errno();
        }

        // SAFETY: By the safety requirements of the `Callbacks` trait, the driver data is of
        // type `T::Data`.
        let data = unsafe { T::Data::borrow(ptr) };

        match T::get_dev_status(dev_ref, data) {
            Ok(status) => {
                // SAFETY: By the C API contract, `stat` is guaranteed to be a valid pointer.
                unsafe {
                    (*stat).total_time = status.total_time;
                    (*stat).busy_time = status.busy_time;
                    (*stat).current_frequency = status.current_frequency;
                    (*stat).private_data = ptr::null_mut();
                }
                0
            }
            Err(e) => e.to_errno(),
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that `dev` is a valid pointer to a `struct device`
    /// and that the driver data has been set to a valid pointer.
    unsafe extern "C" fn get_cur_freq_callback(
        dev: *mut bindings::device,
        freq: *mut usize,
    ) -> core::ffi::c_int {
        from_result(|| {
            // SAFETY: By the C API contract, `dev` is guaranteed to be a valid pointer.
            let dev_ref: &Device = unsafe { Device::from_raw(dev) };

            // SAFETY: `dev_get_drvdata` returns the driver-provided data from the parent device.
            let ptr = unsafe { bindings::dev_get_drvdata(dev_ref.as_raw()) };
            if ptr.is_null() {
                return Err(ENODEV);
            }

            // SAFETY: By the safety requirements of the `Callbacks` trait, the driver data is of
            // type `T::Data`.
            let data = unsafe { T::Data::borrow(ptr) };

            let f = T::get_cur_freq(dev_ref, data)?;

            // SAFETY: By the C API contract, `freq` is guaranteed to be a valid pointer.
            unsafe { *freq = f.try_into().map_err(|_| ERANGE)? };
            Ok(0)
        })
    }
}

impl<T: Callbacks> Drop for Registration<T> {
    fn drop(&mut self) {
        if let Some(cdev) = self.cooling_dev {
            // SAFETY: Pointers are valid.
            unsafe { bindings::devfreq_cooling_unregister(cdev) };
        }

        if let Some(ref dev) = self.opp_notifier_dev {
            // SAFETY: Pointers are valid.
            unsafe { bindings::devfreq_unregister_opp_notifier(dev.as_raw(), self.devfreq) };
        }

        // Unregisted the devfreq device. The profile and gov_data will be automatically freed
        // by the custom release hook we registered in `new` once the last reference is dropped.
        // SAFETY: `self.devfreq` is a valid pointer to a devfreq device registered by us.
        unsafe { bindings::devfreq_remove_device(self.devfreq) };
    }
}
