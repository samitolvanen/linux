// SPDX-License-Identifier: GPL-2.0

//! Generic Dynamic Voltage and Frequency Scaling (DVFS) Framework.
//!
//! C header: [`include/linux/devfreq.h`](srctree/include/linux/devfreq.h)

use crate::{
    bindings,
    device::Device,
    error::{from_err_ptr, from_result, to_result, Result},
    ffi::{c_int, c_void},
    opp::OPP,
    prelude::*,
    str::CStr,
    sync::aref::ARef,
    types::{ForeignOwnable, Opaque, ScopeGuard},
};
use core::{marker::PhantomData, ptr};
use macros::vtable;

/// A reference-counted `devfreq` device.
///
/// # Invariants
///
/// The pointer stored in `Self` is non-null and valid for the lifetime of the [`Devfreq`].
#[repr(transparent)]
pub struct Devfreq(Opaque<bindings::devfreq>);

// SAFETY: The kernel's `struct devfreq` is internally synchronised via its own
// `struct mutex lock`, so the underlying object may be accessed from any thread.
unsafe impl Send for Devfreq {}
// SAFETY: Every method on `Devfreq` is routed through kernel APIs that take
// `devfreq->lock`, so concurrent shared access from multiple threads is sound.
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

    // SAFETY: `ptr` is a valid `dev_pm_opp` pointer returned by
    // `devfreq_recommended_opp`; ownership of the reference transfers to
    // the resulting `ARef<OPP>`.
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

/// Devfreq vtable: `target`, `get_dev_status`, and optional `get_cur_freq`.
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

// SAFETY: `Drop` calls `devfreq_remove_device`, which is callable from any
// thread; the contained raw pointers are not thread-local.
unsafe impl<T: Callbacks> Send for Registration<T> {}
// SAFETY: `&self` exposes only `devfreq()`, whose result is `Devfreq: Sync`
// via `devfreq->lock`. `register_em` and `register_opp_notifier` take
// `&mut self` and so cannot race with themselves.
unsafe impl<T: Callbacks> Sync for Registration<T> {}

impl<T: Callbacks> Registration<T> {
    /// # Safety
    ///
    /// `dev` must be the embedded `struct device` of a `bindings::devfreq`
    /// instance registered through [`Registration::new`], with its drvdata
    /// set to a `RegistrationContext<G::Data, T>` pointer allocated by that
    /// call. Called by the device core from `device_release` when the
    /// kobject's kref drops to zero.
    unsafe extern "C" fn release<G: Governor>(dev: *mut bindings::device) {
        // SAFETY: `dev` is the devfreq's own embedded device, passed by
        // `device_release` when the kobject's kref drops to zero. We
        // stored the `RegistrationContext` pointer in this device's
        // drvdata via `dev_set_drvdata(devfreq_dev, raw_data)` in
        // `Registration::new`, so the cast to
        // `*mut RegistrationContext<G::Data, T>` is sound.
        let ptr =
            unsafe { bindings::dev_get_drvdata(dev) }.cast::<RegistrationContext<G::Data, T>>();
        // SAFETY: The pointer was allocated with `KBox` during `new` and passed to us.
        let registration_context = unsafe { KBox::from_raw(ptr) };

        // `orig_release` reads `_profile` (via `profile->exit`) before our
        // drop runs, so it must fire while `registration_context` is alive.
        if let Some(orig_release) = registration_context.orig_release {
            // SAFETY: `orig_release` is the original kernel release callback.
            unsafe { orig_release(dev) };
        }
    }

    /// RAII wrapper around a registered devfreq.
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
            // INTENTIONAL LEAK: `devfreq_add_device` publishes sysfs via
            // `device_register` before its internal err paths run. A
            // userspace fd opened in that window holds the kobject kref
            // past `put_device`, leaving `struct devfreq` in deferred
            // release with `devfreq->profile` pointing at `_profile`.
            // The deferred `devfreq_dev_release` then dereferences
            // `profile->exit`. The chained wrapper installed below has
            // not run yet on the error path, so `RegistrationContext`
            // has no hook to free after that read; leaking it is the
            // only sound option.
            return Err(e);
        }

        // SAFETY: `ptr` is a valid devfreq pointer since `devfreq_add_device` succeeded.
        let devfreq_dev = unsafe { core::ptr::addr_of_mut!((*ptr).dev) };

        // SAFETY: `devfreq_dev` is a valid pointer.
        unsafe { bindings::dev_set_drvdata(devfreq_dev, raw_data.cast::<c_void>()) };

        // devfreq core dereferences `profile->exit` from its release
        // path. Chain our release before it so `RegistrationContext`
        // outlives the read.
        // SAFETY: `devfreq_dev` is freshly returned by
        // `devfreq_add_device` and not yet published to any other
        // thread; `raw_data` is uniquely owned here.
        unsafe {
            (*raw_data).orig_release = (*devfreq_dev).release;
            (*devfreq_dev).release = Some(Self::release::<G>);
        }

        // Snapshot of the parent's drvdata for the teardown guard to
        // restore on `Err`.
        // SAFETY: `dev.as_raw()` is a valid `struct device` pointer.
        let prior_parent_drvdata = unsafe { bindings::dev_get_drvdata(dev.as_raw()) };

        // The `struct devfreq` is live in sysfs from this point on, so any
        // `Err` returned below must first tear it down or a userspace open
        // of `target_freq` or `cur_freq` can chase a trampoline through
        // the caller state that probe is about to unwind.
        //
        // `devfreq_remove_device` calls `device_unregister`, which waits
        // for kernfs active references to drain, so no further trampoline
        // can fire on the removed devfreq once the guard returns. The
        // chained release installed above runs from `device_unregister`'s
        // release path and frees `raw_data`, so the guard does not need
        // to touch it. The deferred-fd-close release case is handled by
        // that same chained wrapper, which is now in place.
        let dev_raw = dev.as_raw();
        let teardown = ScopeGuard::new(move || {
            // SAFETY: `ptr` is the devfreq returned by `devfreq_add_device`
            // above and is still live until this call completes.
            unsafe { bindings::devfreq_remove_device(ptr) };
            // SAFETY: `dev_raw` is the parent `struct device` passed in by
            // the caller; it outlives this function. After
            // `devfreq_remove_device` returns no devfreq callback can read
            // the parent drvdata for this registration, so restoring it
            // here is race-free.
            unsafe { bindings::dev_set_drvdata(dev_raw, prior_parent_drvdata) };
        });

        teardown.dismiss();
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
    /// `dev` must be a valid pointer to the parent `struct device` of a
    /// devfreq registration whose driver data is either NULL or a
    /// `T::Data` pointer. Called by the devfreq core from the `target`
    /// profile-table slot.
    unsafe extern "C" fn target_callback(
        dev: *mut bindings::device,
        freq: *mut usize,
        flags: u32,
    ) -> c_int {
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
    /// `dev` must be a valid pointer to the parent `struct device` of a
    /// devfreq registration whose driver data is either NULL or a
    /// `T::Data` pointer. Called by the devfreq core from the
    /// `get_dev_status` profile-table slot.
    unsafe extern "C" fn get_dev_status_callback(
        dev: *mut bindings::device,
        stat: *mut bindings::devfreq_dev_status,
    ) -> c_int {
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
    /// `dev` must be a valid pointer to the parent `struct device` of a
    /// devfreq registration whose driver data is either NULL or a
    /// `T::Data` pointer. Called by the devfreq core from the
    /// `get_cur_freq` profile-table slot.
    unsafe extern "C" fn get_cur_freq_callback(
        dev: *mut bindings::device,
        freq: *mut usize,
    ) -> c_int {
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

        // The chained release hook installed by `new` frees `_profile` and
        // `_gov_data` after the devfreq core drops its last reference.
        // SAFETY: `self.devfreq` is a valid pointer to a devfreq device registered by us.
        unsafe { bindings::devfreq_remove_device(self.devfreq) };
    }
}
