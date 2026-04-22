// SPDX-License-Identifier: GPL-2.0

//! Generic Dynamic Voltage and Frequency Scaling (DVFS) Framework.
//!
//! C header: [`include/linux/devfreq.h`](srctree/include/linux/devfreq.h)

use crate::{
    bindings,
    clk::Hertz,
    device::Device,
    error::{from_err_ptr, from_result, to_result, Result},
    ffi::{c_int, c_ulong, c_void},
    impl_flags,
    opp::OPP,
    prelude::*,
    str::CStr,
    sync::aref::ARef,
    types::{ForeignOwnable, Opaque, ScopeGuard},
};
use core::{marker::PhantomData, ptr, ptr::NonNull};
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
    /// `ptr` must point to a valid `struct devfreq` that remains live for
    /// the duration of the lifetime `'a` the caller picks.
    pub(crate) unsafe fn from_raw<'a>(ptr: *mut bindings::devfreq) -> &'a Self {
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
    /// Wraps a raw flags word handed over by the devfreq core.
    ///
    /// Unknown bits are preserved as-is so callbacks can forward the
    /// kernel-supplied value back into [`recommended_opp`] without the
    /// abstraction silently dropping flags the C side knows about.
    pub(crate) fn from_raw(value: u32) -> Self {
        Self(value)
    }
}

/// Helper to find a recommended OPP.
pub fn recommended_opp(
    dev: &Device,
    freq: Hertz,
    flags: DevfreqFlags,
) -> Result<(ARef<OPP>, Hertz)> {
    let mut c_freq: usize = freq.as_hz();

    // SAFETY: `dev.as_raw()` is valid. `c_freq` is a local variable.
    let ptr = unsafe { bindings::devfreq_recommended_opp(dev.as_raw(), &mut c_freq, flags.into()) };

    // SAFETY: `ptr` is a valid `dev_pm_opp` pointer returned by
    // `devfreq_recommended_opp`; ownership of the reference transfers to
    // the resulting `ARef<OPP>`.
    let opp = unsafe { OPP::from_raw_opp_owned(from_err_ptr(ptr)?) }?;
    Ok((opp, Hertz(c_freq as c_ulong)))
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

/// Devfreq vtable: `target`, `get_dev_status`, and optional `get_cur_freq`.
///
/// # Safety
///
/// Implementers must ensure that for every parent `struct device` passed to
/// [`Registration::new`] with this `Callbacks` impl, `dev_get_drvdata`
/// returns either NULL or a valid pointer compatible with
/// `<Self::Data as ForeignOwnable>::borrow`. A NULL drvdata makes the
/// trampolines return `-ENODEV`; any other non-compatible pointer is UB.
#[vtable]
pub unsafe trait Callbacks {
    /// The associated data type stored in the `struct device` driver data.
    type Data: ForeignOwnable + Send + Sync;

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
        Err(EINVAL)
    }
}

mod private {
    /// Sealing super-trait for [`Governor`].
    pub trait Sealed {}
}

/// A devfreq governor.
///
/// This trait is sealed: only in-tree governors declared in this module may
/// implement it. The `NAME` constant identifies a kernel governor whose
/// private state the devfreq core casts from the `data` pointer passed at
/// registration, so the `NAME`/`Data` pairing must match the kernel side
/// exactly. Restricting implementers to this module keeps that pairing
/// auditable in one place.
///
/// # Safety
///
/// Implementers must ensure that `NAME` is a valid null-terminated C string
/// naming a governor that the kernel registers, and that the kernel
/// governor of that name interprets its `data` argument as `Self::Data`.
pub unsafe trait Governor: private::Sealed {
    /// The data type expected by the governor.
    type Data: Send + Sync + 'static;

    /// The name of the governor.
    const NAME: &'static CStr;
}

/// The `simple_ondemand` governor.
pub struct SimpleOndemand;

impl private::Sealed for SimpleOndemand {}

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

/// Optional registration knobs passed to [`Registration::new`].
///
/// `register_em` is applied best-effort: failure leaves the registration
/// without cooling support, queryable via [`Registration::has_em`]. An
/// `opp_notifier_dev` failure aborts the registration.
#[derive(Default)]
pub struct RegistrationOptions {
    /// Request Energy Model cooling-device registration.
    pub register_em: bool,
    /// If `Some`, register an OPP-change notifier on this device.
    pub opp_notifier_dev: Option<ARef<Device>>,
}

/// A wrapper for the registration of a `devfreq` device.
pub struct Registration<T: Callbacks> {
    devfreq: NonNull<bindings::devfreq>,
    cooling_dev: Option<NonNull<bindings::thermal_cooling_device>>,
    opp_notifier_dev: Option<ARef<Device>>,
    _p: PhantomData<T>,
}

// SAFETY: `devfreq` and `cooling_dev` point at kernel objects whose state is
// guarded by their own internal locks (`devfreq->lock` and the thermal core,
// respectively); both subsystems' APIs are callable from any thread, so
// transferring `Registration` ownership across threads is sound.
unsafe impl<T: Callbacks> Send for Registration<T> {}
// SAFETY: The only `&self` operation that crosses the FFI boundary is
// `devfreq()`, which returns `&Devfreq`; `Devfreq` is itself `Sync` through
// `devfreq->lock`. All other fields are immutable after `new` returns.
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
    /// The drvdata-compatibility obligation is discharged once at the
    /// `unsafe impl Callbacks` site, so this constructor is safe.
    pub fn new<G: Governor>(
        dev: &Device,
        initial_freq: Hertz,
        polling_ms: u32,
        gov_data: Option<G::Data>,
        options: RegistrationOptions,
    ) -> Result<Self> {
        let profile = KBox::new(
            bindings::devfreq_dev_profile {
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

        // INTENTIONAL LEAK on the `Err` path: `devfreq_add_device`
        // publishes sysfs via `device_register` before its internal
        // err paths run. A userspace fd opened in that window holds
        // the kobject kref past `put_device`, leaving `struct devfreq`
        // in deferred release with `devfreq->profile` pointing at
        // `_profile`. The deferred `devfreq_dev_release` then
        // dereferences `profile->exit`. The chained wrapper installed
        // below has not run yet on the error path, so
        // `RegistrationContext` has no hook to free after that read;
        // leaking it is the only sound option.
        from_err_ptr(ptr)?;

        // `devfreq_add_device` returns either a valid pointer or an
        // `ERR_PTR`. The `from_err_ptr(ptr)?` above handles `ERR_PTR`;
        // `NonNull::new` fails closed if the pointer is bare NULL
        // (which `from_err_ptr` does not exclude).
        let devfreq_nn = NonNull::new(ptr).ok_or(EINVAL)?;

        // SAFETY: `devfreq_nn` is a non-null `*mut bindings::devfreq` whose
        // pointee was just initialized by `devfreq_add_device`. Taking the
        // address of its `dev` field does not perform a load.
        let devfreq_dev = unsafe { core::ptr::addr_of_mut!((*devfreq_nn.as_ptr()).dev) };

        // SAFETY: `devfreq_dev` is a valid pointer.
        unsafe { bindings::dev_set_drvdata(devfreq_dev, raw_data.cast::<c_void>()) };

        // devfreq core dereferences `profile->exit` from its release
        // path. Chain our release before it so `RegistrationContext`
        // outlives the read.
        // SAFETY: `devfreq_dev` is a valid pointer just returned by
        // `devfreq_add_device`, and `raw_data` is uniquely owned here.
        // The release callback cannot fire until the kref reaches zero,
        // which only happens via the matching `devfreq_remove_device`
        // call in `Registration::drop`; that call is sequenced after
        // this initialization completes, so no concurrent reader of
        // `dev->release` exists in this window.
        unsafe {
            (*raw_data).orig_release = (*devfreq_dev).release;
            (*devfreq_dev).release = Some(Self::release::<G>);
        }

        // Snapshot of the parent's drvdata so the err-path guard can
        // restore it if any later fallible step trips. `new` does not
        // itself overwrite the parent drvdata, so on success the guard
        // restoration is a no-op; the snapshot is taken before any
        // fallible step that might branch away from the dismiss site.
        // SAFETY: `dev.as_raw()` is a valid `struct device` pointer.
        let prior_parent_drvdata = unsafe { bindings::dev_get_drvdata(dev.as_raw()) };
        let dev_raw = dev.as_raw();

        // `drvdata_restore` is declared before `reg` so that on an `Err`
        // return Rust's reverse-declaration drop order runs `reg`'s
        // `Drop` first (which calls `devfreq_remove_device` and drains
        // kernfs active refs, ensuring no further callback can read the
        // parent drvdata) and only then runs the restore. `Drop` therefore
        // owns the devfreq teardown end of the err path; this guard owns
        // only the parent-drvdata restoration.
        let drvdata_restore = ScopeGuard::new(move || {
            // SAFETY: `dev_raw` is the parent `struct device` passed in
            // by the caller; it outlives this function. The enclosing
            // `Registration`'s `Drop` runs before this guard on the err
            // path, so `devfreq_remove_device` has already drained
            // kernfs active refs and no devfreq callback can race the
            // restore.
            unsafe { bindings::dev_set_drvdata(dev_raw, prior_parent_drvdata) };
        });
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
                // `devfreq_cooling_em_register` returns either an
                // `ERR_PTR` (handled in the `Err` arm above) or a valid
                // non-NULL pointer per its kernel-side postcondition.
                // `NonNull::new` fails closed if the pointer is bare
                // NULL; in that case `cooling_dev` stays `None` and we
                // fall through to the same best-effort path as the
                // IS_ERR case.
                reg.cooling_dev = NonNull::new(cdev);
            }
        }

        if let Some(notifier_dev) = options.opp_notifier_dev {
            // SAFETY: `notifier_dev.as_raw()` and `reg.devfreq` are valid pointers.
            to_result(unsafe {
                bindings::devfreq_register_opp_notifier(notifier_dev.as_raw(), reg.devfreq.as_ptr())
            })?;
            reg.opp_notifier_dev = Some(notifier_dev);
        }

        drvdata_restore.dismiss();
        Ok(reg)
    }

    /// Returns the `Devfreq` wrapper.
    pub fn devfreq(&self) -> &Devfreq {
        // SAFETY: `self.devfreq` is a valid pointer.
        unsafe { Devfreq::from_raw(self.devfreq.as_ptr()) }
    }

    /// Returns true if Energy Model cooling registration succeeded.
    ///
    /// Only meaningful when [`RegistrationOptions::register_em`] was set;
    /// false otherwise.
    pub fn has_em(&self) -> bool {
        self.cooling_dev.is_some()
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
            let mut r_freq = Hertz(unsafe { *freq } as c_ulong);
            T::target(dev_ref, &mut r_freq, DevfreqFlags::from_raw(flags), data)?;

            // SAFETY: By the C API contract, `freq` is guaranteed to be a valid pointer.
            unsafe { *freq = r_freq.as_hz() };
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
            unsafe { *freq = f.as_hz() as usize };
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

        // The chained release hook installed by `new` frees `_profile` and
        // `_gov_data` after the devfreq core drops its last reference.
        // SAFETY: `self.devfreq` is a valid pointer to a devfreq device registered by us.
        unsafe { bindings::devfreq_remove_device(self.devfreq.as_ptr()) };
    }
}
