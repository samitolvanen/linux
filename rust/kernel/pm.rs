// SPDX-License-Identifier: GPL-2.0

//! Rust Runtime Power Management abstraction.
//!
//! C headers: [`include/linux/pm_runtime.h`](srctree/include/linux/pm_runtime.h),
//! [`include/linux/pm_domain.h`](srctree/include/linux/pm_domain.h)

use crate::{
    bindings,
    device::{
        self,
        AsBusDevice, //
    },
    error::{
        to_result,
        VTABLE_DEFAULT_ERROR, //
    },
    macros::paste,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::{
            ordering,
            Atomic, //
        },
        Arc, //
    },
    types::ForeignOwnable, //
};

use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    mem::ManuallyDrop, //
};

/// Runtime Power Management modes that determine how a particular PM
/// transition is to be carried out.
/// Corresponds to C Runtime PM flag argument bits:
/// - `RPM_ASYNC`
/// - `RPM_NOWAIT`
/// - `RPM_GET_PUT`
/// - `RPM_AUTO`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Mode(u32);

impl Mode {
    /// Synchronous PM operations - default.
    const SYNC: Mode = Mode(0);
    /// Allow asynchronous PM operations.
    const ASYNC: Mode = Mode(bindings::RPM_ASYNC);
    /// Do not wait for any pending requests to finish.
    const NOWAIT: Mode = Mode(bindings::RPM_NOWAIT);
    /// Acquire a runtime-PM usage reference.
    const ACQUIRE: Mode = Mode(bindings::RPM_GET_PUT);
    /// Use autosuspend.
    const AUTO: Mode = Mode(bindings::RPM_AUTO);
    /// Additional mode for devices supporting idle states.
    /// No counterpart.
    const IDLE: Mode = Mode(1 << 16);

    const fn join(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    fn includes(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

impl core::ops::BitOr for Mode {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for Mode {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::Not for Mode {
    type Output = Self;
    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

impl From<Mode> for c_int {
    #[inline]
    fn from(mode: Mode) -> c_int {
        mode.0 as c_int
    }
}

/// Utility macro for combining multiple request modes
macro_rules! mode {
    ($mode:expr $(, $args:expr)+ $(,)?) => {{
        let mut new_mode = $mode;
        $( new_mode = new_mode.join($args); )+
        new_mode
    }};
}

/// Device's runtime power management status
#[repr(i32)]
pub enum RuntimePMState {
    /// Runtime PM has not been initialized for this device yet.
    UNKNOWN = bindings::rpm_status_RPM_INVALID,
    /// The device is expected to be runtime active and in its normal operating state
    RESUMED = bindings::rpm_status_RPM_ACTIVE,
    /// The device is expected to be suspended, unavailable for normal operations
    SUSPENDED = bindings::rpm_status_RPM_SUSPENDED,
}

/// Runtime power transition scope.
pub struct Scope<Tag> {
    dev: ARef<device::Device>,
    mode: Mode,
    _tag: PhantomData<Tag>,
}

/// Device resumed without incrementing the device's usage count
pub struct Resume;
/// Device resumed with the device's usage count being incremented
pub struct Awake;
/// Device with increased usage reference
pub struct Retain;

/// Resumes the device without acquiring the usage reference.
/// Note: This does not guarantee the device will be kept active
/// for the lifetime of the scope due to potential pending/incoming
/// suspend requests.
///
/// On drop:
/// - If `Mode::IDLE`, calls `__pm_runtime_idle()`:
///   triggers idle notification before attempting to suspend
/// - If `Mode::AUTO`, marks last busy then calls `__pm_runtime_suspend()`.
/// - Otherwise calls `__pm_runtime_suspend()`.
///
/// The guard must be dropped from a context matching the requested transition
/// mode: sync vs async.
#[must_use = "dropping this guard issues the matching runtime PM release request"]
pub struct ResumeScope(Scope<Resume>);

/// Acquires a runtime-PM usage reference and keeps the device powered.
///
/// Requires `Mode::ACQUIRE`. Drop behavior matches `ResumeScope`.
/// The guard must be dropped from a context matching the requested transition
/// mode: sync vs async.
#[must_use = "dropping this guard releases its runtime PM hold"]
pub struct AwakeScope(Scope<Awake>);

/// Prevents the device from getting suspended by holding the usage reference
/// count.
///
/// On drop, calls `pm_runtime_put_noidle()`.
#[must_use = "dropping this guard releases its runtime PM hold"]
pub struct RetainScope(Scope<Retain>);

impl ResumeScope {
    fn new(dev: ARef<device::Device>, mode: Mode) -> Result<Self> {
        if mode.includes(Mode::ACQUIRE) {
            // Mode::ACQUIRE is intended to be used with Awake scope
            // Avoid mixing the modes.
            return Err(EINVAL);
        }

        // Mode::IDLE is internal so strip it off before passing further
        Request::resume(&dev, mode & !Mode::IDLE).map(|()| {
            Self(Scope::<Resume> {
                dev,
                mode,
                _tag: PhantomData,
            })
        })
    }

    fn release_inner(&self) -> Result {
        let scope_mode = self.0.mode & !Mode::IDLE;

        match self.0.mode {
            mode if mode.includes(Mode::IDLE) => {
                Request::idle(&self.0.dev, scope_mode & (Mode::ASYNC | Mode::NOWAIT))
            }
            mode if mode.includes(Mode::AUTO) => {
                Request::mark_last_busy(&self.0.dev);
                Request::suspend(&self.0.dev, scope_mode)
            }
            _ => Request::suspend(&self.0.dev, scope_mode),
        }
    }

    /// Explicitly release the scope
    /// This should be used in favor of regular drop
    /// when error handling is required.
    pub fn release(self) -> Result {
        let result = self.release_inner();
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is `ManuallyDrop`, so `this.0` is never dropped through
        // it. Reading it out here and dropping the result releases the device
        // reference exactly once.
        drop(unsafe { core::ptr::read(&this.0) });
        result
    }
}

impl Drop for ResumeScope {
    fn drop(&mut self) {
        let _ = self.release_inner();
    }
}

impl AwakeScope {
    fn new(dev: ARef<device::Device>, mode: Mode) -> Result<Self> {
        if !mode.includes(Mode::ACQUIRE) {
            return Err(EINVAL);
        }
        // Mode::IDLE is internal so strip it off before passing further
        match Request::resume(&dev, mode & !Mode::IDLE) {
            Ok(()) => {}
            // For async/nowait requests, `EINPROGRESS` means the resume is in
            // flight and the usage reference already keeps the device active.
            Err(e) if e == EINPROGRESS && mode.includes(mode!(Mode::ASYNC, Mode::NOWAIT)) => {}
            Err(e) => {
                Request::put_noidle(&dev);
                return Err(e);
            }
        }

        Ok(Self(Scope::<Awake> {
            dev,
            mode,
            _tag: PhantomData,
        }))
    }

    fn release_inner(&self) -> Result {
        let scope_mode = self.0.mode & !Mode::IDLE;
        match self.0.mode {
            mode if mode.includes(Mode::IDLE) => Request::idle(&self.0.dev, scope_mode),
            mode if mode.includes(Mode::AUTO) => {
                Request::mark_last_busy(&self.0.dev);
                Request::suspend(&self.0.dev, scope_mode)
            }
            _ => Request::idle(&self.0.dev, scope_mode),
        }
    }

    /// Explicitly release the scope
    /// This should be used in favor of regular drop
    /// when error handling is required.
    pub fn release(self) -> Result {
        let result = self.release_inner();
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is `ManuallyDrop`, so `this.0` is never dropped through
        // it. Reading it out here and dropping the result releases the device
        // reference exactly once.
        drop(unsafe { core::ptr::read(&this.0) });
        result
    }
}

impl Drop for AwakeScope {
    fn drop(&mut self) {
        let _ = self.release_inner();
    }
}

impl RetainScope {
    fn new(dev: ARef<device::Device>) -> Result<Self> {
        Request::get_noresume(&dev);
        Ok(Self(Scope::<Retain> {
            dev,
            mode: Mode(0),
            _tag: PhantomData,
        }))
    }

    fn try_new(dev: ARef<device::Device>) -> Result<Self> {
        Request::get_if_active(&dev)?;
        Ok(Self(Scope::<Retain> {
            dev,
            mode: Mode(0),
            _tag: PhantomData,
        }))
    }

    fn release_inner(&self) {
        Request::put_noidle(&self.0.dev);
    }

    /// Explicitly release the scope
    /// This should be used in favor of regular drop
    /// when error handling is required.
    pub fn release(self) -> Result {
        self.release_inner();
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is `ManuallyDrop`, so `this.0` is never dropped through
        // it. Reading it out here and dropping the result releases the device
        // reference exactly once.
        drop(unsafe { core::ptr::read(&this.0) });
        Ok(())
    }
}

impl Drop for RetainScope {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// Runtime PM helpers - wrappers around C runtime PM interface.
struct Request;

#[cfg(CONFIG_PM)]
impl Request {
    #[inline]
    fn active(dev: &ARef<device::Device>) -> bool {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        unsafe { bindings::pm_runtime_active(dev.as_raw()) }
    }

    #[inline]
    fn suspended(dev: &ARef<device::Device>) -> bool {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        unsafe { bindings::pm_runtime_suspended(dev.as_raw()) }
    }

    #[inline]
    fn resume(dev: &ARef<device::Device>, mode: Mode) -> Result {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        to_result(unsafe { bindings::__pm_runtime_resume(dev.as_raw(), mode.into()) })
    }

    #[inline]
    fn idle(dev: &ARef<device::Device>, mode: Mode) -> Result {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        to_result(unsafe { bindings::__pm_runtime_idle(dev.as_raw(), mode.into()) })
    }

    #[inline]
    fn mark_last_busy(dev: &ARef<device::Device>) {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        unsafe {
            bindings::pm_runtime_mark_last_busy(dev.as_raw());
        }
    }

    #[inline]
    fn suspend(dev: &ARef<device::Device>, mode: Mode) -> Result {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        to_result(unsafe { bindings::__pm_runtime_suspend(dev.as_raw(), mode.into()) })
    }

    #[inline]
    fn get_if_active(dev: &ARef<device::Device>) -> Result {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        match unsafe { bindings::pm_runtime_get_if_active(dev.as_raw()) } {
            ret if ret < 0 => Err(Error::from_errno(ret)),
            0 => Err(EAGAIN),
            _ => Ok(()),
        }
    }

    #[inline]
    fn runtime_enable(dev: &ARef<device::Device>) {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        unsafe { bindings::pm_runtime_enable(dev.as_raw()) }
    }

    #[inline]
    fn runtime_disable(dev: &ARef<device::Device>) {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        unsafe { bindings::__pm_runtime_disable(dev.as_raw(), true) };
    }

    #[inline]
    fn barrier(dev: &ARef<device::Device>) {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        unsafe {
            bindings::pm_runtime_barrier(dev.as_raw());
        }
    }
}

#[cfg(not(CONFIG_PM))]
impl Request {
    #[inline]
    fn active(_dev: &ARef<device::Device>) -> bool {
        true
    }

    #[inline]
    fn suspended(_dev: &ARef<device::Device>) -> bool {
        false
    }

    #[inline]
    fn resume(_dev: &ARef<device::Device>, _mode: Mode) -> Result {
        Ok(())
    }

    #[inline]
    fn idle(_dev: &ARef<device::Device>, _mode: Mode) -> Result {
        Err(ENOSYS)
    }

    #[inline]
    fn mark_last_busy(_dev: &ARef<device::Device>) {}

    #[inline]
    fn suspend(_dev: &ARef<device::Device>, _mode: Mode) -> Result {
        Err(ENOSYS)
    }

    #[inline]
    fn get_if_active(_dev: &ARef<device::Device>) -> Result {
        Err(EINVAL)
    }

    #[inline]
    fn runtime_enable(_dev: &ARef<device::Device>) {}

    #[inline]
    fn runtime_disable(_dev: &ARef<device::Device>) {}

    #[inline]
    fn barrier(_dev: &ARef<device::Device>) {}
}

impl Request {
    #[inline]
    fn get_noresume(dev: &ARef<device::Device>) {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        unsafe { bindings::pm_runtime_get_noresume(dev.as_raw()) };
    }

    #[inline]
    fn put_noidle(dev: &ARef<device::Device>) {
        // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
        // guaranteed to be alive and `as_raw()` yields a valid pointer for the
        // duration of this call.
        unsafe { bindings::pm_runtime_put_noidle(dev.as_raw()) };
    }

    #[allow(unused)]
    #[inline]
    fn mark_active(dev: &ARef<device::Device>) -> Result {
        to_result(
            // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
            // guaranteed to be alive and `as_raw()` yields a valid pointer for the
            // duration of this call.
            unsafe { bindings::pm_runtime_set_active(dev.as_raw()) },
        )
    }

    #[allow(unused)]
    #[inline]
    fn mark_suspended(dev: &ARef<device::Device>) -> Result {
        to_result(
            // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
            // guaranteed to be alive and `as_raw()` yields a valid pointer for the
            // duration of this call.
            unsafe { bindings::pm_runtime_set_suspended(dev.as_raw()) },
        )
    }
}

/// Common runtime PM callback entry point
///
/// The generated extern "C" callbacks call into this helper with the raw
/// `struct device *` provided by the PM core. It rebuilds the Rust device
/// reference, retrieves the device's PM registration data and performs
/// handoff to corresponding driver callback.
fn runtime_pm_callback<T, F>(dev: *mut bindings::device, cb: F) -> Result
where
    T: PMOps + 'static,
    F: FnOnce(
        &<T as PMOps>::DeviceType,
        Option<<T as PMOps>::RuntimePayloadType>,
    ) -> Result<
        Option<<T as PMOps>::RuntimePayloadType>,
        (Option<<T as PMOps>::RuntimePayloadType>, Error),
    >,
{
    let dev: &device::Device<device::Bound>  =
             // SAFETY: `dev` is provided by the PM core and remains
             // valid for the duration of the callback.
            unsafe { device::Device::from_raw(dev) };

    // SAFETY: `dev` is provided by the PM core and remains
    // valid for the duration of the callback.
    let ptr = unsafe { (*(*dev.as_raw()).p).rust_private };

    if ptr.is_null() {
        return Err(ENODEV);
    }

    // SAFETY: The runtime PM callback can only be triggered for bound device
    // and once the runtime PM is enabled.
    // `rust_private` is guaranteed to be valid and points to
    // associated RegistrationData<T> type object at least for the duration
    // of this call.
    let payload: Pin<&RegistrationData<T>> =
        unsafe { <Pin<KBox<RegistrationData<T>>> as ForeignOwnable>::borrow(ptr) };

    let pm_dev: &T::DeviceType =
        // SAFETY: The generated `dev_pm_ops` for `T` is installed on devices whose
        // bus-specific type is `T::DeviceType`. Therefore the base `Device<Bound>`
        // passed by the PM core is embedded in a valid `T::DeviceType`; the
        // `AsBusDevice` implementation supplies the correct offset for this cast.
        unsafe { T::DeviceType::from_device(dev) };

    payload.data.transition(|payload| cb(pm_dev, payload))
}

/// Defines generated C runtime PM callback.
///
/// This macro generates the corresponding `unsafe extern "C"` function for
/// requested PM operation and forwards it to [`runtime_pm_callback`].
///
/// # Safety
///
/// The generated function may only be installed in a `dev_pm_ops` table for a
/// device whose PM registration data was created by `Registration<T>`. In other
/// words, the type parameter `T` used for the callback table must match the
/// type parameter `T` used for the stored `RegistrationData<T>`.
///
/// The PM registration must keep the stored registration data alive and pinned
/// until runtime PM is disabled and all in-flight PM callbacks have completed.
macro_rules! define_pm_callback {
    (@parse_desc $name:ident) => { define_pm_callback!(@default $name); };
    (@default $name:ident) => {
        paste!(
          /// Generated runtime PM callback.
          ///
          /// # Safety
          ///
          /// `dev` must be a valid `struct device *` supplied by the PM core for a device
          /// whose runtime PM callbacks and PM registration data were both created
          /// for `T`.
            unsafe extern "C" fn [<$name _callback>]<'a, T:PMOps + 'static>(
                dev: *mut bindings::device
            ) -> c_int
                where
                    <T as PMOps>::DeviceType: 'a
            {
               runtime_pm_callback::<T, _>(dev,T::$name).map(|_| 0).unwrap_or_else(|e| e.to_errno())
            }
        );

    };
}

/// SAFETY:
/// bindings::dev_pm_ops is #[repr(C)], implements Default
/// and the struct itself is all nullable function pointers.
/// There is no padding and all zero bit-pattern is valid
///
const PMOPS_NONE: bindings::dev_pm_ops =
    unsafe { core::mem::MaybeUninit::<bindings::dev_pm_ops>::zeroed().assume_init() };

/// System-sleep suspend wrapper for the suspend, freeze, and poweroff slots.
///
/// Runs the device's runtime-suspend callback via `pm_runtime_force_suspend`,
/// as `DEFINE_RUNTIME_DEV_PM_OPS` does.
///
/// # Safety
///
/// `dev` must be a valid `struct device *` provided by the PM core.
#[cfg(CONFIG_PM_SLEEP)]
unsafe extern "C" fn system_sleep_suspend(dev: *mut bindings::device) -> c_int {
    // SAFETY: The PM core passes a valid `struct device *` to a system-sleep
    // callback and it stays valid for the duration of the call.
    unsafe { bindings::pm_runtime_force_suspend(dev) }
}

/// System-sleep resume wrapper for the resume, thaw, and restore slots.
///
/// Runs the device's runtime-resume callback via `pm_runtime_force_resume`,
/// as `DEFINE_RUNTIME_DEV_PM_OPS` does. On success it then calls
/// [`PMOps::system_resume_done`].
///
/// # Safety
///
/// `dev` must be a valid `struct device *` provided by the PM core for a
/// device whose PM callback table was generated for `T`.
#[cfg(CONFIG_PM_SLEEP)]
unsafe extern "C" fn system_sleep_resume<T: PMOps>(dev: *mut bindings::device) -> c_int {
    // SAFETY: The PM core passes a valid `struct device *` to a system-sleep
    // callback and it stays valid for the duration of the call.
    let ret = unsafe { bindings::pm_runtime_force_resume(dev) };
    if ret != 0 {
        return ret;
    }

    if !T::HAS_SYSTEM_RESUME_DONE {
        return 0;
    }

    let dev: &device::Device<device::Bound> =
        // SAFETY: The PM core passes a valid `struct device *` to a system-sleep
        // callback and it stays valid for the duration of the call. System-sleep
        // callbacks only run for bound devices.
        unsafe { device::Device::from_raw(dev) };

    let pm_dev: &T::DeviceType =
        // SAFETY: The generated `dev_pm_ops` for `T` is installed on devices whose
        // bus-specific type is `T::DeviceType`. Therefore the base `Device<Bound>`
        // passed by the PM core is embedded in a valid `T::DeviceType`. The
        // `AsBusDevice` implementation supplies the correct offset for this cast.
        unsafe { T::DeviceType::from_device(dev) };

    T::system_resume_done(pm_dev);
    0
}

/// Builds the base `dev_pm_ops` carrying the six system-sleep/hibernation
/// slots when the driver opts in via [`PMOps::SYSTEM_SLEEP`].
///
/// Under `CONFIG_PM_SLEEP` the slots point at the generic force-suspend and
/// force-resume wrappers. Otherwise they stay `None`, matching the
/// `pm_sleep_ptr()` gating in C. The runtime slots are filled by the caller.
const fn system_sleep_base<T: PMOps>() -> bindings::dev_pm_ops {
    const_assert!(
        T::SYSTEM_SLEEP || !T::HAS_SYSTEM_RESUME_DONE,
        "PMOps::system_resume_done requires PMOps::SYSTEM_SLEEP"
    );

    if T::SYSTEM_SLEEP {
        #[cfg(CONFIG_PM_SLEEP)]
        return bindings::dev_pm_ops {
            suspend: Some(system_sleep_suspend),
            resume: Some(system_sleep_resume::<T>),
            freeze: Some(system_sleep_suspend),
            thaw: Some(system_sleep_resume::<T>),
            poweroff: Some(system_sleep_suspend),
            restore: Some(system_sleep_resume::<T>),
            ..PMOPS_NONE
        };
    }
    PMOPS_NONE
}

/// Runtime PM callbacks implemented by a driver.
///
/// Defines the [`PMOps`] trait and its corresponding [`bindings::dev_pm_ops`].
///
/// Each generated C callback recovers the Rust bus device from the raw
/// `struct device *`, borrows the registered runtime PM payload, and delegates
/// to the matching [`PMOps`] trait method.
///
/// # Safety
///
/// `PMContext::<T>::PM_OPS` must only be installed for devices whose concrete
/// bus type is `T::DeviceType`, and whose runtime PM registration data was
/// installed by [`Registration::new`] for the same `T`.
///
macro_rules! define_pm_ops {
    ($($name:ident $( : $desc:tt )? ),+ $(,)?) => {
        $( define_pm_callback!( @parse_desc $name $( $desc )?); )+
        define_pm_ops!(@common $( $name ), +);
    };

    (@common $( $name:ident),+ ) => {
        /// Runtime PM callbacks implemented by a driver
        #[vtable]
        pub trait PMOps: Sized
        {
            /// Type of a bus device
            type DeviceType: AsBusDevice<device::Bound>;
            /// Type of the data associated with a PM transitions:
            type RuntimePayloadType: Send;

            /// Opt-in for system-sleep and hibernation support.
            ///
            /// When `true`, the generated `PM_OPS` fills the system-sleep and
            /// hibernation slots with force-suspend and force-resume wrappers
            /// that reuse the runtime PM callbacks. The slots stay unset under
            /// `CONFIG_PM_SLEEP=n`.
            const SYSTEM_SLEEP: bool = false;

            /// Called after a system-sleep resume, thaw, or restore has
            /// re-enabled runtime PM for the device.
            ///
            /// Runtime PM is disabled for the duration of a system-sleep
            /// transition, so runtime PM requests issued in that window fail.
            /// This hook runs once runtime PM is enabled again, which lets a
            /// driver reissue the work those requests would have started. The
            /// device is not necessarily runtime-active when the hook runs.
            /// Implementing this without [`PMOps::SYSTEM_SLEEP`] fails the
            /// build.
            ///
            /// The hook is not called when the resume fails. It runs in
            /// process context with the device lock held and may sleep.
            fn system_resume_done(_dev: &Self::DeviceType) {}

            $(
                #[allow(missing_docs)]
                // Callback-specific docs are provided by the generated `dev_pm_ops`
                // contract on `PMOps`.

                fn $name<'a>(
                    _dev:  &'a Self::DeviceType,
                    _payload: Option<Self::RuntimePayloadType>,
                ) -> Result<Option<Self::RuntimePayloadType>, (Option<Self::RuntimePayloadType>, Error)> {
                    build_error!(VTABLE_DEFAULT_ERROR)
                }
            )+
        }
        paste!(
            impl<T:PMOps + 'static> PMContext<T> {
                /// Driver-provided runtime PM operations.
                ///
                /// A driver implements this trait to handle runtime PM
                /// transitions for its device type.
                ///
                /// Each callback receives the device and the current payload.
                /// On success, it returns the payload to keep for the next
                /// transition. On failure, it returns the payload together
                /// with the error so the previous, or otherwise sane state
                /// can be preserved.
                pub const PM_OPS: bindings::dev_pm_ops = bindings::dev_pm_ops {
                    $( [<$name>]: if T::[<HAS_ $name:upper>] {
                        Some([<$name _callback>]::<T>)
                    } else {
                        None
                    }, )+
                    ..system_sleep_base::<T>()
                };
            }
        );
    }
}

/// RAII guard for ongoing runtime PM payload transition.
///
/// For most of the callbacks this guard is not necessarily needed as
/// the callbacks themselves are being serialized by the runtime PM C code.
/// Still, some like runtime_idle are exempt from that.
#[allow(unused)]
struct PayloadGuard<'a> {
    busy: &'a Atomic<bool>,
}

impl Drop for PayloadGuard<'_> {
    fn drop(&mut self) {
        self.busy.store(false, ordering::Release);
    }
}

struct PMPayload<P> {
    in_flight: Atomic<bool>,
    inner: UnsafeCell<Option<P>>,
}

impl<P> PMPayload<P> {
    /// Attempts to acquire exclusive access to the runtime PM payload.
    ///
    /// Returns `EBUSY` if another runtime PM callback is already transitioning the
    /// payload.
    fn acquire(&self) -> Result<PayloadGuard<'_>> {
        self.in_flight
            .cmpxchg(false, true, ordering::Acquire)
            .map_err(|_| EBUSY)?;
        Ok(PayloadGuard {
            busy: &self.in_flight,
        })
    }

    /// Runs a runtime PM transition with exclusive access to the stored payload.
    ///
    /// This method acquires the in-flight guard, temporarily takes the payload out
    /// of storage The closure must return the payload that should be stored
    /// for the next transition.
    ///
    /// On success, the returned payload replaces the previous payload. On failure,
    /// the closure returns the payload together with the error, and that payload is
    /// restored before the error is propagated.
    ///
    /// Returns `EBUSY` if another runtime PM transition is already in progress.
    fn transition(
        &self,
        f: impl FnOnce(Option<P>) -> Result<Option<P>, (Option<P>, Error)>,
    ) -> Result {
        let _guard = self.acquire()?;
        // SAFETY: Holding `_guard` means this callback successfully changed
        // `in_flight` from false to true. No other caller can hold a `PayloadGuard`
        // until `_guard` is dropped, so this function has exclusive access to `inner`.
        let slot = unsafe { &mut *self.inner.get() };

        let payload = slot.take();

        match f(payload) {
            Ok(new_payload) => {
                *slot = new_payload;
                Ok(())
            }
            Err((old_payload, err)) => {
                *slot = old_payload;
                Err(err)
            }
        }
    }
}

// SAFETY: Although PMPayload's `inner` is an `UnsafeCell`, it is only accessed
// after `in_flight` has been acquired. The atomic flag serializes all mutable
// access to the payload, and `PayloadGuard` clears the flag when the access ends.
unsafe impl<P: Send> Sync for PMPayload<P> {}

struct PMContextInner<T: PMOps> {
    dev: ARef<device::Device>,
    /// Optional driver-selected runtime PM request PMProfiles.
    ///
    /// Set of runtime PM predefined PMProfiles that can be used by the driver
    /// when requesting a PM transition. This might be useful when a driver
    /// has several different PM usage patterns.
    /// See [PMProfile] for more details.
    profiles: KVec<PMProfile>,
    /// Set of PM config options applied for associated device.
    configs: KVec<PMConfig>,
    _marker: PhantomData<T>,
}

/// Runtime PM context tied to a device.
pub struct PMContext<T: PMOps> {
    // Preferably, PMContext could be shared via borrowed reference over
    // a PM registration's lifetime but that complicates things on its own
    // when the context needs to be shared across different Registration types.
    inner: Arc<PMContextInner<T>>,
}

impl<T: PMOps> PMContext<T> {
    /// Enable runtime PM
    pub fn enable(&self, state: RuntimePMState) -> Result {
        Self::apply_config(&self.inner.dev, &self.inner.configs);
        match state {
            RuntimePMState::RESUMED => Request::mark_active(&self.inner.dev),
            RuntimePMState::SUSPENDED => Request::mark_suspended(&self.inner.dev),
            _ => Err(EINVAL),
        }?;
        Request::runtime_enable(&self.inner.dev);
        Ok(())
    }
    /// Disable runtime PM
    pub fn disable(&self) -> Result {
        Self::apply_config(&self.inner.dev, &[PMConfig::AutoSuspend(false)]);
        Request::runtime_disable(&self.inner.dev);
        Ok(())
    }

    /// Returns whether the runtime PM state is active.
    #[inline]
    pub fn active(&self) -> bool {
        Request::active(&self.inner.dev)
    }

    /// Returns whether the runtime PM state is suspended.
    #[inline]
    pub fn suspended(&self) -> bool {
        Request::suspended(&self.inner.dev)
    }

    /// Creates a `ResumeScope` for the given PMProfile.
    #[inline]
    pub fn resume(&self, profile: PMProfile) -> Result<ResumeScope> {
        ResumeScope::new(self.inner.dev.clone(), profile.0)
    }

    /// Creates an `AwakeScope` for the given PMProfile.
    /// Note that for ASYNC request this does not guarantee
    /// the device has been resumed at the time this function returns.
    #[inline]
    pub fn get(&self, profile: PMProfile) -> Result<AwakeScope> {
        AwakeScope::new(self.inner.dev.clone(), profile.0 | Mode::ACQUIRE)
    }

    /// Creates an `AwakeScope` only if the device is runtime-active.
    ///
    /// Acquires a usage reference if and only if the device's runtime PM
    /// status is `RPM_ACTIVE`, without ever resuming it, mirroring
    /// `pm_runtime_get_if_active()`. The reference blocks runtime suspend
    /// until the returned scope is dropped, so this is safe to call from
    /// contexts that must not run the resume callback inline.
    ///
    /// Returns `Ok(None)` when the device is not runtime-active and
    /// `Err(EINVAL)` when runtime PM is disabled for the device.
    #[inline]
    pub fn get_if_active(&self, profile: PMProfile) -> Result<Option<AwakeScope>> {
        match Request::get_if_active(&self.inner.dev) {
            Ok(()) => Ok(Some(AwakeScope(Scope::<Awake> {
                dev: self.inner.dev.clone(),
                mode: profile.0 | Mode::ACQUIRE,
                _tag: PhantomData,
            }))),
            Err(e) if e == EAGAIN => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Creates a `RetainScope` for this device.
    pub fn hold(&self) -> Result<RetainScope> {
        RetainScope::new(self.inner.dev.clone())
    }

    /// Creates a `RetainScope` for an active device.
    pub fn try_hold_active(&self) -> Result<RetainScope> {
        RetainScope::try_new(self.inner.dev.clone())
    }

    /// Runs a closure while holding a `ResumeScope`.
    pub fn with_resume<R>(&self, profile: PMProfile, f: impl FnOnce() -> Result<R>) -> Result<R> {
        if profile.0.includes(Mode::ASYNC) {
            return Err(EINVAL);
        }
        let _scope = self.resume(profile)?;
        f()
    }
    /// Runs a closure while holding an `AwakeScope`.
    ///
    /// The closure runs on a resumed device, so nowait profiles are rejected
    /// alongside async ones. `AwakeScope::new` accepts an in-flight resume for
    /// those, which would let the closure run before that resume completes.
    pub fn with_get<R>(&self, profile: PMProfile, f: impl FnOnce() -> Result<R>) -> Result<R> {
        if profile.0.includes(mode!(Mode::ASYNC, Mode::NOWAIT)) {
            return Err(EINVAL);
        }
        let _scope = self.get(profile)?;
        f()
    }

    /// Runs a closure while holding a `RetainScope`.
    pub fn with_hold<R>(&self, f: impl FnOnce() -> Result<R>) -> Result<R> {
        let _scope = self.hold()?;
        f()
    }

    /// Applies runtime PM configuration options.
    ///
    /// Options are applied in the order provided. The currently supported
    /// options do not report per-option failures.
    fn apply_config(dev: &ARef<device::Device>, opts: &[PMConfig]) {
        #[cfg(not(CONFIG_PM))]
        let _ = opts;
        let _ = dev;
        #[cfg(CONFIG_PM)]
        for opt in opts {
            match opt {
                // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
                // guaranteed to be alive and `as_raw()` yields a valid pointer for the
                // duration of this call.
                PMConfig::IgnoreChildren(v) => unsafe {
                    bindings::pm_suspend_ignore_children(dev.as_raw(), *v)
                },
                // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
                // guaranteed to be alive and `as_raw()` yields a valid pointer for the
                // duration of this call.
                PMConfig::NoCallbacks => unsafe { bindings::pm_runtime_no_callbacks(dev.as_raw()) },
                // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
                // guaranteed to be alive and `as_raw()` yields a valid pointer for the
                // duration of this call.
                PMConfig::IrqSafe => unsafe { bindings::pm_runtime_irq_safe(dev.as_raw()) },
                // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
                // guaranteed to be alive and `as_raw()` yields a valid pointer for the
                // duration of this call.
                PMConfig::AutoSuspend(v) => unsafe {
                    bindings::__pm_runtime_use_autosuspend(dev.as_raw(), *v);
                },
                // SAFETY: `dev` is a valid `&ARef<Device>`, so the underlying `Device` is
                // guaranteed to be alive and `as_raw()` yields a valid pointer for the
                // duration of this call.
                PMConfig::AutoSuspendDelay(v) => unsafe {
                    bindings::pm_runtime_set_autosuspend_delay(dev.as_raw(), *v as i32);
                    bindings::__pm_runtime_use_autosuspend(dev.as_raw(), true);
                },
            }
        }
    }

    /// Get a borrowed reference to PM profiles associated with the PM context.
    pub fn profiles(&self) -> &[PMProfile] {
        &self.inner.profiles
    }

    /// Get a borrowed reference to PM configs associated with the PM context.
    pub fn configs(&self) -> &[PMConfig] {
        &self.inner.configs
    }
}

// Preferably, PMContext could be shared via borrowed reference over
// a PM registration's lifetime but that complicates things on its own
// when the context needs to be shared across different Registration types.
impl<T: PMOps> Clone for PMContext<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

define_pm_ops!(
    // PM state change
    runtime_suspend,
    runtime_resume,
);

/// Runtime PM request PMProfile.
pub struct PMProfile(Mode);

impl PMProfile {
    /// Creates a PMProfile with default SYNC mode set.
    pub const fn new() -> Self {
        Self(Mode::SYNC)
    }
    /// Enables async PM operations for this PMProfile.
    pub const fn r#async(self) -> Self {
        Self(mode!(self.0, Mode::ASYNC))
    }
    /// Use autosuspend
    pub const fn auto(self) -> Self {
        Self(mode!(self.0, Mode::AUTO))
    }
    /// Requests idle handling for this PMProfile.
    pub const fn idle(self) -> Self {
        Self(mode!(self.0, Mode::IDLE))
    }
    /// Do not wait for concurrent requests to finish.
    pub const fn nowait(self) -> Self {
        Self(mode!(self.0, Mode::NOWAIT))
    }
}

impl Default for PMProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration knobs for runtime PM.
pub enum PMConfig {
    /// Ignore child devices when suspending.
    IgnoreChildren(bool),
    /// Disable runtime PM callbacks.
    NoCallbacks,
    /// Mark device as IRQ-safe for runtime PM.
    IrqSafe,
    /// Enable or disable autosuspend.
    AutoSuspend(bool),
    /// Set autosuspend delay (milliseconds).
    AutoSuspendDelay(u32),
}

/// Runtime PM data stored within the `struct device_private' during
/// runtime PM registration.
///
/// The data is associated with PM transitions and it's conceptually owned
/// by the Registration itself.
///
#[repr(C)]
#[pin_data]
struct RegistrationData<T: PMOps> {
    #[pin]
    data: PMPayload<T::RuntimePayloadType>,
}

/// Runtime PM registration for a device.
///
/// A `Registration` installs the runtime PM payload used by the
/// generated [`PMOps`] callbacks and owns the corresponding teardown.
///
/// Dropping the registration disables runtime PM, waits for in-flight runtime PM
/// callbacks to complete, and then removes the stored registration data.
pub struct Registration<T: PMOps + 'static> {
    ctx: PMContext<T>,
}

impl<T: PMOps + 'static> Registration<T> {
    /// Creates a runtime PM registration for `dev`.
    ///
    /// The provided profiles and configuration are stored in the associated
    /// [`PMContext`]. The optional `payload` is stored as a Registration data
    /// and is used to service PM transitions.
    ///
    /// The device must use the callback table generated for the same `T`.
    pub fn new(
        dev: &device::Device<device::Core>,
        profiles: Option<KVec<PMProfile>>,
        configs: Option<KVec<PMConfig>>,
        payload: Option<T::RuntimePayloadType>,
    ) -> Result<Self> {
        let payload = KBox::pin_init(
            RegistrationData::<T> {
                data: PMPayload {
                    in_flight: Atomic::new(false),
                    inner: UnsafeCell::new(payload),
                },
            },
            GFP_KERNEL,
        )?;

        let inner_ctx = Arc::new(
            PMContextInner {
                dev: dev.into(),
                profiles: profiles.unwrap_or_default(),
                configs: configs.unwrap_or_default(),
                _marker: PhantomData,
            },
            GFP_KERNEL,
        )?;

        // SAFETY: `dev` is a live `Device<Core>`, so its raw `struct device` pointer is
        // valid for the duration of this call. The payload allocation is converted into
        // a foreign pointer and owned by this `Registration` until `Drop` clears
        // `rust_private` and reconstructs the `KBox`.
        unsafe {
            let ptr = (*(*dev.as_raw()).p).rust_private;
            if !ptr.is_null() {
                return Err(EBUSY);
            }
            (*(*dev.as_raw()).p).rust_private = payload.into_foreign();
        }

        Ok(Self {
            ctx: PMContext { inner: inner_ctx },
        })
    }
    /// Returns the runtime PM context associated with this registration.
    pub fn ctx(&self) -> &PMContext<T> {
        &self.ctx
    }
}

impl<T: PMOps + 'static> Drop for Registration<T> {
    fn drop(&mut self) {
        // Drain in-flight callbacks before the registration data below is freed.
        Request::runtime_disable(&self.ctx.inner.dev);
        Request::barrier(&self.ctx.inner.dev);

        // SAFETY: The pointer, if non-null, was stored by `Registration::new`
        // using `Pin<KBox<RegistrationData<T>>>::into_foreign`. Runtime PM has
        // been disabled and drained above, so generated callbacks can no longer
        // borrow this data. Clearing `rust_private` prevents later lookup, and
        // `from_foreign` reconstructs the owning allocation so it is dropped.
        unsafe {
            let ptr = (*(*self.ctx.inner.dev.as_raw()).p).rust_private;

            if !ptr.is_null() {
                (*(*self.ctx.inner.dev.as_raw()).p).rust_private = core::ptr::null_mut();
                Pin::<KBox<RegistrationData<T>>>::from_foreign(ptr);
            }
        }
    }
}

/// Attaches `dev` to the PM domains listed in its device-tree node.
///
/// Every power domain referenced by the node is attached with no extra flags,
/// and a runtime-PM device link is created for each, mirroring the C
/// `devm_pm_domain_attach_list()` null-data form.
///
/// A device with no device-tree node or no `power-domains` phandle attaches
/// nothing. When the bus has already attached a single PM domain to the device
/// (`-EEXIST`), that is treated the same way, since that domain is managed by
/// the bus rather than by this list.
///
/// The attachment is devres-managed and detached at unbind.
pub fn attach_pm_domains(dev: &device::Device<device::Bound>) -> Result {
    let mut list: *mut bindings::dev_pm_domain_list = core::ptr::null_mut();

    // SAFETY: `dev` is a bound device, so `as_raw()` yields a valid
    // `struct device *` for the duration of the call. A null `data` is a
    // valid argument, and `&mut list` is a valid writable out-pointer.
    let ret =
        unsafe { bindings::devm_pm_domain_attach_list(dev.as_raw(), core::ptr::null(), &mut list) };

    if ret < 0 {
        let err = Error::from_errno(ret);
        // Already attached by the bus.
        if err == EEXIST {
            return Ok(());
        }
        return Err(err);
    }

    Ok(())
}
