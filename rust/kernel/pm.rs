// SPDX-License-Identifier: GPL-2.0

//! Rust Runtime Power Management abstraction.
//!
//! C header: [`include/linux/pm_runtime.h`](srctree/include/linux/pm_runtime.h)

use crate::{
    bindings,
    bits::bit_u32,
    device::{
        self,
        AsBusDevice, //
    },
    driver,
    error::{
        to_result,
        VTABLE_DEFAULT_ERROR, //
    },
    prelude::*,
    sync::{
        aref::ARef,
        atomic::{
            ordering,
            Atomic,
            AtomicFlag,
            AtomicType, //
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

kernel::impl_flags! {
    /// Runtime Power Management modes that determine how a particular PM
    /// transition is to be carried out.
    /// Corresponds to C Runtime PM flag argument bits:
    /// - `RPM_ASYNC`
    /// - `RPM_NOWAIT`
    /// - `RPM_GET_PUT`
    /// - `RPM_AUTO`
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Mode(u32);

    /// Single RPM mode.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum ModeFlag {
        /// Synchronous PM operations - default.
        Sync = 0,
        /// Allow asynchronous PM operations.
        Async = bindings::RPM_ASYNC,
        /// Do not wait for any pending requests to finish.
        Nowait = bindings::RPM_NOWAIT,
        /// Acquire a runtime-PM usage reference.
        Acquire = bindings::RPM_GET_PUT,
        /// Use autosuspend.
        Auto = bindings::RPM_AUTO,
        /// Additional mode for devices supporting idle states.
        /// No counterpart.
        Idle = bit_u32(16),
    }
}

impl From<Mode> for c_int {
    #[inline]
    fn from(mode: Mode) -> c_int {
        mode.0 as c_int
    }
}

/// Device's runtime power management status.
#[repr(i32)]
pub enum RuntimePMState {
    /// Runtime PM has not been initialized for this device yet.
    Unknown = bindings::rpm_status_RPM_INVALID,
    /// The device is expected to be runtime active and in its normal operating state.
    Resumed = bindings::rpm_status_RPM_ACTIVE,
    /// The device is expected to be suspended, unavailable for normal operations.
    Suspended = bindings::rpm_status_RPM_SUSPENDED,
}

/// Runtime power transition scope.
pub struct Scope<Tag> {
    dev: ARef<device::Device>,
    mode: Mode,
    _tag: PhantomData<Tag>,
}

/// Device resumed without incrementing the device's usage count.
pub struct Resume;
/// Device resumed with the device's usage count being incremented.
pub struct Awake;
/// Device with increased usage reference.
pub struct Retain;

/// Resumes the device without acquiring the usage reference.
/// Note: This does not guarantee the device will be kept active
/// for the lifetime of the scope due to potential pending/incoming
/// suspend requests.
///
/// On drop:
/// - If `ModeFlag::Idle`, calls `__pm_runtime_idle()`:
///   triggers idle notification before attempting to suspend.
/// - If `ModeFlag::Auto`, marks last busy then calls `__pm_runtime_suspend()`.
/// - Otherwise calls `__pm_runtime_suspend()`.
///
/// The guard must be dropped from a context matching the requested transition
/// mode: sync vs async.
#[must_use = "dropping this guard issues the matching runtime PM release request"]
pub struct ResumeScope(Scope<Resume>);

/// Acquires a runtime-PM usage reference and keeps the device powered.
///
/// Requires `ModeFlag::Acquire`. Drop behavior matches `ResumeScope`.
/// The guard must be dropped from a context matching the requested transition
/// mode: sync vs async.
#[must_use = "dropping this guard releases its runtime PM hold"]
pub struct AwakeScope(Scope<Awake>);

/// Prevents the device from getting suspended by holding the usage reference
/// count.
///
/// Releasing the scope, through `release()` or `Drop`, marks the device busy
/// and then calls `pm_runtime_put()`. It may take `dev->power.lock`, a
/// sleeping lock on `PREEMPT_RT`, so it must not happen under a raw spinlock
/// or in hardirq context.
#[must_use = "dropping this guard releases its runtime PM hold"]
pub struct RetainScope(Scope<Retain>);

/// A scope wrapper whose `Drop` issues the release request for its inner
/// [`Scope`].
///
/// # Safety
///
/// `scope()` must return a reference to a [`Scope`] field of `self`.
unsafe trait ScopeWrapper: Sized {
    /// The scope tag.
    type Tag;

    /// Returns the wrapped scope.
    fn scope(&self) -> &Scope<Self::Tag>;
}

/// Moves the inner scope out of `wrapper` without running the wrapper's
/// `Drop`. Dropping the returned scope releases the device reference.
#[inline]
fn take_scope<W: ScopeWrapper>(wrapper: W) -> Scope<W::Tag> {
    let wrapper = ManuallyDrop::new(wrapper);
    // SAFETY: By the `ScopeWrapper` contract, `scope()` returns a field of
    // `wrapper`, which is `ManuallyDrop`, so the field is never dropped
    // through it. Reading it out here moves it exactly once.
    unsafe { core::ptr::read(wrapper.scope()) }
}

// SAFETY: `scope()` returns the wrapper's own field.
unsafe impl ScopeWrapper for ResumeScope {
    type Tag = Resume;

    #[inline]
    fn scope(&self) -> &Scope<Resume> {
        &self.0
    }
}

// SAFETY: `scope()` returns the wrapper's own field.
unsafe impl ScopeWrapper for AwakeScope {
    type Tag = Awake;

    #[inline]
    fn scope(&self) -> &Scope<Awake> {
        &self.0
    }
}

// SAFETY: `scope()` returns the wrapper's own field.
unsafe impl ScopeWrapper for RetainScope {
    type Tag = Retain;

    #[inline]
    fn scope(&self) -> &Scope<Retain> {
        &self.0
    }
}

impl ResumeScope {
    fn new(dev: ARef<device::Device>, mode: Mode) -> Result<Self> {
        if mode.contains(ModeFlag::Acquire) {
            // ModeFlag::Acquire is intended to be used with Awake scope
            // Avoid mixing the modes.
            return Err(EINVAL);
        }

        // ModeFlag::Idle is internal so strip it off before passing further
        Request::resume(&dev, mode & !ModeFlag::Idle).map(|()| {
            Self(Scope::<Resume> {
                dev,
                mode,
                _tag: PhantomData,
            })
        })
    }

    fn release_inner(&self) -> Result {
        let scope_mode = self.0.mode & !ModeFlag::Idle;

        match self.0.mode {
            mode if mode.contains(ModeFlag::Idle) => Request::idle(
                &self.0.dev,
                scope_mode & (ModeFlag::Async | ModeFlag::Nowait),
            ),
            mode if mode.contains(ModeFlag::Auto) => {
                Request::mark_last_busy(&self.0.dev);
                Request::suspend(&self.0.dev, scope_mode)
            }
            _ => Request::suspend(&self.0.dev, scope_mode),
        }
    }

    /// Explicitly release the scope.
    ///
    /// This should be used in favor of regular drop
    /// when error handling is required.
    pub fn release(self) -> Result {
        let result = self.release_inner();
        drop(take_scope(self));
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
        if !mode.contains(ModeFlag::Acquire) {
            return Err(EINVAL);
        }
        // ModeFlag::Idle is internal so strip it off before passing further
        match Request::resume(&dev, mode & !ModeFlag::Idle) {
            Ok(()) => {}
            // For async/nowait requests, `EINPROGRESS` means the resume is in
            // flight and the usage reference already keeps the device active.
            Err(e) if e == EINPROGRESS && mode.contains_any(ModeFlag::Async | ModeFlag::Nowait) => {
            }
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
        let scope_mode = self.0.mode & !ModeFlag::Idle;
        match self.0.mode {
            mode if mode.contains(ModeFlag::Idle) => Request::idle(&self.0.dev, scope_mode),
            mode if mode.contains(ModeFlag::Auto) => {
                Request::mark_last_busy(&self.0.dev);
                Request::suspend(&self.0.dev, scope_mode)
            }
            _ => Request::suspend(&self.0.dev, scope_mode),
        }
    }

    /// Explicitly release the scope.
    ///
    /// This should be used in favor of regular drop
    /// when error handling is required.
    pub fn release(self) -> Result {
        let result = self.release_inner();
        drop(take_scope(self));
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
            mode: Mode(ModeFlag::Sync as u32),
            _tag: PhantomData,
        }))
    }

    fn try_new(dev: ARef<device::Device>) -> Result<Self> {
        Request::get_if_active(&dev)?;
        Ok(Self(Scope::<Retain> {
            dev,
            mode: Mode(ModeFlag::Sync as u32),
            _tag: PhantomData,
        }))
    }

    fn release_inner(&self) -> Result {
        Request::mark_last_busy(&self.0.dev);
        Request::put(&self.0.dev)
    }

    /// Explicitly releases the scope, reporting the outcome of the queued
    /// idle request.
    ///
    /// The usage reference is dropped either way, so an error here leaves
    /// no hold behind and a teardown path can ignore it.
    pub fn release(self) -> Result {
        let result = self.release_inner();
        drop(take_scope(self));
        result
    }
}

impl Drop for RetainScope {
    fn drop(&mut self) {
        let _ = self.release_inner();
    }
}

/// Runtime PM helpers - wrappers around C runtime PM interface.
struct Request;

#[cfg(CONFIG_PM)]
impl Request {
    #[inline]
    fn active(dev: &ARef<device::Device>) -> bool {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        unsafe { bindings::pm_runtime_active(dev.as_raw()) }
    }

    #[inline]
    fn suspended(dev: &ARef<device::Device>) -> bool {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        unsafe { bindings::pm_runtime_suspended(dev.as_raw()) }
    }

    #[inline]
    fn resume(dev: &ARef<device::Device>, mode: Mode) -> Result {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        to_result(unsafe { bindings::__pm_runtime_resume(dev.as_raw(), mode.into()) })
    }

    #[inline]
    fn idle(dev: &ARef<device::Device>, mode: Mode) -> Result {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        to_result(unsafe { bindings::__pm_runtime_idle(dev.as_raw(), mode.into()) })
    }

    /// Drops a usage reference and queues an idle notification, like
    /// `pm_runtime_put()`.
    #[inline]
    fn put(dev: &ARef<device::Device>) -> Result {
        Self::idle(dev, ModeFlag::Acquire | ModeFlag::Async)
    }

    #[inline]
    fn mark_last_busy(dev: &ARef<device::Device>) {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        unsafe {
            bindings::pm_runtime_mark_last_busy(dev.as_raw());
        }
    }

    #[inline]
    fn suspend(dev: &ARef<device::Device>, mode: Mode) -> Result {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        to_result(unsafe { bindings::__pm_runtime_suspend(dev.as_raw(), mode.into()) })
    }

    #[inline]
    fn get_if_active(dev: &ARef<device::Device>) -> Result {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        match unsafe { bindings::pm_runtime_get_if_active(dev.as_raw()) } {
            ret if ret < 0 => Err(Error::from_errno(ret)),
            0 => Err(EAGAIN),
            _ => Ok(()),
        }
    }

    #[inline]
    fn runtime_enable(dev: &ARef<device::Device>) {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        unsafe { bindings::pm_runtime_enable(dev.as_raw()) }
    }

    #[inline]
    fn runtime_disable(dev: &ARef<device::Device>) {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        unsafe { bindings::__pm_runtime_disable(dev.as_raw(), true) };
    }

    #[inline]
    fn barrier(dev: &ARef<device::Device>) {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
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

    // `pm_runtime_put()` discards the `ENOSYS` of the `__pm_runtime_idle()` stub.
    #[inline]
    fn put(_dev: &ARef<device::Device>) -> Result {
        Ok(())
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
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        unsafe { bindings::pm_runtime_get_noresume(dev.as_raw()) };
    }

    #[inline]
    fn put_noidle(dev: &ARef<device::Device>) {
        // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
        // valid pointer for the duration of this call.
        unsafe { bindings::pm_runtime_put_noidle(dev.as_raw()) };
    }

    #[allow(unused)]
    #[inline]
    fn mark_active(dev: &ARef<device::Device>) -> Result {
        to_result(
            // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
            // valid pointer for the duration of this call.
            unsafe { bindings::pm_runtime_set_active(dev.as_raw()) },
        )
    }

    #[allow(unused)]
    #[inline]
    fn mark_suspended(dev: &ARef<device::Device>) -> Result {
        to_result(
            // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
            // valid pointer for the duration of this call.
            unsafe { bindings::pm_runtime_set_suspended(dev.as_raw()) },
        )
    }
}

/// Common runtime PM callback entry point.
///
/// The generated extern "C" callbacks call into this helper with the raw
/// `struct device *` provided by the PM core. It rebuilds the Rust device
/// reference, retrieves the device's PM registration data and performs
/// handoff to corresponding driver callback.
fn runtime_pm_callback<D, T, F>(dev: *mut bindings::device, cb: F) -> Result
where
    D: driver::DriverLayout,
    T: PMOps<D>,
    F: FnOnce(
        &<T as PMOps<D>>::DeviceType,
        Option<<T as PMOps<D>>::RuntimePayloadType>,
    ) -> PMCallbackResult<<T as PMOps<D>>::RuntimePayloadType>,
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
    let payload: Pin<&RegistrationData<D, T>> =
        unsafe { <Pin<KBox<RegistrationData<D, T>>> as ForeignOwnable>::borrow(ptr) };

    let pm_dev: &T::DeviceType =
        // SAFETY: The generated `dev_pm_ops` for `T` is installed on devices whose
        // bus-specific type is `T::DeviceType`. Therefore the base `Device<Bound>`
        // passed by the PM core is embedded in a valid `T::DeviceType`; the
        // `AsBusDevice` implementation supplies the correct offset for this cast.
        unsafe { T::DeviceType::from_device(dev) };

    payload.data.transition(|payload| cb(pm_dev, payload))
}

/// Runtime resume PM callback.
///
/// # Safety
///
/// `dev` must be a valid `struct device *` supplied by the PM core for a device
/// whose runtime PM callbacks and PM registration data were both created
/// for `T`.
#[allow(unused)]
unsafe extern "C" fn runtime_resume_callback<D, T>(dev: *mut bindings::device) -> c_int
where
    D: driver::DriverLayout,
    T: PMOps<D>,
{
    runtime_pm_callback::<D, T, _>(dev, T::runtime_resume)
        .map(|()| 0)
        .unwrap_or_else(|e| e.to_errno())
}
/// Runtime suspend PM callback.
///
/// # Safety
///
/// `dev` must be a valid `struct device *` supplied by the PM core for a device
/// whose runtime PM callbacks and PM registration data were both created
/// for `T`.
#[allow(unused)]
unsafe extern "C" fn runtime_suspend_callback<D, T>(dev: *mut bindings::device) -> c_int
where
    D: driver::DriverLayout,
    T: PMOps<D>,
{
    runtime_pm_callback::<D, T, _>(dev, T::runtime_suspend)
        .map(|()| 0)
        .unwrap_or_else(|e| e.to_errno())
}
/// A `dev_pm_ops` with no callbacks set.
// SAFETY: `bindings::dev_pm_ops` is `#[repr(C)]` and consists of nullable
// function pointers only, so it has no padding and the all-zero bit pattern
// is a valid value.
pub(crate) const PMOPS_NONE: bindings::dev_pm_ops =
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
/// as `DEFINE_RUNTIME_DEV_PM_OPS` does.
///
/// # Safety
///
/// `dev` must be a valid `struct device *` provided by the PM core.
#[cfg(CONFIG_PM_SLEEP)]
unsafe extern "C" fn system_sleep_resume(dev: *mut bindings::device) -> c_int {
    // SAFETY: The PM core passes a valid `struct device *` to a system-sleep
    // callback and it stays valid for the duration of the call.
    unsafe { bindings::pm_runtime_force_resume(dev) }
}

/// Builds the base `dev_pm_ops` carrying the six system-sleep/hibernation
/// slots when the driver opts in via [`PMOps::SYSTEM_SLEEP`].
///
/// Under `CONFIG_PM_SLEEP` the slots point at the generic force-suspend and
/// force-resume wrappers. Otherwise they stay `None`, matching the
/// `pm_sleep_ptr()` gating in C. The runtime slots are filled by the caller.
const fn system_sleep_base<D: driver::DriverLayout, T: PMOps<D>>() -> bindings::dev_pm_ops {
    #[cfg(CONFIG_PM_SLEEP)]
    if T::SYSTEM_SLEEP {
        return bindings::dev_pm_ops {
            suspend: Some(system_sleep_suspend),
            resume: Some(system_sleep_resume),
            freeze: Some(system_sleep_suspend),
            thaw: Some(system_sleep_resume),
            poweroff: Some(system_sleep_suspend),
            restore: Some(system_sleep_resume),
            ..PMOPS_NONE
        };
    }
    PMOPS_NONE
}

/// Runtime PM ops for a driver.
///
/// Parameterized by:
///  - The first type parameter identifies the bus adapter that installs the C
///    [`bindings::dev_pm_ops`].
///  - The second type parameter identifies the Rust driver implementation
///    that provides the runtime PM callbacks and associated payload.
///
/// Intended to be constructed by bus-specific helpers, allowing
/// the bus to ensure that the callback device type matches the device
/// supplied by the C driver core.
pub struct DevPMOps<D, T: ?Sized> {
    #[allow(unused)]
    raw: &'static bindings::dev_pm_ops,
    _p: PhantomData<fn() -> (D, T)>,
}

impl<D, T> DevPMOps<D, T>
where
    D: driver::DriverLayout,
    T: PMOps<D>,
{
    /// Creates a typed runtime PM ops.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `D` is the bus adapter that will install
    /// this ops into the C driver object for `T`, and that `T::DeviceType`
    /// is the bus device type corresponding to that adapter. Safe bus-specific
    /// constructors should wrap this function with those bounds.
    #[allow(unused)]
    pub(crate) const unsafe fn new_unchecked() -> Self {
        Self {
            raw: &PMContext::<D, T>::PM_OPS,
            _p: PhantomData,
        }
    }
}

impl<D, T> DevPMOps<D, T> {
    /// Returns the raw C runtime PM operations table.
    #[allow(unused)]
    pub(crate) const fn as_raw(&self) -> *const bindings::dev_pm_ops {
        self.raw
    }
}

/// Result type returned by runtime PM callbacks.
pub type PMCallbackResult<T> = Result<Option<T>, (Option<T>, Error)>;

/// Runtime PM callbacks implemented by a driver.
///
/// Defines the [`PMOps`] trait and its corresponding [`bindings::dev_pm_ops`].
///
/// The `D` type parameter is the bus adapter that installs the generated PM ops.
/// Implementations should normally be enabled through a
/// bus-specific constructor for [`DevPMOps`], which constrains
/// [`Self::DeviceType`] to the correct bound device type for that bus.
///
/// Each C callback recovers the Rust bus device from the raw
/// `struct device *`, borrows the registered runtime PM payload, and delegates
/// to the matching [`PMOps`] trait method.
#[vtable]
pub trait PMOps<D: driver::DriverLayout>: Sized {
    /// Type of the bound bus device passed to runtime PM callbacks.
    type DeviceType: AsBusDevice<device::Bound>;

    /// Type of the payload moved through runtime PM transitions.
    type RuntimePayloadType: Send;

    /// Opt-in for system-sleep and hibernation support.
    ///
    /// When `true`, the generated `PM_OPS` fills the system-sleep and
    /// hibernation slots with force-suspend and force-resume wrappers
    /// that reuse the runtime PM callbacks. The slots stay unset under
    /// `CONFIG_PM_SLEEP=n`.
    const SYSTEM_SLEEP: bool = false;

    /// Runtime resume callback.
    fn runtime_resume<'a>(
        _dev: &'a Self::DeviceType,
        _payload: Option<Self::RuntimePayloadType>,
    ) -> PMCallbackResult<Self::RuntimePayloadType> {
        build_error!(VTABLE_DEFAULT_ERROR)
    }

    /// Runtime suspend callback.
    fn runtime_suspend<'a>(
        _dev: &'a Self::DeviceType,
        _payload: Option<Self::RuntimePayloadType>,
    ) -> PMCallbackResult<Self::RuntimePayloadType> {
        build_error!(VTABLE_DEFAULT_ERROR)
    }
}

/// RAII guard for ongoing runtime PM payload transition.
///
/// For most of the callbacks this guard is not necessarily needed as
/// the callbacks themselves are being serialized by the runtime PM C code.
/// Still, some like runtime_idle are exempt from that.
#[allow(unused)]
struct PayloadGuard<'a> {
    busy: &'a AtomicFlag,
}

impl Drop for PayloadGuard<'_> {
    fn drop(&mut self) {
        self.busy.store(false, ordering::Release);
    }
}

struct PMPayload<P> {
    in_flight: AtomicFlag,
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
    /// of storage. The closure must return the payload that should be stored
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
// after `in_flight` has been acquired. The AtomicFlag flag serializes all mutable
// access to the payload, and `PayloadGuard` clears the flag when the access ends.
unsafe impl<P: Send> Sync for PMPayload<P> {}

/// Runtime PM state of a [`PMContext`].
///
/// The state alternates between `Disabled` and `Enabled` until
/// `Registration::drop` sets `Dead`, which is final.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
enum PMContextState {
    Disabled = 0,
    Enabled = 1,
    Dead = 2,
}

// SAFETY: `PMContextState` and `i32` have the same size and alignment, and
// `PMContextState` is round-trip transmutable to `i32`.
unsafe impl AtomicType for PMContextState {
    type Repr = i32;
}

struct PMContextInner<D: driver::DriverLayout, T: PMOps<D>> {
    dev: ARef<device::Device>,
    /// A context outliving its registration cannot enable or disable runtime PM.
    state: Atomic<PMContextState>,
    /// Optional driver-selected runtime PM request PMProfiles.
    ///
    /// Set of runtime PM predefined PMProfiles that can be used by the driver
    /// when requesting a PM transition. This might be useful when a driver
    /// has several different PM usage patterns.
    /// See [PMProfile] for more details.
    profiles: KVec<PMProfile>,
    /// Set of PM config options applied for associated device.
    configs: KVec<PMConfig>,
    _marker: PhantomData<fn() -> (D, T)>,
}

/// Runtime PM context tied to a device.
pub struct PMContext<D: driver::DriverLayout, T: PMOps<D>> {
    // Preferably, PMContext could be shared via borrowed reference over
    // a pm Registration's lifetime but that bears complications on its own
    // when the context needs to be shared across different Registration types.
    inner: Arc<PMContextInner<D, T>>,
}

impl<D: driver::DriverLayout, T: PMOps<D>> PMContext<D, T> {
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
    pub(crate) const PM_OPS: bindings::dev_pm_ops = bindings::dev_pm_ops {
        runtime_resume: if T::HAS_RUNTIME_RESUME {
            Some(runtime_resume_callback::<D, T>)
        } else {
            None
        },
        runtime_suspend: if T::HAS_RUNTIME_SUSPEND {
            Some(runtime_suspend_callback::<D, T>)
        } else {
            None
        },
        ..system_sleep_base::<D, T>()
    };

    /// Enable runtime PM.
    ///
    /// Fails with `EINVAL` once the registration has been dropped.
    pub fn enable(&self, state: RuntimePMState) -> Result {
        match self.inner.state.cmpxchg(
            PMContextState::Disabled,
            PMContextState::Enabled,
            ordering::Full,
        ) {
            Ok(_) => (),
            Err(PMContextState::Enabled) => return Err(EBUSY),
            Err(_) => return Err(EINVAL),
        }
        Self::apply_config(&self.inner.dev, &self.inner.configs);
        match state {
            RuntimePMState::Resumed => Request::mark_active(&self.inner.dev),
            RuntimePMState::Suspended => Request::mark_suspended(&self.inner.dev),
            _ => Err(EINVAL),
        }
        .inspect_err(|_| {
            let _ = self.inner.state.cmpxchg(
                PMContextState::Enabled,
                PMContextState::Disabled,
                ordering::Full,
            );
        })?;
        Request::runtime_enable(&self.inner.dev);
        Ok(())
    }
    /// Disable runtime PM.
    ///
    /// Fails with `EINVAL` once the registration has been dropped.
    pub fn disable(&self) -> Result {
        if self
            .inner
            .state
            .cmpxchg(
                PMContextState::Enabled,
                PMContextState::Disabled,
                ordering::Full,
            )
            .is_err()
        {
            return Err(EINVAL);
        }
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
        AwakeScope::new(self.inner.dev.clone(), profile.0 | ModeFlag::Acquire)
    }

    /// Creates an `AwakeScope` only if the device is runtime-active.
    ///
    /// Never resumes the device, mirroring `pm_runtime_get_if_active()`, so
    /// it can be called where the resume callback must not run inline. The
    /// usage reference blocks runtime suspend until the scope is dropped.
    ///
    /// Returns `Ok(None)` when the device is not runtime-active and
    /// `Err(EINVAL)` when runtime PM is disabled for the device.
    #[inline]
    pub fn get_if_active(&self, profile: PMProfile) -> Result<Option<AwakeScope>> {
        match Request::get_if_active(&self.inner.dev) {
            Ok(()) => Ok(Some(AwakeScope(Scope::<Awake> {
                dev: self.inner.dev.clone(),
                mode: profile.0 | ModeFlag::Acquire,
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
        if profile.0.contains(ModeFlag::Async) {
            return Err(EINVAL);
        }
        let _scope = self.resume(profile)?;
        f()
    }
    /// Runs a closure while holding an `AwakeScope`.
    ///
    /// Async and nowait profiles are rejected, since the closure needs a
    /// device that has finished resuming.
    pub fn with_get<R>(&self, profile: PMProfile, f: impl FnOnce() -> Result<R>) -> Result<R> {
        if profile.0.contains_any(ModeFlag::Async | ModeFlag::Nowait) {
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
                // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
                // valid pointer for the duration of this call.
                PMConfig::IgnoreChildren(v) => unsafe {
                    bindings::pm_suspend_ignore_children(dev.as_raw(), *v)
                },
                // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
                // valid pointer for the duration of this call.
                PMConfig::NoCallbacks => unsafe { bindings::pm_runtime_no_callbacks(dev.as_raw()) },
                // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
                // valid pointer for the duration of this call.
                PMConfig::IrqSafe => unsafe { bindings::pm_runtime_irq_safe(dev.as_raw()) },
                // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
                // valid pointer for the duration of this call.
                PMConfig::AutoSuspend(v) => unsafe {
                    bindings::__pm_runtime_use_autosuspend(dev.as_raw(), *v);
                },
                // SAFETY: The `ARef` keeps the device alive, so `as_raw()` yields a
                // valid pointer for the duration of this call.
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
// a pm Registration's lifetime but that bears complications on its own
// when the context needs to be shared across different Registration types.
impl<D: driver::DriverLayout, T: PMOps<D>> Clone for PMContext<D, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Runtime PM request PMProfile.
pub struct PMProfile(Mode);

impl PMProfile {
    /// Creates a PMProfile with default SYNC mode set.
    pub const fn new() -> Self {
        Self(Mode(ModeFlag::Sync as u32))
    }
    /// Enables async PM operations for this PMProfile.
    pub const fn r#async(self) -> Self {
        Self(Mode(self.0 .0 | ModeFlag::Async as u32))
    }
    /// Use autosuspend.
    pub const fn auto(self) -> Self {
        Self(Mode(self.0 .0 | ModeFlag::Auto as u32))
    }
    /// Requests idle handling for this PMProfile.
    pub const fn idle(self) -> Self {
        Self(Mode(self.0 .0 | ModeFlag::Idle as u32))
    }
    /// Do not wait for concurrent requests to finish.
    pub const fn nowait(self) -> Self {
        Self(Mode(self.0 .0 | ModeFlag::Nowait as u32))
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

/// Runtime PM data stored within the `struct device_private` during
/// runtime PM registration.
///
/// The data is associated with PM transitions and it's conceptually owned
/// by the Registration itself.
#[repr(C)]
#[pin_data]
struct RegistrationData<D: driver::DriverLayout, T: PMOps<D>> {
    #[pin]
    data: PMPayload<T::RuntimePayloadType>,
    _marker: PhantomData<fn() -> (D, T)>,
}

/// Runtime PM registration for a device.
///
/// A `Registration` installs the runtime PM payload used by the
/// generated [`PMOps`] callbacks and owns the corresponding teardown.
///
/// Dropping the registration disables runtime PM, waits for in-flight runtime PM
/// callbacks to complete, and then removes the stored registration data. The
/// `'bound` lifetime confines the registration to one driver binding, so it is
/// dropped during probe or at unbind, with the device lock held.
pub struct Registration<'bound, D: driver::DriverLayout, T: PMOps<D>> {
    ctx: PMContext<D, T>,
    _bound: PhantomData<&'bound ()>,
}

impl<'bound, D: driver::DriverLayout, T: PMOps<D>> Registration<'bound, D, T> {
    /// Creates a runtime PM registration for `dev`.
    ///
    /// The provided profiles and configuration are stored in the associated
    /// [`PMContext`]. The optional `payload` is stored as a Registration data
    /// and is used to service PM transitions.
    ///
    /// The device must use the callback represented by `ops`, generated
    /// for the same bus adapter and driver pair `(D, T)`.
    pub fn new(
        dev: &'bound device::Device<device::Core<'_>>,
        ops: DevPMOps<D, T>,
        profiles: Option<KVec<PMProfile>>,
        configs: Option<KVec<PMConfig>>,
        payload: Option<T::RuntimePayloadType>,
    ) -> Result<Self> {
        // SAFETY: For the duration of this call, `dev` is a valid `Device<Core>`,
        // and so is its raw `struct device` pointer.
        unsafe {
            let drv = (*dev.as_raw()).driver;
            if drv.is_null() || (*drv).pm != ops.as_raw() {
                return Err(EINVAL);
            }
        }

        let payload = KBox::pin_init(
            RegistrationData::<D, T> {
                data: PMPayload {
                    in_flight: AtomicFlag::new(false),
                    inner: UnsafeCell::new(payload),
                },
                _marker: PhantomData,
            },
            GFP_KERNEL,
        )?;

        let inner_ctx = Arc::new(
            PMContextInner {
                dev: dev.into(),
                state: Atomic::new(PMContextState::Disabled),
                profiles: profiles.unwrap_or_default(),
                configs: configs.unwrap_or_default(),
                _marker: PhantomData,
            },
            GFP_KERNEL,
        )?;

        // SAFETY: For the duration of this call, `dev` is a valid `Device<Core>`,
        // and so is its raw `struct device` pointer.
        // The payload allocation is converted into a foreign pointer
        // and owned by this `Registration` until `Drop` clears
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
            _bound: PhantomData,
        })
    }
    /// Returns the runtime PM context associated with this registration.
    pub fn ctx(&self) -> &PMContext<D, T> {
        &self.ctx
    }
}

impl<D: driver::DriverLayout, T: PMOps<D>> Drop for Registration<'_, D, T> {
    fn drop(&mut self) {
        // `self.ctx.inner.dev` is the device this registration was
        // created for. Runtime PM is disabled first, and `pm_runtime_barrier`
        // waits for pending runtime PM work/callbacks before the callback data
        // is removed below.
        if self
            .ctx
            .inner
            .state
            .xchg(PMContextState::Dead, ordering::Full)
            == PMContextState::Enabled
        {
            PMContext::<D, T>::apply_config(&self.ctx.inner.dev, &[PMConfig::AutoSuspend(false)]);
            Request::runtime_disable(&self.ctx.inner.dev);
        }
        Request::barrier(&self.ctx.inner.dev);

        // SAFETY: The pointer, if non-null, was stored by `Registration::new`
        // using `Pin<KBox<RegistrationData<T>>>::into_foreign`. Runtime PM has
        // been disabled and drained above, so generated callbacks can no longer
        // borrow this data. `'bound` confines the registration to probe or to
        // the driver's bus device private data, and both are dropped under the
        // device lock, which excludes the system-sleep callbacks. Clearing
        // `rust_private` prevents later lookup, and `from_foreign` reconstructs
        // the owning allocation so it is dropped.
        unsafe {
            let ptr = (*(*self.ctx.inner.dev.as_raw()).p).rust_private;

            if !ptr.is_null() {
                (*(*self.ctx.inner.dev.as_raw()).p).rust_private = core::ptr::null_mut();
                Pin::<KBox<RegistrationData<D, T>>>::from_foreign(ptr);
            }
        }
    }
}
