// SPDX-License-Identifier: GPL-2.0

//! Abstractions for the platform bus.
//!
//! C header: [`include/linux/platform_device.h`](srctree/include/linux/platform_device.h)

use crate::{
    acpi,
    bindings,
    container_of,
    device::{
        self,
        Bound,
        BoundInternal, //
    },
    driver,
    error::{
        from_result,
        to_result, //
    },
    io::Resource,
    irq::{
        self,
        IrqRequest, //
    },
    of,
    page::PAGE_SIZE,
    prelude::*,
    str::{
        as_char_ptr_in_const_context,
        Formatter, //
    },
    types::Opaque,
    ThisModule, //
};

#[cfg(CONFIG_HAS_IOMEM)]
use crate::io::mem::IoRequest;

use core::{
    marker::PhantomData,
    mem::offset_of,
    ptr::{
        addr_of_mut,
        NonNull, //
    },
};

/// An adapter for the registration of platform drivers.
pub struct Adapter<T: Driver>(T);

// SAFETY:
// - `bindings::platform_driver` is a C type declared as `repr(C)`.
// - `T::Data` is the type of the driver's device private data.
// - `struct platform_driver` embeds a `struct device_driver`.
// - `DEVICE_DRIVER_OFFSET` is the correct byte offset to the embedded `struct device_driver`.
unsafe impl<T: Driver> driver::DriverLayout for Adapter<T> {
    type DriverType = bindings::platform_driver;
    type DriverData<'bound> = T::Data<'bound>;
    const DEVICE_DRIVER_OFFSET: usize = core::mem::offset_of!(Self::DriverType, driver);
}

// SAFETY: A call to `unregister` for a given instance of `DriverType` is guaranteed to be valid if
// a preceding call to `register` has been successful.
unsafe impl<T: Driver + 'static> driver::RegistrationOps for Adapter<T> {
    unsafe fn register(
        pdrv: &Opaque<Self::DriverType>,
        name: &'static CStr,
        module: &'static ThisModule,
    ) -> Result {
        let of_table = match T::OF_ID_TABLE {
            Some(table) => table.as_ptr(),
            None => core::ptr::null(),
        };

        let acpi_table = match T::ACPI_ID_TABLE {
            Some(table) => table.as_ptr(),
            None => core::ptr::null(),
        };

        let pm_ops = T::dev_pm_ops()
            .map(|ops| ops.as_raw())
            .unwrap_or(core::ptr::null());

        let dev_groups = T::DEV_GROUPS
            .map(|groups| groups.as_ptr())
            .unwrap_or(core::ptr::null_mut());

        // SAFETY: It's safe to set the fields of `struct platform_driver` on initialization.
        unsafe {
            (*pdrv.get()).driver.name = name.as_char_ptr();
            (*pdrv.get()).probe = Some(Self::probe_callback);
            (*pdrv.get()).remove = Some(Self::remove_callback);
            (*pdrv.get()).driver.of_match_table = of_table;
            (*pdrv.get()).driver.acpi_match_table = acpi_table;
            (*pdrv.get()).driver.pm = pm_ops;
            (*pdrv.get()).driver.dev_groups = dev_groups;
        }

        // SAFETY: `pdrv` is guaranteed to be a valid `DriverType`.
        to_result(unsafe {
            bindings::__platform_driver_register(pdrv.get(), module.as_ptr(), name.as_char_ptr())
        })
    }

    unsafe fn unregister(pdrv: &Opaque<Self::DriverType>) {
        // SAFETY: `pdrv` is guaranteed to be a valid `DriverType`.
        unsafe { bindings::platform_driver_unregister(pdrv.get()) };
    }
}

impl<T: Driver> Adapter<T> {
    extern "C" fn probe_callback(pdev: *mut bindings::platform_device) -> kernel::ffi::c_int {
        // SAFETY: The platform bus only ever calls the probe callback with a valid pointer to a
        // `struct platform_device`.
        //
        // INVARIANT: `pdev` is valid for the duration of `probe_callback()`.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal<'_>>>() };
        // SAFETY: `pdev` matched data is of type `Self::IdInfo`.
        let info = unsafe { <Self as driver::Adapter>::id_info(pdev.as_ref()) };

        from_result(|| {
            let data = T::probe(pdev, info);

            pdev.as_ref().set_drvdata(data)?;
            Ok(0)
        })
    }

    extern "C" fn remove_callback(pdev: *mut bindings::platform_device) {
        // SAFETY: The platform bus only ever calls the remove callback with a valid pointer to a
        // `struct platform_device`.
        //
        // INVARIANT: `pdev` is valid for the duration of `remove_callback()`.
        let pdev = unsafe { &*pdev.cast::<Device<device::CoreInternal<'_>>>() };

        // SAFETY: `remove_callback` is only ever called after a successful call to
        // `probe_callback`, hence it's guaranteed that `Device::set_drvdata()` has been called
        // and stored a `Pin<KBox<T::Data<'_>>>`.
        let data = unsafe { pdev.as_ref().drvdata_borrow::<T::Data<'_>>() };

        T::unbind(pdev, data);
    }
}

impl<T: Driver> driver::Adapter for Adapter<T> {
    type IdInfo = T::IdInfo;

    fn of_id_table() -> Option<of::IdTable<Self::IdInfo>> {
        T::OF_ID_TABLE
    }

    fn acpi_id_table() -> Option<acpi::IdTable<Self::IdInfo>> {
        T::ACPI_ID_TABLE
    }
}

/// Declares a kernel module that exposes a single platform driver.
///
/// # Examples
///
/// ```ignore
/// kernel::module_platform_driver! {
///     type: MyDriver,
///     name: "Module name",
///     authors: ["Author name"],
///     description: "Description",
///     license: "GPL v2",
/// }
/// ```
#[macro_export]
macro_rules! module_platform_driver {
    ($($f:tt)*) => {
        $crate::module_driver!(<T>, $crate::platform::Adapter<T>, { $($f)* });
    };
}

/// The platform driver trait.
///
/// Drivers must implement this trait in order to get a platform driver registered.
///
/// # Examples
///
///```
/// # use kernel::{
/// #     acpi,
/// #     bindings,
/// #     device::Core,
/// #     of,
/// #     platform,
/// # };
/// struct MyDriver;
///
/// kernel::of_device_table!(
///     OF_TABLE,
///     <MyDriver as platform::Driver>::IdInfo,
///     [
///         (of::DeviceId::new(c"test,device"), ())
///     ]
/// );
///
/// kernel::acpi_device_table!(
///     ACPI_TABLE,
///     <MyDriver as platform::Driver>::IdInfo,
///     [
///         (acpi::DeviceId::new(c"LNUXBEEF"), ())
///     ]
/// );
///
/// impl platform::Driver for MyDriver {
///     type IdInfo = ();
///     type Data<'bound> = Self;
///     type PmOps = ();
///
///     const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);
///     const ACPI_ID_TABLE: Option<acpi::IdTable<Self::IdInfo>> = Some(&ACPI_TABLE);
///
///     fn probe<'bound>(
///         _pdev: &'bound platform::Device<Core<'_>>,
///         _id_info: Option<&'bound Self::IdInfo>,
///     ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound {
///         Err(ENODEV)
///     }
/// }
///```
pub trait Driver: 'static {
    /// The type holding driver private data about each device id supported by the driver.
    // TODO: Use associated_type_defaults once stabilized:
    //
    // ```
    // type IdInfo: 'static = ();
    // ```
    type IdInfo: 'static;

    /// The type of the driver's bus device private data.
    type Data<'bound>: Send + 'bound;

    /// The type implementing the driver's runtime PM callbacks.
    ///
    /// [`dev_pm_ops`] returns the callback table built for this type. Use `()` for a driver
    /// without runtime PM callbacks.
    ///
    /// [`dev_pm_ops`]: Driver::dev_pm_ops
    // TODO: Use associated_type_defaults once stabilized:
    //
    // ```
    // type PmOps = ();
    // ```
    type PmOps;

    /// The table of OF device ids supported by the driver.
    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = None;

    /// The table of ACPI device ids supported by the driver.
    const ACPI_ID_TABLE: Option<acpi::IdTable<Self::IdInfo>> = None;

    /// The sysfs device attribute groups exposed under the driver's devices.
    ///
    /// Wired into `driver.dev_groups`, so the core creates the attributes for every device the
    /// driver binds. Build the value with [`device_attribute_groups!`]. The driver-typed table
    /// only accepts attributes declared for this driver.
    ///
    /// [`device_attribute_groups!`]: crate::device_attribute_groups
    const DEV_GROUPS: Option<&'static dyn AttributeGroups<Self>> = None;

    /// Provides driver's PM callbacks, if any.
    fn dev_pm_ops() -> Option<&'static crate::pm::DevPMOps<Adapter<Self>, Self::PmOps>>
    where
        Self: Sized,
    {
        None
    }

    /// Platform driver probe.
    ///
    /// Called when a new platform device is added or discovered.
    /// Implementers should attempt to initialize the device here.
    fn probe<'bound>(
        dev: &'bound Device<device::Core<'_>>,
        id_info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound;

    /// Platform driver unbind.
    ///
    /// Called when a [`Device`] is unbound from its bound [`Driver`]. Implementing this callback
    /// is optional.
    ///
    /// This callback serves as a place for drivers to perform teardown operations that require a
    /// `&Device<Core>` or `&Device<Bound>` reference. For instance, drivers may try to perform I/O
    /// operations to gracefully tear down the device.
    ///
    /// Otherwise, release operations for driver resources should be performed in `Drop`.
    fn unbind<'bound>(dev: &'bound Device<device::Core<'_>>, this: Pin<&Self::Data<'bound>>) {
        let _ = (dev, this);
    }
}

/// The platform device representation.
///
/// This structure represents the Rust abstraction for a C `struct platform_device`. The
/// implementation abstracts the usage of an already existing C `struct platform_device` within Rust
/// code that we get passed from the C side.
///
/// # Invariants
///
/// A [`Device`] instance represents a valid `struct platform_device` created by the C portion of
/// the kernel.
#[repr(transparent)]
pub struct Device<Ctx: device::DeviceContext = device::Normal>(
    Opaque<bindings::platform_device>,
    PhantomData<Ctx>,
);

impl<Ctx: device::DeviceContext> Device<Ctx> {
    fn as_raw(&self) -> *mut bindings::platform_device {
        self.0.get()
    }

    /// Returns the resource at `index`, if any.
    pub fn resource_by_index(&self, index: u32) -> Option<&Resource> {
        // SAFETY: `self.as_raw()` returns a valid pointer to a `struct platform_device`.
        let resource = unsafe {
            bindings::platform_get_resource(self.as_raw(), bindings::IORESOURCE_MEM, index)
        };

        if resource.is_null() {
            return None;
        }

        // SAFETY: `resource` is a valid pointer to a `struct resource` as
        // returned by `platform_get_resource`.
        Some(unsafe { Resource::from_raw(resource) })
    }

    /// Returns the resource with a given `name`, if any.
    pub fn resource_by_name(&self, name: &CStr) -> Option<&Resource> {
        // SAFETY: `self.as_raw()` returns a valid pointer to a `struct
        // platform_device` and `name` points to a valid C string.
        let resource = unsafe {
            bindings::platform_get_resource_byname(
                self.as_raw(),
                bindings::IORESOURCE_MEM,
                name.as_char_ptr(),
            )
        };

        if resource.is_null() {
            return None;
        }

        // SAFETY: `resource` is a valid pointer to a `struct resource` as
        // returned by `platform_get_resource`.
        Some(unsafe { Resource::from_raw(resource) })
    }
}

#[cfg(CONFIG_HAS_IOMEM)]
impl Device<Bound> {
    /// Returns an `IoRequest` for the resource at `index`, if any.
    pub fn io_request_by_index(&self, index: u32) -> Option<IoRequest<'_>> {
        self.resource_by_index(index)
            // SAFETY: `resource` is a valid resource for `&self` during the
            // lifetime of the `IoRequest`.
            .map(|resource| unsafe { IoRequest::new(self.as_ref(), resource) })
    }

    /// Returns an `IoRequest` for the resource with a given `name`, if any.
    pub fn io_request_by_name(&self, name: &CStr) -> Option<IoRequest<'_>> {
        self.resource_by_name(name)
            // SAFETY: `resource` is a valid resource for `&self` during the
            // lifetime of the `IoRequest`.
            .map(|resource| unsafe { IoRequest::new(self.as_ref(), resource) })
    }
}

// SAFETY: `platform::Device` is a transparent wrapper of `struct platform_device`.
// The offset is guaranteed to point to a valid device field inside `platform::Device`.
unsafe impl<Ctx: device::DeviceContext> device::AsBusDevice<Ctx> for Device<Ctx> {
    const OFFSET: usize = offset_of!(bindings::platform_device, dev);
}

macro_rules! define_irq_accessor_by_index {
    (
        $(#[$meta:meta])* $fn_name:ident,
        $request_fn:ident,
        $reg_type:ident,
        $handler_trait:ident
    ) => {
        $(#[$meta])*
        ///
        /// # Safety
        ///
        /// Callers must not `mem::forget()` the resulting registration or otherwise prevent its
        /// [`Drop`] implementation from running.
        pub unsafe fn $fn_name<'a, T: irq::$handler_trait + 'a>(
            &'a self,
            flags: irq::Flags,
            index: u32,
            name: &'static CStr,
            handler: impl PinInit<T, Error> + 'a,
        ) -> impl PinInit<irq::$reg_type<'a, T>, Error> + 'a {
            pin_init::pin_init_scope(move || {
                let request = self.$request_fn(index)?;

                // SAFETY: Caller guarantees the Registration will not be leaked.
                Ok(unsafe {
                    irq::$reg_type::<T>::new(
                        request,
                        flags,
                        name,
                        handler,
                    )
                })
            })
        }
    };
}

macro_rules! define_irq_accessor_by_name {
    (
        $(#[$meta:meta])* $fn_name:ident,
        $request_fn:ident,
        $reg_type:ident,
        $handler_trait:ident
    ) => {
        $(#[$meta])*
        ///
        /// # Safety
        ///
        /// Callers must not `mem::forget()` the resulting registration or otherwise prevent its
        /// [`Drop`] implementation from running.
        pub unsafe fn $fn_name<'a, T: irq::$handler_trait + 'a>(
            &'a self,
            flags: irq::Flags,
            irq_name: &'a CStr,
            name: &'static CStr,
            handler: impl PinInit<T, Error> + 'a,
        ) -> impl PinInit<irq::$reg_type<'a, T>, Error> + 'a {
            pin_init::pin_init_scope(move || {
                let request = self.$request_fn(irq_name)?;

                // SAFETY: Caller guarantees the Registration will not be leaked.
                Ok(unsafe {
                    irq::$reg_type::<T>::new(
                        request,
                        flags,
                        name,
                        handler,
                    )
                })
            })
        }
    };
}

impl Device<Bound> {
    /// Returns an [`IrqRequest`] for the IRQ at the given index, if any.
    pub fn irq_by_index(&self, index: u32) -> Result<IrqRequest<'_>> {
        // SAFETY: `self.as_raw` returns a valid pointer to a `struct platform_device`.
        let irq = unsafe { bindings::platform_get_irq(self.as_raw(), index) };

        if irq < 0 {
            return Err(Error::from_errno(irq));
        }

        // SAFETY: `irq` is guaranteed to be a valid IRQ number for `&self`.
        Ok(unsafe { IrqRequest::new(self.as_ref(), irq as u32) })
    }

    /// Returns an [`IrqRequest`] for the IRQ at the given index, but does not
    /// print an error if the IRQ cannot be obtained.
    pub fn optional_irq_by_index(&self, index: u32) -> Result<IrqRequest<'_>> {
        // SAFETY: `self.as_raw` returns a valid pointer to a `struct platform_device`.
        let irq = unsafe { bindings::platform_get_irq_optional(self.as_raw(), index) };

        if irq < 0 {
            return Err(Error::from_errno(irq));
        }

        // SAFETY: `irq` is guaranteed to be a valid IRQ number for `&self`.
        Ok(unsafe { IrqRequest::new(self.as_ref(), irq as u32) })
    }

    /// Returns an [`IrqRequest`] for the IRQ with the given name, if any.
    pub fn irq_by_name(&self, name: &CStr) -> Result<IrqRequest<'_>> {
        // SAFETY: `self.as_raw` returns a valid pointer to a `struct platform_device`.
        let irq = unsafe { bindings::platform_get_irq_byname(self.as_raw(), name.as_char_ptr()) };

        if irq < 0 {
            return Err(Error::from_errno(irq));
        }

        // SAFETY: `irq` is guaranteed to be a valid IRQ number for `&self`.
        Ok(unsafe { IrqRequest::new(self.as_ref(), irq as u32) })
    }

    /// Returns an [`IrqRequest`] for the IRQ with the given name, but does not
    /// print an error if the IRQ cannot be obtained.
    pub fn optional_irq_by_name(&self, name: &CStr) -> Result<IrqRequest<'_>> {
        // SAFETY: `self.as_raw` returns a valid pointer to a `struct platform_device`.
        let irq = unsafe {
            bindings::platform_get_irq_byname_optional(self.as_raw(), name.as_char_ptr())
        };

        if irq < 0 {
            return Err(Error::from_errno(irq));
        }

        // SAFETY: `irq` is guaranteed to be a valid IRQ number for `&self`.
        Ok(unsafe { IrqRequest::new(self.as_ref(), irq as u32) })
    }

    define_irq_accessor_by_index!(
        /// Returns a [`irq::Registration`] for the IRQ at the given index.
        request_irq_by_index,
        irq_by_index,
        Registration,
        Handler
    );
    define_irq_accessor_by_name!(
        /// Returns a [`irq::Registration`] for the IRQ with the given name.
        request_irq_by_name,
        irq_by_name,
        Registration,
        Handler
    );
    define_irq_accessor_by_index!(
        /// Does the same as [`Self::request_irq_by_index`], except that it does
        /// not print an error message if the IRQ cannot be obtained.
        request_optional_irq_by_index,
        optional_irq_by_index,
        Registration,
        Handler
    );
    define_irq_accessor_by_name!(
        /// Does the same as [`Self::request_irq_by_name`], except that it does
        /// not print an error message if the IRQ cannot be obtained.
        request_optional_irq_by_name,
        optional_irq_by_name,
        Registration,
        Handler
    );

    define_irq_accessor_by_index!(
        /// Returns a [`irq::ThreadedRegistration`] for the IRQ at the given index.
        request_threaded_irq_by_index,
        irq_by_index,
        ThreadedRegistration,
        ThreadedHandler
    );
    define_irq_accessor_by_name!(
        /// Returns a [`irq::ThreadedRegistration`] for the IRQ with the given name.
        request_threaded_irq_by_name,
        irq_by_name,
        ThreadedRegistration,
        ThreadedHandler
    );
    define_irq_accessor_by_index!(
        /// Does the same as [`Self::request_threaded_irq_by_index`], except
        /// that it does not print an error message if the IRQ cannot be
        /// obtained.
        request_optional_threaded_irq_by_index,
        optional_irq_by_index,
        ThreadedRegistration,
        ThreadedHandler
    );
    define_irq_accessor_by_name!(
        /// Does the same as [`Self::request_threaded_irq_by_name`], except that
        /// it does not print an error message if the IRQ cannot be obtained.
        request_optional_threaded_irq_by_name,
        optional_irq_by_name,
        ThreadedRegistration,
        ThreadedHandler
    );
}

// SAFETY: `Device` is a transparent wrapper of a type that doesn't depend on `Device`'s generic
// argument.
kernel::impl_device_context_deref!(unsafe { Device });
kernel::impl_device_context_into_aref!(Device);

impl<'a> crate::dma::Device<'a> for Device<device::Core<'a>> {}

// SAFETY: Instances of `Device` are always reference-counted.
unsafe impl crate::sync::aref::AlwaysRefCounted for Device {
    fn inc_ref(&self) {
        // SAFETY: The existence of a shared reference guarantees that the refcount is non-zero.
        unsafe { bindings::get_device(self.as_ref().as_raw()) };
    }

    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: The safety requirements guarantee that the refcount is non-zero.
        unsafe { bindings::platform_device_put(obj.cast().as_ptr()) }
    }
}

impl<Ctx: device::DeviceContext> AsRef<device::Device<Ctx>> for Device<Ctx> {
    fn as_ref(&self) -> &device::Device<Ctx> {
        // SAFETY: By the type invariant of `Self`, `self.as_raw()` is a pointer to a valid
        // `struct platform_device`.
        let dev = unsafe { addr_of_mut!((*self.as_raw()).dev) };

        // SAFETY: `dev` points to a valid `struct device`.
        unsafe { device::Device::from_raw(dev) }
    }
}

impl<Ctx: device::DeviceContext> TryFrom<&device::Device<Ctx>> for &Device<Ctx> {
    type Error = kernel::error::Error;

    fn try_from(dev: &device::Device<Ctx>) -> Result<Self, Self::Error> {
        // SAFETY: By the type invariant of `Device`, `dev.as_raw()` is a valid pointer to a
        // `struct device`.
        if !unsafe { bindings::dev_is_platform(dev.as_raw()) } {
            return Err(EINVAL);
        }

        // SAFETY: We've just verified that the bus type of `dev` equals
        // `bindings::platform_bus_type`, hence `dev` must be embedded in a valid
        // `struct platform_device` as guaranteed by the corresponding C code.
        let pdev = unsafe { container_of!(dev.as_raw(), bindings::platform_device, dev) };

        // SAFETY: `pdev` is a valid pointer to a `struct platform_device`.
        Ok(unsafe { &*pdev.cast() })
    }
}

// SAFETY: A `Device` is always reference-counted and can be released from any thread.
unsafe impl Send for Device {}

// SAFETY: `Device` can be shared among threads because all methods of `Device`
// (i.e. `Device<Normal>) are thread safe.
unsafe impl Sync for Device {}

// SAFETY: Same as `Device<Normal>` -- the underlying `struct platform_device` is the same;
// `Bound` is a zero-sized type-state marker that does not affect thread safety.
unsafe impl Sync for Device<device::Bound> {}

#[allow(clippy::new_without_default)]
impl<T> crate::pm::DevPMOps<Adapter<T>, T>
where
    T: Driver<PmOps = T> + crate::pm::PMOps<Adapter<T>, DeviceType = Device<device::Bound>>,
{
    /// Creates a platform driver's runtime PM callbacks for `T`.
    ///
    /// This constructor is available only when `T` is a platform driver that
    /// names itself as its [`Driver::PmOps`], and its runtime PM callbacks
    /// accept a bound platform device.
    pub const fn new() -> Self {
        // SAFETY: `Adapter<T>` is the platform bus adapter for `T`, and the
        // bound above forces PM callbacks to receive a platform bound device.
        // `Driver<PmOps = T>` means registering `T` installs the table built
        // for `T`, or no table at all, and `pm::Registration`'s constructors
        // reject the latter by requiring `(*drv).pm` to equal this table.
        unsafe { crate::pm::DevPMOps::new_unchecked() }
    }
}

impl<T, U> crate::pm::DevPMOps<Adapter<T>, U>
where
    T: Driver<PmOps = U>,
    U: crate::pm::PMOps<Adapter<T>, DeviceType = Device<device::Bound>>,
{
    /// Creates a platform driver's runtime PM callbacks implemented by its [`Driver::PmOps`].
    ///
    /// This constructor is available only when `T` is a platform driver whose `PmOps` is `U`,
    /// and the runtime PM callbacks of `U` accept a bound platform device.
    pub const fn for_driver() -> Self {
        // SAFETY: `Adapter<T>` is the platform bus adapter for `T`, and the
        // bound above forces PM callbacks to receive a platform bound device.
        // `Driver<PmOps = U>` means registering `T` installs the table built
        // for `U`, or no table at all, and `pm::Registration`'s constructors
        // reject the latter by requiring `(*drv).pm` to equal this table.
        unsafe { crate::pm::DevPMOps::new_unchecked() }
    }
}

/// A read-write sysfs device attribute.
///
/// Implement this on a unit type to describe one named attribute. [`device_attribute_groups!`]
/// collects implementors into the table installed in [`Driver::DEV_GROUPS`], after which the core
/// creates the file under each bound device's sysfs directory and dispatches reads to [`show`] and
/// writes to [`store`].
///
/// The attribute is created with mode `0644` (read for everyone, write for root).
///
/// The sysfs core can invoke [`show`] and [`store`] concurrently, so the driver data must be
/// [`Sync`].
///
/// [`device_attribute_groups!`]: crate::device_attribute_groups
/// [`show`]: DeviceAttribute::show
/// [`store`]: DeviceAttribute::store
pub trait DeviceAttribute
where
    for<'a> <Self::Driver as Driver>::Data<'a>: Sync,
{
    /// The platform driver the attribute belongs to.
    ///
    /// The group table built by [`device_attribute_groups!`] carries this type. An attribute
    /// therefore only installs in this driver's [`Driver::DEV_GROUPS`], and the trampolines
    /// borrow the `Driver::Data` the bus stored at probe time.
    ///
    /// [`device_attribute_groups!`]: crate::device_attribute_groups
    type Driver: Driver;

    /// The sysfs file name.
    const NAME: &'static CStr;

    /// Formats the attribute value into `writer`.
    ///
    /// The text written to `writer` becomes the file contents.
    fn show(
        dev: &device::Device<Bound>,
        data: Pin<&<Self::Driver as Driver>::Data<'_>>,
        writer: &mut Formatter<'_>,
    ) -> Result;

    /// Parses and applies a value written to the attribute.
    ///
    /// `buf` is the NUL-terminated string the user wrote.
    fn store(
        dev: &device::Device<Bound>,
        data: Pin<&<Self::Driver as Driver>::Data<'_>>,
        buf: &CStr,
    ) -> Result;
}

/// Builds the `device_attribute` for a [`DeviceAttribute`] implementor.
///
/// Used by [`device_attribute_groups!`]. Not meant to be called directly.
#[doc(hidden)]
// `struct attribute` gains lockdep fields under `CONFIG_DEBUG_LOCK_ALLOC`, so the rest-init is
// required there.
#[allow(clippy::needless_update)]
pub const fn device_attribute<D, T>() -> bindings::device_attribute
where
    D: Driver,
    T: DeviceAttribute<Driver = D>,
    for<'a> D::Data<'a>: Sync,
{
    let mut dev_attr = bindings::device_attribute {
        attr: bindings::attribute {
            name: as_char_ptr_in_const_context(T::NAME),
            mode: 0o644,
            ..pin_init::zeroed()
        },
        ..pin_init::zeroed()
    };
    // `show` and `store` live in `__SYSFS_FUNCTION_ALTERNATIVE` blocks, a union
    // normally and a struct under `CONFIG_CFI`, so assign the members by name
    // on the zeroed value to cover both layouts.
    dev_attr.__bindgen_anon_1.show = Some(device_attribute_show::<T>);
    dev_attr.__bindgen_anon_2.store = Some(device_attribute_store::<T>);
    dev_attr
}

/// The `show` trampoline for a [`DeviceAttribute`] implementor.
///
/// # Safety
///
/// `dev` must point at a live device bound to `T::Driver`, and `buf` must be writable for
/// `PAGE_SIZE` bytes, as sysfs guarantees when it invokes a `device_attribute` show.
unsafe extern "C" fn device_attribute_show<T: DeviceAttribute>(
    dev: *mut bindings::device,
    _attr: *mut bindings::device_attribute,
    buf: *mut c_char,
) -> isize {
    from_result(|| {
        // SAFETY: the driver core scopes the attribute file to the bound window, so sysfs only
        // invokes `show` while `dev` is a live, bound device.
        let dev = unsafe { device::Device::<BoundInternal>::from_raw(dev) };

        // SAFETY: the driver-typed group table installs the attribute only under `T::Driver`,
        // whose `probe()` stored a `Pin<KBox<<T::Driver as Driver>::Data<'_>>>` as the private
        // data, and the attribute file only dispatches while the device remains bound.
        let data = unsafe { dev.drvdata_borrow::<<T::Driver as Driver>::Data<'_>>() };

        // SAFETY: sysfs guarantees `buf` is writable for one page.
        let slice = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), PAGE_SIZE) };
        let mut writer = Formatter::new(slice);

        T::show(dev, data, &mut writer)?;
        // A show that fills the whole buffer returns `PAGE_SIZE`, which sysfs
        // rejects, so clamp that case.
        Ok(core::cmp::min(writer.bytes_written(), PAGE_SIZE - 1) as isize)
    })
}

/// The `store` trampoline for a [`DeviceAttribute`] implementor.
///
/// # Safety
///
/// `dev` must point at a live device bound to `T::Driver`, and `buf` must be a NUL-terminated
/// string, as sysfs guarantees when it invokes a `device_attribute` store.
unsafe extern "C" fn device_attribute_store<T: DeviceAttribute>(
    dev: *mut bindings::device,
    _attr: *mut bindings::device_attribute,
    buf: *const c_char,
    count: usize,
) -> isize {
    from_result(|| {
        // SAFETY: the driver core scopes the attribute file to the bound window, so sysfs only
        // invokes `store` while `dev` is a live, bound device.
        let dev = unsafe { device::Device::<BoundInternal>::from_raw(dev) };

        // SAFETY: the driver-typed group table installs the attribute only under `T::Driver`,
        // whose `probe()` stored a `Pin<KBox<<T::Driver as Driver>::Data<'_>>>` as the private
        // data, and the attribute file only dispatches while the device remains bound.
        let data = unsafe { dev.drvdata_borrow::<<T::Driver as Driver>::Data<'_>>() };

        // SAFETY: sysfs NUL-terminates the store buffer, so scanning to the NUL stays in bounds.
        let buf = unsafe { CStr::from_char_ptr(buf) };

        T::store(dev, data, buf)?;
        Ok(count as isize)
    })
}

/// A `'static` table of sysfs attribute groups for [`Driver::DEV_GROUPS`].
///
/// Build one with [`device_attribute_groups!`]. The trait lets the table be stored behind a
/// `&'static dyn`, and its driver parameter ties the table to the driver whose data the
/// attribute callbacks borrow.
///
/// # Safety
///
/// - `as_ptr` must return a pointer to a NULL-terminated `attribute_group` array that stays
///   valid for reads while `self` is alive.
/// - Every attribute in the array must be built for driver `D`, i.e. from [`DeviceAttribute`]
///   implementors whose `Driver` is `D`.
///
/// [`device_attribute_groups!`]: crate::device_attribute_groups
pub unsafe trait AttributeGroups<D: Driver> {
    /// Returns a pointer to the NULL-terminated `attribute_group` array for `driver.dev_groups`.
    fn as_ptr(&self) -> *mut *const bindings::attribute_group;
}

/// Storage for `N` `device_attribute`s.
///
/// A `device_attribute` holds raw pointers, so it is not `Sync`. This wrapper carries the manual
/// impl that lets [`device_attribute_groups!`] place the attributes in a `static`.
#[repr(transparent)]
#[doc(hidden)]
pub struct Attrs<const N: usize>([bindings::device_attribute; N]);

// SAFETY: The attributes are only read by the kernel from the thread-safe sysfs core, and are
// immutable for their `'static` lifetime.
unsafe impl<const N: usize> Sync for Attrs<N> {}

impl<const N: usize> Attrs<N> {
    /// Wraps an array of attributes.
    pub const fn new(attrs: [bindings::device_attribute; N]) -> Self {
        Self(attrs)
    }
}

/// A NULL-terminated array of `N` `device_attribute` pointers, as the kernel reads from
/// `attribute_group.attrs`.
///
/// Built by [`device_attribute_groups!`] from a `static` [`Attrs`]. The entries point into that
/// storage, so it must not move.
///
/// # Invariants
///
/// The first `N` entries point at live `device_attribute`s and `sentinel` is NULL.
#[repr(C)]
#[doc(hidden)]
pub struct RawAttrs<const N: usize> {
    attrs: [*mut bindings::attribute; N],
    sentinel: *mut bindings::attribute,
}

// SAFETY: The pointers are only read by the kernel from the thread-safe sysfs core, and the data
// they reference is immutable for the array's `'static` lifetime.
unsafe impl<const N: usize> Sync for RawAttrs<N> {}

impl<const N: usize> RawAttrs<N> {
    /// Builds the pointer array from `'static` attribute storage.
    pub const fn new(attrs: &'static Attrs<N>) -> Self {
        let mut ptrs = [core::ptr::null_mut(); N];
        let mut i = 0;
        while i < N {
            ptrs[i] = core::ptr::from_ref(&attrs.0[i])
                .cast::<bindings::attribute>()
                .cast_mut();
            i += 1;
        }
        // INVARIANT: the loop fills all `N` entries from the `'static`
        // attributes, and sentinel is null.
        Self {
            attrs: ptrs,
            sentinel: core::ptr::null_mut(),
        }
    }

    /// Returns the pointer to install in `attribute_group.attrs`.
    pub const fn as_ptr(&self) -> *mut *mut bindings::attribute {
        // Derive from `self`, not `self.attrs`, so the pointer has correct provenance to access
        // the sentinel.
        core::ptr::from_ref(self).cast_mut().cast()
    }
}

/// An `attribute_group` over a `'static` [`RawAttrs`].
///
/// Built by [`device_attribute_groups!`]. The group points at the attribute array, so that array
/// must not move.
///
/// # Invariants
///
/// `attrs` points at a NULL-terminated `device_attribute` pointer array.
#[repr(transparent)]
#[doc(hidden)]
pub struct RawGroup(bindings::attribute_group);

impl RawGroup {
    /// Builds the group from a `'static` attribute pointer array.
    pub const fn new<const N: usize>(attrs: &'static RawAttrs<N>) -> Self {
        // INVARIANT: `attrs` is the `'static` `RawAttrs` pointer array, NULL-terminated by its
        // invariant.
        Self(bindings::attribute_group {
            __bindgen_anon_2: bindings::attribute_group__bindgen_ty_2 {
                attrs: attrs.as_ptr(),
            },
            ..pin_init::zeroed()
        })
    }
}

// SAFETY: The pointers are only read by the kernel from the thread-safe sysfs core, and the data
// they reference is immutable for the table's `'static` lifetime.
unsafe impl Sync for RawGroup {}

/// A NULL-terminated array of one `attribute_group` pointer for `driver.dev_groups`.
///
/// Built by [`device_attribute_groups!`] from a `static` [`RawGroup`], which it points at, so that
/// group must not move.
///
/// # Invariants
///
/// - `groups[0]` points at a live `attribute_group` and `sentinel` is NULL.
/// - Every attribute reachable through `groups[0]` is built for driver `D`.
#[repr(C)]
#[doc(hidden)]
pub struct RawGroups<D: Driver> {
    groups: [*const bindings::attribute_group; 1],
    sentinel: *const bindings::attribute_group,
    _driver: PhantomData<fn() -> D>,
}

impl<D: Driver> RawGroups<D> {
    /// Builds the group array from a `'static` group.
    ///
    /// # Safety
    ///
    /// Every attribute reachable through `group` must have been built for driver `D`, i.e. from
    /// [`DeviceAttribute`] implementors whose `Driver` is `D`.
    pub const unsafe fn new(group: &'static RawGroup) -> Self {
        // INVARIANT: `groups[0]` is the `'static` `RawGroup`, sentinel is null, and the caller
        // guarantees every attribute reachable through `group` is built for `D`.
        Self {
            groups: [core::ptr::from_ref(group).cast()],
            sentinel: core::ptr::null(),
            _driver: PhantomData,
        }
    }
}

// SAFETY: The pointers are only read by the kernel from the thread-safe sysfs core, and the data
// they reference is immutable for the table's `'static` lifetime.
unsafe impl<D: Driver> Sync for RawGroups<D> {}

// SAFETY: By the type invariants `as_ptr` returns a NULL-terminated array valid while `self`
// lives, and every attribute in it is built for `D`.
unsafe impl<D: Driver> AttributeGroups<D> for RawGroups<D> {
    fn as_ptr(&self) -> *mut *const bindings::attribute_group {
        // Derive from `self`, not `self.groups`, so the pointer has correct provenance to access
        // the sentinel.
        core::ptr::from_ref(self).cast_mut().cast()
    }
}

/// Defines a `'static` [`AttributeGroups`] table from a list of [`DeviceAttribute`] types.
///
/// Mirrors the C `DEVICE_ATTR_RW` plus `ATTRIBUTE_GROUPS` pair. It emits one `device_attribute` per
/// type and a group with a NULL-terminated attribute array, and binds the result to a
/// `static $name` ready to assign to [`Driver::DEV_GROUPS`].
///
/// # Examples
///
/// ```ignore
/// struct Profiling;
///
/// impl platform::DeviceAttribute for Profiling {
///     type Driver = MyDriver;
///     const NAME: &'static CStr = c"profiling";
///
///     fn show(
///         _dev: &device::Device<Bound>,
///         data: Pin<&MyData<'_>>,
///         writer: &mut Formatter<'_>,
///     ) -> Result {
///         writeln!(writer, "{}", data.mask())?;
///         Ok(())
///     }
///
///     fn store(_dev: &device::Device<Bound>, data: Pin<&MyData<'_>>, buf: &CStr) -> Result {
///         data.set_mask(buf.to_str()?.trim().parse().map_err(|_| EINVAL)?);
///         Ok(())
///     }
/// }
///
/// kernel::device_attribute_groups!(MY_GROUPS, MyDriver, [Profiling]);
///
/// impl platform::Driver for MyDriver {
///     const DEV_GROUPS: Option<&'static dyn platform::AttributeGroups<Self>> = Some(&MY_GROUPS);
///     // ...
/// }
/// ```
#[macro_export]
macro_rules! device_attribute_groups {
    ($name:ident, $driver:ty, [$($attr:ty),+ $(,)?]) => {
        $crate::macros::paste! {
            // The attributes, their pointer array, the group, and the group array reference each
            // other by address, so each lives in its own `static`, as the C `ATTRIBUTE_GROUPS`
            // macro lays them out.
            static [<$name _ATTRS>]: $crate::platform::Attrs<
                { <[()]>::len(&[$($crate::device_attribute_groups!(@unit $attr)),+]) }> =
                $crate::platform::Attrs::new(
                    [$($crate::platform::device_attribute::<$driver, $attr>()),+]);
            static [<$name _RAW_ATTRS>]: $crate::platform::RawAttrs<
                { <[()]>::len(&[$($crate::device_attribute_groups!(@unit $attr)),+]) }> =
                $crate::platform::RawAttrs::new(&[<$name _ATTRS>]);
            static [<$name _GROUP>]: $crate::platform::RawGroup =
                $crate::platform::RawGroup::new(&[<$name _RAW_ATTRS>]);
            // SAFETY: every attribute above is built through `device_attribute::<$driver, _>`,
            // which requires its `Driver` to be `$driver`.
            static $name: $crate::platform::RawGroups<$driver> =
                unsafe { $crate::platform::RawGroups::new(&[<$name _GROUP>]) };
        }
    };

    (@unit $attr:ty) => {
        ()
    };
}
