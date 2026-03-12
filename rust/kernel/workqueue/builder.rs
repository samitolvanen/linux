// SPDX-License-Identifier: GPL-2.0

//! Workqueue builders.

use kernel::{
    alloc::AllocError,
    prelude::*,
    workqueue::{
        OwnedQueue, //
        Queue,
    }, //
};

use core::{
    marker::PhantomData,
    ptr::{
        self,
        NonNull, //
    },
};

/// Workqueue builder.
///
/// A valid combination of workqueue flags contains one of the base flags (`WQ_UNBOUND`, `WQ_BH`,
/// or `WQ_PERCPU`) and a combination of modifier flags that are compatible with the selected base
/// flag.
///
/// For details, please refer to `Documentation/core-api/workqueue.rst`.
pub struct Builder<Kind> {
    flags: bindings::wq_flags,
    max_active: i32,
    _kind: PhantomData<Kind>,
}

pub enum TypeUnbound {}
pub enum TypePercpu {}
pub enum TypePowerEfficient {}
pub enum TypeBH {}
pub enum TypeOrdered {}

/// Entry-points to the builder API.
impl Queue {
    /// Build a workqueue whose work may execute on any cpu.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_unbound().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from unbound wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "WQ_UNBOUND")]
    pub fn new_unbound() -> Builder<TypeUnbound> {
        Builder {
            flags: bindings::wq_flags_WQ_UNBOUND,
            max_active: 0,
            _kind: PhantomData,
        }
    }

    /// Build a workqueue whose work items are bound to the CPU they are queued on.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_percpu().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from percpu wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "WQ_PERCPU")]
    pub fn new_percpu() -> Builder<TypePercpu> {
        Builder {
            flags: bindings::wq_flags_WQ_PERCPU,
            max_active: 0,
            _kind: PhantomData,
        }
    }

    /// Build a power-efficient workqueue.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_power_efficient().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from power-efficient wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "WQ_POWER_EFFICIENT")]
    pub fn new_power_efficient() -> Builder<TypePowerEfficient> {
        Builder {
            flags: bindings::wq_flags_WQ_PERCPU | bindings::wq_flags_WQ_POWER_EFFICIENT,
            max_active: 0,
            _kind: PhantomData,
        }
    }

    /// Build a single-threaded workqueue that executes jobs in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_ordered().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from ordered wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "alloc_ordered_workqueue")]
    #[doc(alias = "__WQ_ORDERED")]
    pub fn new_ordered() -> Builder<TypeOrdered> {
        Builder {
            flags: bindings::wq_flags_WQ_UNBOUND | bindings::wq_flags___WQ_ORDERED,
            max_active: 1,
            _kind: PhantomData,
        }
    }

    /// Build a workqueue that executes in bottom-half (softirq) context.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_bh().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from BH wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "WQ_BH")]
    pub fn new_bh() -> Builder<TypeBH> {
        Builder {
            flags: bindings::wq_flags_WQ_PERCPU | bindings::wq_flags_WQ_BH,
            max_active: 0,
            _kind: PhantomData,
        }
    }
}

/// Options that may be used with all workqueue types.
impl<Kind> Builder<Kind> {
    /// Mark this workqueue high priority.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_unbound().highpri().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from highpri wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "WQ_HIGHPRI")]
    pub fn highpri(mut self) -> Self {
        self.flags |= bindings::wq_flags_WQ_HIGHPRI;
        self
    }

    /// Creates the workqueue.
    ///
    /// The provided name is used verbatim as the workqueue name.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// // create an unbound workqueue registered with sysfs
    /// let wq = Queue::new_unbound().sysfs().build(c"my-wq")?;
    ///
    /// // spawn a work item on it
    /// wq.try_spawn(
    ///     GFP_KERNEL,
    ///     || pr_warn!("Printing from my-wq"),
    /// )?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "alloc_workqueue")]
    pub fn build(self, name: &CStr) -> Result<OwnedQueue, AllocError> {
        // SAFETY:
        // * c"%s" is compatible with passing the name as a c-string.
        // * the builder only permits valid flag combinations
        let ptr = unsafe {
            bindings::alloc_workqueue(
                c"%s".as_char_ptr(),
                self.flags,
                self.max_active,
                name.as_char_ptr().cast::<c_void>(),
            )
        };

        // INVARIANT: We successfully created the workqueue, so we can return ownership to the
        // caller.
        Ok(OwnedQueue {
            queue: NonNull::new(ptr).ok_or(AllocError)?.cast(),
        })
    }

    /// Creates the workqueue.
    ///
    /// # Examples
    ///
    /// This example shows how to pass a Rust string formatter to the workqueue name, creating
    /// workqueues with names such as `my-wq-1` and `my-wq-2`.
    ///
    /// ```
    /// use kernel::workqueue::{Queue, OwnedQueue};
    ///
    /// fn my_wq(num: u32) -> Result<OwnedQueue> {
    ///     // create a percpu workqueue called my-wq-{num}
    ///     let wq = Queue::new_percpu().build_fmt(fmt!("my-wq-{num}"))?;
    ///     Ok(wq)
    /// }
    /// ```
    #[inline]
    pub fn build_fmt(self, name: kernel::fmt::Arguments<'_>) -> Result<OwnedQueue, AllocError> {
        // SAFETY:
        // * c"%pA" is compatible with passing an `Arguments` pointer.
        // * the builder only permits valid flag combinations
        let ptr = unsafe {
            bindings::alloc_workqueue(
                c"%pA".as_char_ptr(),
                self.flags,
                self.max_active,
                ptr::from_ref(&name).cast::<c_void>(),
            )
        };

        // INVARIANT: We successfully created the workqueue, so we can return ownership to the
        // caller.
        Ok(OwnedQueue {
            queue: NonNull::new(ptr).ok_or(AllocError)?.cast(),
        })
    }
}

/// Indicates that this workqueue is threaded.
pub trait TypeThreaded {}
impl TypeThreaded for TypeUnbound {}
impl TypeThreaded for TypePercpu {}
impl TypeThreaded for TypePowerEfficient {}

/// Options that are not available on BH or ordered workqueues.
impl<Kind: TypeThreaded> Builder<Kind> {
    /// Set the maximum number of concurrently executing work items.
    ///
    /// For percpu workqueues this is per-CPU. If not set, a default value of
    /// `WQ_DFL_ACTIVE` is used. The maximum value is `WQ_MAX_ACTIVE`.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_unbound().max_active(16).build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from wq with max_active=16"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    pub fn max_active(mut self, max_active: u32) -> Self {
        // If provided `max_active` is greater than `i32::MAX`, then we need to trigger the C-side
        // comparison with `WQ_MAX_ACTIVE`, which we can do by clamping to `i32::MAX`.
        self.max_active = i32::try_from(max_active).unwrap_or(i32::MAX);
        self
    }

    /// Mark this workqueue as cpu intensive.
    ///
    /// Work items will not contribute to the concurrency level, preventing
    /// them from stalling other work items in the same per-CPU worker pool.
    /// This is meaningless for unbound workqueues.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_unbound().cpu_intensive().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from cpu-intensive wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "WQ_CPU_INTENSIVE")]
    pub fn cpu_intensive(mut self) -> Self {
        self.flags |= bindings::wq_flags_WQ_CPU_INTENSIVE;
        self
    }
}

/// Indicates that this workqueue runs in a normal context (as opposed to softirq context).
pub trait TypeNormal {}
impl TypeNormal for TypeUnbound {}
impl TypeNormal for TypePercpu {}
impl TypeNormal for TypePowerEfficient {}
impl TypeNormal for TypeOrdered {}

/// Options that are not available on BH workqueues.
impl<Kind: TypeNormal> Builder<Kind> {
    /// Make this workqueue visible in sysfs.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_unbound().sysfs().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from sysfs wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "WQ_SYSFS")]
    pub fn sysfs(mut self) -> Self {
        self.flags |= bindings::wq_flags_WQ_SYSFS;
        self
    }

    /// Allow this workqueue to be frozen during suspend.
    ///
    /// Work items on the workqueue are drained and no new work items start
    /// execution until thawed.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_unbound().freezable().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from freezable wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "WQ_FREEZABLE")]
    pub fn freezable(mut self) -> Self {
        self.flags |= bindings::wq_flags_WQ_FREEZABLE;
        self
    }

    /// This workqueue may be used during memory reclaim.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_unbound().mem_reclaim().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from mem_reclaim wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "WQ_MEM_RECLAIM")]
    pub fn mem_reclaim(mut self) -> Self {
        self.flags |= bindings::wq_flags_WQ_MEM_RECLAIM;
        self
    }
}

/// Options only available on a power-efficient workqueue.
impl Builder<TypePowerEfficient> {
    /// Configure this power-efficient workqueue to be percpu.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::workqueue::Queue;
    ///
    /// let wq = Queue::new_power_efficient().percpu().build(c"my-wq")?;
    /// wq.try_spawn(GFP_KERNEL, || pr_info!("Hello from percpu power-efficient wq"))?;
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    #[doc(alias = "WQ_PERCPU")]
    pub fn percpu(mut self) -> Self {
        self.flags &= !bindings::wq_flags_WQ_UNBOUND;
        self.flags |= bindings::wq_flags_WQ_PERCPU;
        self
    }
}
