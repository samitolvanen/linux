// SPDX-License-Identifier: GPL-2.0

//! IOMMU page table management.
//!
//! C header: [`include/io-pgtable.h`](srctree/include/io-pgtable.h)

use crate::bindings;
use crate::types::Opaque;
use core::marker::PhantomData;
use core::mem;
use core::num::NonZeroU64;

use crate::device;
use crate::error::code::*;
use crate::error::to_result;
use crate::error::Result;
use crate::types::ForeignOwnable;
use crate::types::ScopeGuard;

/// Protection flags used with IOMMU mappings.
pub mod prot {
    /// Read access.
    pub const READ: u32 = bindings::IOMMU_READ;
    /// Write access.
    pub const WRITE: u32 = bindings::IOMMU_WRITE;
    /// Request cache coherency.
    pub const CACHE: u32 = bindings::IOMMU_CACHE;
    /// Request no-execute permission.
    pub const NOEXEC: u32 = bindings::IOMMU_NOEXEC;
    /// MMIO peripheral mapping.
    pub const MMIO: u32 = bindings::IOMMU_MMIO;
    /// Privileged mapping.
    pub const PRIV: u32 = bindings::IOMMU_PRIV;
}

/// Represents a requested io_pgtable configuration.
pub struct Config {
    /// Quirk bitmask (type-specific).
    pub quirks: usize,
    /// Valid page sizes, as a bitmask of powers of two.
    pub pgsize_bitmap: usize,
    /// Input address space size in bits.
    pub ias: usize,
    /// Output address space size in bits.
    pub oas: usize,
    /// IOMMU uses coherent accesses for page table walks.
    pub coherent_walk: bool,
}

/// `IOMMU` callbacks for `TLB` and page table management.
///
/// Users must implement this trait to perform the `TLB` flush actions for this
/// `IOMMU`, if required.
pub trait FlushOps {
    /// User-specified type owned by the [`IOPagetable`] that will be passed to TLB
    /// operations.
    type Data: ForeignOwnable + Send + Sync;

    /// Synchronously invalidate the entire TLB context.
    fn tlb_flush_all(data: <Self::Data as ForeignOwnable>::Borrowed<'_>);

    /// Synchronously invalidate all intermediate TLB state (sometimes referred
    /// to as the "walk cache") for a virtual address range.
    fn tlb_flush_walk(
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        iova: usize,
        size: usize,
        granule: usize,
    );

    /// Optional callback to queue up leaf TLB invalidation for a single page.
    ///
    /// IOMMUs that cannot batch TLB invalidation operations efficiently will
    /// typically issue them here, but others may decide to update the
    /// iommu_iotlb_gather structure and defer the invalidation until
    /// iommu_iotlb_sync() instead.
    ///
    // TODO: Implement the gather argument for batching.
    fn tlb_add_page(
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        iova: usize,
        granule: usize,
    );
}

/// Inner page table information that is shared across all table types.
///
/// # Invariants
///
/// - [`self.ops`] is valid and non-null.
/// - [`self.cfg`] is valid.
/// - [`self.data`] is valid and points to the data passed to `IoPageTable::new_fmt`.
#[doc(hidden)]
pub struct IoPageTableInner {
    ops: *mut bindings::io_pgtable_ops,
    cfg: Opaque<bindings::io_pgtable_cfg>,
    data: *mut core::ffi::c_void,
}

/// Helper trait to get the config type for a single page table type from the union.
pub trait GetConfig {
    /// Returns the specific output configuration for this page table type.
    fn cfg(iopt: &impl IoPageTable) -> &Self
    where
        Self: Sized;
}

mod private {
    pub trait Sealed {}
}

/// A generic IOMMU page table
pub trait IoPageTable: private::Sealed {
    #[doc(hidden)]
    const FLUSH_OPS: bindings::iommu_flush_ops;

    #[doc(hidden)]
    fn new_fmt<T: FlushOps>(
        dev: &device::Device,
        format: u32,
        config: Config,
        data: T::Data,
    ) -> Result<IoPageTableInner> {
        let ptr: *mut core::ffi::c_void = data.into_foreign().cast();
        let guard = ScopeGuard::new(|| {
            // SAFETY: `ptr` came from a previous call to `into_foreign`.
            unsafe { T::Data::from_foreign(ptr.cast()) };
        });

        // SAFETY: this type was manually checked to be valid to zero-initialize.
        let __bindgen_anon_1 = unsafe { mem::zeroed() };

        let mut raw_cfg = bindings::io_pgtable_cfg {
            quirks: config.quirks,
            pgsize_bitmap: config.pgsize_bitmap,
            ias: config.ias.try_into()?,
            oas: config.oas.try_into()?,
            coherent_walk: config.coherent_walk,
            tlb: &Self::FLUSH_OPS,
            iommu_dev: dev.as_raw(),
            alloc: None,
            free: None,
            __bindgen_anon_1,
        };

        // SAFETY: there are no specific safety requirements for this call. We
        // simply make sure that all the arguments are valid.
        let ops = unsafe {
            bindings::alloc_io_pgtable_ops(
                format as bindings::io_pgtable_fmt,
                &mut raw_cfg,
                ptr.cast(),
            )
        };

        if ops.is_null() {
            return Err(EINVAL);
        }

        guard.dismiss();
        Ok(IoPageTableInner {
            ops,
            cfg: Opaque::new(raw_cfg),
            data: ptr,
        })
    }

    /// Map a range of pages.
    fn map_pages(
        &mut self,
        iova: usize,
        paddr: usize,
        pgsize: usize,
        pgcount: usize,
        prot: u32,
    ) -> Result<usize> {
        let mut mapped: usize = 0;

        // SAFETY: `self.ops` is valid as per the invariant of `IoPageTableInner`.
        to_result(unsafe {
            (*self.inner_mut().ops).map_pages.unwrap()(
                self.inner_mut().ops,
                iova,
                paddr as u64,
                pgsize,
                pgcount,
                prot as i32,
                bindings::GFP_KERNEL,
                &mut mapped,
            )
        })?;

        Ok(mapped)
    }

    /// Unmap a range of pages.
    fn unmap_pages(
        &mut self,
        iova: usize,
        pgsize: usize,
        pgcount: usize,
        // TODO: gather: *mut iommu_iotlb_gather,
    ) -> usize {
        // SAFETY: `self.ops` is valid as per the invariants of `IoPageTableInner`.
        unsafe {
            (*self.inner_mut().ops).unmap_pages.unwrap()(
                self.inner_mut().ops,
                iova,
                pgsize,
                pgcount,
                core::ptr::null_mut(),
            )
        }
    }

    /// Translate an IOVA to the corresponding physical address, if mapped.
    fn iova_to_phys(&mut self, iova: usize) -> Option<NonZeroU64> {
        // SAFETY: `self.ops` is valid as per the invariants of `IoPageTableInner`.
        let iova_to_phys =
            unsafe { (*self.inner_mut().ops).iova_to_phys.unwrap()(self.inner_mut().ops, iova) };

        NonZeroU64::new(iova_to_phys)
    }

    #[doc(hidden)]
    fn inner_mut(&mut self) -> &mut IoPageTableInner;

    #[doc(hidden)]
    fn inner(&self) -> &IoPageTableInner;

    #[doc(hidden)]
    fn raw_cfg(&self) -> &bindings::io_pgtable_cfg {
        // SAFETY: It is valid to manufacture a reference here.
        unsafe { &*self.inner().cfg.get() }
    }
}

/// # Safety
///
/// This function is only safe to be called by the IOMMU C code.
unsafe extern "C" fn tlb_flush_all_callback<T: FlushOps>(cookie: *mut core::ffi::c_void) {
    // SAFETY:
    //
    // - `cookie` was passed to `into_foreign()` in `IoPageTable::new_fmt`.
    // - We do not overlap with any call to borrow() or borrow_mut().
    T::tlb_flush_all(unsafe { T::Data::borrow(cookie.cast()) });
}

/// # Safety
///
/// This function is only safe to be called by the IOMMU C code.
unsafe extern "C" fn tlb_flush_walk_callback<T: FlushOps>(
    iova: usize,
    size: usize,
    granule: usize,
    cookie: *mut core::ffi::c_void,
) {
    // SAFETY:
    //
    // - `cookie` was passed to `into_foreign()` in `IoPageTable::new_fmt`.
    // - We do not overlap with any call to borrow() or borrow_mut().
    T::tlb_flush_walk(
        unsafe { T::Data::borrow(cookie.cast()) },
        iova,
        size,
        granule,
    );
}

/// # Safety
///
/// This function is only safe to be called by the IOMMU C code.
unsafe extern "C" fn tlb_add_page_callback<T: FlushOps>(
    _gather: *mut bindings::iommu_iotlb_gather,
    iova: usize,
    granule: usize,
    cookie: *mut core::ffi::c_void,
) {
    // SAFETY:
    //
    // - `cookie` was passed to `into_foreign()` in `IoPageTable::new_fmt`.
    // - We do not overlap with any call to borrow() or borrow_mut().
    T::tlb_add_page(unsafe { T::Data::borrow(cookie.cast()) }, iova, granule);
}

macro_rules! iopt_cfg {
    ($name:ident, $field:ident, $type:ident) => {
        /// An IOMMU page table configuration for a specific kind of pagetable.
        pub type $name = bindings::$type;

        impl GetConfig for $name {
            fn cfg(iopt: &impl IoPageTable) -> &$name {
                // SAFETY: The very purpose of this macro is to provide a safe
                // way to access the field by implementing GetConfig for a
                // particular type.
                unsafe { &iopt.raw_cfg().__bindgen_anon_1.$field }
            }
        }
    };
}

macro_rules! iopt_type {
    ($type:ident, $cfg:ty, $fmt:ident) => {
        /// Represents an IOPagetable of this type.
        pub struct $type<T: FlushOps>(IoPageTableInner, PhantomData<T>);

        impl<T: FlushOps> $type<T> {
            /// Creates a new IOPagetable implementation of this type.
            pub fn new(dev: &device::Device, config: Config, data: T::Data) -> Result<Self> {
                Ok(Self(
                    <Self as IoPageTable>::new_fmt::<T>(dev, bindings::$fmt, config, data)?,
                    PhantomData,
                ))
            }

            /// Get the configuration for this IOPagetable.
            pub fn cfg(&self) -> &$cfg {
                <$cfg as GetConfig>::cfg(self)
            }
        }

        impl<T: FlushOps> private::Sealed for $type<T> {}

        impl<T: FlushOps> IoPageTable for $type<T> {
            const FLUSH_OPS: bindings::iommu_flush_ops = bindings::iommu_flush_ops {
                tlb_flush_all: Some(tlb_flush_all_callback::<T>),
                tlb_flush_walk: Some(tlb_flush_walk_callback::<T>),
                tlb_add_page: Some(tlb_add_page_callback::<T>),
            };

            fn inner(&self) -> &IoPageTableInner {
                &self.0
            }

            fn inner_mut(&mut self) -> &mut IoPageTableInner {
                &mut self.0
            }
        }

        impl<T: FlushOps> Drop for $type<T> {
            fn drop(&mut self) {
                // SAFETY: The pointer is valid by the type invariant.
                unsafe { bindings::free_io_pgtable_ops(self.0.ops) };

                // Free context data.
                //
                // SAFETY: This matches the call to `into_foreign` from `new` in the success case.
                unsafe { T::Data::from_foreign(self.0.data.cast()) };
            }
        }
    };
}

iopt_cfg!(
    ARMLPAES1Cfg,
    arm_lpae_s1_cfg,
    io_pgtable_cfg__bindgen_ty_1__bindgen_ty_1
);
iopt_cfg!(
    ARMLPAES2Cfg,
    arm_lpae_s2_cfg,
    io_pgtable_cfg__bindgen_ty_1__bindgen_ty_2
);
iopt_cfg!(
    ARMv7SCfg,
    arm_v7s_cfg,
    io_pgtable_cfg__bindgen_ty_1__bindgen_ty_3
);
iopt_cfg!(
    ARMMaliLPAECfg,
    arm_mali_lpae_cfg,
    io_pgtable_cfg__bindgen_ty_1__bindgen_ty_4
);
iopt_cfg!(
    AppleDARTCfg,
    apple_dart_cfg,
    io_pgtable_cfg__bindgen_ty_1__bindgen_ty_5
);
iopt_cfg!(AmdCfg, amd, io_pgtable_cfg__bindgen_ty_1__bindgen_ty_6);

iopt_type!(ARM32LPAES1, ARMLPAES1Cfg, io_pgtable_fmt_ARM_32_LPAE_S1);
iopt_type!(ARM32LPAES2, ARMLPAES2Cfg, io_pgtable_fmt_ARM_32_LPAE_S2);
iopt_type!(ARM64LPAES1, ARMLPAES1Cfg, io_pgtable_fmt_ARM_64_LPAE_S1);
iopt_type!(ARM64LPAES2, ARMLPAES2Cfg, io_pgtable_fmt_ARM_64_LPAE_S2);
iopt_type!(ARMv7S, ARMv7SCfg, io_pgtable_fmt_ARM_V7S);
iopt_type!(ARMMaliLPAE, ARMMaliLPAECfg, io_pgtable_fmt_ARM_MALI_LPAE);
iopt_type!(AMDIOMMUV1, AmdCfg, io_pgtable_fmt_AMD_IOMMU_V1);
iopt_type!(AppleDART, AppleDARTCfg, io_pgtable_fmt_APPLE_DART);
iopt_type!(AppleDART2, AppleDARTCfg, io_pgtable_fmt_APPLE_DART2);
