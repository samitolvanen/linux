// SPDX-License-Identifier: GPL-2.0

//! IO-agnostic memory mapping interfaces.
//!
//! This crate provides bindings for the `struct iosys_map` type, which provides a common interface
//! for memory mappings which can reside within coherent memory, or within IO memory.
//!
//! C header: [`include/linux/iosys-map.h`](srctree/include/linux/pci.h)

use crate::{
    prelude::*,
    transmute::{AsBytes, FromBytes},
};
use bindings;
use core::{
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ops::{Deref, DerefMut, Range},
    slice,
};

/// Raw unsized representation of a `struct iosys_map`.
///
/// This struct is a transparent wrapper around `struct iosys_map`. The C API does not provide the
/// size of the mapping by default, and thus this type also does not include the size of the
/// mapping. As such, it cannot be used for actually accessing the underlying data pointed to by the
/// mapping.
///
/// With the exception of kernel crates which may provide their own wrappers around `RawIoSysMap`,
/// users will typically not interact with this type directly.
pub struct RawIoSysMap<T: AsBytes + FromBytes>(bindings::iosys_map, PhantomData<T>);

impl<T: AsBytes + FromBytes> RawIoSysMap<T> {
    /// Convert from a raw `bindings::iosys_map`.
    #[expect(unused)]
    #[inline]
    pub(crate) fn from_raw(val: bindings::iosys_map) -> Self {
        Self(val, PhantomData)
    }

    /// Convert from a `RawIoSysMap<T>` to a raw `bindings::iosys_map` ref.
    #[inline]
    pub(crate) fn as_raw(&self) -> &bindings::iosys_map {
        &self.0
    }

    /// Convert from a `RawIoSysMap<T>` to a raw mutable `bindings::iosys_map` ref.
    #[inline]
    pub(crate) fn as_raw_mut(&mut self) -> &mut bindings::iosys_map {
        &mut self.0
    }

    /// Returns whether the mapping is within IO memory space or not.
    #[inline]
    pub fn is_iomem(&self) -> bool {
        self.0.is_iomem
    }

    /// Returns the size of a single item in this mapping.
    pub const fn item_size(&self) -> usize {
        mem::size_of::<T>()
    }

    /// Returns a mutable address to the memory pointed to by this iosys map.
    ///
    /// Note that this address is not guaranteed to reside in system memory, and may reside in IO
    /// memory.
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut T {
        if self.is_iomem() {
            // SAFETY: We confirmed above that this iosys map is contained within iomem, so it's
            // safe to read vaddr_iomem
            unsafe { self.0.__bindgen_anon_1.vaddr_iomem }
        } else {
            // SAFETY: We confirmed above that this iosys map is not contaned within iomem, so it's
            // safe to read vaddr.
            unsafe { self.0.__bindgen_anon_1.vaddr }
        }
        .cast()
    }

    /// Returns an immutable address to the memory pointed to by this iosys map.
    ///
    /// Note that this address is not guaranteed to reside in system memory, and may reside in IO
    /// memory.
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.as_mut_ptr().cast_const()
    }
}

// SAFETY: As we make no guarantees about the validity of the mapping, there's no issue with sending
// this type between threads.
unsafe impl<T: AsBytes + FromBytes> Send for RawIoSysMap<T> {}

impl<T: AsBytes + FromBytes> Clone for RawIoSysMap<T> {
    fn clone(&self) -> Self {
        Self(self.0, PhantomData)
    }
}

/// A sized version of a [`RawIoSysMap`].
///
/// Since this type includes the size of the [`RawIoSysMap`], it can be used for accessing the
/// underlying data pointed to by it.
///
/// # Invariants
///
/// - The iosys mapping referenced by this type is guaranteed to be of at least `size` bytes in
///   size
/// - The iosys mapping referenced by this type is valid for the lifetime `'a`.
#[derive(Clone)]
pub struct IoSysMapRef<'a, T: AsBytes + FromBytes> {
    map: RawIoSysMap<T>,
    size: usize,
    _p: PhantomData<&'a T>,
}

impl<'a, T: AsBytes + FromBytes> IoSysMapRef<'a, T> {
    /// Create a new [`IoSysMapRef`] from a [`RawIoSysMap`].
    ///
    /// # Safety
    ///
    /// - The caller guarantees that the mapping referenced by `map` is of at least `size` bytes in
    ///   size.
    /// - The caller guarantees that the mapping referenced by `map` remains valid for the lifetime
    ///   of `'a`.
    #[allow(unused)]
    pub(crate) unsafe fn new(map: RawIoSysMap<T>, size: usize) -> IoSysMapRef<'a, T> {
        // INVARIANT: Our safety contract fulfills the type invariants of `IoSysMapRef`.
        IoSysMapRef {
            map,
            size,
            _p: PhantomData,
        }
    }

    /// Return the size of the `IoSysMapRef`.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns an immutable reference slice to data from the region starting from `offset`.
    ///
    /// `offset` and `count` are in units of `T`. Note that this function requires that the
    /// underlying iosys mapping does not reside within iomem.
    ///
    /// This function can return the following errors:
    ///
    /// * [`ENOTSUPP`] if the memory region resides in iomem.
    /// * [`EOVERFLOW`] if calculating the length of the slice results in an overflow.
    /// * [`EINVAL`] if the slice would go out of bounds of the memory region.
    ///
    /// # Safety
    ///
    /// * The caller promises that the memory pointed to by for this `IoSysMapRef` is not written to
    ///   while the returned slice is live.
    /// * Callers must ensure that this call does not race with a write to the same region while the
    ///   returned slice is alive.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::iosys_map::*;
    ///
    /// # fn test() -> Result {
    /// # let map = tests::VecIoSysMap::new(&[1, 2, 3])?;
    /// # let map = map.get();
    /// // SAFETY: We are the only ones with access to `map`.
    /// let slice = unsafe { map.as_slice(0, 3)? };
    /// assert_eq!(*slice, [1, 2, 3]);
    ///
    /// let slice = unsafe { map.as_slice(1, 2)? };
    /// assert_eq!(*slice, [2, 3]);
    /// # Ok::<(), Error>(()) }
    /// # assert!(test().is_ok());
    /// ```
    pub unsafe fn as_slice(&self, offset: usize, count: usize) -> Result<&[T]> {
        if self.is_iomem() {
            return Err(ENOTSUPP);
        }

        let range = self.validate_range(offset, count)?;

        // SAFETY:
        // * `self.validate_range()` is guaranteed to return a range within this memory allocation
        //   that is contained within the iosys_map and is properly aligned to the size of
        //   `T`.
        // * We checked above that the memory pointed to by this iosys map doesn't reside in iomem,
        //   so it must reside in system memory - ensuring that `self.addr_mut()` returns a valid
        //   virtual memory address.
        Ok(unsafe { slice::from_raw_parts(self.as_ptr().byte_add(range.start), count) })
    }

    /// Returns a mutable reference slice to data from the region starting from `offset`.
    ///
    /// `offset` and `count` are in units of `T`. Note that this function requires that the
    /// underlying iosys mapping does not reside within iomem.
    ///
    /// For a list of errors this function can return, see [`as_slice`](Self::as_slice).
    ///
    /// # Safety
    ///
    /// The caller promises that the memory region pointed to by this `IoSysMapRef` is not written
    /// to or read from while the returned slice is live.
    pub unsafe fn as_mut_slice(&mut self, offset: usize, count: usize) -> Result<&mut [T]> {
        if self.is_iomem() {
            return Err(ENOTSUPP);
        }

        let range = self.validate_range(offset, count)?;

        // SAFETY:
        // * `self.validate_range()` is guaranteed to return a range within this memory allocation
        //   that is contained within the iosys_map and is properly aligned to the size of
        //   `T`.
        // * We checked above that the memory pointed to by this iosys map doesn't reside in iomem,
        //   so it must reside in system memory - ensuring that `self.addr_mut()` returns a valid
        //   virtual memory address.
        Ok(unsafe { slice::from_raw_parts_mut(self.as_mut_ptr().byte_add(range.start), count) })
    }

    /// Writes `src` to the region starting from `offset`.
    ///
    /// `offset` is in units of `T`, not the number of bytes.
    ///
    /// This function can return the following errors:
    ///
    /// * [`EOVERFLOW`] if calculating the length of the slice results in an overflow.
    /// * [`EINVAL`] if the slice would go out of bounds of the memory region.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::iosys_map::*;
    ///
    /// # fn test() -> Result {
    /// # let map = tests::VecIoSysMap::new(&[0; 3])?;
    /// # let mut map = map.get();
    /// map.write(&[1, 2, 3], 0)?; // (now [1, 2, 3])
    /// map.write(&[4], 2)?; // (now [1, 2, 4])
    ///
    /// // SAFETY: We are the only ones with access to `map`
    /// let slice = unsafe { map.as_slice(0, 3)? };
    /// assert_eq!(slice, [1, 2, 4]);
    ///
    /// # Ok::<(), Error>(()) }
    /// # assert!(test().is_ok());
    /// ```
    pub fn write(&mut self, src: &[T], offset: usize) -> Result {
        let range = self.validate_range(offset, src.len())?;

        // SAFETY:
        // - The address pointed to by this iosys_map is guaranteed to be valid via IoSysMapRef's
        //   type invariants.
        // - `self.validate_range()` always returns a valid range of memory within said memory.
        unsafe {
            bindings::iosys_map_memcpy_to(
                self.as_raw_mut(),
                range.start,
                src.as_ptr().cast(),
                range.len(),
            )
        };

        Ok(())
    }

    /// Attempt to compute the offset of an item within the iosys map using its index.
    ///
    /// Returns an error if an overflow occurs.
    ///
    /// # Safety
    ///
    /// This function checks for overflows, but it explicitly does not check if the offset goes out
    /// of bounds. It is the caller's responsibility to check for this before using the returned
    /// offset with the iosys_map API.
    unsafe fn item_from_index(&self, idx: usize) -> Result<usize> {
        self.item_size().checked_mul(idx).ok_or(EOVERFLOW)
    }

    /// Common helper to compute and validate a range for a specific data type applied from
    /// within the allocated region of the iosys mapping.
    ///
    /// This function returns the computed range if it doesn't overflow, and the range is valid
    /// within the allocated region of the iosys mapping. This is so that the computation may
    /// be reused.
    ///
    /// On success, the range returned by this function is guaranteed:
    ///
    /// * To be a valid range of memory within the virtual mapping for this gem object.
    /// * To be properly aligned to [`RawIoSysMap::item_size()`].
    fn validate_range(&self, offset: usize, count: usize) -> Result<Range<usize>> {
        // SAFETY: If the offset is out of bounds, we'll catch this via overflow checks or when
        // checking range_end.
        let offset = unsafe { self.item_from_index(offset)? };
        let range_size = count.checked_mul(self.item_size()).ok_or(EOVERFLOW)?;
        let range_end = offset.checked_add(range_size).ok_or(EOVERFLOW)?;

        if range_end > self.size() {
            return Err(EINVAL);
        }

        // INVARIANT: Since `offset` and `count` are both in units of `T`, we're guaranteed that the
        // range returned here is properly aligned to `T`.
        Ok(offset..range_end)
    }

    /// Common helper to compute the memory address of an item within the iosys mapping.
    ///
    /// Public but hidden, since it should only be used from [`iosys_map_read`] and
    /// [`iosys_map_write`].
    #[doc(hidden)]
    pub fn ptr_from_index(&self, offset: usize) -> Result<*mut T> {
        // SAFETY: We check if the resulting offset goes out of bounds below.
        let offset = unsafe { self.item_from_index(offset)? };

        if offset.checked_add(self.item_size()).ok_or(EOVERFLOW)? > self.size() {
            return Err(EINVAL);
        }

        // SAFETY: We confirmed that `offset` + the item size does not go out of bounds above.
        Ok(unsafe { self.as_mut_ptr().byte_add(offset) })
    }

    // TODO:
    // This function is currently needed for making the iosys_map_read!() and iosys_map_write!()
    // macros work due to a combination of a few limitations:
    //
    // * The current C API for iosys_map requires that we use offsets for reading/writing
    //   iosys_maps.
    // * Calculating the offset of a field within a struct requires that we either:
    //   * Use field projection for calculating the offset of the field. We don't have this yet.
    //   * Explicitly specify the type of the struct, which would be cumbersome to require in the
    //     read/write macros.
    //   * Provide a typed pointer (or other reference) to the struct in question, allowing the
    //     use of &raw const and &raw mut.
    //     * Keep in mind: we can't simply cast the offset of an item in the iosys map into a typed
    //       pointer to fulfill the third option. While having invalid memory addresses as pointers
    //       is ok, adding an offset to a pointer in rust requires that the resulting memory address
    //       is within the same allocation. Since an invalid pointer has no allocation, we can't
    //       make that guarantee.
    //
    // So, until we have field projection the way we workaround this:
    //
    // * Calculate the offset (self.item_from_index()) of the struct within the iosys map
    // * Calculate the memory address of the struct using the offset from the last step
    //   (self.ptr_from_index()).
    // * Use that memory address with &raw const/&raw mut in order to calculate the memory address
    //   of the desired field, ensuring it remains in the same allocation (happens within the
    //   macros).
    // * Convert the address from the last step back into an offset within the iosys map
    //   (offset_from_ptr()).
    //
    // Once we do get field projection, this silly code should be removed.
    //
    /// Convert a pointer to an item within the iosys map back into an offset.
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid pointer to data within the iosys map.
    unsafe fn offset_from_ptr<F>(&self, ptr: *const F) -> usize {
        // SAFETY: `ptr` always points to data within the memory pointed to by the iosys map,
        // meaning it is within the same memory allocation.
        //
        // Additionally, since `ptr` is within the iosys mapping, the offset here will always be
        // positive and safe to cast to a usize.
        // (TODO: replace this with byte_offset_from_unsigned once it's available in the kernel)
        unsafe { ptr.byte_offset_from(self.as_ptr()) as usize }
    }

    /// Reads the value of `field` and ensures that its type is [`FromBytes`].
    ///
    /// # Safety
    ///
    /// This must be called from the [`iosys_map_read`] macro which ensures that the `field`
    /// pointer is validated beforehand.
    ///
    /// Public but hidden since it should only be used from the [`iosys_map_read`] macro.
    #[doc(hidden)]
    pub unsafe fn field_read<F: FromBytes>(&self, field: *const F) -> F {
        let mut field_val = MaybeUninit::<F>::uninit();

        // SAFETY: `field` is guaranteed valid via our safety contract.
        let offset = unsafe { self.offset_from_ptr(field) };

        // SAFETY: Since we verified `field` is valid above, `offset_from_ptr` will always return a
        // valid offset within the iosys map.
        unsafe {
            bindings::iosys_map_memcpy_from(
                field_val.as_mut_ptr().cast(),
                self.as_raw(),
                offset,
                mem::size_of::<F>(),
            )
        }

        // SAFETY: We just initialized `field_val` above.
        unsafe { field_val.assume_init() }
    }

    /// Writes the value of `field` and ensures that its type is [`AsBytes`].
    ///
    /// # Safety
    ///
    /// This must be called from the [`iosys_map_write`] macro which ensures that the `field`
    /// pointers validated beforehand.
    ///
    /// Public but hidden since it should only be used from the [`iosys_map_write`] macro.
    #[doc(hidden)]
    pub unsafe fn field_write<F: AsBytes>(&mut self, field: *mut F, val: F) {
        // SAFETY: `field` is guaranteed valid via our safety contract.
        let offset = unsafe { self.offset_from_ptr(field) };

        // SAFETY: `offset_from_ptr` always returns a valid offset within the iosys map.
        unsafe {
            bindings::iosys_map_memcpy_to(
                self.as_raw_mut(),
                offset,
                core::ptr::from_ref(&val).cast(),
                mem::size_of::<F>(),
            )
        }
    }
}

impl<'a, T: AsBytes + FromBytes> Deref for IoSysMapRef<'a, T> {
    type Target = RawIoSysMap<T>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<'a, T: AsBytes + FromBytes> DerefMut for IoSysMapRef<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

/// Reads from a field of an item from an iosys map ref.
///
/// # Examples
///
/// ```
/// use kernel::{iosys_map::*, transmute::*};
///
/// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// struct MyStruct { a: u32, b: u16 }
///
/// // SAFETY: All bit patterns are acceptable values for `MyStruct`.
/// unsafe impl FromBytes for MyStruct {};
/// // SAFETY: Instances of `MyStruct` have no uninitialized portions.
/// unsafe impl AsBytes for MyStruct {};
///
/// # fn test() -> Result {
/// # let map = tests::VecIoSysMap::new(&[MyStruct { a: 42, b: 2 }; 3])?;
/// # let map = map.get();
/// let whole = kernel::iosys_map_read!(map[2])?;
/// assert_eq!(whole, MyStruct { a: 42, b: 2 });
///
/// let field = kernel::iosys_map_read!(map[1].b)?;
/// assert_eq!(field, 2);
/// # Ok::<(), Error>(()) }
/// # assert!(test().is_ok());
/// ```
#[macro_export]
macro_rules! iosys_map_read {
    ($map:expr, $idx:expr, $($field:tt)*) => {{
        (|| -> ::core::result::Result<_, $crate::error::Error> {
            let map = &$map;
            let item = $crate::iosys_map::IoSysMapRef::ptr_from_index(map, $idx)?;

            // SAFETY: `ptr_from_index()` ensures that `item` is always a valid (although
            // potentially not dereferenceable, which is fine here) pointer to within the iosys
            // mapping.
            unsafe {
                let ptr_field = &raw const (*item) $($field)*;
                ::core::result::Result::Ok(
                    $crate::iosys_map::IoSysMapRef::field_read(map, ptr_field)
                )
            }
        })()
    }};
    ($map:ident [ $idx: expr ] $($field:tt)* ) => {
        $crate::iosys_map_read!($map, $idx, $($field)*)
    };
    ($($map:ident).* [ $idx:expr ] $($field:tt)* ) => {
        $crate::iosys_map_read!($($map).*, $idx, $($field)*)
    };
}

/// Writes to a field of an item from an iosys map ref.
///
/// # Examples
///
/// ```
/// use kernel::{iosys_map::*, transmute::*};
///
/// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// struct MyStruct { a: u32, b: u16 };
///
/// // SAFETY: All bit patterns are acceptable values for `MyStruct`.
/// unsafe impl FromBytes for MyStruct {};
/// // SAFETY: Instances of `MyStruct` have no uninitialized portions.
/// unsafe impl AsBytes for MyStruct {};
///
/// # fn test() -> Result {
/// # let map = tests::VecIoSysMap::new(&[MyStruct { a: 42, b: 2 }; 3])?;
/// # let mut map = map.get();
/// kernel::iosys_map_write!(map[2].b = 1337)?;
/// # assert_eq!(kernel::iosys_map_read!(map[2].b)?, 1337);
///
/// kernel::iosys_map_write!(map[1] = MyStruct { a: 10, b: 20 })?;
/// # assert_eq!(kernel::iosys_map_read!(map[1])?, MyStruct { a: 10, b: 20 });
/// # Ok::<(), Error>(()) }
/// # assert!(test().is_ok());
/// ```
#[macro_export]
macro_rules! iosys_map_write {
    ($map:ident [ $idx:expr ] $($field:tt)*) => {{
        $crate::iosys_map_write!($map, $idx, $($field)*)
    }};
    ($($map:ident).* [ $idx:expr ] $($field:tt)* ) => {{
        $crate::iosys_map_write!($($map).*, $idx, $($field)*)
    }};
    ($map:expr, $idx:expr, = $val:expr) => {
        (|| -> ::core::result::Result<_, $crate::error::Error> {
            // (expand these outside of the unsafe block (clippy::macro-metavars-in-unsafe)
            let map = &mut $map;
            let val = $val;

            let item = $crate::iosys_map::IoSysMapRef::ptr_from_index(map, $idx)?;
            // SAFETY: `item_from_index` ensures that `item` is always a valid item.
            unsafe { $crate::iosys_map::IoSysMapRef::field_write(map, item, val) };
            ::core::result::Result::Ok(())
        })()
    };
    ($map:expr, $idx:expr, $(.$field:ident)* = $val:expr) => {
        (|| -> ::core::result::Result<_, $crate::error::Error> {
            // (expand these outside of the unsafe block (clippy::macro-metavars-in-unsafe)
            let map = &mut $map;
            let val = $val;

            let item = $crate::iosys_map::IoSysMapRef::ptr_from_index(map, $idx)?;

            // SAFETY: `ptr_from_index()` ensures that `item` is always a valid (although
            // potentially not dereferenceable, which is fine here) pointer to within the iosys
            // mapping.
            unsafe {
                let ptr_field = &raw mut (*item) $(.$field)*;
                $crate::iosys_map::IoSysMapRef::field_write(map, ptr_field, val)
            };
            ::core::result::Result::Ok(())
        })()
    };
}

#[doc(hidden)]
#[kunit_tests(rust_iosys_map)]
pub mod tests {
    use super::*;

    /// A helper struct for managed IoSysMapRef structs which point to a [`Vec`].
    pub struct VecIoSysMap<T: AsBytes + FromBytes + Clone> {
        map: RawIoSysMap<T>,
        vec: KVec<T>,
    }

    impl<T: AsBytes + FromBytes + Clone> VecIoSysMap<T> {
        pub fn new(src: &[T]) -> Result<Self> {
            let mut vec = KVec::<T>::new();

            vec.extend_from_slice(src, GFP_KERNEL)?;

            let map = RawIoSysMap(
                bindings::iosys_map {
                    is_iomem: false,
                    __bindgen_anon_1: bindings::iosys_map__bindgen_ty_1 {
                        vaddr: vec.as_mut_ptr().cast(),
                    },
                },
                PhantomData,
            );

            Ok(Self { map, vec })
        }

        pub fn get(&self) -> IoSysMapRef<'_, T> {
            // SAFETY: `map` points to `vec`, so the size of `map` is the size of the `vec`.
            unsafe { IoSysMapRef::new(self.map.clone(), self.vec.len() * self.map.item_size()) }
        }
    }

    #[test]
    fn basic() -> Result {
        let map = VecIoSysMap::new(&[0; 3])?;
        let mut map = map.get();

        map.write(&[1, 2, 3], 0)?;

        // SAFETY: We are the only ones with access to map.
        assert_eq!(unsafe { map.as_slice(0, 3)? }, [1, 2, 3]);

        map.write(&[42], 1)?;

        // SAFETY: We are the only ones with access to the map.
        assert_eq!(unsafe { map.as_slice(0, 3)? }, [1, 42, 3]);

        // SAFETY: We are the only ones with access to the map.
        assert_eq!(unsafe { map.as_slice(1, 1)? }, [42]);

        Ok(())
    }

    #[test]
    fn oob_accesses() -> Result {
        let map = VecIoSysMap::new(&[0; 3])?;
        let mut map = map.get();

        // SAFETY: We are the only ones with access to map.
        assert!(unsafe { map.as_slice(0, 4) }.is_err());

        // SAFETY: We are the only ones with access to map.
        assert!(unsafe { map.as_slice(1, 3) }.is_err());

        assert!(map.write(&[1, 2, 3, 69], 0).is_err());
        assert!(map.write(&[1, 2, 3], 69).is_err());

        Ok(())
    }

    #[test]
    fn overflows() -> Result {
        let map = VecIoSysMap::new(&[0; 3])?;
        let mut map = map.get();

        // SAFETY: We are the only ones with access to map.
        assert!(unsafe { map.as_slice(usize::MAX, 3) }.is_err());

        // SAFETY: We are the only ones with access to map.
        assert!(unsafe { map.as_slice(0, usize::MAX) }.is_err());

        assert!(map.write(&[1, 2, 3], usize::MAX).is_err());

        Ok(())
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    struct TestStruct {
        a: u32,
        b: u64,
    }

    // SAFETY: All bit patterns are acceptable values for `TestStruct`.
    unsafe impl FromBytes for TestStruct {}
    // SAFETY: Instances of `TestStruct` have no uninitialized portions.
    unsafe impl AsBytes for TestStruct {}

    #[test]
    fn basic_macro() -> Result {
        let mut expected = [TestStruct { a: 1, b: 2 }; 5];
        let map = VecIoSysMap::new(&expected)?;
        let mut map = map.get();

        iosys_map_write!(map[3].a = u32::MAX)?;
        expected[3].a = u32::MAX;

        assert_eq!(iosys_map_read!(map[3].a)?, u32::MAX);
        assert_eq!(iosys_map_read!(map[3])?, TestStruct { a: u32::MAX, b: 2 });

        // Compare the entire array, so that we catch any mis-sized writes.
        // SAFETY: We are the only ones with access to map.
        assert_eq!(expected, unsafe { map.as_slice(0, 5)? });

        Ok(())
    }

    #[test]
    fn macro_oob_accesses() -> Result {
        let map = VecIoSysMap::new(&[TestStruct { a: 1, b: 2 }; 3])?;
        let mut map = map.get();

        assert!(iosys_map_read!(map[5].b).is_err());
        assert!(iosys_map_read!(map[1000]).is_err());
        assert!(iosys_map_write!(map[6969].a = 999).is_err());
        assert!(iosys_map_write!(map[243] = TestStruct { a: 99, b: 22 }).is_err());

        Ok(())
    }

    #[test]
    fn macro_overflows() -> Result {
        let map = VecIoSysMap::new(&[TestStruct { a: 1, b: 2 }; 3])?;
        let mut map = map.get();

        assert!(iosys_map_read!(map[usize::MAX]).is_err());
        assert!(iosys_map_read!(map[usize::MAX].b).is_err());
        assert!(iosys_map_write!(map[usize::MAX] = TestStruct { a: 1, b: 1 }).is_err());
        assert!(iosys_map_write!(map[usize::MAX].b = 1).is_err());

        Ok(())
    }
}
