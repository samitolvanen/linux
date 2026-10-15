// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2025 Google LLC.

use super::{
    Attribute,
    BinaryReader,
    BinaryWriter,
    Reader,
    SeqShow,
    Writer, //
};

use crate::{
    debugfs::callback_adapters::Adapter,
    error::from_result,
    fmt,
    fs::file,
    module::{
        this_module,
        ModuleMetadata, //
    },
    prelude::*,
    seq_file::SeqFile,
    seq_print,
    uaccess::UserSlice, //
};

use core::marker::PhantomData;

#[cfg(CONFIG_DEBUG_FS)]
use core::ops::Deref;

/// # Invariant
///
/// `FileOps<T>` will always contain an `operations` which is safe to use for a file backed
/// off an inode which has a pointer to a `T` in its private data that is safe to convert
/// into a reference.
pub(super) struct FileOps<T> {
    #[cfg(CONFIG_DEBUG_FS)]
    operations: bindings::file_operations,
    #[cfg(CONFIG_DEBUG_FS)]
    mode: u16,
    _phantom: PhantomData<T>,
}

impl<T> FileOps<T> {
    /// # Safety
    ///
    /// The caller asserts that the provided `operations` is safe to use for a file whose
    /// inode has a pointer to `T` in its private data that is safe to convert into a reference.
    const unsafe fn new(operations: bindings::file_operations, mode: u16) -> Self {
        Self {
            #[cfg(CONFIG_DEBUG_FS)]
            operations,
            #[cfg(CONFIG_DEBUG_FS)]
            mode,
            _phantom: PhantomData,
        }
    }

    #[cfg(CONFIG_DEBUG_FS)]
    pub(crate) const fn mode(&self) -> u16 {
        self.mode
    }
}

impl<T: Adapter> FileOps<T> {
    pub(super) const fn adapt(&self) -> &FileOps<T::Inner> {
        // SAFETY: `Adapter` asserts that `T` can be legally cast to `T::Inner`.
        unsafe { core::mem::transmute(self) }
    }
}

#[cfg(CONFIG_DEBUG_FS)]
impl<T> Deref for FileOps<T> {
    type Target = bindings::file_operations;

    fn deref(&self) -> &Self::Target {
        &self.operations
    }
}

struct WriterAdapter<T>(T);

impl<'a, T: Writer> fmt::Display for WriterAdapter<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.write(f)
    }
}

/// Implements `open` for `file_operations` via `single_open` to fill out a `seq_file`.
///
/// # Safety
///
/// * `inode`'s private pointer must point to a value of type `T` which will outlive the `inode`
///   and will not have any unique references alias it during the call.
/// * `file` must point to a live, not-yet-initialized file object.
unsafe extern "C" fn writer_open<T: Writer + Sync>(
    inode: *mut bindings::inode,
    file: *mut bindings::file,
) -> c_int {
    // SAFETY: The caller ensures that `inode` is a valid pointer.
    let data = unsafe { (*inode).i_private };
    // SAFETY:
    // * `file` is acceptable by caller precondition.
    // * `print_act` will be called on a `seq_file` with private data set to the third argument,
    //   so we meet its safety requirements.
    // * The `data` pointer passed in the third argument is a valid `T` pointer that outlives
    //   this call by caller preconditions.
    unsafe { bindings::single_open(file, Some(writer_act::<T>), data) }
}

/// Prints private data stashed in a seq_file to that seq file.
///
/// # Safety
///
/// `seq` must point to a live `seq_file` whose private data is a valid pointer to a `T` which may
/// not have any unique references alias it during the call.
unsafe extern "C" fn writer_act<T: Writer + Sync>(
    seq: *mut bindings::seq_file,
    _: *mut c_void,
) -> c_int {
    // SAFETY: By caller precondition, this pointer is valid pointer to a `T`, and
    // there are not and will not be any unique references until we are done.
    let data = unsafe { &*((*seq).private.cast::<T>()) };
    // SAFETY: By caller precondition, `seq_file` points to a live `seq_file`, so we can lift
    // it.
    let seq_file = unsafe { SeqFile::from_raw(seq) };
    seq_print!(seq_file, "{}", WriterAdapter(data));
    0
}

/// Show callback for `SeqShow` types.
///
/// # Safety
///
/// The seq_file core guarantees that `seq` points to a live `seq_file`
/// whose private data is a valid pointer to a `T` with no outstanding
/// mutable references.
unsafe extern "C" fn seq_file_show<S: SeqShow<T>, T: Sync>(
    seq: *mut bindings::seq_file,
    _: *mut c_void,
) -> c_int {
    // SAFETY: `seq->private` is a valid `T` pointer with no outstanding
    // mutable references.
    let data = unsafe { &*((*seq).private.cast::<T>()) };
    // SAFETY: `seq` points to a live `seq_file`.
    let m = unsafe { SeqFile::from_raw(seq) };
    from_result(|| S::show(data, m).map(|()| 0))
}

/// Open callback for `SeqShow` types.
///
/// # Safety
///
/// The VFS guarantees that `inode` is valid with `i_private` pointing to a
/// valid `T` that remains valid for the duration of the call, and that `file`
/// points to a live, uninitialized file object.
unsafe extern "C" fn seq_file_open<S: SeqShow<T>, T: Sync>(
    inode: *mut bindings::inode,
    file: *mut bindings::file,
) -> c_int {
    // SAFETY: `inode` is valid per VFS. `i_private` points to a valid `T`
    // (guaranteed by the `FileOps<T>` invariants).
    let data = unsafe { (*inode).i_private.cast::<T>() };

    // SAFETY: `file` is valid per VFS; `data` matches `seq_file_show`'s contract.
    unsafe { bindings::single_open(file, Some(seq_file_show::<S, T>), data.cast()) }
}

pub(crate) trait SeqReadFile<M, T> {
    const FILE_OPS: FileOps<T>;
}

/// Returns whether `format` has one conversion of an `unsigned long long`, and no other.
const fn is_attribute_format(format: &CStr) -> bool {
    let bytes = format.to_bytes();
    let mut conversions = 0;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }

        i += 1;
        if i < bytes.len() && bytes[i] == b'%' {
            i += 1;
            continue;
        }

        while i < bytes.len() && matches!(bytes[i], b'#' | b'0' | b'-' | b' ' | b'+') {
            i += 1;
        }

        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }

        if i + 2 >= bytes.len() || bytes[i] != b'l' || bytes[i + 1] != b'l' {
            return false;
        }

        if !matches!(bytes[i + 2], b'd' | b'i' | b'o' | b'u' | b'x' | b'X') {
            return false;
        }

        i += 3;
        conversions += 1;
    }

    conversions == 1
}

/// Reads the value of an [`Attribute`] for `simple_attr_read()`.
///
/// # Safety
///
/// `data` must point to a valid `T`, and `val` must be valid for writes.
unsafe extern "C" fn attribute_get<A: Attribute<T>, T: Sync>(
    data: *mut c_void,
    val: *mut u64,
) -> c_int {
    // SAFETY: Per the safety requirements, `data` points to a valid `T`.
    let data = unsafe { &*data.cast::<T>() };

    match A::get(data) {
        Ok(value) => {
            // SAFETY: Per the safety requirements, `val` is valid for writes.
            unsafe { *val = value };
            0
        }
        Err(e) => e.to_errno(),
    }
}

/// Writes the value of an [`Attribute`] for `simple_attr_write()`.
///
/// # Safety
///
/// `data` must point to a valid `T`.
unsafe extern "C" fn attribute_set<A: Attribute<T>, T: Sync>(data: *mut c_void, val: u64) -> c_int {
    // SAFETY: Per the safety requirements, `data` points to a valid `T`.
    let data = unsafe { &*data.cast::<T>() };

    from_result(|| A::set(data, val).map(|()| 0))
}

/// Opens an [`Attribute`] file.
///
/// # Safety
///
/// The VFS guarantees that `inode` is valid with `i_private` pointing to a valid `T` while the
/// file is open, and that `file` points to a live, uninitialized file object.
unsafe extern "C" fn attribute_open<A: Attribute<T>, T: Sync>(
    inode: *mut bindings::inode,
    file: *mut bindings::file,
) -> c_int {
    // SAFETY: `inode` and `file` are valid per the safety requirements. `simple_attr_open()`
    // passes `i_private`, a valid `T`, to the callbacks. `A::FORMAT` has one conversion of an
    // `unsigned long long`, as `AttributeFile::FILE_OPS` checks.
    unsafe {
        bindings::simple_attr_open(
            inode,
            file,
            Some(attribute_get::<A, T>),
            Some(attribute_set::<A, T>),
            A::FORMAT.as_char_ptr(),
        )
    }
}

pub(crate) trait AttributeFile<M, T> {
    const FILE_OPS: FileOps<T>;
}

impl<M: ModuleMetadata, A: Attribute<T>, T: Sync> AttributeFile<M, T> for A {
    const FILE_OPS: FileOps<T> = {
        assert!(
            is_attribute_format(A::FORMAT),
            "the format must have one conversion of an unsigned long long"
        );

        let operations = bindings::file_operations {
            owner: this_module::<M>().as_ptr(),
            open: Some(attribute_open::<Self, T>),
            release: Some(bindings::simple_attr_release),
            read: Some(bindings::simple_attr_read),
            write: Some(bindings::simple_attr_write),
            ..pin_init::zeroed()
        };
        // SAFETY: `attribute_open` treats `inode->i_private` as a valid `&T` reference,
        // satisfying the `FileOps::new` contract. The other operations are the stock
        // `simple_attr` implementations.
        unsafe { FileOps::new(operations, 0o600) }
    };
}

impl<M: ModuleMetadata, S: SeqShow<T>, T: Sync> SeqReadFile<M, T> for S {
    const FILE_OPS: FileOps<T> = {
        let operations = bindings::file_operations {
            owner: this_module::<M>().as_ptr(),
            read: Some(bindings::seq_read),
            llseek: Some(bindings::seq_lseek),
            release: Some(bindings::single_release),
            open: Some(seq_file_open::<Self, T>),
            ..pin_init::zeroed()
        };
        // SAFETY: `read` and `llseek` are stock `seq_file` implementations.
        // `seq_file_open` treats `inode->i_private` as a valid `&T` reference,
        // satisfying the `FileOps::new` contract.
        unsafe { FileOps::new(operations, 0o400) }
    };
}

// Work around lack of generic const items.
pub(crate) trait ReadFile<M, T> {
    const FILE_OPS: FileOps<T>;
}

impl<M: ModuleMetadata, T: Writer + Sync> ReadFile<M, T> for T {
    const FILE_OPS: FileOps<T> = {
        let operations = bindings::file_operations {
            owner: this_module::<M>().as_ptr(),
            read: Some(bindings::seq_read),
            llseek: Some(bindings::seq_lseek),
            release: Some(bindings::single_release),
            open: Some(writer_open::<Self>),
            ..pin_init::zeroed()
        };
        // SAFETY: `operations` is all stock `seq_file` implementations except for `writer_open`.
        // `open`'s only requirement beyond what is provided to all open functions is that the
        // inode's data pointer must point to a `T` that will outlive it, which matches the
        // `FileOps` requirements.
        unsafe { FileOps::new(operations, 0o400) }
    };
}

fn read<T: Reader + Sync>(data: &T, buf: *const c_char, count: usize) -> isize {
    let mut reader = UserSlice::new(UserPtr::from_ptr(buf as *mut c_void), count).reader();

    if let Err(e) = data.read_from_slice(&mut reader) {
        return e.to_errno() as isize;
    }

    count as isize
}

/// # Safety
///
/// `file` must be a valid pointer to a `file` struct.
/// The `private_data` of the file must contain a valid pointer to a `seq_file` whose
/// `private` data in turn points to a `T` that implements `Reader`.
/// `buf` must be a valid user-space buffer.
pub(crate) unsafe extern "C" fn write<T: Reader + Sync>(
    file: *mut bindings::file,
    buf: *const c_char,
    count: usize,
    _ppos: *mut bindings::loff_t,
) -> isize {
    // SAFETY: The file was opened with `single_open`, which sets `private_data` to a `seq_file`.
    let seq = unsafe { &mut *((*file).private_data.cast::<bindings::seq_file>()) };
    // SAFETY: By caller precondition, this pointer is live and points to a value of type `T`.
    let data = unsafe { &*(seq.private as *const T) };
    read(data, buf, count)
}

// A trait to get the file operations for a type.
pub(crate) trait ReadWriteFile<M, T> {
    const FILE_OPS: FileOps<T>;
}

impl<M: ModuleMetadata, T: Writer + Reader + Sync> ReadWriteFile<M, T> for T {
    const FILE_OPS: FileOps<T> = {
        let operations = bindings::file_operations {
            owner: this_module::<M>().as_ptr(),
            open: Some(writer_open::<T>),
            read: Some(bindings::seq_read),
            write: Some(write::<T>),
            llseek: Some(bindings::seq_lseek),
            release: Some(bindings::single_release),
            ..pin_init::zeroed()
        };
        // SAFETY: `operations` is all stock `seq_file` implementations except for `writer_open`
        // and `write`.
        // `writer_open`'s only requirement beyond what is provided to all open functions is that
        // the inode's data pointer must point to a `T` that will outlive it, which matches the
        // `FileOps` requirements.
        // `write` only requires that the file's private data pointer points to `seq_file`
        // which points to a `T` that will outlive it, which matches what `writer_open`
        // provides.
        unsafe { FileOps::new(operations, 0o600) }
    };
}

/// # Safety
///
/// `inode` must be a valid pointer to an `inode` struct.
/// `file` must be a valid pointer to a `file` struct.
unsafe extern "C" fn write_only_open(
    inode: *mut bindings::inode,
    file: *mut bindings::file,
) -> c_int {
    // SAFETY: The caller ensures that `inode` and `file` are valid pointers.
    unsafe { (*file).private_data = (*inode).i_private };
    0
}

/// # Safety
///
/// * `file` must be a valid pointer to a `file` struct.
/// * The `private_data` of the file must contain a valid pointer to a `T` that implements
///   `Reader`.
/// * `buf` must be a valid user-space buffer.
pub(crate) unsafe extern "C" fn write_only_write<T: Reader + Sync>(
    file: *mut bindings::file,
    buf: *const c_char,
    count: usize,
    _ppos: *mut bindings::loff_t,
) -> isize {
    // SAFETY: The caller ensures that `file` is a valid pointer and that `private_data` holds a
    // valid pointer to `T`.
    let data = unsafe { &*((*file).private_data as *const T) };
    read(data, buf, count)
}

pub(crate) trait WriteFile<M, T> {
    const FILE_OPS: FileOps<T>;
}

impl<M: ModuleMetadata, T: Reader + Sync> WriteFile<M, T> for T {
    const FILE_OPS: FileOps<T> = {
        let operations = bindings::file_operations {
            owner: this_module::<M>().as_ptr(),
            open: Some(write_only_open),
            write: Some(write_only_write::<T>),
            llseek: Some(bindings::noop_llseek),
            ..pin_init::zeroed()
        };
        // SAFETY:
        // * `write_only_open` populates the file private data with the inode private data
        // * `write_only_write`'s only requirement is that the private data of the file point to
        //   a `T` and be legal to convert to a shared reference, which `write_only_open`
        //   satisfies.
        unsafe { FileOps::new(operations, 0o200) }
    };
}

extern "C" fn blob_read<T: BinaryWriter>(
    file: *mut bindings::file,
    buf: *mut c_char,
    count: usize,
    ppos: *mut bindings::loff_t,
) -> isize {
    // SAFETY:
    // - `file` is a valid pointer to a `struct file`.
    // - The type invariant of `FileOps` guarantees that `private_data` points to a valid `T`.
    let this = unsafe { &*((*file).private_data.cast::<T>()) };

    // SAFETY:
    // - `ppos` is a valid `file::Offset` pointer.
    // - We have exclusive access to `ppos`.
    let pos: &mut file::Offset = unsafe { &mut *ppos };

    let mut writer = UserSlice::new(UserPtr::from_ptr(buf.cast()), count).writer();

    let ret = || -> Result<isize> {
        let written = this.write_to_slice(&mut writer, pos)?;

        Ok(written.try_into()?)
    }();

    match ret {
        Ok(n) => n,
        Err(e) => e.to_errno() as isize,
    }
}

/// Representation of [`FileOps`] for read only binary files.
pub(crate) trait BinaryReadFile<M, T> {
    const FILE_OPS: FileOps<T>;
}

impl<M: ModuleMetadata, T: BinaryWriter + Sync> BinaryReadFile<M, T> for T {
    const FILE_OPS: FileOps<T> = {
        let operations = bindings::file_operations {
            owner: this_module::<M>().as_ptr(),
            read: Some(blob_read::<T>),
            llseek: Some(bindings::default_llseek),
            open: Some(bindings::simple_open),
            ..pin_init::zeroed()
        };

        // SAFETY:
        // - The private data of `struct inode` does always contain a pointer to a valid `T`.
        // - `simple_open()` stores the `struct inode`'s private data in the private data of the
        //   corresponding `struct file`.
        // - `blob_read()` re-creates a reference to `T` from the `struct file`'s private data.
        // - `default_llseek()` does not access the `struct file`'s private data.
        unsafe { FileOps::new(operations, 0o400) }
    };
}

extern "C" fn blob_write<T: BinaryReader>(
    file: *mut bindings::file,
    buf: *const c_char,
    count: usize,
    ppos: *mut bindings::loff_t,
) -> isize {
    // SAFETY:
    // - `file` is a valid pointer to a `struct file`.
    // - The type invariant of `FileOps` guarantees that `private_data` points to a valid `T`.
    let this = unsafe { &*((*file).private_data.cast::<T>()) };

    // SAFETY:
    // - `ppos` is a valid `file::Offset` pointer.
    // - We have exclusive access to `ppos`.
    let pos: &mut file::Offset = unsafe { &mut *ppos };

    let mut reader = UserSlice::new(UserPtr::from_ptr(buf.cast_mut().cast()), count).reader();

    let ret = || -> Result<isize> {
        let read = this.read_from_slice(&mut reader, pos)?;

        Ok(read.try_into()?)
    }();

    match ret {
        Ok(n) => n,
        Err(e) => e.to_errno() as isize,
    }
}

/// Representation of [`FileOps`] for write only binary files.
pub(crate) trait BinaryWriteFile<M, T> {
    const FILE_OPS: FileOps<T>;
}

impl<M: ModuleMetadata, T: BinaryReader + Sync> BinaryWriteFile<M, T> for T {
    const FILE_OPS: FileOps<T> = {
        let operations = bindings::file_operations {
            owner: this_module::<M>().as_ptr(),
            write: Some(blob_write::<T>),
            llseek: Some(bindings::default_llseek),
            open: Some(bindings::simple_open),
            ..pin_init::zeroed()
        };

        // SAFETY:
        // - The private data of `struct inode` does always contain a pointer to a valid `T`.
        // - `simple_open()` stores the `struct inode`'s private data in the private data of the
        //   corresponding `struct file`.
        // - `blob_write()` re-creates a reference to `T` from the `struct file`'s private data.
        // - `default_llseek()` does not access the `struct file`'s private data.
        unsafe { FileOps::new(operations, 0o200) }
    };
}

/// Representation of [`FileOps`] for read/write binary files.
pub(crate) trait BinaryReadWriteFile<M, T> {
    const FILE_OPS: FileOps<T>;
}

impl<M: ModuleMetadata, T: BinaryWriter + BinaryReader + Sync> BinaryReadWriteFile<M, T> for T {
    const FILE_OPS: FileOps<T> = {
        let operations = bindings::file_operations {
            owner: this_module::<M>().as_ptr(),
            read: Some(blob_read::<T>),
            write: Some(blob_write::<T>),
            llseek: Some(bindings::default_llseek),
            open: Some(bindings::simple_open),
            ..pin_init::zeroed()
        };

        // SAFETY:
        // - The private data of `struct inode` does always contain a pointer to a valid `T`.
        // - `simple_open()` stores the `struct inode`'s private data in the private data of the
        //   corresponding `struct file`.
        // - `blob_read()` re-creates a reference to `T` from the `struct file`'s private data.
        // - `blob_write()` re-creates a reference to `T` from the `struct file`'s private data.
        // - `default_llseek()` does not access the `struct file`'s private data.
        unsafe { FileOps::new(operations, 0o600) }
    };
}

#[kunit_tests(rust_debugfs_attribute)]
mod tests {
    use super::*;
    use crate::{
        sync::atomic::{
            Atomic,
            Relaxed, //
        },
        LocalModule, //
    };

    struct Counter;

    impl Attribute<Atomic<u64>> for Counter {
        const FORMAT: &'static CStr = c"0x%08llx\n";

        fn get(data: &Atomic<u64>) -> Result<u64> {
            Ok(data.load(Relaxed))
        }

        fn set(data: &Atomic<u64>, val: u64) -> Result {
            if val == u64::MAX {
                return Err(EINVAL);
            }

            data.store(val, Relaxed);
            Ok(())
        }
    }

    #[test]
    fn attribute_formats() {
        assert!(is_attribute_format(c"%llu\n"));
        assert!(is_attribute_format(c"0x%08llx\n"));
        assert!(is_attribute_format(c"100%% %lld\n"));

        assert!(!is_attribute_format(c"none\n"));
        assert!(!is_attribute_format(c"%llu %llu\n"));
        assert!(!is_attribute_format(c"%s\n"));
        assert!(!is_attribute_format(c"%lu\n"));
        assert!(!is_attribute_format(c"%ll"));
    }

    #[test]
    fn attribute_callbacks() {
        let _ops = &<Counter as AttributeFile<LocalModule, Atomic<u64>>>::FILE_OPS;

        let counter = Atomic::new(0u64);
        let data = core::ptr::from_ref(&counter).cast_mut().cast::<c_void>();
        let mut val = 0;

        // SAFETY: `data` points to a valid `Atomic<u64>`.
        assert_eq!(unsafe { attribute_set::<Counter, _>(data, 42) }, 0);
        // SAFETY: `data` points to a valid `Atomic<u64>`, and `val` is valid for writes.
        assert_eq!(unsafe { attribute_get::<Counter, _>(data, &mut val) }, 0);
        assert_eq!(val, 42);

        // SAFETY: `data` points to a valid `Atomic<u64>`.
        let ret = unsafe { attribute_set::<Counter, _>(data, u64::MAX) };
        assert_eq!(ret, EINVAL.to_errno());
        assert_eq!(counter.load(Relaxed), 42);
    }
}
