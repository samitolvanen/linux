// SPDX-License-Identifier: GPL-2.0 or MIT

use core::mem::ManuallyDrop;
use core::ops::ControlFlow;
use core::ops::Deref;
use core::sync::atomic::AtomicU32;
use global::GlobalInterface;
use kernel::alloc::allocator::Kmalloc;
use kernel::bindings::SZ_1G;
use kernel::devres::Devres;
use kernel::drm::mm;
use kernel::firmware;
use kernel::io::mem::IoMem;
use kernel::new_mutex;
use kernel::platform;
use kernel::prelude::*;
use kernel::sizes::SZ_8K;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use parse::Section;

use crate::driver::TyrDevice;
use crate::gem;
use crate::gem::KernelVaPlacement;
use crate::gem::ObjectRef;
use crate::gpu::GpuInfo;
use crate::mmu::vm::map_flags;
use crate::mmu::vm::Vm;
use crate::mmu::vm::VmLayout;
use crate::mmu::vm::WithLockedVm;
use crate::mmu::Mmu;
use crate::wait::Wait;
use crate::wait::WaitResult;

const CSF_MCU_SHARED_REGION_START: u32 = 0x04000000;
const CSF_MCU_SHARED_REGION_SIZE: u32 = 0x04000000;

pub(crate) mod global;
pub(crate) mod irq;
mod parse;

/// The metadata stored in a `drm_mm` node to track a borrow.
#[derive(Debug)]
enum BorrowedMode {
    Shared { refcount: AtomicU32 },
    Exclusive,
}

/// A type alias for a `drm_mm` node that contains `BorrowedMode` metadata.
type BorrowNode = mm::NodeData<(), BorrowedMode>;

/// The inner data of a shared section guard, containing common fields.
///
/// This struct is not intended to be used directly. It is wrapped by `SharedSectionGuard` and
/// `SharedSectionGuardMut` to provide safe access to the shared section.
pub(crate) struct SharedSectionGuardInner {
    shared_section: Arc<SharedSection>,
    start: usize,
    end: usize,
}

impl SharedSectionGuardInner {
    /// Returns the length of the borrowed range.
    fn len(&self) -> usize {
        self.end - self.start
    }

    /// Returns a mutable pointer to the start of the borrowed range in the shared section.
    fn as_mut_ptr(&self) -> Result<*mut core::ffi::c_void> {
        let section_ptr = Arc::as_ptr(&self.shared_section.section) as *mut KBox<Section>;
        // SAFETY: The `drm_mm` allocator ensures that borrows do not conflict.
        // A mutable pointer is obtained here to call `vmap()`, which is safe
        // because it is an idempotent, one-time initialization.
        let section = unsafe { &mut *section_ptr };
        let vmap = section.mem.vmap()?;
        let vmap = vmap.as_mut_ptr();

        // SAFETY: `self.start` is a valid offset into the shared section, as guaranteed by the
        // `SharedSection` when this guard was created.
        let offset = unsafe { vmap.add(self.start) };

        Ok(offset)
    }

    /// Reads a value of type `T` from the given offset within the borrowed range.
    pub(crate) fn read_at<T>(&self, offset: usize) -> Result<T> {
        if offset + core::mem::size_of::<T>() > self.len() {
            return Err(EINVAL);
        }

        let base_ptr = self.as_mut_ptr()?;
        // SAFETY: We checked that the read is within the bounds of the borrowed range.
        let ptr = unsafe { base_ptr.add(offset) };

        // Make sure all writes took place before we read the memory.
        kernel::sync::barrier::smp_mb();

        // SAFETY: The pointer is guaranteed to be valid for a read of `size_of::<T>()` bytes, as
        // checked above.
        Ok(unsafe { core::ptr::read_volatile(ptr as *const T) })
    }

    /// Reads a value of type `T` from the start of the borrowed range.
    pub(crate) fn read<T>(&self) -> Result<T> {
        self.read_at(0)
    }
}

/// A guard representing a shared (read-only) borrow of a range in the shared section.
///
/// This guard ensures that the borrowed range is not concurrently written to by other parts of the
/// kernel. It is safe to have multiple shared guards for the same range. When the guard is
/// dropped, the shared borrow is released.
pub(crate) struct SharedSectionGuard {
    inner: SharedSectionGuardInner,
    node: *const BorrowNode,
}

impl Drop for SharedSectionGuard {
    fn drop(&mut self) {
        // SAFETY: The pointer is guaranteed to be valid because it was created from a valid `Pin<KBox>`
        // that was leaked. The data it points to is `Sync`, so we can safely access the `refcount`.
        let node_data = unsafe { &*self.node };
        if let BorrowedMode::Shared { refcount } = &**node_data {
            if refcount.fetch_sub(1, core::sync::atomic::Ordering::Release) == 1 {
                // This is the last reference. We can now reconstruct the `Pin<KBox>` and release the
                // borrow.
                // SAFETY: This is safe because we are the last owner of the shared borrow, as indicated
                // by the reference count dropping to zero. We can now take ownership of the `Pin<KBox>`
                // and release the node.
                let node = unsafe { Pin::from(KBox::from_raw(self.node as *mut BorrowNode)) };
                let _ = self.inner.shared_section.release(node);
            }
        }
    }
}

impl Deref for SharedSectionGuard {
    type Target = SharedSectionGuardInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// A guard representing an exclusive (read-write) borrow of a range in the shared section.
///
/// This guard ensures that the borrowed range is not concurrently accessed by other parts of the
/// kernel. Only one exclusive guard can exist for a given range at a time. When the guard is
/// dropped, the exclusive borrow is released.
pub(crate) struct SharedSectionGuardMut {
    inner: SharedSectionGuardInner,
    node: ManuallyDrop<Pin<KBox<BorrowNode>>>,
}

impl SharedSectionGuardMut {
    /// Writes a value of type `T` to the given offset within the borrowed range.
    pub(crate) fn write_at<T>(&self, offset: usize, value: T) -> Result {
        if offset + core::mem::size_of::<T>() > self.len() {
            return Err(EINVAL);
        }

        let base_ptr = self.as_mut_ptr()?;
        // SAFETY: We checked that the write is within the bounds of the borrowed range.
        let ptr = unsafe { base_ptr.add(offset) };

        // Make sure all writes took place before we update the memory.
        kernel::sync::barrier::smp_mb();

        // SAFETY: The pointer is guaranteed to be valid for a write of `size_of::<T>()` bytes, as
        // checked above.
        unsafe {
            core::ptr::write_volatile(ptr as *mut T, value);
        }

        Ok(())
    }

    /// Writes a value of type `T` to the start of the borrowed range.
    pub(crate) fn write<T>(&self, value: T) -> Result {
        self.write_at(0, value)
    }
}

impl Drop for SharedSectionGuardMut {
    fn drop(&mut self) {
        // SAFETY: The `ManuallyDrop` ensures we only drop this once. We are the exclusive owner of
        // the `Pin<KBox>`, so we can safely take it and release it.
        let node = unsafe { ManuallyDrop::take(&mut self.node) };
        let _ = self.inner.shared_section.release(node);
    }
}

impl Deref for SharedSectionGuardMut {
    type Target = SharedSectionGuardInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
/// An allocator for managing borrows of the shared memory section.
///
/// This allocator uses a `drm_mm` allocator to track shared and exclusive borrows of ranges within
/// the shared section. It also maintains a cache of `drm_mm` nodes to reduce allocation overhead.
#[pin_data]
pub(crate) struct SharedSection {
    section: Arc<KBox<Section>>,
    allocator: mm::Allocator<(), BorrowedMode>,
    #[pin]
    node_cache: Mutex<Vec<Pin<KBox<BorrowNode>>, Kmalloc>>,
}

impl SharedSection {
    const NODE_CACHE_SIZE: usize = 16;

    /// Creates a new `SharedSection` for the given shared section.
    fn new(section: KBox<Section>) -> Result<impl PinInit<Self>> {
        let section = Arc::new(section, GFP_KERNEL)?;
        let allocator = mm::Allocator::new(0, section.mem.size() as u64, ())?;
        Ok(pin_init!(Self {
            section,
            allocator,
            node_cache <- new_mutex!(Vec::new()),
        }))
    }

    /// Gets a `BorrowNode` from the cache or creates a new one if the cache is empty.
    fn get_node(self: &Arc<Self>, mode: BorrowedMode) -> Result<Pin<KBox<BorrowNode>>> {
        let mut cache = self.node_cache.lock();
        if let Some(mut node) = cache.pop() {
            // We're reusing a cached node. Initialize it.
            *node.as_mut().inner_mut() = mode;
            Ok(node)
        } else {
            Ok(Pin::from(self.allocator.allocate_node_data(mode)?))
        }
    }

    /// Checks that the given range is within the bounds of the shared section and returns the
    /// offset from the beginning of the section.
    fn get_offset(&self, mcu_va: u64, size: u64) -> Result<u64> {
        let shared_mem_start = u64::from(self.section.va.start);
        let shared_mem_end = u64::from(self.section.va.end);

        if mcu_va < shared_mem_start || (mcu_va + size) > shared_mem_end {
            return Err(EINVAL);
        }

        Ok(mcu_va - shared_mem_start)
    }

    /// Borrows a range of the shared section for shared (read-only) access.
    ///
    /// This will attempt to reserve the given range in the `drm_mm` allocator. If the range is
    /// already borrowed exclusively, this will fail. If the range is already borrowed for shared
    /// access, the reference count for the existing borrow will be incremented.
    pub(crate) fn borrow_bytes(
        self: &Arc<Self>,
        mcu_va: u64,
        size: u64,
    ) -> Result<SharedSectionGuard> {
        let offset = self.get_offset(mcu_va, size)?;
        let node = self.get_node(BorrowedMode::Shared { refcount: 1.into() })?;
        let result = self
            .allocator
            .reserve_node_from_node_data(node, offset, size, 0);

        let node_ptr = match result {
            Ok(node) => {
                // This is the first shared borrow. We leak the `KBox` and store a raw pointer.
                // The refcount is already 1.
                // When the last `SharedSectionGuard` is dropped, it will reconstruct the
                // `Pin<KBox>` from the raw pointer and drop it, which will free the node.

                // SAFETY: `Pin::into_inner_unchecked` is safe because we are not moving the
                // `BorrowNode` out of the `KBox`. We are just converting the `KBox` into a raw
                // pointer, which will be used to reconstruct the `KBox` later. The data
                // remains pinned at the same memory location.
                let node_ptr = KBox::into_raw(unsafe { Pin::into_inner_unchecked(node) });
                Ok(node_ptr as *const _)
            }
            Err((e, node)) => {
                // We failed to reserve the node, so cache it for later use.
                self.release(node)?;

                if e != ENOSPC {
                    return Err(e);
                }

                // The reservation failed because the range is already in use. The request
                // is for a shared allocation, so check if we can use the existing borrow.
                let mut found_node = None;

                self.allocator
                    .for_each_node_in_range(offset, offset + size, |node_data| {
                        // We don't support partially overlapping borrows, so if the conflicting
                        // borrow isn't for the exact same memory range, don't tag along.
                        if node_data.start() == offset && node_data.size() == size {
                            if let BorrowedMode::Shared { refcount } = &**node_data {
                                // Increment the reference count for the existing shared borrow and
                                // return the node.
                                refcount.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

                                // This pointer remains valid as long as the reference count remains
                                // non-zero.
                                found_node = Some(node_data as *const _);
                            }
                        }

                        // We only have to look at the first conflicting allocation.
                        ControlFlow::Break(())
                    });

                if let Some(node_ptr) = found_node {
                    Ok(node_ptr)
                } else {
                    Err(e)
                }
            }
        }?;

        Ok(SharedSectionGuard {
            inner: SharedSectionGuardInner {
                shared_section: self.clone(),
                start: offset as usize,
                end: (offset + size) as usize,
            },
            node: node_ptr,
        })
    }

    /// Borrows a range of the shared section for shared (read-only) access, with the size
    /// inferred from the generic type `T`.
    pub(crate) fn borrow<T>(self: &Arc<Self>, mcu_va: u64) -> Result<SharedSectionGuard> {
        self.borrow_bytes(mcu_va, core::mem::size_of::<T>() as u64)
    }

    /// Borrows a range of the shared section for exclusive (read-write) access.
    ///
    /// This will attempt to reserve the given range in the `drm_mm` allocator. If the range is
    /// already borrowed, this will fail.
    pub(crate) fn borrow_mut_bytes(
        self: &Arc<Self>,
        mcu_va: u64,
        size: u64,
    ) -> Result<SharedSectionGuardMut> {
        let offset = self.get_offset(mcu_va, size)?;
        let node = self.get_node(BorrowedMode::Exclusive)?;
        let result = self
            .allocator
            .reserve_node_from_node_data(node, offset, size, 0);

        let node = match result {
            Ok(node) => Ok(node),
            Err((e, node)) => {
                // We failed to reserve the node, so cache it for later use.
                self.release(node)?;
                Err(e)
            }
        }?;

        Ok(SharedSectionGuardMut {
            inner: SharedSectionGuardInner {
                shared_section: self.clone(),
                start: offset as usize,
                end: (offset + size) as usize,
            },
            node: ManuallyDrop::new(node),
        })
    }

    /// Borrows a range of the shared section for exclusive (read-write) access, with the size
    /// inferred from the generic type `T`.
    pub(crate) fn borrow_mut<T>(self: &Arc<Self>, mcu_va: u64) -> Result<SharedSectionGuardMut> {
        self.borrow_mut_bytes(mcu_va, core::mem::size_of::<T>() as u64)
    }

    /// Releases a `BorrowNode`, either by returning it to the cache or by freeing it.
    fn release(&self, mut node: Pin<KBox<BorrowNode>>) -> Result {
        self.allocator.remove_node(&mut node);
        let mut guard = self.node_cache.lock();

        if guard.len() < Self::NODE_CACHE_SIZE {
            // Reset the node so it can be reused and cache it.
            node.as_mut().reset_node();
            guard.push(node, GFP_KERNEL)?;
        }

        Ok(())
    }

    /// Borrows a region, reads a `T` from it, and releases the borrow.
    pub(crate) fn read_once<T: Copy>(self: &Arc<Self>, mcu_va: u64) -> Result<T> {
        self.borrow::<T>(mcu_va)?.read()
    }

    /// Borrows a region, writes a `T` to it, and releases the borrow.
    pub(crate) fn write_once<T: Copy>(self: &Arc<Self>, mcu_va: u64, value: T) -> Result {
        self.borrow_mut::<T>(mcu_va)?.write(value)
    }
}

/// A range into the shared section that is known to be valid.
///
/// This can be obtained via a call to [`Firmware::to_kmap_range(mcu_va, size)`].
///
/// # Invariants
///
/// `self.start..self.end` is a valid range into the shared section. This means
/// that it can safely be dereferenced by the CPU.
///
pub(crate) struct SharedSectionRange {
    shared_section: Arc<Mutex<KBox<Section>>>,
    start: usize,
    end: usize,
}

impl SharedSectionRange {
    fn len(&self) -> usize {
        self.end - self.start
    }

    fn as_mut_ptr(&self) -> Result<*mut core::ffi::c_void> {
        let mut shared_section = self.shared_section.lock();
        let vmap = shared_section.mem.vmap()?;
        let vmap = vmap.as_mut_ptr();

        // SAFETY: safe by the type invariant.
        let offset = unsafe { vmap.add(self.start) };

        Ok(offset)
    }

    fn read<T>(&self) -> Result<T> {
        if core::mem::size_of::<T>() > self.len() {
            return Err(EINVAL);
        }

        let ptr = self.as_mut_ptr()?;

        // SAFETY: we know that this pointer is aligned and valid for reads for
        // at least size_of::<Self>() bytes.
        Ok(unsafe { core::ptr::read_volatile(ptr as *const T) })
    }

    fn write<T>(&self, value: T) -> Result {
        if core::mem::size_of::<T>() > self.len() {
            return Err(EINVAL);
        }

        let ptr = self.as_mut_ptr()?;

        // SAFETY: we know that this pointer is aligned and valid for writes for
        // at least size_of::<Self>() bytes.
        unsafe {
            core::ptr::write_volatile(ptr as *mut T, value);
        }

        Ok(())
    }
}

/// An offset into the shared section that is known to point to the request field.
///
/// It is more convenient to use this type than reading or writing the memory
/// areas directly since it implements the XOR logic to handle the communication
/// of requests and acknowledgements.
pub(crate) struct RequestField {
    req: SharedSectionRange,
    ack: SharedSectionRange,
}

impl RequestField {
    fn new(shared_section: &SharedSectionRange, req_offset: usize, ack_offset: usize) -> Self {
        let req = SharedSectionRange {
            shared_section: shared_section.shared_section.clone(),
            start: shared_section.start + req_offset,
            end: shared_section.start + req_offset + core::mem::size_of::<u32>(),
        };

        let ack = SharedSectionRange {
            shared_section: shared_section.shared_section.clone(),
            start: shared_section.start + ack_offset,
            end: shared_section.start + ack_offset + core::mem::size_of::<u32>(),
        };

        Self { req, ack }
    }

    /// Toggle acknowledge bits to send an event to the FW
    ///
    /// The Host -> FW event/message passing was designed to be lockless, with each side of
    /// the channel having its writeable section. Events are signaled as a difference between
    /// the host and FW side in the req/ack registers (when a bit differs, there's an event
    /// pending, when they are the same, nothing needs attention).
    ///
    /// This helper allows one to update the req register based on the current value of the
    /// ack register managed by the FW. Toggling a specific bit will flag an event. In order
    /// for events to be re-evaluated, the interface doorbell needs to be rung.
    pub(crate) fn toggle_reqs(&self, reqs: u32) -> Result {
        let cur_req_val = self.req.read::<u32>()?;
        let ack_val = self.ack.read::<u32>()?;
        let new_val = ((ack_val ^ reqs) & reqs) | (cur_req_val & !reqs);

        self.req.write::<u32>(new_val)
    }

    /// Update bits to reflect a configuration change.
    ///
    /// Not all bits work in a toggle fashion. Some bits are used to configure the FW
    /// and need to be set to 0 or 1. This function bypasses the toggle logic and
    /// directly sets the bits in the req register.
    pub(crate) fn update_reqs(&self, val: u32, reqs: u32) -> Result {
        let cur_req_val = self.req.read::<u32>()?;
        let new_val = (cur_req_val & !reqs) | (val & reqs);

        self.req.write::<u32>(new_val)
    }

    /// Returns whether any requests are pending for `reqs`.
    ///
    /// Requests are pending when the value of the given bit in the req differs
    /// from the one in ack.
    pub(crate) fn pending_reqs(&self, reqs: u32) -> Result<bool> {
        let cur_req_val = self.req.read::<u32>()? & reqs;
        let cur_ack_val = self.ack.read::<u32>()? & reqs;

        Ok((cur_req_val ^ cur_ack_val) != 0)
    }

    /// Waits for the given requests to be acknowledged.
    ///
    /// This will sleep for at most `timeout_ms` milliseconds.
    pub(crate) fn wait_acks(&self, reqs: u32, events_wait: &Wait, timeout_ms: u32) -> Result {
        events_wait.wait_interruptible_timeout(timeout_ms, |()| {
            if !self.pending_reqs(reqs)? {
                Ok(WaitResult::Ok)
            } else {
                Ok(WaitResult::Retry)
            }
        })
    }
}

/// Our interface to the MCU.
#[pin_data]
pub(crate) struct Firmware {
    #[pin]
    /// The sections read from the firmware binary. These sections are loaded
    /// into GPU memory via BOs.
    sections: Mutex<KVec<KBox<Section>>>,

    /// The global FW interface.
    #[pin]
    global_iface: Mutex<GlobalInterface>,

    /// The VM where we load the firmware into. This VM is always bound to AS0.
    vm: Arc<Mutex<Vm>>,

    /// A condvar representing a wait on a firmware event.
    ///
    /// We notify all waiters on every interrupt.
    #[pin]
    event_wait: Arc<Wait>,
}

impl Firmware {
    pub(crate) fn init(
        tdev: &TyrDevice,
        pdev: &platform::Device,
        gpu_info: &GpuInfo,
        mmu: Pin<&Mutex<Mmu>>,
        iomem: Arc<Devres<IoMem>>,
        event_wait: Arc<Wait>,
    ) -> Result<impl PinInit<Self>> {
        let vm = {
            let auto_kernel_va = CSF_MCU_SHARED_REGION_START as u64
                ..CSF_MCU_SHARED_REGION_START as u64 + CSF_MCU_SHARED_REGION_SIZE as u64;

            let mut mmu = mmu.lock();

            // Create the FW VM. This will be used to communicate between the CPU
            // and the MCU.
            let vm = mmu.create_vm(
                tdev,
                pdev,
                gpu_info,
                true,
                VmLayout {
                    user: 0..0,
                    kernel: 0..4 * SZ_1G as u64,
                },
                auto_kernel_va,
                iomem.clone(),
            )?;

            mmu.bind_vm(vm.clone(), gpu_info, &iomem)?;

            vm
        };

        let mut sections = Self::read_sections(tdev, iomem.clone(), gpu_info, vm.clone())?;

        let shared_section = match sections.iter().position(|section| section.is_shared()) {
            Some(index) => sections.remove(index)?,
            None => {
                dev_err!(tdev.as_ref(), "No shared section found in firmware");
                return Err(EINVAL);
            }
        };

        let global_iface = GlobalInterface::new(shared_section, iomem.clone(), event_wait.clone())?;

        Ok(pin_init!(Self {
            sections <- new_mutex!(sections),
            global_iface <- new_mutex!(global_iface),
            vm,
            event_wait,
        }))
    }

    pub(crate) fn alloc_queue_mem(&self, tdev: &TyrDevice) -> Result<ObjectRef> {
        let flags =
            map_flags::Flags::from(map_flags::NOEXEC) | map_flags::Flags::from(map_flags::UNCACHED);
        let va = KernelVaPlacement::Auto { size: SZ_8K };

        self.vm
            .with_lock_taken(|vm| gem::new_kernel_object(tdev, tdev.iomem.clone(), vm, va, flags))
    }

    pub(crate) fn alloc_suspend_buf(
        &self,
        tdev: &TyrDevice,
        suspend_size: usize,
    ) -> Result<ObjectRef> {
        let flags = map_flags::Flags::from(map_flags::NOEXEC);
        let va = KernelVaPlacement::Auto { size: suspend_size };

        self.vm
            .with_lock_taken(|vm| gem::new_kernel_object(tdev, tdev.iomem.clone(), vm, va, flags))
    }

    /// Provide access to the global interface, but as a closure so we can at
    /// least try to reduce the scope of the lock in as much as possible.
    pub(crate) fn with_locked_global_iface<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut GlobalInterface) -> Result<R>,
    {
        let mut global_iface = self.global_iface.lock();
        f(&mut global_iface)
    }
}

macro_rules! impl_shared_section_read {
    ($type:ty) => {
        impl $type {
            /// Reads the control interface from the given pointer.
            ///
            /// Note that the area pointed to by `ptr` is shared with the MCU, so we
            /// cannot simply parse it or cast it to &Self.
            ///
            /// Merely taking a reference to it would be UB, as the MCU can change the
            /// underlying memory at any time, as it is a core running its own code.
            pub(super) fn read(range: &SharedSectionRange) -> Result<Self> {
                // Make sure all writes took place before we read the memory.
                kernel::sync::barrier::smp_mb();

                let ptr = range.as_mut_ptr()?;
                // SAFETY: we know that this pointer is aligned and valid for reads for
                // at least size_of::<Self>() bytes.
                Ok(unsafe { core::ptr::read_volatile(ptr as *const Self) })
            }
        }
    };
}
pub(crate) use impl_shared_section_read;

macro_rules! impl_shared_section_write {
    ($type:ty) => {
        impl $type {
            /// Writes the control interface to the given pointer.
            ///
            /// Note that the area pointed to by `ptr` is shared with the MCU, so we
            /// cannot simply parse it or cast it to &mut Self.
            ///
            /// Merely taking a reference to it would be UB, as the MCU can change the
            /// underlying memory at any time, as it is a core running its own code.
            pub(super) fn write(self, range: &mut SharedSectionRange) -> Result<()> {
                // Make sure all writes took place before we update the memory.
                kernel::sync::barrier::smp_mb();

                let ptr = range.as_mut_ptr()?;
                // SAFETY: we know that this pointer is aligned and valid for writes for
                // at least size_of::<Self>() bytes.
                unsafe {
                    core::ptr::write_volatile(ptr as *mut Self, self);
                }

                Ok(())
            }
        }
    };
}
pub(crate) use impl_shared_section_write;

macro_rules! impl_shared_section_rw {
    ($type:ty) => {
        crate::fw::impl_shared_section_read!($type);
        crate::fw::impl_shared_section_write!($type);
    };
}
pub(crate) use impl_shared_section_rw;

/// Standardizes the interface to the shared section entries.
///
/// This helps to ensure that the same names are used consistently across the
/// different sections, and that no part of the implementation is forgotten.
pub(crate) trait SharedSectionEntry {
    /// The type of the area written by the CPU in order to set CSF control
    /// parameters.
    type Control;

    /// The type of the area written by the CPU as input to CSF.
    type Input;

    /// The type of the area written by CSF.
    type Output;

    fn read_control(&self) -> Result<Self::Control>;
    fn write_control(&mut self, control: Self::Control) -> Result;

    fn read_input(&self) -> Result<Self::Input>;
    fn write_input(&mut self, input: Self::Input) -> Result;

    fn read_output(&self) -> Result<Self::Output>;

    fn input_request(&self) -> Result<RequestField>;

    fn doorbell_request(&self) -> Result<RequestField> {
        pr_err!("Doorbell request not supported for this interface");
        Err(ENOTSUPP)
    }

    fn interrupt_ack(&self) -> Result<RequestField> {
        pr_err!("Interrupt ack not supported for this interface");
        Err(ENOTSUPP)
    }
}

/// Add modinfo to the module file such as firmware files needed
pub(crate) struct ModInfoBuilder<const N: usize>(firmware::ModInfoBuilder<N>);

impl<const N: usize> ModInfoBuilder<N> {
    /// A list of firmware files + paths needed
    const FILES: &'static [&'static str] = &[
        "arm/mali/arch10.8/mali_csffw.bin",
        // Add more files here as needed in future
    ];

    /// Create the builder that generated the info at compile-time
    pub(crate) const fn create(
        module_name: &'static kernel::str::CStr,
    ) -> kernel::firmware::ModInfoBuilder<N> {
        let mut bld = kernel::firmware::ModInfoBuilder::new(module_name);
        // Walk over files listed above and add them to modinfo
        let mut i = 0;
        while i < Self::FILES.len() {
            bld = bld.new_entry().push(Self::FILES[i]);
            i += 1;
        }
        bld
    }
}
