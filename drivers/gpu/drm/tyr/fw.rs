// SPDX-License-Identifier: GPL-2.0 or MIT

use global::GlobalInterface;
use kernel::bindings::SZ_1G;
use kernel::devres::Devres;
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
use crate::mmu::Mmu;
use crate::wait::Wait;
use crate::wait::WaitResult;

const CSF_MCU_SHARED_REGION_START: u32 = 0x04000000;
const CSF_MCU_SHARED_REGION_SIZE: u32 = 0x04000000;

pub(crate) mod global;
pub(crate) mod irq;
mod parse;

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
            )?;

            mmu.bind_vm(vm.clone(), gpu_info, &iomem)?;

            vm
        };

        let mut sections = Self::read_sections(tdev, iomem.clone(), gpu_info, vm.clone())?;

        let shared_section = match sections.iter().position(|section| {
                section.is_shared()
        }) {
            Some(index) => sections.remove(index)?,
            None        => {
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

        gem::new_kernel_object(tdev, tdev.iomem.clone(), self.vm.clone(), va, flags)
    }

    pub(crate) fn alloc_suspend_buf(
        &self,
        tdev: &TyrDevice,
        suspend_size: usize,
    ) -> Result<ObjectRef> {
        let flags = map_flags::Flags::from(map_flags::NOEXEC);
        let va = KernelVaPlacement::Auto { size: suspend_size };

        gem::new_kernel_object(tdev, tdev.iomem.clone(), self.vm.clone(), va, flags)
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

    fn doobell_request(&self) -> Result<RequestField> {
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
    pub (crate) const fn create(module_name: &'static kernel::str::CStr)
        -> kernel::firmware::ModInfoBuilder<N> {
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
