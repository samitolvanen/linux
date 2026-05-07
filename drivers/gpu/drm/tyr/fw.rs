// SPDX-License-Identifier: GPL-2.0 or MIT

//! Firmware loading and management for Mali CSF GPU.
//!
//! This module handles loading the Mali GPU firmware binary, parsing it into sections,
//! and mapping those sections into the MCU's virtual address space. Each firmware section
//! has specific properties (read/write/execute permissions, cache modes) and must be loaded
//! at specific virtual addresses expected by the MCU.
//!
//! See [`Firmware`] for the main firmware management interface and [`Section`] for
//! individual firmware sections.
//!
//! [`Firmware`]: crate::fw::Firmware
//! [`Section`]: crate::fw::Section

use kernel::{
    bits::genmask_u32,
    devres::Devres,
    drm::{
        gem::BaseObject,
        Uninit, //
    },
    firmware,
    impl_flags,
    io::{
        poll,
        Io, //
    },
    new_mutex,
    platform,
    prelude::*,
    sizes::SZ_8K,
    str::CString,
    sync::{
        Arc,
        ArcBorrow,
        Mutex, //
    },
    time,
    types::ARef, //
};

use global::GlobalInterface;

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice, //
    },
    fw::parser::{
        FwParser,
        ParsedSection, //
    },
    gem,
    gem::{
        KernelBo,
        KernelBoVaAlloc,
        MappedBo, //
    },
    mmu::Mmu,
    new_wait,
    regs::gpu_control::{
        McuControlMode,
        McuStatus,
        GPU_ID,
        MCU_CONTROL,
        MCU_STATUS, //
    },
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    },
    wait::Wait,
    wait::WaitResult, //
};

pub(crate) mod global;
pub(crate) mod irq;
mod parser;

impl_flags!(
    #[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
    pub(super) struct SectionFlags(u32);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum SectionFlag {
        Read = 1 << 0,
        Write = 1 << 1,
        Exec = 1 << 2,
        CacheModeNone = 0 << 3,
        CacheModeCached = 1 << 3,
        CacheModeUncachedCoherent = 2 << 3,
        CacheModeCachedCoherent = 3 << 3,
        Prot = 1 << 5,
        Shared = 1 << 30,
        Zero = 1 << 31,
    }
);

pub(super) const CACHE_MODE_MASK: SectionFlags = SectionFlags(genmask_u32(3..=4));

pub(super) const CSF_MCU_SHARED_REGION_START: u32 = 0x04000000;

impl SectionFlags {
    fn cache_mode(&self) -> SectionFlags {
        *self & CACHE_MODE_MASK
    }
}

impl TryFrom<u32> for SectionFlags {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let valid_flags = SectionFlags::from(SectionFlag::Read)
            | SectionFlags::from(SectionFlag::Write)
            | SectionFlags::from(SectionFlag::Exec)
            | CACHE_MODE_MASK
            | SectionFlags::from(SectionFlag::Prot)
            | SectionFlags::from(SectionFlag::Shared)
            | SectionFlags::from(SectionFlag::Zero);

        if value & valid_flags.0 != value {
            Err(EINVAL)
        } else {
            Ok(Self(value))
        }
    }
}

/// A parsed section of the firmware binary.
struct Section {
    // Raw firmware section data for reset purposes
    #[expect(dead_code)]
    data: KVec<u8>,

    // Keep the BO backing this firmware section so that both the
    // GPU mapping and CPU mapping remain valid until the Section is dropped.
    #[expect(dead_code)]
    mem: gem::KernelBo,

    /// The VA range for this section in MCU address space.
    va: core::ops::Range<u64>,

    /// The flags for this section.
    flags: SectionFlags,
}

impl Section {
    /// Whether this is the shared section used for MCU <-> host communication.
    fn is_shared(&self) -> bool {
        self.va.start == CSF_MCU_SHARED_REGION_START as u64
            && self.flags.contains(SectionFlag::Shared)
    }
}

pub(super) const CSF_MCU_SHARED_REGION_SIZE: u32 = 0x04000000;

/// Backing storage for the shared section, used by the global interface.
///
/// This wraps the GEM buffer object and VA range for CPU-side access to
/// the shared section memory where MCU <-> host communication happens.
pub(crate) struct SharedSectionBacking {
    /// A reference to the shared section used for CPU access (vmap).
    mem: Arc<MappedBo>,
    /// The MCU VA range for the shared section.
    va: core::ops::Range<u64>,
}

impl SharedSectionBacking {
    fn new(mem: Arc<MappedBo>, va: core::ops::Range<u64>) -> Self {
        Self { mem, va }
    }

    fn va_start(&self) -> u64 {
        self.va.start
    }

    fn va_end(&self) -> u64 {
        self.va.end
    }

    fn size(&self) -> usize {
        self.mem.size()
    }

    fn vmap_addr(&self) -> Result<*mut u8> {
        let vmap = self.mem.vmap();
        Ok(vmap.addr() as *mut u8)
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
pub(crate) struct SharedSectionRange {
    shared_section: Arc<Mutex<SharedSectionBacking>>,
    start: usize,
    end: usize,
}

impl SharedSectionRange {
    fn len(&self) -> usize {
        self.end - self.start
    }

    fn as_mut_ptr(&self) -> Result<*mut core::ffi::c_void> {
        let shared_section = self.shared_section.lock();
        let vmap = shared_section.vmap_addr()?;

        // SAFETY: safe by the type invariant.
        let offset = unsafe { vmap.add(self.start) };

        Ok(offset as *mut core::ffi::c_void)
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
    fn new(
        req_section: &SharedSectionRange,
        req_offset: usize,
        ack_section: &SharedSectionRange,
        ack_offset: usize,
    ) -> Self {
        let req = SharedSectionRange {
            shared_section: req_section.shared_section.clone(),
            start: req_section.start + req_offset,
            end: req_section.start + req_offset + core::mem::size_of::<u32>(),
        };

        let ack = SharedSectionRange {
            shared_section: ack_section.shared_section.clone(),
            start: ack_section.start + ack_offset,
            end: ack_section.start + ack_offset + core::mem::size_of::<u32>(),
        };

        Self { req, ack }
    }

    /// Toggle acknowledge bits to send an event to the FW
    pub(crate) fn toggle_reqs(&self, reqs: u32) -> Result {
        let cur_req_val = self.req.read::<u32>()?;
        let ack_val = self.ack.read::<u32>()?;
        let new_val = ((ack_val ^ reqs) & reqs) | (cur_req_val & !reqs);

        self.req.write::<u32>(new_val)
    }

    /// Update bits to reflect a configuration change.
    pub(crate) fn update_reqs(&self, val: u32, reqs: u32) -> Result {
        let cur_req_val = self.req.read::<u32>()?;
        let new_val = (cur_req_val & !reqs) | (val & reqs);

        self.req.write::<u32>(new_val)
    }

    /// Returns whether any requests are pending for `reqs`.
    pub(crate) fn pending_reqs(&self, reqs: u32) -> Result<bool> {
        let cur_req_val = self.req.read::<u32>()? & reqs;
        let cur_ack_val = self.ack.read::<u32>()? & reqs;

        Ok((cur_req_val ^ cur_ack_val) != 0)
    }

    /// Waits for the given requests to be acknowledged.
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

/// Standardizes the interface to the shared section entries.
pub(crate) trait SharedSectionEntry {
    type Control;
    type Input;
    type Output;

    fn read_control(&self) -> Result<Self::Control>;
    #[expect(dead_code)]
    fn write_control(&mut self, control: Self::Control) -> Result;

    fn read_input(&self) -> Result<Self::Input>;
    fn write_input(&mut self, input: Self::Input) -> Result;

    fn read_output(&self) -> Result<Self::Output>;

    fn input_request(&self) -> Result<RequestField>;

    fn doorbell_request(&self) -> Result<RequestField> {
        pr_err!("Doorbell request not supported for this interface");
        Err(ENOTSUPP)
    }

    #[expect(dead_code)]
    fn interrupt_ack(&self) -> Result<RequestField> {
        pr_err!("Interrupt ack not supported for this interface");
        Err(ENOTSUPP)
    }
}

macro_rules! impl_shared_section_read {
    ($type:ty) => {
        impl $type {
            pub(super) fn read(range: &SharedSectionRange) -> Result<Self> {
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
            #[allow(dead_code)]
            pub(super) fn write(self, range: &mut SharedSectionRange) -> Result<()> {
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
/// Loaded firmware with sections mapped into MCU VM.
#[pin_data(PinnedDrop)]
pub(crate) struct Firmware {
    /// Platform device reference (needed to access the MCU JOB_IRQ registers).
    pdev: ARef<platform::Device>,

    /// Iomem need to access registers.
    iomem: Arc<Devres<IoMem>>,

    /// MCU VM.
    vm: Arc<Vm>,

    /// List of firmware sections.
    sections: KVec<Section>,

    /// The global FW interface.
    #[pin]
    global_iface: Mutex<Option<GlobalInterface>>,

    /// A condvar representing a wait on a firmware event.
    pub(crate) event_wait: Arc<Wait>,
}

#[pinned_drop]
impl PinnedDrop for Firmware {
    fn drop(self: Pin<&mut Self>) {
        // AS slots retain a VM ref, we need to kill the circular ref manually.
        self.vm.kill();
    }
}

impl Firmware {
    fn init_section_mem(mem: &mut KernelBo, data: &KVec<u8>) -> Result {
        if data.is_empty() {
            return Ok(());
        }

        let vmap = mem.bo.vmap::<0>()?;
        let size = mem.bo.size();

        if data.len() > size {
            pr_err!("fw section {} bigger than BO {}\n", data.len(), size);
            return Err(EINVAL);
        }

        for (i, &byte) in data.iter().enumerate() {
            vmap.try_write8(byte, i)?;
        }

        Ok(())
    }

    fn request(
        pdev: &platform::Device,
        iomem: &Arc<Devres<IoMem>>,
        ddev: &TyrDrmDevice<Uninit>,
    ) -> Result<kernel::firmware::Firmware> {
        // SAFETY: pdev is a bound device.
        let dev = unsafe { pdev.as_ref().as_bound() };
        let io = (*iomem).access(dev)?;
        let gpu_id = io.read(GPU_ID);

        let path = CString::try_from_fmt(fmt!(
            "arm/mali/arch{}.{}/mali_csffw.bin",
            gpu_id.arch_major().get(),
            gpu_id.arch_minor().get()
        ))?;

        kernel::firmware::Firmware::request(&path, ddev.as_ref())
    }

    fn load(
        pdev: &platform::Device,
        iomem: &Arc<Devres<IoMem>>,
        ddev: &TyrDrmDevice<Uninit>,
    ) -> Result<(kernel::firmware::Firmware, KVec<ParsedSection>)> {
        let fw = Self::request(pdev, iomem, ddev)?;
        let mut parser = FwParser::new(fw.data());

        let parsed_sections = parser.parse()?;

        Ok((fw, parsed_sections))
    }

    /// Load firmware and map sections into MCU VM.
    pub(crate) fn new(
        pdev: &platform::Device,
        iomem: Arc<Devres<IoMem>>,
        ddev: &TyrDrmDevice<Uninit>,
        mmu: ArcBorrow<'_, Mmu>,
    ) -> Result<Arc<Firmware>> {
        // Set the auto-VA range to the MCU shared region.  FW sections
        // with explicit VAs are reserved below to prevent collisions.
        let fw_kernel_va_start = CSF_MCU_SHARED_REGION_START as u64;
        let fw_kernel_va_end = (CSF_MCU_SHARED_REGION_START + CSF_MCU_SHARED_REGION_SIZE) as u64;

        let vm = Vm::new(
            pdev,
            ddev,
            mmu,
            iomem.as_arc_borrow(),
            fw_kernel_va_start..fw_kernel_va_end,
        )?;

        let (fw, parsed_sections) = Self::load(pdev, &iomem, ddev)?;

        vm.activate()?;

        let mut sections = KVec::new();
        let mut shared_section_backing = None;

        for parsed in parsed_sections {
            let size = (parsed.va.end - parsed.va.start) as usize;
            let va = u64::from(parsed.va.start);
            let va_end = u64::from(parsed.va.end);

            let mut mem = KernelBo::new(
                ddev,
                vm.as_arc_borrow(),
                size.try_into().unwrap(),
                KernelBoVaAlloc::Explicit(va),
                parsed.vm_map_flags,
            )?;

            let section_start = parsed.data_range.start as usize;
            let section_end = parsed.data_range.end as usize;
            let mut data = KVec::new();

            // Ensure that the firmware slice is not out of bounds.
            let fw_data = fw.data();
            let bytes = fw_data.get(section_start..section_end).ok_or(EINVAL)?;
            data.extend_from_slice(bytes, GFP_KERNEL)?;

            Self::init_section_mem(&mut mem, &data)?;

            // Reserve FW section VA ranges to prevent auto-allocation collisions.
            if va >= fw_kernel_va_start && va_end <= fw_kernel_va_end {
                vm.reserve_kernel_range(va, va_end)?;
            }

            let section_flags = parsed.section_flags;
            let is_shared = va == CSF_MCU_SHARED_REGION_START as u64
                && section_flags.contains(SectionFlag::Shared);

            if is_shared {
                let shared_obj = MappedBo::new(&mem.bo)?;
                shared_section_backing = Some(SharedSectionBacking::new(shared_obj, va..va_end));
            }

            sections.push(
                Section {
                    data,
                    mem,
                    va: va..va_end,
                    flags: section_flags,
                },
                GFP_KERNEL,
            )?;
        }

        let event_wait = new_wait!()?;

        // Create the global interface from the shared section if found.
        let global_iface = match shared_section_backing {
            Some(backing) => {
                let glb = GlobalInterface::new(backing, iomem.clone(), event_wait.clone())?;
                Some(glb)
            }
            None => {
                pr_err!("Firmware shared section not found, global interface unavailable\n");
                None
            }
        };

        let firmware = Arc::pin_init(
            try_pin_init!(Firmware {
                    pdev: pdev.into(),
                    iomem,
                    vm,
                    sections,
                    global_iface <- new_mutex!(global_iface),
                    event_wait,
            }),
            GFP_KERNEL,
        )?;

        Ok(firmware)
    }

    pub(crate) fn boot(&self) -> Result {
        // SAFETY: Boot is currently only called in the probe path, so we're sure we have a bound
        // device.
        let dev = unsafe { self.pdev.as_ref().as_bound() };
        let io = (self.iomem).access(dev)?;
        io.write_reg(MCU_CONTROL::zeroed().with_req(McuControlMode::Auto));

        if let Err(e) = poll::read_poll_timeout(
            || Ok(io.read(MCU_STATUS)),
            |status| status.value() == McuStatus::Enabled,
            time::Delta::from_millis(1),
            time::Delta::from_millis(100),
        ) {
            let status = io.read(MCU_STATUS);
            pr_err!("MCU failed to boot, status: {:?}", status.value());
            return Err(e);
        }
        Ok(())
    }

    /// Allocate a CS ring-buffer interface in the FW VM (AS0).
    pub(crate) fn alloc_queue_mem(&self, tdev: &TyrDrmDevice) -> Result<Arc<MappedBo>> {
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        gem::new_kernel_object(tdev, &self.vm, SZ_8K, flags)
    }

    /// Allocate a suspend buffer in the FW VM (AS0).
    pub(crate) fn alloc_suspend_buf(
        &self,
        tdev: &TyrDrmDevice,
        suspend_size: usize,
    ) -> Result<Arc<MappedBo>> {
        let flags = VmMapFlags::from(VmFlag::Noexec);
        gem::new_kernel_object(tdev, &self.vm, suspend_size, flags)
    }

    /// Provide access to the global interface, but as a closure so we can at
    /// least try to reduce the scope of the lock in as much as possible.
    pub(crate) fn with_locked_global_iface<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut GlobalInterface) -> Result<R>,
    {
        let mut guard = self.global_iface.lock();
        let global_iface = (&mut *guard).as_mut().ok_or(EINVAL)?;
        f(global_iface)
    }

    /// Enable the global interface after the MCU has booted.
    ///
    /// This reads the control structures from the shared section, sets up CSG
    /// slots, configures timers, and enables the global interface for use.
    pub(crate) fn enable_global_iface(
        &self,
        tdev: &TyrDrmDevice,
        gpu_info: &crate::gpu::GpuInfo,
        core_clk: &kernel::clk::Clk,
    ) -> Result {
        self.with_locked_global_iface(|glb| glb.enable(tdev, gpu_info, core_clk))
    }
}

/// Add modinfo to the module file such as firmware files needed
pub(crate) struct ModInfoBuilder<const N: usize>(firmware::ModInfoBuilder<N>);

impl<const N: usize> ModInfoBuilder<N> {
    const FILES: &'static [&'static str] = &["arm/mali/arch10.8/mali_csffw.bin"];

    pub(crate) const fn create(
        module_name: &'static kernel::str::CStr,
    ) -> kernel::firmware::ModInfoBuilder<N> {
        let mut bld = kernel::firmware::ModInfoBuilder::new(module_name);
        let mut i = 0;
        while i < Self::FILES.len() {
            bld = bld.new_entry().push(Self::FILES[i]);
            i += 1;
        }
        bld
    }
}
