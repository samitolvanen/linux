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
    clk::Clk,
    device::{
        Bound,
        Device, //
    },
    drm::{
        gem::BaseObject, //
    },
    io::{
        mem::DevresIoMem,
        poll,
        Io, //
    },
    new_mutex,
    num::Bounded,
    platform,
    prelude::*,
    register,
    sizes::{
        SZ_2M,
        SZ_8K, //
    },
    str::CString,
    sync::{
        atomic::{
            Acquire,
            Atomic, //
        },
        Arc,
        ArcBorrow,
        Mutex, //
    },
    time, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice,
        TyrRegisters, //
    },
    fw::{
        global::GlobalInterface,
        parser::{
            FwParser,
            ParsedSection, //
        }, //
    },
    gem,
    gem::{
        KernelBo,
        KernelBoVaAlloc, //
    },
    gpu::GpuInfo,

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
    wait::{
        Wait,
        WaitResult, //
    }, //
};

pub(crate) mod global;
mod interfaces;
pub(crate) mod irq;
mod parser;
mod region;

/// Maximum number of CSG interfaces supported by hardware.
const MAX_CSG: usize = 16;

/// Maximum number of CS interfaces supported by hardware.
const MAX_CS: usize = 16;

/// MCU virtual address where the CSF shared memory region starts.
///
/// This region contains the firmware interface structures for communication between
/// the CPU driver and MCU firmware, including the GLB_CONTROL_BLOCK at this base address.
/// The firmware binary contains a section marked to be loaded at this address.
pub(super) const CSF_MCU_SHARED_REGION_START: u32 = 0x04000000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum CacheMode {
    None = 0,
    Cached = 1,
    UncachedCoherent = 2,
    CachedCoherent = 3,
}

impl From<Bounded<u32, 2>> for CacheMode {
    fn from(value: Bounded<u32, 2>) -> Self {
        match value.get() {
            0 => Self::None,
            1 => Self::Cached,
            2 => Self::UncachedCoherent,
            3 => Self::CachedCoherent,
            _ => unreachable!(),
        }
    }
}

impl From<CacheMode> for Bounded<u32, 2> {
    fn from(value: CacheMode) -> Self {
        Bounded::try_new(value as u32).unwrap()
    }
}

register! {
    base: TyrRegisters;

     #[allow(non_upper_case_globals)]
    pub(super) SectionFlags(u32) @ 0x0 {
        0:0 read => bool;
        1:1 write => bool;
        2:2 exec => bool;
        4:3 cache_mode => CacheMode;
        5:5 prot => bool;
        30:30 shared => bool;
        31:31 zero => bool;
    }
}

impl SectionFlags {
    const VALID_MASK: u32 = Self::READ_MASK
        | Self::WRITE_MASK
        | Self::EXEC_MASK
        | Self::CACHE_MODE_MASK
        | Self::PROT_MASK
        | Self::SHARED_MASK
        | Self::ZERO_MASK;

    fn try_from_fw(value: u32) -> Result<Self> {
        if value & !Self::VALID_MASK != 0 {
            Err(EINVAL)
        } else {
            Ok(Self::from_raw(value))
        }
    }
}

/// A parsed section of the firmware binary.
pub(crate) struct Section {
    // Raw firmware section data for reset purposes
    #[expect(dead_code)]
    data: KVec<u8>,

    // Keep the BO backing this firmware section so that both the
    // GPU mapping and CPU mapping remain valid until the Section is dropped.
    mem: gem::KernelBo,
}

/// Loaded firmware with sections mapped into MCU VM.
pub(crate) struct Firmware<'drm> {
    /// The bound device the firmware sections are mapped for.
    dev: &'drm platform::Device<Bound>,

    /// Device-managed handle to the GPU MMIO register mapping, held so
    /// `Drop` can stop the MCU.
    iomem: Arc<DevresIoMem<SZ_2M>>,

    /// MCU VM.
    vm: Arc<Vm>,

    /// List of firmware sections.
    sections: KVec<Section>,

    /// A condvar representing a wait on a firmware event.
    pub(crate) ready_wait: Arc<Wait>,

    /// Latched to `true` by the IRQ handler when the firmware signals readiness via the GLB bit.
    pub(crate) fw_ready: Arc<Atomic<bool>>,

    /// The global FW interface.
    global_iface: Pin<KBox<Mutex<GlobalInterface>>>,
}

impl<'drm> Drop for Firmware<'drm> {
    fn drop(&mut self) {
        // Stop the MCU before releasing its firmware mappings and memory.
        if let Ok(io) = self.iomem.access(self.dev.as_ref()) {
            let _ = self.stop(io);
        }

        // AS slots retain a VM ref, we need to kill the circular ref manually.
        self.vm.kill();
    }
}

impl<'drm> Firmware<'drm> {
    fn init_section_mem(dev: &Device, mem: &mut KernelBo, data: &KVec<u8>) -> Result {
        if data.is_empty() {
            return Ok(());
        }

        let vmap = mem.bo().vmap::<0>()?;
        let size = mem.bo().size();

        if data.len() > size {
            dev_err!(dev, "fw section {} bigger than BO {}", data.len(), size);
            return Err(EINVAL);
        }

        for (i, &byte) in data.iter().enumerate() {
            vmap.try_write8(byte, i)?;
        }

        Ok(())
    }

    fn request(ddev: &TyrDrmDevice, gpu_info: &GpuInfo) -> Result<kernel::firmware::Firmware> {
        let gpu_id = GPU_ID::from_raw(gpu_info.gpu_id);

        let path = CString::try_from_fmt(fmt!(
            "arm/mali/arch{}.{}/mali_csffw.bin",
            gpu_id.arch_major().get(),
            gpu_id.arch_minor().get()
        ))?;

        kernel::firmware::Firmware::request(&path, ddev.as_ref().as_ref())
    }

    fn load(
        dev: &Device,
        ddev: &TyrDrmDevice,
        gpu_info: &GpuInfo,
    ) -> Result<(kernel::firmware::Firmware, KVec<ParsedSection>)> {
        let fw = Self::request(ddev, gpu_info)?;
        let mut parser = FwParser::new(dev, fw.data());

        let parsed_sections = parser.parse()?;

        Ok((fw, parsed_sections))
    }

    /// Load firmware and map sections into MCU VM.
    pub(crate) fn new(
        pdev: &'drm platform::Device<Bound>,
        iomem: Arc<DevresIoMem<SZ_2M>>,
        ddev: &TyrDrmDevice,
        mmu: ArcBorrow<'_, Mmu>,
        gpu_info: &GpuInfo,
    ) -> Result<Firmware<'drm>> {
        let dev = pdev.as_ref();
        let vm = Vm::new(pdev, ddev, mmu, gpu_info)?;
        vm.activate()?;

        let result = (|| {
            let (fw, parsed_sections) = Self::load(dev, ddev, gpu_info)?;
            let mut sections = KVec::new();
            for parsed in parsed_sections {
                let size = u64::from(parsed.va.end.checked_sub(parsed.va.start).ok_or(EINVAL)?);

                let va = u64::from(parsed.va.start);

                let mut mem = KernelBo::new(
                    dev,
                    ddev,
                    vm.clone(),
                    size,
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

                Self::init_section_mem(dev, &mut mem, &data)?;

                sections.push(Section { data, mem }, GFP_KERNEL)?;
            }

            Ok(Firmware {
                dev: pdev,
                iomem,
                vm: vm.clone(),
                sections,
                ready_wait: new_wait!()?,
                fw_ready: Arc::new(Atomic::new(false), GFP_KERNEL)?,
                global_iface: KBox::pin_init(new_mutex!(GlobalInterface::new()?), GFP_KERNEL)?,
            })
        })();

        if result.is_err() {
            vm.kill();
        }

        result
    }

    /// Get the shared memory section containing firmware interface structures.
    pub(crate) fn shared_section(&self) -> Result<&Section> {
        self.sections
            .iter()
            .find(|section| section.mem.va_range().start == u64::from(CSF_MCU_SHARED_REGION_START))
            .ok_or_else(|| {
                dev_err!(
                    self.dev,
                    "CSF shared section not found at 0x{:08x}",
                    CSF_MCU_SHARED_REGION_START
                );
                EINVAL
            })
    }

    pub(crate) fn boot(&self, io: &IoMem<'_>) -> Result {
        io.write_reg(MCU_CONTROL::zeroed().with_req(McuControlMode::Auto));

        if let Err(e) = poll::read_poll_timeout(
            || Ok(io.read(MCU_STATUS)),
            |status| status.value() == McuStatus::Enabled,
            time::Delta::from_millis(1),
            time::Delta::from_millis(100),
        ) {
            let status = io.read(MCU_STATUS);
            dev_err!(self.dev, "MCU failed to boot, status: {:?}", status.value());
            return Err(e);
        }

        Ok(())
    }

    fn stop(&self, io: &IoMem<'_>) -> Result {
        io.write_reg(MCU_CONTROL::zeroed().with_req(McuControlMode::Disable));

        if let Err(e) = poll::read_poll_timeout(
            || Ok(io.read(MCU_STATUS)),
            |status| status.value() == McuStatus::Disabled,
            time::Delta::from_micros(10),
            time::Delta::from_millis(100),
        ) {
            let status = io.read(MCU_STATUS);
            dev_err!(self.dev, "MCU failed to stop, status: {:?}", status.value());
            return Err(e);
        }

        Ok(())
    }

    /// Waits until the firmware signals readiness via the GLB IRQ bit.
    pub(crate) fn wait_ready(&self, timeout_ms: u32) -> Result {
        self.ready_wait.wait_interruptible_timeout(timeout_ms, || {
            if self.fw_ready.load(Acquire) {
                Ok(WaitResult::Done)
            } else {
                Ok(WaitResult::Retry)
            }
        })
    }

    /// Enable the global interface.
    pub(crate) fn enable_global_interface(
        &self,
        gpu_info: &GpuInfo,
        core_clk: &Clk,
        io: &IoMem<'_>,
    ) -> Result {
        let shared_section = self.shared_section()?;
        self.with_locked_global_iface(|global_iface| {
            global_iface.enable(
                self.vm.dev(),
                io,
                shared_section,
                gpu_info,
                core_clk,
                &self.ready_wait,
            )
        })
    }

    pub(crate) fn with_locked_global_iface<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut GlobalInterface) -> Result<R>,
    {
        let mut global_iface = self.global_iface.lock();
        f(&mut global_iface)
    }

    pub(crate) fn csif_info_counts(&self) -> Result<(u32, u32, u32, u32)> {
        self.with_locked_global_iface(|global_iface| {
            let csg = global_iface.csg(0).ok_or(EINVAL)?;
            let cs = csg.cs(0).ok_or(EINVAL)?;

            Ok((
                global_iface.csg_slot_count()?,
                csg.cs_slot_count()?,
                cs.work_regs()?,
                cs.scoreboards()?,
            ))
        })
    }

    pub(crate) fn group_suspend_buf_sizes(&self) -> Result<(u32, u32)> {
        self.with_locked_global_iface(|global_iface| {
            let csg = global_iface.csg(0).ok_or(EINVAL)?;

            csg.suspend_buf_sizes()
        })
    }

    /// Allocate a CS ring-buffer interface in the FW VM (AS0).
    pub(crate) fn alloc_queue_mem(&self, ddev: &TyrDrmDevice) -> Result<Arc<gem::MappedBo>> {
        let dev = self.dev.as_ref();
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);

        gem::new_kernel_object(dev, ddev, &self.vm, SZ_8K, flags)
    }

    pub(crate) fn alloc_suspend_buf(
        &self,
        ddev: &TyrDrmDevice,
        suspend_size: usize,
    ) -> Result<Arc<gem::MappedBo>> {
        let dev = self.dev.as_ref();
        let flags = VmMapFlags::from(VmFlag::Noexec);

        gem::new_kernel_object(dev, ddev, &self.vm, suspend_size, flags)
    }
}
