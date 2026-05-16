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
    firmware,
    io::{
        mem::DevresIoMem,
        poll,
        Io, //
    },
    platform,
    prelude::*,
    sizes::{
        SZ_2M,
        SZ_8K, //
    },
    str::CString,
    sync::{
        Arc,
        ArcBorrow, //
    },
    time, //
};

use crate::{
    driver::{
        CleanupQueue,
        IoMem,
        TyrDrmDevice, //
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

/// Size of the MCU CSF shared memory region.
pub(super) const CSF_MCU_SHARED_REGION_SIZE: u32 = 0x04000000;

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

    /// Firmware sections, held to keep their mappings alive while the MCU runs.
    #[expect(dead_code)]
    sections: KVec<Section>,

    /// Firmware IRQ state, including readiness and event wait objects.
    irq_state: irq::JobIrqState,

    /// The global FW interface.
    global_iface: Arc<GlobalInterface<'drm>>,
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
    fn find_shared_section<'a>(dev: &Device, sections: &'a KVec<Section>) -> Result<&'a Section> {
        sections
            .iter()
            .find(|section| section.mem.va_range().start == u64::from(CSF_MCU_SHARED_REGION_START))
            .ok_or_else(|| {
                dev_err!(
                    dev,
                    "CSF shared section not found at 0x{:08x}",
                    CSF_MCU_SHARED_REGION_START
                );
                EINVAL
            })
    }

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

    fn load(dev: &Device, ddev: &TyrDrmDevice, gpu_info: &GpuInfo) -> Result<KVec<ParsedSection>> {
        let fw = Self::request(ddev, gpu_info)?;
        let mut parser = FwParser::new(dev, fw.data());

        parser.parse()
    }

    /// Load firmware and map sections into MCU VM.
    pub(crate) fn new(
        pdev: &'drm platform::Device<Bound>,
        iomem: Arc<DevresIoMem<SZ_2M>>,
        ddev: &TyrDrmDevice,
        mmu: ArcBorrow<'_, Mmu>,
        gpu_info: &GpuInfo,
        coherent: bool,
        cleanup_wq: Arc<CleanupQueue>,
    ) -> Result<Firmware<'drm>> {
        let dev = pdev.as_ref();
        let vm = Vm::new_fw(
            pdev,
            ddev,
            mmu,
            gpu_info,
            u64::from(CSF_MCU_SHARED_REGION_START),
            u64::from(CSF_MCU_SHARED_REGION_SIZE),
            coherent,
        )?;
        vm.activate()?;

        let result = (|| {
            let parsed_sections = Self::load(dev, ddev, gpu_info)?;
            let mut sections = KVec::new();
            for parsed in parsed_sections {
                let ParsedSection {
                    data,
                    va,
                    vm_map_flags,
                } = parsed;
                let size = u64::from(va.end.checked_sub(va.start).ok_or(EINVAL)?);

                let va = u64::from(va.start);
                let end = va + size;

                let mut mem = KernelBo::new(
                    dev,
                    ddev,
                    vm.clone(),
                    size,
                    KernelBoVaAlloc::Explicit(va),
                    vm_map_flags,
                    coherent,
                    cleanup_wq.clone(),
                )?;

                let auto_va_start = u64::from(CSF_MCU_SHARED_REGION_START);
                let auto_va_end = auto_va_start + u64::from(CSF_MCU_SHARED_REGION_SIZE);
                if end > auto_va_start && va < auto_va_end {
                    vm.reserve_kernel_range(va.max(auto_va_start), end.min(auto_va_end))?;
                }

                Self::init_section_mem(dev, &mut mem, &data)?;

                sections.push(Section { data, mem }, GFP_KERNEL)?;
            }

            let irq_state = irq::JobIrqState::new()?;
            let user_as_slot_count = mmu.as_slot_count().saturating_sub(1);
            let shared_section = Self::find_shared_section(dev, &sections)?;
            let global_iface = Arc::pin_init(
                GlobalInterface::new(
                    pdev.as_ref(),
                    iomem.clone(),
                    shared_section,
                    *gpu_info,
                    &irq_state,
                    user_as_slot_count,
                )?,
                GFP_KERNEL,
            )?;

            Ok(Firmware {
                dev: pdev,
                iomem,
                vm: vm.clone(),
                sections,
                irq_state,
                global_iface,
            })
        })();

        if result.is_err() {
            vm.kill();
        }

        result
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
        self.irq_state.wait_ready(timeout_ms)
    }

    pub(crate) fn irq_state(&self) -> irq::JobIrqState {
        self.irq_state.clone()
    }

    pub(crate) fn global_iface(&self) -> Arc<GlobalInterface<'drm>> {
        self.global_iface.clone()
    }

    /// Enable the global interface.
    pub(crate) fn enable_global_interface(&self, core_clk: &Clk, io: &IoMem<'_>) -> Result {
        self.global_iface.enable(core_clk, io)
    }

    pub(crate) fn csif_info_counts(&self) -> Result<(u32, u32, u32, u32)> {
        self.global_iface.csif_info_counts()
    }

    pub(crate) fn group_suspend_buf_sizes(&self) -> Result<(u32, u32)> {
        self.global_iface.group_suspend_buf_sizes()
    }

    pub(crate) fn with_csg_mut<F, R>(&self, csg_idx: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut global::CsgInterface) -> Result<R>,
    {
        self.global_iface.with_csg_mut(csg_idx, f)
    }

    pub(crate) fn ring_csg_doorbell(&self, csg_idx: usize) -> Result {
        self.global_iface.ring_csg_doorbell(csg_idx)
    }

    /// Allocate a CS ring-buffer interface in the FW VM (AS0).
    pub(crate) fn alloc_queue_mem(&self, ddev: &TyrDrmDevice) -> Result<Arc<gem::MappedBo>> {
        let dev = self.dev.as_ref();
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);

        gem::new_kernel_object(
            dev,
            ddev,
            &self.vm,
            SZ_8K,
            flags,
            ddev.coherent,
            ddev.cleanup_wq.clone(),
        )
    }

    pub(crate) fn alloc_suspend_buf(
        &self,
        ddev: &TyrDrmDevice,
        suspend_size: usize,
    ) -> Result<Arc<gem::MappedBo>> {
        let dev = self.dev.as_ref();
        let flags = VmMapFlags::from(VmFlag::Noexec);

        gem::new_kernel_object(
            dev,
            ddev,
            &self.vm,
            suspend_size,
            flags,
            ddev.coherent,
            ddev.cleanup_wq.clone(),
        )
    }
}

/// Add modinfo entries for the firmware blobs needed by Tyr.
pub(crate) struct ModInfoBuilder<const N: usize>(firmware::ModInfoBuilder<N>);

impl<const N: usize> ModInfoBuilder<N> {
    const FILES: &'static [&'static str] = &["arm/mali/arch10.8/mali_csffw.bin"];

    pub(crate) const fn create(
        module_name: &'static kernel::str::CStr,
    ) -> kernel::firmware::ModInfoBuilder<N> {
        let mut builder = kernel::firmware::ModInfoBuilder::new(module_name);
        let mut index = 0;

        while index < Self::FILES.len() {
            builder = builder.new_entry().push(Self::FILES[index]);
            index += 1;
        }

        builder
    }
}
