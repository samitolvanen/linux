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

use core::sync::atomic::{
    AtomicBool,
    Ordering, //
};

use kernel::{
    bits::genmask_u32,
    devres::Devres,
    drm::{
        gem::BaseObject,
        Uninit, //
    },
    impl_flags,
    io::{
        poll,
        Io, //
    },
    new_mutex,
    platform,
    prelude::*,
    str::CString,
    sync::{
        aref::ARef,
        Arc,
        ArcBorrow, //
    },
    time, //
};

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
    vm::Vm,
    wait::{
        Wait,
        WaitResult, //
    }, //
};

pub(crate) mod irq;
mod parser;

/// Maximum number of CSG interfaces supported by hardware.
const MAX_CSG: usize = 16;

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
}

/// Loaded firmware with sections mapped into MCU VM.
pub(crate) struct Firmware {
    /// Platform device reference (needed to access the MCU JOB_IRQ registers).
    pdev: ARef<platform::Device>,

    /// Iomem need to access registers.
    iomem: Arc<Devres<IoMem>>,

    /// MCU VM.
    vm: Arc<Vm>,

    /// List of firmware sections.
    #[expect(dead_code)]
    sections: KVec<Section>,

    /// A condvar representing a wait on a firmware event.
    pub(crate) ready_wait: Arc<Wait>,

    /// Latched to `true` by the IRQ handler when the firmware signals readiness via the GLB bit.
    pub(crate) fw_ready: Arc<AtomicBool>,
}

impl Drop for Firmware {
    fn drop(&mut self) {
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
        ddev: &TyrDrmDevice<Uninit>,
        gpu_info: &GpuInfo,
    ) -> Result<kernel::firmware::Firmware> {
        let gpu_id = GPU_ID::from_raw(gpu_info.gpu_id);

        let path = CString::try_from_fmt(fmt!(
            "arm/mali/arch{}.{}/mali_csffw.bin",
            gpu_id.arch_major().get(),
            gpu_id.arch_minor().get()
        ))?;

        kernel::firmware::Firmware::request(&path, ddev.as_ref())
    }

    fn load(
        ddev: &TyrDrmDevice<Uninit>,
        gpu_info: &GpuInfo,
    ) -> Result<(kernel::firmware::Firmware, KVec<ParsedSection>)> {
        let fw = Self::request(ddev, gpu_info)?;
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
        gpu_info: &GpuInfo,
    ) -> Result<Arc<Firmware>> {
        let vm = Vm::new(pdev, ddev, mmu, gpu_info)?;

        let (fw, parsed_sections) = Self::load(ddev, gpu_info)?;

        vm.activate()?;

        let mut sections = KVec::new();
        for parsed in parsed_sections {
            let size = (parsed.va.end - parsed.va.start) as usize;
            let va = u64::from(parsed.va.start);

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

            sections.push(Section { data, mem }, GFP_KERNEL)?;
        }

        let firmware = Arc::new(
            Firmware {
                pdev: pdev.into(),
                iomem,
                vm,
                sections,
                ready_wait: new_wait!()?,
                fw_ready: Arc::new(AtomicBool::new(false), GFP_KERNEL)?,
            },
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

    /// Waits until the firmware signals readiness via the GLB IRQ bit.
    pub(crate) fn wait_ready(&self, timeout_ms: u32) -> Result {
        self.ready_wait.wait_interruptible_timeout(timeout_ms, || {
            if self.fw_ready.load(Ordering::Acquire) {
                Ok(WaitResult::Done)
            } else {
                Ok(WaitResult::Retry)
            }
        })
    }
}
