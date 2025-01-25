// SPDX-License-Identifier: GPL-2.0 or MIT

use crate::regs::*;
use kernel::bits;
use kernel::bits::genmask_u32;
use kernel::devres::Devres;
use kernel::io;
use kernel::io::mem::IoMem;
use kernel::platform;
use kernel::prelude::*;
use kernel::time;
use kernel::transmute::AsBytes;

pub(crate) mod irq;

#[repr(C)]
// This can be queried by userspace to get information about the GPU.
pub(crate) struct GpuInfo {
    pub(crate) gpu_id: u32,
    pub(crate) csf_id: u32,
    pub(crate) gpu_rev: u32,
    pub(crate) core_features: u32,
    pub(crate) l2_features: u32,
    pub(crate) tiler_features: u32,
    pub(crate) mem_features: u32,
    pub(crate) mmu_features: u32,
    pub(crate) thread_features: u32,
    pub(crate) max_threads: u32,
    pub(crate) thread_max_workgroup_size: u32,
    pub(crate) thread_max_barrier_size: u32,
    pub(crate) coherency_features: u32,
    pub(crate) texture_features: [u32; 4],
    pub(crate) as_present: u32,
    pub(crate) shader_present: u64,
    pub(crate) tiler_present: u64,
    pub(crate) l2_present: u64,
}

impl GpuInfo {
    pub(crate) fn new(iomem: &Devres<IoMem>) -> Result<Self> {
        let gpu_id = GPU_ID.read(iomem)?;
        let csf_id = GPU_CSF_ID.read(iomem)?;
        let gpu_rev = GPU_REVID.read(iomem)?;
        let core_features = GPU_CORE_FEATURES.read(iomem)?;
        let l2_features = GPU_L2_FEATURES.read(iomem)?;
        let tiler_features = GPU_TILER_FEATURES.read(iomem)?;
        let mem_features = GPU_MEM_FEATURES.read(iomem)?;
        let mmu_features = GPU_MMU_FEATURES.read(iomem)?;
        let thread_features = GPU_THREAD_FEATURES.read(iomem)?;
        let max_threads = GPU_THREAD_MAX_THREADS.read(iomem)?;
        let thread_max_workgroup_size = GPU_THREAD_MAX_WORKGROUP_SIZE.read(iomem)?;
        let thread_max_barrier_size = GPU_THREAD_MAX_BARRIER_SIZE.read(iomem)?;
        let coherency_features = GPU_COHERENCY_FEATURES.read(iomem)?;

        let texture_features = GPU_TEXTURE_FEATURES0.read(iomem)?;

        let as_present = GPU_AS_PRESENT.read(iomem)?;

        let shader_present = GPU_SHADER_PRESENT_LO.read(iomem)? as u64;
        let shader_present = shader_present | (GPU_SHADER_PRESENT_HI.read(iomem)? as u64) << 32;

        let tiler_present = GPU_TILER_PRESENT_LO.read(iomem)? as u64;
        let tiler_present = tiler_present | (GPU_TILER_PRESENT_HI.read(iomem)? as u64) << 32;

        let l2_present = GPU_L2_PRESENT_LO.read(iomem)? as u64;
        let l2_present = l2_present | (GPU_L2_PRESENT_HI.read(iomem)? as u64) << 32;

        Ok(Self {
            gpu_id,
            csf_id,
            gpu_rev,
            core_features,
            l2_features,
            tiler_features,
            mem_features,
            mmu_features,
            thread_features,
            max_threads,
            thread_max_workgroup_size,
            thread_max_barrier_size,
            coherency_features,
            texture_features: [texture_features, 0, 0, 0],
            as_present,
            shader_present,
            tiler_present,
            l2_present,
        })
    }

    pub(crate) fn log(&self, pdev: &platform::Device) {
        let major = (self.gpu_id >> 16) & 0xff;
        let minor = (self.gpu_id >> 8) & 0xff;
        let status = self.gpu_id & 0xff;

        let model_name = if let Some(model) = GPU_MODELS
            .iter()
            .find(|&f| f.major == major && f.minor == minor)
        {
            model.name
        } else {
            "unknown"
        };

        dev_info!(
            pdev.as_ref(),
            "mali-{} id 0x{:x} major 0x{:x} minor 0x{:x} status 0x{:x}",
            model_name,
            self.gpu_id >> 16,
            major,
            minor,
            status
        );

        dev_info!(
            pdev.as_ref(),
            "Features: L2:{:#x} Tiler:{:#x} Mem:{:#x} MMU:{:#x} AS:{:#x}",
            self.l2_features,
            self.tiler_features,
            self.mem_features,
            self.mmu_features,
            self.as_present
        );

        dev_info!(
            pdev.as_ref(),
            "shader_present=0x{:016x} l2_present=0x{:016x} tiler_present=0x{:016x}",
            self.shader_present,
            self.l2_present,
            self.tiler_present
        );
    }

    pub(crate) fn va_bits(&self) -> u32 {
        self.mmu_features & bits::genmask_u32(7, 0)
    }

    pub(crate) fn pa_bits(&self) -> u32 {
        (self.mmu_features >> 8) & bits::genmask_u32(7, 0)
    }
}

// SAFETY:
//
// This type is the same type exposed by Panthor's uAPI. As it's declared as
// #repr(C), we can be sure that the layout is the same. Therefore, it is safe
// to expose this to userspace.
unsafe impl AsBytes for GpuInfo {}

struct GpuModels {
    name: &'static str,
    major: u32,
    minor: u32,
}

const GPU_MODELS: [GpuModels; 1] = [GpuModels {
    name: "g610",
    major: 10,
    minor: 7,
}];

#[allow(dead_code)]
pub(crate) struct GpuId {
    pub(crate) arch_major: u32,
    pub(crate) arch_minor: u32,
    pub(crate) arch_rev: u32,
    pub(crate) prod_major: u32,
    pub(crate) ver_major: u32,
    pub(crate) ver_minor: u32,
    pub(crate) ver_status: u32,
}

impl From<u32> for GpuId {
    fn from(value: u32) -> Self {
        GpuId {
            arch_major: (value & genmask_u32(31, 28)) >> 28,
            arch_minor: (value & genmask_u32(27, 24)) >> 24,
            arch_rev: (value & genmask_u32(23, 20)) >> 20,
            prod_major: (value & genmask_u32(19, 16)) >> 16,
            ver_major: (value & genmask_u32(15, 12)) >> 12,
            ver_minor: (value & genmask_u32(11, 4)) >> 4,
            ver_status: value & genmask_u32(3, 0),
        }
    }
}

/// Powers on the l2 block.
pub(crate) fn l2_power_on(iomem: &Devres<IoMem>) -> Result<()> {
    let op = || L2_PWRTRANS_LO.read(iomem);

    let cond = |pwr_trans: &u32| *pwr_trans == 0;

    let _ = io::poll::read_poll_timeout(
        op,
        cond,
        time::Delta::from_millis(100),
        Some(time::Delta::from_millis(200)),
    )?;

    L2_PWRON_LO.write(iomem, 1)?;

    let op = || L2_READY_LO.read(iomem);
    let cond = |l2_ready: &u32| *l2_ready == 1;

    let _ = io::poll::read_poll_timeout(
        op,
        cond,
        time::Delta::from_millis(100),
        Some(time::Delta::from_millis(200)),
    )?;

    Ok(())
}
