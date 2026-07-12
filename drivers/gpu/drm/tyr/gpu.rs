// SPDX-License-Identifier: GPL-2.0 or MIT

pub(crate) mod irq;

use core::ops::{
    Deref,
    DerefMut, //
};
use kernel::{
    device::{
        Bound,
        Device, //
    },
    devres::Devres,
    io::{
        poll,
        register::Array,
        Io, //
    },
    platform,
    prelude::*,
    time::Delta,
    transmute::AsBytes,
    uapi, //
};

use crate::{
    driver::{
        IoMem,
        TyrPlatformDriverData, //
    },
    pwr,
    regs::{
        gpu_control::*,
        join_u64,
        pwr_control, //
    }, //
};

/// Number of CS work registers the kernel reserves at the top of the
/// register file for its own wrapper prologue/epilogue. Per the CSF
/// programming manual; constant across all current CSF chips.
pub(crate) const UNPRESERVED_CS_REG_COUNT: u32 = 4;

/// CSIF (Command Stream Interface) information.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct CsifInfo {
    pub(crate) csg_slot_count: u32,
    pub(crate) cs_slot_count: u32,
    pub(crate) cs_reg_count: u32,
    pub(crate) scoreboard_slot_count: u32,
    pub(crate) unpreserved_cs_reg_count: u32,
    pub(crate) pad: u32,
}

// SAFETY: Same layout as drm_panthor_csif_info, repr(C) with no padding.
unsafe impl AsBytes for CsifInfo {}

/// Struct containing information that can be queried by userspace. This is read from
/// the GPU's registers.
///
/// # Invariants
///
/// - The layout of this struct is identical to the C `struct drm_panthor_gpu_info`.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct GpuInfo(pub(crate) uapi::drm_panthor_gpu_info);

impl GpuInfo {
    pub(crate) fn new(
        dev: &Device<Bound>,
        iomem: &Devres<IoMem>,
        coherency: CoherencyMode,
    ) -> Result<Self> {
        let io = (*iomem).access(dev)?;

        let gpu_id = io.read(GPU_ID);

        // Architecture 14 and later report the present bitmaps through
        // PWR_CONTROL instead of GPU_CONTROL.
        let (shader_present, tiler_present, l2_present) = if gpu_id.arch_major().get() >= 14 {
            (
                join_u64(
                    io.read(pwr_control::PWR_SHADER_PRESENT_LO).into_raw(),
                    io.read(pwr_control::PWR_SHADER_PRESENT_HI).into_raw(),
                ),
                join_u64(
                    io.read(pwr_control::PWR_TILER_PRESENT_LO).into_raw(),
                    io.read(pwr_control::PWR_TILER_PRESENT_HI).into_raw(),
                ),
                join_u64(
                    io.read(pwr_control::PWR_L2_PRESENT_LO).into_raw(),
                    io.read(pwr_control::PWR_L2_PRESENT_HI).into_raw(),
                ),
            )
        } else {
            (
                join_u64(
                    io.read(SHADER_PRESENT_LO).into_raw(),
                    io.read(SHADER_PRESENT_HI).into_raw(),
                ),
                join_u64(
                    io.read(TILER_PRESENT_LO).into_raw(),
                    io.read(TILER_PRESENT_HI).into_raw(),
                ),
                join_u64(
                    io.read(L2_PRESENT_LO).into_raw(),
                    io.read(L2_PRESENT_HI).into_raw(),
                ),
            )
        };

        Ok(Self(uapi::drm_panthor_gpu_info {
            gpu_id: gpu_id.into_raw(),
            gpu_rev: io.read(REVIDR).into_raw(),
            csf_id: io.read(CSF_ID).into_raw(),
            l2_features: io.read(L2_FEATURES).into_raw(),
            tiler_features: io.read(TILER_FEATURES).into_raw(),
            mem_features: io.read(MEM_FEATURES).into_raw(),
            mmu_features: io.read(MMU_FEATURES).into_raw(),
            thread_features: io.read(THREAD_FEATURES).into_raw(),
            max_threads: io.read(THREAD_MAX_THREADS).into_raw(),
            thread_max_workgroup_size: io.read(THREAD_MAX_WORKGROUP_SIZE).into_raw(),
            thread_max_barrier_size: io.read(THREAD_MAX_BARRIER_SIZE).into_raw(),
            coherency_features: io.read(COHERENCY_FEATURES).into_raw(),
            texture_features: [
                io.read(TEXTURE_FEATURES::at(0)).supported_formats().get(),
                io.read(TEXTURE_FEATURES::at(1)).supported_formats().get(),
                io.read(TEXTURE_FEATURES::at(2)).supported_formats().get(),
                io.read(TEXTURE_FEATURES::at(3)).supported_formats().get(),
            ],
            as_present: io.read(AS_PRESENT).into_raw(),
            selected_coherency: coherency as u32,
            shader_present,
            l2_present,
            tiler_present,
            core_features: io.read(CORE_FEATURES).into_raw(),
            // Padding must be zero.
            pad: 0,
            gpu_features: join_u64(
                io.read(GPU_FEATURES_LO).into_raw(),
                io.read(GPU_FEATURES_HI).into_raw(),
            ),
        }))
    }

    pub(crate) fn log(&self, dev: &Device<Bound>) {
        let gpu_id = GPU_ID::from_raw(self.gpu_id);

        dev_info!(
            dev,
            "mali-{} GPU_ID 0x{:x} major 0x{:x} minor 0x{:x} status 0x{:x}",
            self.model_name(),
            gpu_id.into_raw(),
            gpu_id.ver_major().get(),
            gpu_id.ver_minor().get(),
            gpu_id.ver_status().get()
        );

        dev_info!(
            dev,
            "Features: L2:{:#x} Tiler:{:#x} Mem:{:#x} MMU:{:#x} AS:{:#x}",
            self.l2_features,
            self.tiler_features,
            self.mem_features,
            self.mmu_features,
            self.as_present,
        );

        dev_info!(
            dev,
            "shader_present=0x{:016x} l2_present=0x{:016x} tiler_present=0x{:016x}",
            self.shader_present,
            self.l2_present,
            self.tiler_present,
        );
    }

    pub(crate) fn heap_context_stride(&self) -> u32 {
        let line_size = 1u32 << L2_FEATURES::from_raw(self.l2_features).line_size().get();
        let heap_context_size = 32u32;

        heap_context_size.next_multiple_of(line_size)
    }

    /// Returns the product name, or `"unknown"` for an unrecognized GPU.
    fn model_name(&self) -> &'static str {
        let gpu_id = GPU_ID::from_raw(self.gpu_id);
        let arch_major = gpu_id.arch_major().get();
        let prod_major = gpu_id.prod_major().get();
        let ray_intersection = (self.gpu_features & GPU_FEATURES_RAY_INTERSECTION) != 0;
        let shader_core_count = self.shader_present.count_ones();

        match (arch_major, prod_major) {
            (10, 2) => "g710",
            (10, 3) => "g510",
            (10, 4) => "g310",
            (10, 7) => "g610",
            (11, 2) => {
                if shader_core_count > 10 && ray_intersection {
                    "g715-immortalis"
                } else if shader_core_count >= 7 {
                    "g715"
                } else {
                    "g615"
                }
            }
            (11, 3) => "g615",
            (12, 0) => {
                if shader_core_count >= 10 && ray_intersection {
                    "g720-immortalis"
                } else if shader_core_count >= 6 {
                    "g720"
                } else {
                    "g620"
                }
            }
            (12, 1) => "g620",
            (13, 0) => {
                if shader_core_count >= 10 && ray_intersection {
                    "g925-immortalis"
                } else if shader_core_count >= 6 {
                    "g725"
                } else {
                    "g625"
                }
            }
            (13, 1) => "g625",
            (14, 0) => "g1-ultra",
            (14, 1) => "g1-premium",
            (14, 3) => "g1-pro",
            _ => "unknown",
        }
    }
}

impl Deref for GpuInfo {
    type Target = uapi::drm_panthor_gpu_info;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for GpuInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// SAFETY: `GpuInfo`'s invariant guarantees that it is the same type that is
// already exposed to userspace by the C driver. This implies that it fulfills
// the requirements for `AsBytes`.
//
// This means:
//
// - No implicit padding,
// - No kernel pointers,
// - No interior mutability.
unsafe impl AsBytes for GpuInfo {}

/// `gpu_features` bit set when the GPU supports ray intersection.
const GPU_FEATURES_RAY_INTERSECTION: u64 = 1 << 2;

/// `gpu_features` bit set when the GPU has a ray traversal unit.
const GPU_FEATURES_RAY_TRAVERSAL: u64 = 1 << 5;

/// Selects the coherency protocol to program into `COHERENCY_ENABLE`.
///
/// The ACE protocol has never been supported for CSF GPUs.
pub(crate) fn select_coherency(
    dev: &Device<Bound>,
    iomem: &Devres<IoMem>,
    coherent: bool,
) -> Result<CoherencyMode> {
    if !coherent {
        return Ok(CoherencyMode::None);
    }

    let io = (*iomem).access(dev)?;
    if io.read(COHERENCY_FEATURES).ace_lite() {
        Ok(CoherencyMode::AceLite)
    } else {
        dev_err!(dev, "Coherency not supported by the device\n");
        Err(ENOTSUPP)
    }
}

/// Per-SoC match data attached to a device-tree `compatible`.
///
/// The ASN hash must be reprogrammed each time the L2 block powers up.
#[derive(Clone, Copy, Default)]
pub(crate) struct SocData {
    /// Custom L2 address-space-number hash to program before L2 power-up,
    /// or `None` to keep the hardware default.
    pub(crate) asn_hash: Option<[u32; 3]>,
}

/// Hardware operations selected by GPU architecture major.
///
/// Bound once at probe and dispatched at every hardware access.
#[derive(Clone, Copy)]
pub(crate) enum HwOps {
    /// Architectures 10 through 13.
    V10,
    /// Architecture 14, driving resets and power through PWR_CONTROL.
    V14 {
        /// Whether the GPU has a ray traversal unit, a subdomain of the
        /// shader power domain.
        has_rtu: bool,
        /// L2 domain present bitmap.
        l2_present: u64,
    },
}

impl HwOps {
    /// Selects the operations for the GPU behind `iomem`.
    pub(crate) fn bind(dev: &Device<Bound>, iomem: &Devres<IoMem>) -> Result<Self> {
        let io = (*iomem).access(dev)?;
        match io.read(GPU_ID).arch_major().get() {
            10..=13 => Ok(Self::V10),
            14 => Ok(Self::V14 {
                has_rtu: join_u64(
                    io.read(GPU_FEATURES_LO).into_raw(),
                    io.read(GPU_FEATURES_HI).into_raw(),
                ) & GPU_FEATURES_RAY_TRAVERSAL
                    != 0,
                l2_present: join_u64(
                    io.read(pwr_control::PWR_L2_PRESENT_LO).into_raw(),
                    io.read(pwr_control::PWR_L2_PRESENT_HI).into_raw(),
                ),
            }),
            _ => Err(EOPNOTSUPP),
        }
    }

    fn soft_reset(self, dev: &Device, iomem: &Devres<IoMem>) -> Result {
        match self {
            Self::V10 => soft_reset(dev, iomem),
            Self::V14 { .. } => pwr::reset_soft(dev, iomem),
        }
    }

    fn l2_power_off(self, dev: &Device<Bound>, iomem: &Devres<IoMem>) -> Result {
        match self {
            Self::V10 => l2_power_off(dev, iomem),
            Self::V14 {
                has_rtu,
                l2_present,
            } => pwr::l2_power_off(dev, iomem, l2_present, has_rtu),
        }
    }

    fn l2_power_on(
        self,
        dev: &Device,
        iomem: &Devres<IoMem>,
        coherency: CoherencyMode,
        soc_data: SocData,
    ) -> Result {
        match self {
            Self::V10 => l2_power_on(dev, iomem, coherency, soc_data),
            // The PWR_CONTROL path programs neither the coherency mode nor
            // the ASN hash.
            Self::V14 {
                has_rtu,
                l2_present,
            } => pwr::l2_power_on(dev, iomem, l2_present, has_rtu),
        }
    }

    /// Runs one synchronous GPU reset pass.
    ///
    /// On success, the GPU is left in a state suitable for reinitialization.
    pub(crate) fn reset(
        self,
        dev: &Device,
        iomem: &Devres<IoMem>,
        coherency: CoherencyMode,
        soc_data: SocData,
    ) -> Result {
        self.soft_reset(dev, iomem)?;
        self.l2_power_on(dev, iomem, coherency, soc_data)?;
        Ok(())
    }
}

/// Powers off the L2 block.
fn l2_power_off(dev: &Device<Bound>, iomem: &Devres<IoMem>) -> Result {
    let io = (*iomem).access(dev)?;
    io.write_reg(L2_PWROFF_LO::zeroed().with_const_request::<1>());

    poll::read_poll_timeout(
        || {
            let io = (*iomem).access(dev)?;
            Ok(io.read(L2_PWRTRANS_LO))
        },
        |status| status.changing() == 0,
        Delta::from_micros(100),
        Delta::from_millis(20),
    )
    .inspect_err(|_| dev_err!(dev, "Failed to power off the GPU.\n"))?;

    Ok(())
}

/// Programs the custom L2 ASN hash before the L2 block powers up.
///
/// A no-op when the device tree supplies no hash. The hash needs
/// architecture 11 or newer, so on older cores it is logged and skipped
/// while the L2 still powers up.
fn l2_config_set(dev: &Device, io: &IoMem, soc_data: SocData) {
    let Some(asn_hash) = soc_data.asn_hash else {
        return;
    };

    if io.read(GPU_ID).arch_major().get() < 11 {
        dev_err!(dev, "Custom ASN hash not supported by the device\n");
        return;
    }

    io.write(GPU_ASN_HASH::at(0), GPU_ASN_HASH::from_raw(asn_hash[0]));
    io.write(GPU_ASN_HASH::at(1), GPU_ASN_HASH::from_raw(asn_hash[1]));
    io.write(GPU_ASN_HASH::at(2), GPU_ASN_HASH::from_raw(asn_hash[2]));

    io.write_reg(io.read(L2_CONFIG).with_asn_hash_enable(true));
}

/// Powers on the l2 block.
fn l2_power_on(
    dev: &Device,
    iomem: &Devres<IoMem>,
    coherency: CoherencyMode,
    soc_data: SocData,
) -> Result {
    {
        let io = iomem.try_access().ok_or(ENODEV)?;
        // The coherency protocol must be selected before the L2 powers up.
        io.write_reg(COHERENCY_ENABLE::zeroed().with_l2_cache_protocol_select(coherency));
        l2_config_set(dev, &io, soc_data);
        io.write_reg(L2_PWRON_LO::zeroed().with_const_request::<1>());
    }

    poll::read_poll_timeout(
        || {
            let io = iomem.try_access().ok_or(ENODEV)?;
            Ok(io.read(L2_READY_LO))
        },
        |status| status.ready() == 1,
        Delta::from_millis(1),
        Delta::from_millis(100),
    )
    .inspect_err(|_| dev_err!(dev, "Failed to power on the GPU."))?;

    Ok(())
}

/// Issues a soft reset command and waits for reset-complete IRQ status.
fn soft_reset(dev: &Device, iomem: &Devres<IoMem>) -> Result {
    // The revocable guard sits in an RCU read-side critical section, so
    // it is re-acquired per access and never held across the sleeping
    // poll below.
    {
        let io = iomem.try_access().ok_or(ENODEV)?;

        // Clear any stale reset-complete IRQ state before issuing a new soft reset.
        io.write_reg(GPU_IRQ_CLEAR::zeroed().with_reset_completed(true));

        io.write_reg(GPU_COMMAND::reset(ResetMode::SoftReset));
    }

    poll::read_poll_timeout(
        || {
            let io = iomem.try_access().ok_or(ENODEV)?;
            Ok(io.read(GPU_IRQ_RAWSTAT))
        },
        |status| status.reset_completed(),
        Delta::from_millis(1),
        Delta::from_millis(100),
    )
    .inspect_err(|_| dev_err!(dev, "GPU reset timed out."))?;

    Ok(())
}

/// Masks the interrupts and powers the L2 block off for runtime suspend.
pub(crate) fn suspend(dev: &platform::Device<Bound>, data: Pin<&TyrPlatformDriverData>) {
    let bound = dev.as_ref();
    let tdev = &data.device;
    tdev.gpu_irq
        .quiesce(bound, &tdev.iomem, irq::gpu_irq_disable);
    let _ = tdev.hw_ops.l2_power_off(bound, &tdev.iomem);
    if let Some(pwr_irq) = &data.pwr_irq {
        pwr_irq.quiesce(bound, &tdev.iomem, pwr::pwr_irq_disable);
    }
}

/// Powers the L2 block on and unmasks the interrupts for runtime resume.
pub(crate) fn resume(dev: &platform::Device<Bound>, data: Pin<&TyrPlatformDriverData>) -> Result {
    let bound = dev.as_ref();
    let tdev = &data.device;
    let io = tdev.iomem.access(bound)?;
    if let Some(pwr_irq) = &data.pwr_irq {
        pwr_irq.clear_suspended();
        pwr::pwr_irq_enable(io);
    }
    tdev.gpu_irq.clear_suspended();
    irq::gpu_irq_enable(io);
    tdev.hw_ops
        .l2_power_on(bound, &tdev.iomem, tdev.coherency, tdev.soc_data)
}
