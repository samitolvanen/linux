// SPDX-License-Identifier: GPL-2.0 or MIT

#![allow(dead_code)]

use kernel::bits::bit_u64;
use kernel::devres::Devres;
use kernel::io::mem::IoMem;
use kernel::{bits::bit_u32, prelude::*};

/// Represents a register in the Register Set
pub(crate) struct Register<const OFFSET: usize>;

impl<const OFFSET: usize> Register<OFFSET> {
    #[inline]
    pub(crate) fn read(&self, iomem: &Devres<IoMem>) -> Result<u32> {
        (*iomem).try_access().ok_or(ENODEV)?.try_read32(OFFSET)
    }

    #[inline]
    pub(crate) fn write(&self, iomem: &Devres<IoMem>, value: u32) -> Result<()> {
        (*iomem)
            .try_access()
            .ok_or(ENODEV)?
            .try_write32(value, OFFSET)
    }
}

pub(crate) const GPU_ID: Register<0x0> = Register;
pub(crate) const GPU_L2_FEATURES: Register<0x4> = Register;
pub(crate) const GPU_CORE_FEATURES: Register<0x8> = Register;
pub(crate) const GPU_CSF_ID: Register<0x1c> = Register;
pub(crate) const GPU_REVID: Register<0x280> = Register;
pub(crate) const GPU_TILER_FEATURES: Register<0xc> = Register;
pub(crate) const GPU_MEM_FEATURES: Register<0x10> = Register;
pub(crate) const GPU_MMU_FEATURES: Register<0x14> = Register;
pub(crate) const GPU_AS_PRESENT: Register<0x18> = Register;
pub(crate) const GPU_INT_RAWSTAT: Register<0x20> = Register;

pub(crate) const GPU_INT_RAWSTAT_FAULT: u32 = bit_u32(0);
pub(crate) const GPU_INT_RAWSTAT_PROTECTED_FAULT: u32 = bit_u32(1);
pub(crate) const GPU_INT_RAWSTAT_RESET_COMPLETED: u32 = bit_u32(8);
pub(crate) const GPU_INT_RAWSTAT_POWER_CHANGED_SINGLE: u32 = bit_u32(9);
pub(crate) const GPU_INT_RAWSTAT_POWER_CHANGED_ALL: u32 = bit_u32(10);
pub(crate) const GPU_INT_RAWSTAT_CLEAN_CACHES_COMPLETED: u32 = bit_u32(17);
pub(crate) const GPU_INT_RAWSTAT_DOORBELL_STATUS: u32 = bit_u32(18);
pub(crate) const GPU_INT_RAWSTAT_MCU_STATUS: u32 = bit_u32(19);

pub(crate) const GPU_INT_CLEAR: Register<0x24> = Register;
pub(crate) const GPU_INT_MASK: Register<0x28> = Register;
pub(crate) const GPU_INT_STAT: Register<0x2c> = Register;
pub(crate) const GPU_CMD: Register<0x30> = Register;
pub(crate) const GPU_THREAD_FEATURES: Register<0xac> = Register;
pub(crate) const GPU_THREAD_MAX_THREADS: Register<0xa0> = Register;
pub(crate) const GPU_THREAD_MAX_WORKGROUP_SIZE: Register<0xa4> = Register;
pub(crate) const GPU_THREAD_MAX_BARRIER_SIZE: Register<0xa8> = Register;
pub(crate) const GPU_TEXTURE_FEATURES0: Register<0xb0> = Register;
pub(crate) const GPU_SHADER_PRESENT_LO: Register<0x100> = Register;
pub(crate) const GPU_SHADER_PRESENT_HI: Register<0x104> = Register;
pub(crate) const GPU_TILER_PRESENT_LO: Register<0x110> = Register;
pub(crate) const GPU_TILER_PRESENT_HI: Register<0x114> = Register;
pub(crate) const GPU_L2_PRESENT_LO: Register<0x120> = Register;
pub(crate) const GPU_L2_PRESENT_HI: Register<0x124> = Register;
pub(crate) const L2_READY_LO: Register<0x160> = Register;
pub(crate) const L2_READY_HI: Register<0x164> = Register;
pub(crate) const L2_PWRON_LO: Register<0x1a0> = Register;
pub(crate) const L2_PWRON_HI: Register<0x1a4> = Register;
pub(crate) const L2_PWRTRANS_LO: Register<0x220> = Register;
pub(crate) const L2_PWRTRANS_HI: Register<0x204> = Register;
pub(crate) const L2_PWRACTIVE_LO: Register<0x260> = Register;
pub(crate) const L2_PWRACTIVE_HI: Register<0x264> = Register;

pub(crate) const MCU_CONTROL: Register<0x700> = Register;
pub(crate) const MCU_CONTROL_ENABLE: u32 = 1;
pub(crate) const MCU_CONTROL_AUTO: u32 = 2;
pub(crate) const MCU_CONTROL_DISABLE: u32 = 0;

pub(crate) const MCU_STATUS: Register<0x704> = Register;
pub(crate) const MCU_STATUS_DISABLED: u32 = 0;
pub(crate) const MCU_STATUS_ENABLED: u32 = 1;
pub(crate) const MCU_STATUS_HALT: u32 = 2;
pub(crate) const MCU_STATUS_FATAL: u32 = 3;

pub(crate) const GPU_COHERENCY_FEATURES: Register<0x300> = Register;

pub(crate) const JOB_INT_RAWSTAT: Register<0x1000> = Register;
pub(crate) const JOB_INT_CLEAR: Register<0x1004> = Register;
pub(crate) const JOB_INT_MASK: Register<0x1008> = Register;
pub(crate) const JOB_INT_STAT: Register<0x100c> = Register;

pub(crate) const JOB_INT_GLOBAL_IF: u32 = bit_u32(31);

pub(crate) const MMU_INT_RAWSTAT: Register<0x2000> = Register;
pub(crate) const MMU_INT_CLEAR: Register<0x2004> = Register;
pub(crate) const MMU_INT_MASK: Register<0x2008> = Register;
pub(crate) const MMU_INT_STAT: Register<0x200c> = Register;

pub(crate) const AS_TRANSCFG_ADRMODE_UNMAPPED: u64 = bit_u64(0);
pub(crate) const AS_TRANSCFG_ADRMODE_IDENTITY: u64 = bit_u64(1);
pub(crate) const AS_TRANSCFG_ADRMODE_AARCH64_4K: u64 = bit_u64(2) | bit_u64(1);
pub(crate) const AS_TRANSCFG_ADRMODE_AARCH64_64K: u64 = bit_u64(3);
pub(crate) const fn as_transcfg_ina_bits(x: u64) -> u64 {
    x << 6
}
pub(crate) const fn as_transcfg_outa_bits(x: u64) -> u64 {
    x << 14
}
pub(crate) const AS_TRANSCFG_SL_CONCAT: u64 = bit_u64(22);
pub(crate) const AS_TRANSCFG_PTW_MEMATTR_NC: u64 = bit_u64(24);
pub(crate) const AS_TRANSCFG_PTW_MEMATTR_WB: u64 = bit_u64(25);
pub(crate) const AS_TRANSCFG_PTW_SH_NS: u64 = 0 << 28;
pub(crate) const AS_TRANSCFG_PTW_SH_OS: u64 = bit_u64(29);
pub(crate) const AS_TRANSCFG_PTW_SH_IS: u64 = bit_u64(29) | bit_u64(28);
pub(crate) const AS_TRANSCFG_PTW_RA: u64 = bit_u64(30);
pub(crate) const AS_TRANSCFG_DISABLE_HIER_AP: u64 = bit_u64(33);
pub(crate) const AS_TRANSCFG_DISABLE_AF_FAULT: u64 = bit_u64(34);
pub(crate) const AS_TRANSCFG_WXN: u64 = bit_u64(35);

pub(crate) const MMU_BASE: usize = 0x2400;
pub(crate) const MMU_AS_SHIFT: usize = 6;

const fn mmu_as(as_nr: usize) -> usize {
    MMU_BASE + (as_nr << MMU_AS_SHIFT)
}

pub(crate) struct AsRegister(usize);

impl AsRegister {
    fn new(as_nr: usize, offset: usize) -> Result<Self> {
        if as_nr >= 32 {
            Err(EINVAL)
        } else {
            Ok(AsRegister(mmu_as(as_nr) + offset))
        }
    }

    #[inline]
    pub(crate) fn read(&self, iomem: &Devres<IoMem>) -> Result<u32> {
        (*iomem).try_access().ok_or(ENODEV)?.try_read32(self.0)
    }

    #[inline]
    pub(crate) fn write(&self, iomem: &Devres<IoMem>, value: u32) -> Result<()> {
        (*iomem)
            .try_access()
            .ok_or(ENODEV)?
            .try_write32(value, self.0)
    }
}

pub(crate) fn as_transtab_lo(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x0)
}

pub(crate) fn as_transtab_hi(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x4)
}

pub(crate) fn as_memattr_lo(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x8)
}

pub(crate) fn as_memattr_hi(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0xc)
}

pub(crate) fn as_lockaddr_lo(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x10)
}

pub(crate) fn as_lockaddr_hi(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x14)
}

pub(crate) fn as_command(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x18)
}

pub(crate) fn as_faultstatus(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x1c)
}

pub(crate) const AS_FAULTSTATUS_ACCESS_TYPE_MASK: u32 = 0x3 << 8;
pub(crate) const AS_FAULTSTATUS_ACCESS_TYPE_ATOMIC: u32 = 0x0 << 8;
pub(crate) const AS_FAULTSTATUS_ACCESS_TYPE_EX: u32 = 0x1 << 8;
pub(crate) const AS_FAULTSTATUS_ACCESS_TYPE_READ: u32 = 0x2 << 8;
pub(crate) const AS_FAULTSTATUS_ACCESS_TYPE_WRITE: u32 = 0x3 << 8;

pub(crate) fn as_faultaddress_lo(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x20)
}

pub(crate) fn as_faultaddress_hi(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x24)
}

pub(crate) const AS_COMMAND_NOP: u32 = 0;
pub(crate) const AS_COMMAND_UPDATE: u32 = 1;
pub(crate) const AS_COMMAND_LOCK: u32 = 2;
pub(crate) const AS_COMMAND_UNLOCK: u32 = 3;
pub(crate) const AS_COMMAND_FLUSH_PT: u32 = 4;
pub(crate) const AS_COMMAND_FLUSH_MEM: u32 = 5;

pub(crate) fn as_status(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x28)
}

pub(crate) const AS_STATUS_ACTIVE: u32 = bit_u32(0);

pub(crate) fn as_transcfg_lo(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x30)
}
pub(crate) fn as_transcfg_hi(as_nr: usize) -> Result<AsRegister> {
    AsRegister::new(as_nr, 0x34)
}

pub(crate) const AS_LOCK_REGION_MIN_SIZE: u32 = bit_u32(15);

pub(crate) const AS_MEMATTR_AARCH64_INNER_ALLOC_IMPL: u32 = 2 << 2;

pub(crate) fn as_memattr_aarch64_inner_alloc_expl(w: bool, r: bool) -> u32 {
    (3 << 2) | ((w as u32) << 0) | ((r as u32) << 1)
}
pub(crate) const AS_MEMATTR_AARCH64_SH_MIDGARD_INNER: u32 = 0 << 4;
pub(crate) const AS_MEMATTR_AARCH64_SH_CPU_INNER: u32 = 1 << 4;
pub(crate) const AS_MEMATTR_AARCH64_SH_CPU_INNER_SHADER_COH: u32 = 2 << 4;
pub(crate) const AS_MEMATTR_AARCH64_SHARED: u32 = 0 << 6;
pub(crate) const AS_MEMATTR_AARCH64_INNER_OUTER_NC: u32 = 1 << 6;
pub(crate) const AS_MEMATTR_AARCH64_INNER_OUTER_WB: u32 = 2 << 6;
pub(crate) const AS_MEMATTR_AARCH64_FAULT: u32 = 3 << 6;

pub(crate) struct Doorbell(usize);

impl Doorbell {
    pub(crate) fn new(doorbell_id: usize) -> Self {
        Doorbell(0x80000 + (doorbell_id * 0x10000))
    }

    #[inline]
    pub(crate) fn read(&self, iomem: &Devres<IoMem>) -> Result<u32> {
        (*iomem).try_access().ok_or(ENODEV)?.try_read32(self.0)
    }

    #[inline]
    pub(crate) fn write(&self, iomem: &Devres<IoMem>, value: u32) -> Result<()> {
        (*iomem)
            .try_access()
            .ok_or(ENODEV)?
            .try_write32(value, self.0)
    }
}

pub(crate) const CSF_GLB_DOORBELL_ID: usize = 0;
