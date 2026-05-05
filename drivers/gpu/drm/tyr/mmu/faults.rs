// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU fault reporting.
//!
//! This module decodes per-address-space MMU fault status and address registers
//! into human-readable error reports. Keeping the decoding here lets the MMU IRQ
//! path report faults without forcing the top-level MMU or driver code to know
//! the raw register layout.

use kernel::{
    bits::bit_u32,
    io::{
        register::Array,
        Io, //
    },
    prelude::*,
    str::CStr, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice, //
    },
    regs::mmu_control::mmu_as_control, //
};

const EXCEPTION_MAP: &[(u32, &CStr)] = &[
    (0x00, c"OK"),
    (0x04, c"TERMINATED"),
    (0x05, c"KABOOM"),
    (0x06, c"EUREKA"),
    (0x08, c"ACTIVE"),
    (0x0f, c"CS_RES_TERM"),
    (0x3f, c"MAX_NON_FAULT"),
    (0x40, c"CS_CONFIG_FAULT"),
    (0x41, c"CS_UNRECOVERABLE"),
    (0x44, c"CS_ENDPOINT_FAULT"),
    (0x48, c"CS_BUS_FAULT"),
    (0x49, c"CS_INSTR_INVALID"),
    (0x4a, c"CS_CALL_STACK_OVERFLOW"),
    (0x4b, c"CS_INHERIT_FAULT"),
    (0x50, c"INSTR_INVALID_PC"),
    (0x51, c"INSTR_INVALID_ENC"),
    (0x55, c"INSTR_BARRIER_FAULT"),
    (0x58, c"DATA_INVALID_FAULT"),
    (0x59, c"TILE_RANGE_FAULT"),
    (0x5a, c"ADDR_RANGE_FAULT"),
    (0x5b, c"IMPRECISE_FAULT"),
    (0x60, c"OOM"),
    (0x68, c"CSF_FW_INTERNAL_ERROR"),
    (0x69, c"CSF_RES_EVICTION_TIMEOUT"),
    (0x80, c"GPU_BUS_FAULT"),
    (0x88, c"GPU_SHAREABILITY_FAULT"),
    (0x89, c"SYS_SHAREABILITY_FAULT"),
    (0x8a, c"GPU_CACHEABILITY_FAULT"),
    (0xc0, c"TRANSLATION_FAULT_0"),
    (0xc1, c"TRANSLATION_FAULT_1"),
    (0xc2, c"TRANSLATION_FAULT_2"),
    (0xc3, c"TRANSLATION_FAULT_3"),
    (0xc4, c"TRANSLATION_FAULT_4"),
    (0xc8, c"PERM_FAULT_0"),
    (0xc9, c"PERM_FAULT_1"),
    (0xca, c"PERM_FAULT_2"),
    (0xcb, c"PERM_FAULT_3"),
    (0xd9, c"ACCESS_FLAG_1"),
    (0xda, c"ACCESS_FLAG_2"),
    (0xdb, c"ACCESS_FLAG_3"),
    (0xe0, c"ADDR_SIZE_FAULT_IN"),
    (0xe4, c"ADDR_SIZE_FAULT_OUT0"),
    (0xe5, c"ADDR_SIZE_FAULT_OUT1"),
    (0xe6, c"ADDR_SIZE_FAULT_OUT2"),
    (0xe7, c"ADDR_SIZE_FAULT_OUT3"),
    (0xe8, c"MEM_ATTR_FAULT_0"),
    (0xe9, c"MEM_ATTR_FAULT_1"),
    (0xea, c"MEM_ATTR_FAULT_2"),
    (0xeb, c"MEM_ATTR_FAULT_3"),
];

fn get_exception_name(code: u32) -> &'static CStr {
    for &(exception_code, name) in EXCEPTION_MAP {
        if exception_code == code {
            return name;
        }
    }

    c"UNKNOWN"
}

fn access_type_name(fault_status: u32) -> &'static str {
    match (fault_status >> 8) & 0x3 {
        0 => "ATOMIC",
        1 => "EXECUTE",
        2 => "READ",
        3 => "WRITE",
        _ => "UNKNOWN",
    }
}

pub(super) fn decode_faults(tdev: &TyrDrmDevice, mut status: u32, io: &IoMem<'_>) -> Result {
    while status != 0 {
        let as_index = (status | (status >> 16)).trailing_zeros();
        let mask = bit_u32(as_index);

        let fault_status_reg =
            mmu_as_control::FAULTSTATUS::try_at(as_index as usize).ok_or(EINVAL)?;
        let fault_addr_lo_reg =
            mmu_as_control::FAULTADDRESS_LO::try_at(as_index as usize).ok_or(EINVAL)?;
        let fault_addr_hi_reg =
            mmu_as_control::FAULTADDRESS_HI::try_at(as_index as usize).ok_or(EINVAL)?;

        let fault_status_raw = io.read(fault_status_reg).into_raw();
        let addr_lo = io.read(fault_addr_lo_reg).into_raw();
        let addr_hi = io.read(fault_addr_hi_reg).into_raw();
        let addr = u64::from(addr_lo) | (u64::from(addr_hi) << 32);

        let exception_type = fault_status_raw & 0xff;
        let access_type = (fault_status_raw >> 8) & 0x3;
        let source_id = fault_status_raw >> 16;

        let decoded_status = if fault_status_raw & (1 << 10) != 0 {
            "DECODER FAULT"
        } else {
            "SLAVE FAULT"
        };

        dev_err!(
            tdev.as_ref(),
            "Unhandled Page fault in AS{} at VA 0x{:016X}\n\
                raw fault status: 0x{:X}\n\
                decoded fault status: {}\n\
                exception type 0x{:X}: {}\n\
                access type 0x{:X}: {}\n\
                source id 0x{:X}\n",
            as_index,
            addr,
            fault_status_raw,
            decoded_status,
            exception_type,
            get_exception_name(exception_type),
            access_type,
            access_type_name(fault_status_raw),
            source_id,
        );

        status &= !mask;
    }

    Ok(())
}
