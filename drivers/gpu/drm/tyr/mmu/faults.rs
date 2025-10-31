// SPDX-License-Identifier: GPL-2.0 or MIT

//! Fault reporting.

use crate::regs::*;
use kernel::c_str;
use kernel::devres::Devres;
use kernel::io::mem::IoMem;
use kernel::prelude::*;
use kernel::str::CStr;

pub(crate) const EXCEPTION_MAP: &[(u32, &CStr)] = &[
    (0x00, c_str!("OK")),
    (0x04, c_str!("TERMINATED")),
    (0x05, c_str!("KABOOM")),
    (0x06, c_str!("EUREKA")),
    (0x08, c_str!("ACTIVE")),
    (0x0f, c_str!("CS_RES_TERM")),
    (0x3f, c_str!("MAX_NON_FAULT")),
    (0x40, c_str!("CS_CONFIG_FAULT")),
    (0x41, c_str!("CS_UNRECOVERABLE")),
    (0x44, c_str!("CS_ENDPOINT_FAULT")),
    (0x48, c_str!("CS_BUS_FAULT")),
    (0x49, c_str!("CS_INSTR_INVALID")),
    (0x4a, c_str!("CS_CALL_STACK_OVERFLOW")),
    (0x4b, c_str!("CS_INHERIT_FAULT")),
    (0x50, c_str!("INSTR_INVALID_PC")),
    (0x51, c_str!("INSTR_INVALID_ENC")),
    (0x55, c_str!("INSTR_BARRIER_FAULT")),
    (0x58, c_str!("DATA_INVALID_FAULT")),
    (0x59, c_str!("TILE_RANGE_FAULT")),
    (0x5a, c_str!("ADDR_RANGE_FAULT")),
    (0x5b, c_str!("IMPRECISE_FAULT")),
    (0x60, c_str!("OOM")),
    (0x68, c_str!("CSF_FW_INTERNAL_ERROR")),
    (0x69, c_str!("CSF_RES_EVICTION_TIMEOUT")),
    (0x80, c_str!("GPU_BUS_FAULT")),
    (0x88, c_str!("GPU_SHAREABILITY_FAULT")),
    (0x89, c_str!("SYS_SHAREABILITY_FAULT")),
    (0x8a, c_str!("GPU_CACHEABILITY_FAULT")),
    (0xc0, c_str!("TRANSLATION_FAULT_0")),
    (0xc1, c_str!("TRANSLATION_FAULT_1")),
    (0xc2, c_str!("TRANSLATION_FAULT_2")),
    (0xc3, c_str!("TRANSLATION_FAULT_3")),
    (0xc4, c_str!("TRANSLATION_FAULT_4")),
    (0xc8, c_str!("PERM_FAULT_0")),
    (0xc9, c_str!("PERM_FAULT_1")),
    (0xca, c_str!("PERM_FAULT_2")),
    (0xcb, c_str!("PERM_FAULT_3")),
    (0xd9, c_str!("ACCESS_FLAG_1")),
    (0xda, c_str!("ACCESS_FLAG_2")),
    (0xdb, c_str!("ACCESS_FLAG_3")),
    (0xe0, c_str!("ADDR_SIZE_FAULT_IN")),
    (0xe4, c_str!("ADDR_SIZE_FAULT_OUT0")),
    (0xe5, c_str!("ADDR_SIZE_FAULT_OUT1")),
    (0xe6, c_str!("ADDR_SIZE_FAULT_OUT2")),
    (0xe7, c_str!("ADDR_SIZE_FAULT_OUT3")),
    (0xe8, c_str!("MEM_ATTR_FAULT_0")),
    (0xe9, c_str!("MEM_ATTR_FAULT_1")),
    (0xea, c_str!("MEM_ATTR_FAULT_2")),
    (0xeb, c_str!("MEM_ATTR_FAULT_3")),
];

pub(crate) fn get_exception_name(code: u32) -> &'static CStr {
    for &(exception_code, name) in EXCEPTION_MAP {
        if exception_code == code {
            return name;
        }
    }
    c_str!("UNKNOWN")
}

pub(crate) fn access_type_name(fault_status: u32) -> &'static str {
    match fault_status & AS_FAULTSTATUS_ACCESS_TYPE_MASK {
        AS_FAULTSTATUS_ACCESS_TYPE_ATOMIC => "ATOMIC",
        AS_FAULTSTATUS_ACCESS_TYPE_READ => "READ",
        AS_FAULTSTATUS_ACCESS_TYPE_WRITE => "WRITE",
        AS_FAULTSTATUS_ACCESS_TYPE_EX => "EXECUTE",
        _ => "UNKNOWN",
    }
}

/// Decodes a MMU fault, printing a message to the kernel log.
pub(super) fn decode_faults(mut status: u32, iomem: &Devres<IoMem>) -> Result {
    while status != 0 {
        let as_index = (status | (status >> 16)).trailing_zeros();
        let mask = kernel::bits::bit_u32(as_index);

        let mut addr: u64;

        let fault_status: u32 = as_faultstatus(as_index as usize).unwrap().read(iomem)?;
        addr = as_faultaddress_lo(as_index as usize).unwrap().read(iomem)? as u64;
        addr |= (as_faultaddress_hi(as_index as usize).unwrap().read(iomem)? as u64) << 32;

        let exception_type: u32 = fault_status & 0xff;
        let access_type: u32 = (fault_status >> 8) & 0x3;
        let source_id: u32 = fault_status >> 16;

        pr_err!(
            "Unhandled Page fault in AS{} at VA 0x{:016X}\n\
                raw fault status: 0x{:X}\n\
                decoded fault status: {}\n\
                exception type 0x{:X}: {}\n\
                access type 0x{:X}: {}\n\
                source id 0x{:X}\n",
            as_index,
            addr,
            fault_status,
            if fault_status & (1 << 10) != 0 {
                "DECODER FAULT"
            } else {
                "SLAVE FAULT"
            },
            exception_type,
            get_exception_name(exception_type),
            access_type,
            access_type_name(fault_status),
            source_id
        );

        // Update status to process the next fault
        status &= !mask;
    }

    Ok(())
}
