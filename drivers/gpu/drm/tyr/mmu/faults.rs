// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU fault reporting.
//!
//! This module decodes per-address-space MMU fault status and address registers
//! into human-readable error reports. Keeping the decoding here lets the MMU IRQ
//! path report faults without forcing the top-level MMU or driver code to know
//! the raw register layout.

use kernel::{c_str, devres::Devres, io::register::Array, io::Io, prelude::*, str::CStr};

use crate::{
    driver::{IoMem, TyrDrmDevice},
    regs::mmu_control::mmu_as_control,
    trace,
};

const EXCEPTION_MAP: &[(u32, &CStr)] = &[
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

fn get_exception_name(code: u32) -> &'static CStr {
    for &(exception_code, name) in EXCEPTION_MAP {
        if exception_code == code {
            return name;
        }
    }

    c_str!("UNKNOWN")
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

/// Snapshot of the kernel-visible ringbuffer state for both command
/// streams of the group bound to a faulting AS slot, returned by
/// [`read_cs_ringbuf_ptrs`].
struct CsRingbufSnapshot {
    cs0_insert: u64,
    cs0_extract: u64,
    cs1_insert: u64,
    cs1_extract: u64,
    /// Eight u64 ringbuffer words around `cs0_extract`, all zero when
    /// no kernel mapping for the cs0 ringbuf was available. See
    /// [`crate::sched::queue::Queue::ringbuf_window_around_extract`].
    ringbuf_words: [u64; 8],
}

/// Returns the ringbuffer cursors and an EXTRACT-centred ringbuf
/// snapshot for the group currently bound to `csg_id`, or all zeros
/// when the slot is not bound or its queues cannot be read.
fn read_cs_ringbuf_ptrs(tdev: &TyrDrmDevice, csg_id: usize) -> CsRingbufSnapshot {
    let csg_slot_manager = tdev.csg_slot_manager.lock();
    let Some(slot_data) = csg_slot_manager.slot_data(csg_id) else {
        return CsRingbufSnapshot {
            cs0_insert: 0,
            cs0_extract: 0,
            cs1_insert: 0,
            cs1_extract: 0,
            ringbuf_words: [0u64; 8],
        };
    };
    let queues = &slot_data.group().queues;
    let cs0 = queues.first();
    let (cs0_insert, cs0_extract) = cs0.and_then(|q| q.ringbuf_ptrs().ok()).unwrap_or((0, 0));
    let (cs1_insert, cs1_extract) = queues
        .get(1)
        .and_then(|q| q.ringbuf_ptrs().ok())
        .unwrap_or((0, 0));
    let ringbuf_words = cs0
        .map(|q| q.ringbuf_window_around_extract(cs0_extract))
        .unwrap_or([0u64; 8]);
    CsRingbufSnapshot {
        cs0_insert,
        cs0_extract,
        cs1_insert,
        cs1_extract,
        ringbuf_words,
    }
}

pub(super) fn decode_faults(mut status: u32, iomem: &Devres<IoMem>, tdev: &TyrDrmDevice) -> Result {
    while status != 0 {
        let as_index = (status | (status >> 16)).trailing_zeros();
        let mask = kernel::bits::bit_u32(as_index);

        let fault_status_reg =
            mmu_as_control::FAULTSTATUS::try_at(as_index as usize).ok_or(EINVAL)?;
        let fault_addr_lo_reg =
            mmu_as_control::FAULTADDRESS_LO::try_at(as_index as usize).ok_or(EINVAL)?;
        let fault_addr_hi_reg =
            mmu_as_control::FAULTADDRESS_HI::try_at(as_index as usize).ok_or(EINVAL)?;

        // Drop the IO guard before doing anything that may sleep.
        let (fault_status_raw, addr_lo, addr_hi) = {
            let io = iomem.try_access().ok_or(EINVAL)?;
            (
                io.read(fault_status_reg).into_raw(),
                io.read(fault_addr_lo_reg).into_raw(),
                io.read(fault_addr_hi_reg).into_raw(),
            )
        };
        let addr = u64::from(addr_lo) | (u64::from(addr_hi) << 32);

        let exception_type = fault_status_raw & 0xff;
        let access_type = (fault_status_raw >> 8) & 0x3;
        let source_id = fault_status_raw >> 16;

        let (group_id, csg_id) = tdev.mmu.bound_group_for_as_slot(as_index as usize);
        let snapshot = if csg_id == u32::MAX {
            CsRingbufSnapshot {
                cs0_insert: 0,
                cs0_extract: 0,
                cs1_insert: 0,
                cs1_extract: 0,
                ringbuf_words: [0u64; 8],
            }
        } else {
            read_cs_ringbuf_ptrs(tdev, csg_id as usize)
        };

        trace::mmu_fault(
            as_index,
            addr,
            fault_status_raw,
            exception_type,
            access_type,
            source_id,
            group_id,
            csg_id,
            snapshot.cs0_insert,
            snapshot.cs0_extract,
            snapshot.cs1_insert,
            snapshot.cs1_extract,
            snapshot.ringbuf_words,
        );

        let decoded_status = if fault_status_raw & (1 << 10) != 0 {
            "DECODER FAULT"
        } else {
            "SLAVE FAULT"
        };

        pr_err!(
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
