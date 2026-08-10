// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU fault reporting.
//!
//! This module decodes per-address-space MMU fault status and address registers
//! into human-readable error reports. Keeping the decoding here lets the MMU IRQ
//! path report faults without forcing the top-level MMU or driver code to know
//! the raw register layout.

use kernel::{
    io::{
        register::Array,
        Io, //
    },
    prelude::*,
    str::CStr,
    time::Delta, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice, //
    },
    regs::{
        mmu_control::mmu_as_control,
        MAX_AS, //
    },
    sched::Scheduler,
    trace,
    vm::VaClass, //
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

pub(crate) fn get_exception_name(code: u32) -> &'static CStr {
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

/// Reports where `addr` sits in the mapping tree of the VM used by the
/// group bound to the faulting AS slot.
fn report_fault_va(tdev: &TyrDrmDevice, csg_id: u32, group_uid: u64, addr: u64) {
    if csg_id == u32::MAX {
        pr_err!("fault VA 0x{:016X}: no group bound, VM unknown\n", addr);
        return;
    }

    let Some(vm) = Scheduler::vm_for_csg(tdev, csg_id as usize, group_uid) else {
        pr_err!("fault VA 0x{:016X}: group gone, VM unknown\n", addr);
        return;
    };

    match vm.try_classify_va(addr) {
        Err(()) => pr_err!("fault VA 0x{:016X}: gpuvm busy, not classified\n", addr),
        Ok(VaClass::Mapped { map, bo_offset }) => pr_err!(
            "fault VA 0x{:016X} is mapped: mapping 0x{:016X} size 0x{:X}, \
                BO base 0x{:016X} size 0x{:X} offset 0x{:X}\n",
            addr,
            map.va,
            map.size,
            map.bo_va_base,
            map.bo_size,
            bo_offset,
        ),
        Ok(VaClass::Unmapped { below, above }) => {
            pr_info!("fault VA 0x{:016X} is not mapped\n", addr);
            match below {
                Some(m) => pr_info!("  nearest below: 0x{:016X} size 0x{:X}\n", m.va, m.size),
                None => pr_info!("  nearest below: none\n"),
            }
            match above {
                Some(m) => pr_info!("  nearest above: 0x{:016X} size 0x{:X}\n", m.va, m.size),
                None => pr_info!("  nearest above: none\n"),
            }
        }
    }
}

/// Reports the tiler-heap chunk the faulting address belonged to, if
/// the pool of the group bound to the faulting AS slot still has a
/// record of one, followed by the current state of that pool's heaps.
fn report_heap_for_fault(tdev: &TyrDrmDevice, csg_id: u32, group_uid: u64, addr: u64) {
    if csg_id == u32::MAX {
        return;
    }

    let Some(pool) = Scheduler::heap_pool_for_csg(tdev, csg_id as usize, group_uid) else {
        pr_info!(
            "fault VA 0x{:016X}: no heap pool, or its lock is contended\n",
            addr
        );
        return;
    };

    match pool.lookup_chunk_va(addr) {
        None => pr_err!("fault VA 0x{:016X}: in no recorded heap chunk\n", addr),
        Some(record) => {
            let (state, age) = match record.free {
                Some(free) => ("freed", free.elapsed()),
                None => (
                    "LIVE, allocated",
                    record.alloc.map_or(Delta::ZERO, |a| a.elapsed()),
                ),
            };
            pr_err!(
                "fault VA 0x{:016X} in heap chunk 0x{:016X} size 0x{:X}, {} {}us ago\n",
                addr,
                record.va,
                record.size,
                state,
                age.as_micros_ceil(),
            );
        }
    }

    pool.dump_for_log();
}

pub(super) fn decode_faults(tdev: &TyrDrmDevice, status: u32, io: &IoMem<'_>) -> Result {
    let faulted = status | (status >> 16);

    for as_index in 0..MAX_AS {
        if faulted & (1u32 << as_index) == 0 {
            continue;
        }

        let fault_status_reg = mmu_as_control::FAULTSTATUS::try_at(as_index).ok_or(EINVAL)?;
        let fault_addr_lo_reg = mmu_as_control::FAULTADDRESS_LO::try_at(as_index).ok_or(EINVAL)?;
        let fault_addr_hi_reg = mmu_as_control::FAULTADDRESS_HI::try_at(as_index).ok_or(EINVAL)?;

        let fault_status_raw = io.read(fault_status_reg).into_raw();
        let addr_lo = io.read(fault_addr_lo_reg).into_raw();
        let addr_hi = io.read(fault_addr_hi_reg).into_raw();
        let addr = u64::from(addr_lo) | (u64::from(addr_hi) << 32);

        let exception_type = fault_status_raw & 0xff;
        let access_type = (fault_status_raw >> 8) & 0x3;
        let source_id = fault_status_raw >> 16;

        let (group_id, group_uid, csg_id) = tdev
            .registration_guard()
            .map(|guard| {
                guard.registration_data_with(|reg_data| {
                    reg_data.mmu.bound_group_for_as_slot(as_index)
                })
            })
            .unwrap_or((u64::MAX, u64::MAX, u32::MAX));
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
            as_index as u32,
            addr,
            fault_status_raw,
            exception_type,
            access_type,
            source_id,
            group_id,
            group_uid,
            csg_id,
            snapshot.cs0_insert,
            snapshot.cs0_extract,
            snapshot.cs1_insert,
            snapshot.cs1_extract,
            snapshot.ringbuf_words,
        );

        if csg_id != u32::MAX {
            Scheduler::dump_heap_for_csg(
                tdev,
                csg_id as usize,
                group_uid,
                trace::HeapDumpTrigger::MmuFault,
            );
        }

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

        report_fault_va(tdev, csg_id, group_uid, addr);
        report_heap_for_fault(tdev, csg_id, group_uid, addr);
    }

    Ok(())
}
