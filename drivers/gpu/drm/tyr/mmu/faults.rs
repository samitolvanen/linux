// SPDX-License-Identifier: GPL-2.0 or MIT

//! MMU fault reporting.
//!
//! This module decodes per-address-space MMU fault status and address registers
//! into human-readable error reports. Keeping the decoding here lets the MMU IRQ
//! path report faults without forcing the top-level MMU or driver code to know
//! the raw register layout.

use kernel::{
    c_str,
    devres::Devres,
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
    heap,
    regs::mmu_control::mmu_as_control,
    sched::Scheduler,
    trace,
    vm::VaClass, //
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

/// Reports where `addr` sits in the mapping tree of the VM used by the
/// group bound to the faulting AS slot. Returns whether a mapping covers
/// it, reporting an unknown mapping state as false.
fn report_fault_va(tdev: &TyrDrmDevice, csg_id: u32, group_uid: u64, addr: u64) -> bool {
    if csg_id == u32::MAX {
        pr_err!("fault VA 0x{:016X}: no group bound, VM unknown\n", addr);
        return false;
    }

    let Some(vm) = Scheduler::vm_for_csg(tdev, csg_id as usize, group_uid) else {
        pr_err!("fault VA 0x{:016X}: group gone, VM unknown\n", addr);
        return false;
    };

    match vm.try_classify_va(addr) {
        Err(()) => {
            pr_err!("fault VA 0x{:016X}: gpuvm busy, not classified\n", addr);
            false
        }
        Ok(VaClass::Mapped { map, bo_offset }) => {
            pr_err!(
                "fault VA 0x{:016X} is mapped: mapping 0x{:016X} size 0x{:X}, \
                BO base 0x{:016X} size 0x{:X} offset 0x{:X}\n",
                addr,
                map.va,
                map.size,
                map.bo_va_base,
                map.bo_size,
                bo_offset,
            );
            true
        }
        Ok(VaClass::Unmapped { below, above }) => {
            pr_err!("fault VA 0x{:016X} is not mapped\n", addr);
            match below {
                Some(m) => pr_err!("  nearest below: 0x{:016X} size 0x{:X}\n", m.va, m.size),
                None => pr_err!("  nearest below: none\n"),
            }
            match above {
                Some(m) => pr_err!("  nearest above: 0x{:016X} size 0x{:X}\n", m.va, m.size),
                None => pr_err!("  nearest above: none\n"),
            }
            false
        }
    }
}

/// High bits a fault address is retried without, one at a time. A chunk
/// address comes from the kernel window at the top of the VA space and
/// carries neither bit, so a ledger hit is strong evidence. User
/// mappings can carry both, so a mapping hit is not.
const CANDIDATE_BITS: [u32; 2] = [36, 37];

/// Name for the object a retry resolved to, for the fault report line.
fn probe_result_name(result: trace::FaultBitProbeResult) -> &'static str {
    match result {
        trace::FaultBitProbeResult::Miss => "nothing",
        trace::FaultBitProbeResult::LiveChunk => "LIVE heap chunk",
        trace::FaultBitProbeResult::FreedChunk => "freed heap chunk",
        trace::FaultBitProbeResult::Mapped => "mapping",
    }
}

/// Retries the chunk ledger and the mapping tree with each of
/// `CANDIDATE_BITS` cleared from `addr`, reporting the first bit that
/// resolves. An address that carries a candidate bit but matches nothing
/// gets an explicit miss record; one that carries neither gets no record
/// at all.
///
/// Costs one ledger scan and one mapping lookup per candidate bit.
///
/// Downstream-only debug aid; not for upstream.
fn probe_injected_bits(
    tdev: &TyrDrmDevice,
    csg_id: u32,
    group_uid: u64,
    pool: &heap::Pool,
    addr: u64,
) {
    if !CANDIDATE_BITS
        .into_iter()
        .any(|bit| addr & (1u64 << bit) != 0)
    {
        return;
    }

    let vm = Scheduler::vm_for_csg(tdev, csg_id as usize, group_uid);

    for bit in CANDIDATE_BITS {
        let mask = 1u64 << bit;
        if addr & mask == 0 {
            continue;
        }

        let masked = addr & !mask;
        let hit = match pool.lookup_chunk_va(masked) {
            Some(record) if record.free.is_some() => {
                Some((record.va, trace::FaultBitProbeResult::FreedChunk))
            }
            Some(record) => Some((record.va, trace::FaultBitProbeResult::LiveChunk)),
            None => vm
                .as_ref()
                .and_then(|vm| vm.try_classify_va(masked).ok())
                .and_then(|class| match class {
                    VaClass::Mapped { map, .. } => {
                        Some((map.va, trace::FaultBitProbeResult::Mapped))
                    }
                    VaClass::Unmapped { .. } => None,
                }),
        };

        let Some((base, result)) = hit else {
            continue;
        };

        pr_err!(
            "fault VA 0x{:016X}: clearing bit {} gives 0x{:016X}, in {} 0x{:016X} offset 0x{:X}\n",
            addr,
            bit,
            masked,
            probe_result_name(result),
            base,
            masked - base,
        );
        trace::fault_va_bit_probe(addr, mask, masked, base, masked - base, result);
        return;
    }

    pr_err!("fault VA 0x{:016X}: no injected bit resolves it\n", addr);
    trace::fault_va_bit_probe(addr, 0, 0, 0, 0, trace::FaultBitProbeResult::Miss);
}

/// Reports the tiler-heap chunk the faulting address belonged to, if
/// the pool of the group bound to the faulting AS slot still has a
/// record of one, followed by the current state of that pool's heaps.
/// An address that `mapped` reports outside every mapping and that no
/// chunk record covers is handed to `probe_injected_bits`.
fn report_heap_for_fault(
    tdev: &TyrDrmDevice,
    csg_id: u32,
    group_uid: u64,
    addr: u64,
    mapped: bool,
) {
    if csg_id == u32::MAX {
        return;
    }

    let Some(pool) = Scheduler::heap_pool_for_csg(tdev, csg_id as usize, group_uid) else {
        pr_err!(
            "fault VA 0x{:016X}: no heap pool, or its lock is contended\n",
            addr
        );
        return;
    };

    match pool.lookup_chunk_va(addr) {
        None => {
            pr_err!("fault VA 0x{:016X}: in no recorded heap chunk\n", addr);
            if !mapped {
                probe_injected_bits(tdev, csg_id, group_uid, &pool, addr);
            }
        }
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

    pool.dump_for_log(tdev);
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

        let (group_id, group_uid, csg_id) = tdev.mmu.bound_group_for_as_slot(as_index as usize);
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

        let mapped = report_fault_va(tdev, csg_id, group_uid, addr);
        report_heap_for_fault(tdev, csg_id, group_uid, addr, mapped);

        status &= !mask;
    }

    Ok(())
}
