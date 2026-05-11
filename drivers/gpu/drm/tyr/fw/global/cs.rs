// SPDX-License-Identifier: GPL-2.0 or MIT

//! Command stream interface implementation.
//!
//! This module owns the runtime CS interface state discovered through the
//! firmware global interface. Keeping it here lets the GLB-facing code stop
//! carrying per-CS control-block details inline.

use kernel::{c_str, io::Io, prelude::*, str::CStr};

use super::SharedSectionInfo;
use crate::fw::interfaces::{
    CsBlockedReason, CsState, CsWaitCondition, FwInterface, CS_ACK, CS_ACK_IRQ_MASK, CS_BASE,
    CS_CONFIG, CS_CONTROL_BLOCK_SIZE, CS_FATAL, CS_FATAL_INFO, CS_FAULT, CS_FAULT_INFO,
    CS_HEAP_ADDRESS, CS_HEAP_FRAG_END, CS_HEAP_VT_END, CS_HEAP_VT_START,
    CS_KERNEL_INPUT_BLOCK_SIZE, CS_KERNEL_OUTPUT_BLOCK_SIZE, CS_REQ, CS_SIZE,
    CS_STATUS_BLOCKED_REASON, CS_STATUS_SCOREBOARDS, CS_STATUS_WAIT, CS_STATUS_WAIT_SYNC_POINTER,
    CS_STATUS_WAIT_SYNC_VALUE, CS_STATUS_WAIT_SYNC_VALUE_HI, CS_TILER_HEAP_END,
    CS_TILER_HEAP_START, CS_USER_INPUT, CS_USER_OUTPUT, STREAM_FEATURES, STREAM_INPUT_VA,
    STREAM_OUTPUT_VA,
};

/// Names for [`CS_FATAL.exception_type`] codes, used by [`CsInterface::decode_fatal`].
const FATAL_EXCEPTION_NAMES: &[(u32, &CStr)] = &[
    (0x00, c_str!("OK")),
    (0x40, c_str!("CS_CONFIG_FAULT")),
    (0x41, c_str!("CS_UNRECOVERABLE")),
    (0x44, c_str!("CS_ENDPOINT_FAULT")),
    (0x48, c_str!("CS_BUS_FAULT")),
    (0x49, c_str!("CS_INVALID_INSTRUCTION")),
    (0x4A, c_str!("CS_CALL_STACK_OVERFLOW")),
    (0x68, c_str!("FIRMWARE_INTERNAL_ERROR")),
];

/// Names for [`CS_FAULT.exception_type`] codes, used by [`CsInterface::decode_fault`].
const FAULT_EXCEPTION_NAMES: &[(u32, &CStr)] = &[
    (0x00, c_str!("OK")),
    (0x05, c_str!("KABOOM")),
    (0x0F, c_str!("CS_RESOURCE_TERMINATED")),
    (0x48, c_str!("CS_BUS_FAULT")),
    (0x4B, c_str!("CS_INHERIT_FAULT")),
    (0x50, c_str!("INSTR_INVALID_PC")),
    (0x51, c_str!("INSTR_INVALID_ENC")),
    (0x55, c_str!("INSTR_BARRIER_FAULT")),
    (0x58, c_str!("DATA_INVALID_FAULT")),
    (0x59, c_str!("TILE_RANGE_FAULT")),
    (0x5A, c_str!("ADDR_RANGE_FAULT")),
    (0x5B, c_str!("IMPRECISE_FAULT")),
    (0x69, c_str!("RESOURCE_EVICTION_TIMEOUT")),
];

fn exception_name(table: &[(u32, &'static CStr)], code: u32) -> &'static CStr {
    for &(c, name) in table {
        if c == code {
            return name;
        }
    }
    c_str!("UNKNOWN")
}

/// Offset from GROUP_CONTROL_BLOCK start to the first STREAM_CONTROL block.
const CS_CONTROL_OFFSET: usize = 0x40;

enum CsInterfaceState {
    Disabled,
    Enabled(EnabledCsInterface),
}

struct EnabledCsInterface {
    cs_control: FwInterface<CS_CONTROL_BLOCK_SIZE>,
    cs_input: FwInterface<CS_KERNEL_INPUT_BLOCK_SIZE>,
    cs_output: FwInterface<CS_KERNEL_OUTPUT_BLOCK_SIZE>,
}

pub(crate) struct CsInterface {
    state: CsInterfaceState,
    #[expect(dead_code)]
    cs_idx: usize,
}

pub(crate) struct HeapOutputState {
    pub(crate) heap_address: u64,
    pub(crate) vt_start: u32,
    pub(crate) vt_end: u32,
    pub(crate) frag_end: u32,
}

/// Snapshot of the per-CS sync-wait state captured from
/// `CS_STATUS_WAIT` and the matching `CS_STATUS_WAIT_SYNC_*` words.
pub(crate) struct CsStatusWait {
    /// Wait condition (`Le` or `Gt`).
    pub(crate) condition: CsWaitCondition,
    /// Whether the wait observes a 64-bit (`true`) or 32-bit (`false`)
    /// sync object.
    pub(crate) sync64: bool,
    /// GPU virtual address of the awaited sync object.
    pub(crate) sync_ptr: u64,
    /// Reference value the wait compares against, assembled from the
    /// low half (`CS_STATUS_WAIT_SYNC_VALUE`) and, for 64-bit waits,
    /// the high half (`CS_STATUS_WAIT_SYNC_VALUE_HI`).
    pub(crate) ref_val: u64,
}

impl CsInterface {
    pub(super) fn new(cs_idx: usize) -> Result<Self> {
        Ok(Self {
            state: CsInterfaceState::Disabled,
            cs_idx,
        })
    }

    pub(super) fn enable(
        &mut self,
        shared_section: &SharedSectionInfo,
        csg_control_offset: usize,
        cs_idx: usize,
        cs_stride: usize,
    ) -> Result {
        let cs_control_offset = CS_CONTROL_OFFSET + cs_idx * cs_stride;
        let cs_control_va =
            shared_section.va_range.start + csg_control_offset as u64 + cs_control_offset as u64;

        let cs_control = FwInterface::<CS_CONTROL_BLOCK_SIZE>::new(
            &shared_section.vmap,
            &shared_section.va_range,
            cs_control_va,
        )?;

        let input_va = cs_control.read(STREAM_INPUT_VA).value().get();
        let cs_input = FwInterface::<CS_KERNEL_INPUT_BLOCK_SIZE>::new(
            &shared_section.vmap,
            &shared_section.va_range,
            input_va.into(),
        )?;

        let output_va = cs_control.read(STREAM_OUTPUT_VA).value().get();
        let cs_output = FwInterface::<CS_KERNEL_OUTPUT_BLOCK_SIZE>::new(
            &shared_section.vmap,
            &shared_section.va_range,
            output_va.into(),
        )?;

        self.state = CsInterfaceState::Enabled(EnabledCsInterface {
            cs_control,
            cs_input,
            cs_output,
        });

        Ok(())
    }

    pub(in super::super) fn work_regs(&self) -> Result<u32> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled
            .cs_control
            .read(STREAM_FEATURES)
            .work_registers()
            .get())
    }

    pub(in super::super) fn scoreboards(&self) -> Result<u32> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_control.read(STREAM_FEATURES).scoreboards().get())
    }

    #[allow(dead_code)]
    pub(crate) fn read_input_req(&self) -> Result<CS_REQ> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_input.read(CS_REQ))
    }

    #[allow(dead_code)]
    pub(crate) fn write_input_req(&self, req: CS_REQ) {
        if let CsInterfaceState::Enabled(enabled) = &self.state {
            enabled.cs_input.write(CS_REQ, req);
        }
    }

    /// Clears the `CS_REQ.state` field (sets it to `CsState::Stop`).
    ///
    /// No doorbell is rung; the reset takes effect on the next
    /// `CSG_REQ.state = Start` transition.
    ///
    /// Returns [`EINVAL`] if the interface is not enabled.
    pub(crate) fn clear_input_req_state(&self) -> Result {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        let cur = enabled.cs_input.read(CS_REQ);
        enabled
            .cs_input
            .write(CS_REQ, cur.with_state(CsState::Stop));
        Ok(())
    }

    #[allow(dead_code)]
    pub(in super::super) fn write_tiler_heap(
        &self,
        start: CS_TILER_HEAP_START,
        end: CS_TILER_HEAP_END,
    ) {
        if let CsInterfaceState::Enabled(enabled) = &self.state {
            enabled.cs_input.write(CS_TILER_HEAP_START, start);
            enabled.cs_input.write(CS_TILER_HEAP_END, end);
        }
    }

    pub(crate) fn write_tiler_heap_raw(&self, start: u64, end: u64) {
        self.write_tiler_heap(
            CS_TILER_HEAP_START::from_raw(start),
            CS_TILER_HEAP_END::from_raw(end),
        );
    }

    #[allow(dead_code)]
    pub(crate) fn read_output_ack(&self) -> Result<CS_ACK> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_output.read(CS_ACK))
    }

    pub(crate) fn read_heap_output_state(&self) -> Result<HeapOutputState> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(HeapOutputState {
            heap_address: enabled.cs_output.read(CS_HEAP_ADDRESS).pointer().get(),
            vt_start: enabled.cs_output.read(CS_HEAP_VT_START).value().get(),
            vt_end: enabled.cs_output.read(CS_HEAP_VT_END).value().get(),
            frag_end: enabled.cs_output.read(CS_HEAP_FRAG_END).value().get(),
        })
    }

    pub(crate) fn read_status_blocked_reason(&self) -> Result<CsBlockedReason> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        enabled.cs_output.read(CS_STATUS_BLOCKED_REASON).reason()
    }

    /// Reads `CS_STATUS_SCOREBOARDS.nonzero`.
    ///
    /// A non-zero return means the CS is still observing one or more
    /// in-flight scoreboard entries.
    pub(crate) fn read_status_scoreboards(&self) -> Result<u32> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled
            .cs_output
            .read(CS_STATUS_SCOREBOARDS)
            .nonzero()
            .get())
    }

    /// Reads the active `CS_STATUS_WAIT_SYNC_*` snapshot when the CS is
    /// blocked on a `SYNC_WAIT` instruction.
    ///
    /// Returns the decoded condition (Le/Gt), the size of the awaited
    /// sync object, the GPU VA being polled and the reference value
    /// (assembled from the low / high halves for 64-bit waits).
    pub(crate) fn read_status_wait_sync(&self) -> Result<CsStatusWait> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        let wait = enabled.cs_output.read(CS_STATUS_WAIT);
        let condition = wait.sync_wait_condition()?;
        let sync64 = wait.sync_wait_size();

        let sync_ptr = enabled
            .cs_output
            .read(CS_STATUS_WAIT_SYNC_POINTER)
            .pointer()
            .get();
        let lo = enabled
            .cs_output
            .read(CS_STATUS_WAIT_SYNC_VALUE)
            .value()
            .get();
        let ref_val = if sync64 {
            let hi = enabled
                .cs_output
                .read(CS_STATUS_WAIT_SYNC_VALUE_HI)
                .value()
                .get();
            (u64::from(hi) << 32) | u64::from(lo)
        } else {
            u64::from(lo)
        };

        Ok(CsStatusWait {
            condition,
            sync64,
            sync_ptr,
            ref_val,
        })
    }

    /// Logs the contents of `CS_FATAL` / `CS_FATAL_INFO` and returns the
    /// raw exception-type code from `CS_FATAL.exception_type`.
    ///
    /// Returns [`EINVAL`] if the interface is not enabled.
    pub(crate) fn decode_fatal(&self, csg_id: usize, cs_id: u32) -> Result<u32> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        let fatal = enabled.cs_output.read(CS_FATAL).into_raw();
        let info = enabled.cs_output.read(CS_FATAL_INFO).into_raw();
        let exception_type = fatal & 0xFF;
        let exception_data = (fatal >> 8) & 0x00FF_FFFF;
        let name = exception_name(FATAL_EXCEPTION_NAMES, exception_type);

        pr_err!(
            "CSG slot: {} CS slot: {}\n\
             CS_FATAL.EXCEPTION_TYPE: 0x{:x} ({})\n\
             CS_FATAL.EXCEPTION_DATA: 0x{:x}\n\
             CS_FATAL_INFO: 0x{:x}\n",
            csg_id,
            cs_id,
            exception_type,
            name.to_str().unwrap_or("UNKNOWN"),
            exception_data,
            info,
        );

        Ok(exception_type)
    }

    /// Logs the contents of `CS_FAULT` / `CS_FAULT_INFO` and returns the
    /// raw exception-type code from `CS_FAULT.exception_type`.
    ///
    /// Returns [`EINVAL`] if the interface is not enabled.
    pub(crate) fn decode_fault(&self, csg_id: usize, cs_id: u32) -> Result<u32> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        let fault = enabled.cs_output.read(CS_FAULT).into_raw();
        let info = enabled.cs_output.read(CS_FAULT_INFO).into_raw();
        let exception_type = fault & 0xFF;
        let exception_data = (fault >> 8) & 0x00FF_FFFF;
        let name = exception_name(FAULT_EXCEPTION_NAMES, exception_type);

        pr_err!(
            "CSG slot: {} CS slot: {}\n\
             CS_FAULT.EXCEPTION_TYPE: 0x{:x} ({})\n\
             CS_FAULT.EXCEPTION_DATA: 0x{:x}\n\
             CS_FAULT_INFO: 0x{:x}\n",
            csg_id,
            cs_id,
            exception_type,
            name.to_str().unwrap_or("UNKNOWN"),
            exception_data,
            info,
        );

        Ok(exception_type)
    }
}
