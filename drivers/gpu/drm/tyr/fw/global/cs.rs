// SPDX-License-Identifier: GPL-2.0 or MIT

//! Command stream (CS) code.
//!
//! Represents a single hardware queue for command submission.
//!
//! Each CSG will expose a number of command streams that is firmware dependent.

use kernel::bits::bit_u32;
use kernel::bits::genmask_u32;
use kernel::c_str;
use kernel::prelude::*;

use crate::fw::global::GlobalInterface;
use crate::fw::impl_shared_section_read;
use crate::fw::impl_shared_section_rw;
use crate::fw::RequestField;
use crate::fw::SharedSectionEntry;
use crate::fw::SharedSectionRange;
use constants::*;

/// Used to decode command stream faults.
pub(crate) const FAULT_EXCEPTION_MAP: &[(u32, &CStr)] = &[
    (0x00, c_str!("OK")),
    (0x05, c_str!("KABOOM")),
    (0x0f, c_str!("CS_RESOURCE_TERMINATED")),
    (0x48, c_str!("CS_BUS_FAULT")),
    (0x4b, c_str!("CS_INHERIT_FAULT")),
    (0x50, c_str!("INSTR_INVALID_PC")),
    (0x51, c_str!("INSTR_INVALID_ENC")),
    (0x55, c_str!("INSTR_BARRIER_FAULT")),
    (0x58, c_str!("DATA_INVALID_FAULT")),
    (0x59, c_str!("TILE_RANGE_FAULT")),
    (0x5a, c_str!("ADDR_RANGE_FAULT")),
    (0x5b, c_str!("IMPRECISE_FAULT")),
    (0x69, c_str!("RESOURCE_EVICTION_TIMEOUT")),
];

pub(crate) fn fault_exception_name(code: u32) -> &'static CStr {
    for &(exception_code, name) in FAULT_EXCEPTION_MAP {
        if exception_code == code {
            return name;
        }
    }
    c_str!("UNKNOWN")
}

/// Used to decode command stream fatal errors.
pub(crate) const FATAL_EXCEPTION_MAP: &[(u32, &CStr)] = &[
    (0x00, c_str!("OK")),
    (0x40, c_str!("CS_CONFIG_FAULT")),
    (0x44, c_str!("CS_ENDPOINT_FAULT")),
    (0x48, c_str!("CS_BUS_FAULT")),
    (0x49, c_str!("CS_INVALID_INSTRUCTION")),
    (0x4a, c_str!("CS_CALL_STACK_OVERFLOW")),
    (0x68, c_str!("FIRMWARE_INTERNAL_ERROR")),
];

pub(crate) fn fatal_exception_name(code: u32) -> &'static CStr {
    for &(exception_code, name) in FATAL_EXCEPTION_MAP {
        if exception_code == code {
            return name;
        }
    }
    c_str!("UNKNOWN")
}

pub(crate) mod constants {
    #![allow(dead_code)]
    use kernel::bits::bit_u32;
    use kernel::bits::genmask_u32;

    const CS_STATE_STOP: u32 = 0;

    const CS_STATE_START: u32 = 1;

    pub(crate) const CS_EXTRACT_EVENT: u32 = bit_u32(4);

    /// Enable idle events for sync/wait. If this is enabled, the CS is
    /// considered idle when it is stalled due to a sync/wait dependency.
    ///
    /// This will trigger an IDLE event and also raise an interrupt if the IDLE
    /// interrupt mask flag is also enabled.
    pub(crate) const CS_IDLE_SYNC_WAIT: u32 = bit_u32(8);

    /// Same as [`CS_IDLE_SYNC_WAIT`] but for protected mode.
    ///
    /// This will trigger an IDLE event and also raise an interrupt if the IDLE
    /// interrupt mask flag is also enabled.
    pub(crate) const CS_IDLE_PROTM_PENDING: u32 = bit_u32(9);

    /// Enable idle events for empty ring buffers.
    ///
    /// Note that if this is enabled, command streams stalled because their ring
    /// buffers are empty contribute to the IDLE event and interrupt.
    ///
    /// This will trigger an IDLE event and also raise an interrupt if the IDLE
    /// interrupt mask flag is also enabled.
    pub(crate) const CS_IDLE_EMPTY: u32 = bit_u32(10);

    /// Enable idle events for resource requests, i.e.: the stream is considered
    /// idle when it is waiting for the required resource requests to be
    /// allocated to it.
    ///
    /// This will trigger an IDLE event and also raise an interrupt if the IDLE
    /// interrupt mask flag is also enabled.
    pub(crate) const CS_IDLE_RESOURCE_REQ: u32 = bit_u32(11);

    /// Clear the tiler out-of-memory notification. This means that the CPU can
    /// be notified again that the tiler has run out of memory.
    ///
    /// Note that this is updated when the global doorbell is written.
    pub(crate) const CS_TILER_OOM: u32 = bit_u32(26);

    /// Clear the protected mode pending notification. This means that the CPU c
    /// an be notified again that the command stream is waiting for protected
    /// mode.
    ///
    /// Note that this is updated when the global doorbell is written.
    pub(crate) const CS_PROTM_PENDING: u32 = bit_u32(27);

    /// Clear the fatal error notification. This means that the CPU can be
    /// notified again that the command stream has encountered a non-recoverable
    /// error.
    ///
    /// Note that this is updated when the global doorbell is written.
    pub(crate) const CS_FATAL: u32 = bit_u32(30);

    /// Clear the fault notification. This means that the CPU can be notified
    /// again that the command stream has encountered a recoverable error.
    ///
    /// Note that this is updated when the global doorbell is written.
    pub(crate) const CS_FAULT: u32 = bit_u32(31);

    pub(crate) const CS_STATE_MASK: u32 = genmask_u32(2, 0);

    pub(crate) const CS_REQ_MASK: u32 = CS_STATE_MASK
        | CS_EXTRACT_EVENT
        | CS_IDLE_SYNC_WAIT
        | CS_IDLE_PROTM_PENDING
        | CS_IDLE_EMPTY
        | CS_IDLE_RESOURCE_REQ;

    pub(crate) const CS_EVT_MASK: u32 = CS_TILER_OOM | CS_PROTM_PENDING | CS_FATAL | CS_FAULT;
}

pub(crate) struct CommandStream {
    cs_id: usize,
    csg_id: usize,

    control_area: SharedSectionRange,
    input_area: SharedSectionRange,
    output_area: SharedSectionRange,

    state: StreamState,
}

impl CommandStream {
    pub(crate) fn init(
        glb_iface: &mut GlobalInterface,
        iface_offset: u32,
        csg_id: usize,
        cs_id: usize,
    ) -> Result<Self> {
        if iface_offset as usize + core::mem::size_of::<Self>()
            >= glb_iface.shared_section.lock().mem.size()
        {
            pr_err!("CSG interface would overrun the shared section");
            return Err(EINVAL);
        }

        let control_area = SharedSectionRange {
            shared_section: glb_iface.shared_section.clone(),
            start: iface_offset as usize,
            end: core::mem::size_of::<Control>(),
        };

        let control = Control::read(&control_area)?;

        let input_area =
            glb_iface.shared_range(control.input_va.into(), core::mem::size_of::<Input>())?;

        let output_area =
            glb_iface.shared_range(control.output_va.into(), core::mem::size_of::<Output>())?;

        Ok(CommandStream {
            cs_id,
            csg_id,
            control_area,
            input_area,
            output_area,
            state: StreamState::Stop,
        })
    }

    pub(crate) fn set_state(&mut self, state: StreamState) -> Result {
        self.input_request()?
            .update_reqs(state as u32, CS_STATE_MASK)?;

        self.state = state;
        Ok(())
    }

    /// Decode a fatal error.
    pub(crate) fn decode_fatal(&self) -> Result {
        let output = self.read_output()?;
        let exception_type = output.cs_fatal_exception_type();
        let exception_data = output.cs_fatal_exception_data();
        let exception_name = fatal_exception_name(exception_type);

        pr_warn!(
            "CSG slot: {} CS slot: {}\n\
             CS_FATAL.EXCEPTION_TYPE: 0x{:x} ({})\n\
             CS_FATAL.EXCEPTION_DATA: 0x{:x}\n\
             CS_FATAL.FATAL_INFO: 0x{:x}\n",
            self.csg_id,
            self.cs_id,
            exception_type,
            exception_name.to_str().unwrap_or("UNKNOWN"),
            exception_data,
            output.fatal_info,
        );

        Ok(())
    }

    pub(crate) fn decode_fault(&self) -> Result {
        let output = self.read_output()?;
        let exception_type = output.cs_fault_exception_type();
        let exception_data = output.cs_fault_exception_data();
        let exception_name = fault_exception_name(exception_type);

        pr_warn!(
            "CSG slot: {} CS slot: {}\n\
             CS_FAULT.EXCEPTION_TYPE: 0x{:x} ({})\n\
             CS_FAULT.EXCEPTION_DATA: 0x{:x}\n\
             CS_FAULT.FAULT_INFO: 0x{:x}\n",
            self.csg_id,
            self.cs_id,
            exception_type,
            exception_name.to_str().unwrap_or("UNKNOWN"),
            exception_data,
            output.fault_info,
        );

        Ok(())
    }
}

impl SharedSectionEntry for CommandStream {
    type Control = Control;
    type Input = Input;
    type Output = Output;

    fn read_control(&self) -> Result<Self::Control> {
        Control::read(&self.control_area)
    }

    fn write_control(&mut self, control: Self::Control) -> Result {
        control.write(&mut self.control_area)
    }

    fn read_input(&self) -> Result<Self::Input> {
        Input::read(&self.input_area)
    }

    fn write_input(&mut self, input: Self::Input) -> Result {
        input.write(&mut self.input_area)
    }

    fn read_output(&self) -> Result<Self::Output> {
        Output::read(&self.output_area)
    }

    fn input_request(&self) -> Result<RequestField> {
        Ok(RequestField::new(
            &self.input_area,
            core::mem::offset_of!(Input, req),
            core::mem::offset_of!(Output, ack),
        ))
    }
}

#[repr(C)]
pub(crate) struct Control {
    pub(crate) features: u32,
    pub(crate) input_va: u32,
    pub(crate) output_va: u32,
}

impl Control {
    /// Returns the number of work registers available in the command stream.
    pub(crate) fn work_regs(&self) -> u32 {
        (self.features & genmask_u32(7, 0)) + 1
    }

    /// Returns the number of scoreboards available in the command stream.
    pub(crate) fn scoreboards(&self) -> u32 {
        (self.features & genmask_u32(15, 8)) >> 8
    }

    /// Whether this command stream supports compute workloads.
    pub(crate) fn supports_compute(&self) -> bool {
        self.features & bit_u32(16) != 0
    }

    /// Whether this command stream supports fragment workloads.
    pub(crate) fn supports_fragment(&self) -> bool {
        self.features & bit_u32(17) != 0
    }

    /// Whether this command stream supports tiler workloads.
    pub(crate) fn supports_tiler(&self) -> bool {
        self.features & bit_u32(18) != 0
    }
}

#[repr(C)]
pub(crate) struct Input {
    pub(crate) req: u32,
    pub(crate) config: u32,
    pub(crate) reserved1: u32,
    pub(crate) ack_irq_mask: u32,
    pub(crate) ringbuf_base: u64,
    pub(crate) ringbuf_size: u32,
    pub(crate) reserved2: u32,
    pub(crate) heap_start: u64,
    pub(crate) heap_end: u64,
    pub(crate) ringbuf_input: u64,
    pub(crate) ringbuf_output: u64,
    pub(crate) instr_config: u32,
    pub(crate) instrbuf_size: u32,
    pub(crate) instrbuf_base: u64,
    pub(crate) instrbuf_offset_ptr: u64,
}

impl Input {
    pub(crate) fn set_priority(&mut self, priority: u8) -> Result {
        if priority >= 16 {
            pr_err!("Invalid priority value: {}", priority);
            return Err(EINVAL);
        }

        self.config |= u32::from(priority) & genmask_u32(3, 0);
        Ok(())
    }

    pub(crate) fn set_doorbell_id(&mut self, doorbell_id: u32) -> Result {
        if doorbell_id == 0 || doorbell_id > 63 {
            pr_err!("Invalid doorbell value: {}", doorbell_id);
            return Err(EINVAL);
        }

        self.config |= (doorbell_id << 8) & genmask_u32(15, 8);
        Ok(())
    }
}

#[repr(C)]
pub(crate) struct Output {
    pub(crate) ack: u32,
    pub(crate) reserved1: [u32; 15],
    pub(crate) status_cmd_ptr: u64,
    pub(crate) status_wait: u32,
    pub(crate) status_req_resource: u32,
    pub(crate) status_wait_sync_ptr: u64,
    pub(crate) status_wait_sync_value: u32,
    pub(crate) status_scoreboards: u32,
    pub(crate) status_blocked_reason: u32,
    pub(crate) status_wait_sync_value_hi: u32,
    pub(crate) reserved2: [u32; 6],
    pub(crate) fault: u32,
    pub(crate) fatal: u32,
    pub(crate) fault_info: u64,
    pub(crate) fatal_info: u64,
    pub(crate) reserved3: [u32; 10],
    pub(crate) heap_vt_start: u32,
    pub(crate) heap_vt_end: u32,
    pub(crate) reserved4: u32,
    pub(crate) heap_frag_end: u32,
    pub(crate) heap_address: u64,
}

impl Output {
    pub(crate) fn cs_fault_exception_type(&self) -> u32 {
        self.fault & genmask_u32(7, 0)
    }

    pub(crate) fn cs_fault_exception_data(&self) -> u32 {
        self.fault >> 8 & genmask_u32(23, 0)
    }

    pub(crate) fn cs_fatal_exception_type(&self) -> u32 {
        self.fatal & genmask_u32(7, 0)
    }

    pub(crate) fn cs_fatal_exception_data(&self) -> u32 {
        self.fatal >> 8 & genmask_u32(23, 0)
    }

    pub(crate) fn status_wait(&self) -> Result<StatusWait> {
        let status = self.status_wait;

        let sb_mask = status & genmask_u32(15, 0);
        let sb_source = (status & genmask_u32(19, 16)) >> 16;
        let gt = (status & bit_u32(24)) != 0;
        let progress_wait = (status & bit_u32(28)) != 0;
        let protm_pend = (status & bit_u32(29)) != 0;
        let sync64 = (status & bit_u32(30)) != 0;
        let sync_wait = (status & bit_u32(31)) != 0;

        Ok(StatusWait {
            sb_mask,
            sb_source,
            gt,
            progress_wait,
            protm_pend,
            sync64,
            sync_wait,
        })
    }

    pub(crate) fn blocked_reason(&self) -> Result<BlockedReason> {
        let reason = self.status_blocked_reason & genmask_u32(3, 0);

        let blocked_reason = match reason {
            0 => BlockedReason::Unblocked,
            1 => BlockedReason::SbWait,
            2 => BlockedReason::ProgressWait,
            3 => BlockedReason::SyncWait,
            5 => BlockedReason::Deferred,
            6 => BlockedReason::Resource,
            7 => BlockedReason::Flush,
            _ => return Err(EINVAL),
        };

        Ok(blocked_reason)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum StreamState {
    /// Stop the command stream. The execution of command stream instructions
    /// stops and any job active runs to completion before the STOP request
    /// completes (unless terminated at the CSG level).
    Stop,
    /// Initialize the command stream and start execution.
    Start,
}

pub(crate) struct StatusWait {
    /// Mask denoting which scoreboard entries are being waited on by this
    /// command stream.
    sb_mask: u32,

    /// Source of the scoreboard wait status, if any.
    sb_source: u32,

    /// Whether the condition is a greater-than comparison.
    gt: bool,

    /// Whether the command stream is waiting for a PROGRESS_WAIT instruction.
    progress_wait: bool,

    /// Whether the command stream is waiting for protected mode execution.
    protm_pend: bool,

    /// Whether the sync object is 32 or 64 bits wide.
    sync64: bool,

    /// Whether the command stream is waiting for a SYNC_WAIT instruction.
    sync_wait: bool,
}

pub(crate) enum BlockedReason {
    /// The command stream is not blocked.
    Unblocked = 0,

    /// Blocked on scoreboards.
    SbWait = 1,

    /// Blocked on PROGRESS_WAIT instruction.
    ProgressWait = 2,

    /// Blocked on SYNC_WAIT32 or SYNC_WAIT64 instruction.
    SyncWait = 3,

    /// Awaiting storage for a deferred instruction.
    Deferred = 5,

    /// Waiting for resource allocation.
    Resource = 6,

    /// Waiting on the completion of a synchronous FLUSH_CACHE2 instruction.
    Flush = 7,
}

impl_shared_section_rw!(Control);
impl_shared_section_rw!(Input);
impl_shared_section_read!(Output);

/// The input interface for the ring buffer.
///
/// This area is only written by the CPU.
///
/// [`RingBufferInput::insert`] and [`RingBufferOutput::extract`] control the
/// ends of the ring buffer; if both are identical, the buffer is considered
/// empty.
#[repr(C)]
pub(crate) struct RingBufferInput {
    /// Offset of the input point into the ring buffer.
    ///
    /// New instructions are appended to this offset by the CPU.
    pub(crate) insert: u64,

    /// Used to initialize the initial extract offset for the ring buffer.
    pub(crate) extract_init: u64,
}

/// The output interface for the ring buffer.
///
/// This area is only written by CSF.
///
/// [`RingBufferInput::insert`] and [`RingBufferOutput::extract`] control the
/// ends of the ring buffer; if both are identical, the buffer is considered
/// empty.
#[repr(C)]
pub(crate) struct RingBufferOutput {
    /// Offset of the extract point from the ring buffer.
    ///
    /// Ahead of this point, all instructions have been consumed by CSF, so this
    /// provides an indication of free space for inserting new instructions in
    /// the buffer. Locations in the ring buffer before this point can be
    /// reused.
    pub(crate) extract: u64,

    /// Indicates whether the command stream is active on hardware.
    pub(crate) active: u32,
}
