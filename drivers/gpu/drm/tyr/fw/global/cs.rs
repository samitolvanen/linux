// SPDX-License-Identifier: GPL-2.0 or MIT

//! Command stream interface implementation.
//!
//! This module owns the runtime CS interface state discovered through the
//! firmware global interface. Keeping it here lets the GLB-facing code stop
//! carrying per-CS control-block details inline.

use kernel::{
    device::Device,
    io::{
        Io,
        Region, //
    },
    prelude::*, //
};

use super::SharedSectionInfo;
use crate::fw::interfaces::{
    CsState,
    FwInterface,
    CS_ACK,
    CS_CONTROL_BLOCK_SIZE,
    CS_HEAP_ADDRESS,
    CS_HEAP_FRAG_END,
    CS_HEAP_VT_END,
    CS_HEAP_VT_START,
    CS_KERNEL_INPUT_BLOCK_SIZE,
    CS_KERNEL_OUTPUT_BLOCK_SIZE,
    CS_REQ,
    CS_TILER_HEAP_END,
    CS_TILER_HEAP_START,
    STREAM_FEATURES,
    STREAM_INPUT_VA,
    STREAM_OUTPUT_VA, //
};
use crate::fw::region::FwRegion;

/// Offset from GROUP_CONTROL_BLOCK start to the first STREAM_CONTROL block.
const CS_CONTROL_OFFSET: usize = 0x40;

/// State of a CS interface.
enum CsInterfaceState {
    /// Interface is not yet initialized.
    Disabled,
    /// Interface is initialized and operational.
    Enabled(EnabledCsInterface),
}

/// When enabled, a CS Interface has control, input, and output system memory interfaces.
struct EnabledCsInterface {
    /// Control block interface - provides CS capabilities and configuration.
    cs_control: FwInterface<Region<CS_CONTROL_BLOCK_SIZE>>,
    /// Input block interface - driver writes CS requests here.
    cs_input: FwInterface<FwRegion<CS_KERNEL_INPUT_BLOCK_SIZE>>,
    /// Output block interface - firmware writes CS acknowledgements here.
    cs_output: FwInterface<FwRegion<CS_KERNEL_OUTPUT_BLOCK_SIZE>>,
}

/// Command Stream Interface
///
/// The CS interface controls operations for a specific CS.
pub(crate) struct CsInterface {
    /// Current interface state (Disabled or Enabled).
    state: CsInterfaceState,
    /// CS identifier/index number.
    #[expect(dead_code)]
    cs_idx: usize,
}

/// Firmware-written tiler heap state for a command stream.
pub(crate) struct HeapOutputState {
    pub(crate) heap_address: u64,
    pub(crate) vt_start: u32,
    pub(crate) vt_end: u32,
    pub(crate) frag_end: u32,
}

impl CsInterface {
    /// Creates a new disabled CS interface.
    pub(super) fn new(cs_idx: usize) -> Result<Self> {
        Ok(Self {
            state: CsInterfaceState::Disabled,
            cs_idx,
        })
    }

    /// Enables the CS interface.
    ///
    /// This calculates the runtime offset of this CS's control block and creates
    /// a bounded interface to access it. It then reads the input/output interface
    /// addresses from the CS control block.
    pub(super) fn enable(
        &mut self,
        dev: &Device,
        shared_section: &SharedSectionInfo,
        csg_control_offset: usize,
        cs_idx: usize,
        cs_stride: usize,
    ) -> Result {
        let vmap = &shared_section.vmap;
        let va_range = &shared_section.va_range;

        // Calculate the runtime offset for this CS's control block.
        let cs_control_offset = CS_CONTROL_OFFSET + cs_idx * cs_stride;

        // The CS control block's MCU virtual address is relative to the shared section start.
        let cs_control_va = va_range.start + csg_control_offset as u64 + cs_control_offset as u64;

        // Create a bounded interface for this CS's control block at the calculated address.
        let cs_control =
            FwInterface::<Region<CS_CONTROL_BLOCK_SIZE>>::new(dev, vmap, va_range, cs_control_va)?;

        // Read the input and output VAs from the CS control block.
        let input_va = cs_control.read(STREAM_INPUT_VA).value().get();
        let cs_input = FwInterface::<FwRegion<CS_KERNEL_INPUT_BLOCK_SIZE>>::new(
            dev,
            vmap,
            va_range,
            input_va.into(),
        )?;

        let output_va = cs_control.read(STREAM_OUTPUT_VA).value().get();
        let cs_output = FwInterface::<FwRegion<CS_KERNEL_OUTPUT_BLOCK_SIZE>>::new(
            dev,
            vmap,
            va_range,
            output_va.into(),
        )?;

        let enabled = EnabledCsInterface {
            cs_control,
            cs_input,
            cs_output,
        };

        self.state = CsInterfaceState::Enabled(enabled);

        Ok(())
    }

    pub(in super::super) fn work_regs(&self) -> Result<u32> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(e) => e,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled
            .cs_control
            .read(STREAM_FEATURES)
            .work_registers()
            .get()
            + 1)
    }

    pub(in super::super) fn scoreboards(&self) -> Result<u32> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(e) => e,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_control.read(STREAM_FEATURES).scoreboards().get())
    }

    pub(crate) fn read_input_req(&self) -> Result<CS_REQ> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(e) => e,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_input.read(CS_REQ))
    }

    pub(crate) fn write_input_req(&self, req: CS_REQ) {
        if let CsInterfaceState::Enabled(enabled) = &self.state {
            enabled.cs_input.write(CS_REQ, req);
        }
    }

    /// Clears the `CS_REQ.state` field (sets it to `CsState::Stop`).
    ///
    /// No doorbell is rung. The reset takes effect on the next
    /// `CSG_REQ.state = Start` transition.
    ///
    /// Returns `EINVAL` if the interface is not enabled.
    pub(crate) fn clear_input_req_state(&self) -> Result {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(e) => e,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        let cur = enabled.cs_input.read(CS_REQ);
        enabled
            .cs_input
            .write(CS_REQ, cur.with_state(CsState::Stop));
        Ok(())
    }

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
        )
    }

    pub(crate) fn read_output_ack(&self) -> Result<CS_ACK> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(e) => e,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_output.read(CS_ACK))
    }

    pub(crate) fn read_heap_output_state(&self) -> Result<HeapOutputState> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(e) => e,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(HeapOutputState {
            heap_address: enabled.cs_output.read(CS_HEAP_ADDRESS).pointer().get(),
            vt_start: enabled.cs_output.read(CS_HEAP_VT_START).value().get(),
            vt_end: enabled.cs_output.read(CS_HEAP_VT_END).value().get(),
            frag_end: enabled.cs_output.read(CS_HEAP_FRAG_END).value().get(),
        })
    }
}
