// SPDX-License-Identifier: GPL-2.0 or MIT

//! Command stream interface implementation.
//!
//! This module owns the runtime CS interface state discovered through the
//! firmware global interface. Keeping it here lets the GLB-facing code stop
//! carrying per-CS control-block details inline.

use kernel::{
    io::Io,
    prelude::*,
};

use super::SharedSectionInfo;
use crate::fw::{
    interfaces::{
        CS_ACK,
        FwInterface,
        CS_REQ,
        CS_TILER_HEAP_END,
        CS_TILER_HEAP_START,
        STREAM_FEATURES,
        STREAM_INPUT_VA,
        STREAM_OUTPUT_VA,
        CS_CONTROL_BLOCK_SIZE,
        CS_KERNEL_INPUT_BLOCK_SIZE,
        CS_KERNEL_OUTPUT_BLOCK_SIZE,
    },
};

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

pub(in super::super) struct CsInterface {
    state: CsInterfaceState,
    #[expect(dead_code)]
    cs_idx: usize,
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
        let cs_control_va = shared_section.va_range.start
            + csg_control_offset as u64
            + cs_control_offset as u64;

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

        Ok(enabled.cs_control.read(STREAM_FEATURES).work_registers().get())
    }

    pub(in super::super) fn scoreboards(&self) -> Result<u32> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_control.read(STREAM_FEATURES).scoreboards().get())
    }

    #[allow(dead_code)]
    pub(in super::super) fn read_input_req(&self) -> Result<CS_REQ> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_input.read(CS_REQ))
    }

    #[allow(dead_code)]
    pub(in super::super) fn write_input_req(&self, req: CS_REQ) {
        if let CsInterfaceState::Enabled(enabled) = &self.state {
            enabled.cs_input.write(CS_REQ, req);
        }
    }

    #[allow(dead_code)]
    pub(in super::super) fn write_tiler_heap(
        &self,
        start: CS_TILER_HEAP_START,
        end: CS_TILER_HEAP_END,
    ) {
        if let CsInterfaceState::Enabled(enabled) = &self.state {
            enabled
                .cs_input
                .write(CS_TILER_HEAP_START, start);
            enabled
                .cs_input
                .write(CS_TILER_HEAP_END, end);
        }
    }

    #[allow(dead_code)]
    pub(in super::super) fn read_output_ack(&self) -> Result<CS_ACK> {
        let enabled = match &self.state {
            CsInterfaceState::Enabled(enabled) => enabled,
            CsInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_output.read(CS_ACK))
    }
}
