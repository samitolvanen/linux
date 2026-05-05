// SPDX-License-Identifier: GPL-2.0 or MIT

//! Command stream group interface implementation.
//!
//! This module owns the runtime CSG interface state discovered through the
//! firmware global interface. It keeps the CSG-to-CS discovery and suspend-size
//! queries out of the older monolithic interfaces file.

use kernel::{
    io::Io,
    prelude::*,
};

use super::cs::CsInterface;
use crate::fw::{
    interfaces::{
        FwInterface,
        GROUP_INPUT_VA,
        GROUP_OUTPUT_VA,
        GROUP_PROTM_SUSPEND_SIZE,
        GROUP_STREAM_NUM,
        GROUP_STREAM_STRIDE,
        GROUP_SUSPEND_SIZE,
        CSG_CONTROL_BLOCK_SIZE,
        CSG_INPUT_BLOCK_SIZE,
        CSG_OUTPUT_BLOCK_SIZE,
        CS_CONTROL_BLOCK_SIZE,
    },
    Section,
    MAX_CS,
};

/// Offset from GLB_CONTROL_BLOCK start to the first GROUP_CONTROL block.
const CSG_GROUP_CONTROL_OFFSET: usize = 0x1000;

enum CsgInterfaceState {
    Disabled,
    Enabled(EnabledCsgInterface),
}

struct EnabledCsgInterface {
    csg_control: FwInterface<CSG_CONTROL_BLOCK_SIZE>,
    #[expect(dead_code)]
    csg_input: FwInterface<CSG_INPUT_BLOCK_SIZE>,
    #[expect(dead_code)]
    csg_output: FwInterface<CSG_OUTPUT_BLOCK_SIZE>,
    cs_stride: usize,
    cs_num: usize,
    cs: KVec<CsInterface>,
}

pub(in super::super) struct CsgInterface {
    state: CsgInterfaceState,
    #[expect(dead_code)]
    csg_idx: usize,
}

impl CsgInterface {
    pub(in super::super) fn new(csg_idx: usize) -> Result<Self> {
        Ok(Self {
            state: CsgInterfaceState::Disabled,
            csg_idx,
        })
    }

    pub(in super::super) fn enable(
        &mut self,
        shared_section: &Section,
        csg_idx: usize,
        csg_stride: usize,
    ) -> Result {
        let vmap = shared_section.mem.bo.owned_vmap::<0>()?;
        let va_range = shared_section.mem.va_range();

        let csg_control_offset = CSG_GROUP_CONTROL_OFFSET + csg_idx * csg_stride;
        let csg_control_va = va_range.start + csg_control_offset as u64;

        let csg_control =
            FwInterface::<CSG_CONTROL_BLOCK_SIZE>::new(&vmap, &va_range, csg_control_va)?;

        let input_va = csg_control.read(GROUP_INPUT_VA).value().get();
        let csg_input =
            FwInterface::<CSG_INPUT_BLOCK_SIZE>::new(&vmap, &va_range, input_va.into())?;

        let output_va = csg_control.read(GROUP_OUTPUT_VA).value().get();
        let csg_output =
            FwInterface::<CSG_OUTPUT_BLOCK_SIZE>::new(&vmap, &va_range, output_va.into())?;

        let cs_stride = csg_control.read(GROUP_STREAM_STRIDE).value().get() as usize;
        if cs_stride < CS_CONTROL_BLOCK_SIZE {
            pr_err!(
                "CS stride {} is smaller than control block size {}\n",
                cs_stride,
                CS_CONTROL_BLOCK_SIZE
            );
            return Err(EINVAL);
        }

        let cs_num = csg_control.read(GROUP_STREAM_NUM).value().get();
        if cs_num as usize > MAX_CS {
            pr_err!(
                "Too many CS: hardware reports {}, max supported {}\n",
                cs_num,
                MAX_CS
            );
            return Err(EINVAL);
        }

        self.state = CsgInterfaceState::Enabled(EnabledCsgInterface {
            csg_control,
            csg_input,
            csg_output,
            cs_stride,
            cs_num: cs_num as usize,
            cs: KVec::with_capacity(cs_num as usize, GFP_KERNEL)?,
        });

        self.init_cs(shared_section, csg_control_offset)
    }

    fn init_cs(&mut self, shared_section: &Section, csg_control_offset: usize) -> Result {
        let enabled = match &mut self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        for cs_idx in 0..enabled.cs_num {
            let mut cs = CsInterface::new(cs_idx)?;
            cs.enable(shared_section, csg_control_offset, cs_idx, enabled.cs_stride)?;
            enabled.cs.push(cs, GFP_KERNEL)?;
        }

        Ok(())
    }

    pub(in super::super) fn suspend_buf_sizes(&self) -> Result<(u32, u32)> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        let suspend_size = enabled.csg_control.read(GROUP_SUSPEND_SIZE).value().get();
        let protm_suspend_size = enabled
            .csg_control
            .read(GROUP_PROTM_SUSPEND_SIZE)
            .value()
            .get();

        Ok((suspend_size, protm_suspend_size))
    }

    pub(in super::super) fn cs(&self, index: usize) -> Option<&CsInterface> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return None,
        };

        enabled.cs.get(index)
    }

    pub(in super::super) fn cs_slot_count(&self) -> Result<u32> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_num as u32)
    }
}