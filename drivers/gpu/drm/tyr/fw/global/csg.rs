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

use super::{
    cs::CsInterface,
    SharedSectionInfo,
};
use crate::fw::{
    interfaces::{
        CSG_ACK,
        CSG_CONTROL_BLOCK_SIZE,
        CSG_DB_ACK,
        CSG_DB_REQ,
        CSG_INPUT_BLOCK_SIZE,
        CSG_IRQ_ACK,
        CSG_IRQ_REQ,
        CSG_OUTPUT_BLOCK_SIZE,
        CSG_REQ,
        FwInterface,
        GROUP_INPUT_VA,
        GROUP_OUTPUT_VA,
        GROUP_PROTM_SUSPEND_SIZE,
        GROUP_STREAM_NUM,
        GROUP_STREAM_STRIDE,
        GROUP_SUSPEND_SIZE,
        CS_CONTROL_BLOCK_SIZE,
    },
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
    csg_input: FwInterface<CSG_INPUT_BLOCK_SIZE>,
    csg_output: FwInterface<CSG_OUTPUT_BLOCK_SIZE>,
    cs_stride: usize,
    cs_num: usize,
    cs: KVec<CsInterface>,
}

pub(crate) struct CsgInterface {
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

    pub(super) fn enable(
        &mut self,
        shared_section: &SharedSectionInfo,
        csg_idx: usize,
        csg_stride: usize,
    ) -> Result {
        let csg_control_offset = CSG_GROUP_CONTROL_OFFSET + csg_idx * csg_stride;
        let csg_control_va = shared_section.va_range.start + csg_control_offset as u64;

        let csg_control =
            FwInterface::<CSG_CONTROL_BLOCK_SIZE>::new(
                &shared_section.vmap,
                &shared_section.va_range,
                csg_control_va,
            )?;

        let input_va = csg_control.read(GROUP_INPUT_VA).value().get();
        let csg_input = FwInterface::<CSG_INPUT_BLOCK_SIZE>::new(
            &shared_section.vmap,
            &shared_section.va_range,
            input_va.into(),
        )?;

        let output_va = csg_control.read(GROUP_OUTPUT_VA).value().get();
        let csg_output = FwInterface::<CSG_OUTPUT_BLOCK_SIZE>::new(
            &shared_section.vmap,
            &shared_section.va_range,
            output_va.into(),
        )?;

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

    fn init_cs(&mut self, shared_section: &SharedSectionInfo, csg_control_offset: usize) -> Result {
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

    #[allow(dead_code)]
    pub(crate) fn cs_mut(&mut self, index: usize) -> Option<&mut CsInterface> {
        let enabled = match &mut self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return None,
        };

        enabled.cs.get_mut(index)
    }

    #[allow(dead_code)]
    pub(in super::super) fn read_input_req(&self) -> Result<CSG_REQ> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_input.read(CSG_REQ))
    }

    #[allow(dead_code)]
    pub(in super::super) fn write_input_req(&self, req: CSG_REQ) {
        if let CsgInterfaceState::Enabled(enabled) = &self.state {
            enabled.csg_input.write(CSG_REQ, req);
        }
    }

    #[allow(dead_code)]
    pub(crate) fn read_input_db_req(&self) -> Result<CSG_DB_REQ> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_input.read(CSG_DB_REQ))
    }

    #[allow(dead_code)]
    pub(crate) fn write_input_db_req(&self, req: CSG_DB_REQ) {
        if let CsgInterfaceState::Enabled(enabled) = &self.state {
            enabled.csg_input.write(CSG_DB_REQ, req);
        }
    }

    #[allow(dead_code)]
    pub(crate) fn read_input_irq_ack(&self) -> Result<CSG_IRQ_ACK> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_input.read(CSG_IRQ_ACK))
    }

    #[allow(dead_code)]
    pub(crate) fn write_input_irq_ack(&self, ack: CSG_IRQ_ACK) {
        if let CsgInterfaceState::Enabled(enabled) = &self.state {
            enabled.csg_input.write(CSG_IRQ_ACK, ack);
        }
    }

    #[allow(dead_code)]
    pub(in super::super) fn read_output_ack(&self) -> Result<CSG_ACK> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_output.read(CSG_ACK))
    }

    #[allow(dead_code)]
    pub(in super::super) fn read_output_db_ack(&self) -> Result<CSG_DB_ACK> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_output.read(CSG_DB_ACK))
    }

    #[allow(dead_code)]
    pub(crate) fn read_output_irq_req(&self) -> Result<CSG_IRQ_REQ> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_output.read(CSG_IRQ_REQ))
    }

    pub(in super::super) fn cs_slot_count(&self) -> Result<u32> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(enabled) => enabled,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_num as u32)
    }
}