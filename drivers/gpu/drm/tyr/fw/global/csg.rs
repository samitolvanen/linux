// SPDX-License-Identifier: GPL-2.0 or MIT

//! Command stream group interface implementation.
//!
//! This module owns the runtime CSG interface state discovered through the
//! firmware global interface. It keeps the CSG-to-CS discovery and suspend-size
//! queries out of the older monolithic interfaces file.

use kernel::{
    device::Device,
    io::{
        Io,
        Region, //
    },
    prelude::*, //
};

use super::{
    cs::CsInterface,
    SharedSectionInfo, //
};
use crate::fw::{
    interfaces::{
        FwInterface,
        CSG_ACK,
        CSG_CONTROL_BLOCK_SIZE,
        CSG_DB_ACK,
        CSG_DB_REQ,
        CSG_INPUT_BLOCK_SIZE,
        CSG_IRQ_ACK,
        CSG_IRQ_REQ,
        CSG_OUTPUT_BLOCK_SIZE,
        CSG_REQ,
        CS_CONTROL_BLOCK_SIZE,
        GROUP_INPUT_VA,
        GROUP_OUTPUT_VA,
        GROUP_PROTM_SUSPEND_SIZE,
        GROUP_STREAM_NUM,
        GROUP_STREAM_STRIDE,
        GROUP_SUSPEND_SIZE, //
    },
    region::FwRegion,
    MAX_CS, //
};

/// Offset from GLB_CONTROL_BLOCK start to the first GROUP_CONTROL block.
const CSG_GROUP_CONTROL_OFFSET: usize = 0x1000;

/// CSG software priority bands.
///
/// Mirrors `enum drm_panthor_group_priority` from the Panthor UAPI
/// (Low / Medium / High / Realtime). The integer discriminants match
/// the UAPI values so a `TryFrom<u8>` round-trips a UAPI integer
/// directly. The scheduler walks priorities high-to-low and uses
/// `Priority` as an array index, so the discriminant values must
/// stay stable.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u8)]
pub(crate) enum Priority {
    Low = 0,
    Medium = 1,
    High = 2,
    RealTime = 3,
}

impl Priority {
    /// Number of distinct software priority bands.
    pub(crate) const fn num_priorities() -> usize {
        Self::RealTime as usize + 1
    }
}

impl TryFrom<u8> for Priority {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Priority::Low),
            1 => Ok(Priority::Medium),
            2 => Ok(Priority::High),
            3 => Ok(Priority::RealTime),
            _ => Err(EINVAL),
        }
    }
}

/// State of a CSG interface.
enum CsgInterfaceState {
    /// Interface is not yet initialized.
    Disabled,
    /// Interface is initialized and operational.
    Enabled(EnabledCsgInterface),
}

/// When enabled, a CSG Interface has control, input, and output system memory interfaces.
struct EnabledCsgInterface {
    /// Control block interface - provides CSG capabilities and configuration.
    csg_control: FwInterface<Region<CSG_CONTROL_BLOCK_SIZE>>,
    /// Input block interface - driver writes CSG requests here.
    csg_input: FwInterface<FwRegion<CSG_INPUT_BLOCK_SIZE>>,
    /// Output block interface - firmware writes CSG acknowledgements here.
    csg_output: FwInterface<Region<CSG_OUTPUT_BLOCK_SIZE>>,
    /// Runtime stride between CS control blocks (read from GROUP_STREAM_STRIDE).
    cs_stride: usize,
    /// Number of CS interfaces reported by hardware for this CSG.
    cs_num: usize,
    /// Discovered CS interfaces.
    cs: KVec<CsInterface>,
}

/// Command Stream Group Interface
///
/// The CSG interface controls operations for a specific CSG.
pub(crate) struct CsgInterface {
    /// Current interface state (Disabled or Enabled).
    state: CsgInterfaceState,
    /// CSG identifier/index number.
    #[expect(dead_code)]
    csg_idx: usize,
}

impl CsgInterface {
    /// Creates a new disabled CSG interface.
    pub(in super::super) fn new(csg_idx: usize) -> Result<Self> {
        Ok(Self {
            state: CsgInterfaceState::Disabled,
            csg_idx,
        })
    }

    /// Enables the CSG interface.
    ///
    /// This calculates the runtime offset of this CSG's control block and creates
    /// a bounded interface to access it. It then reads the input/output interface
    /// addresses from the CSG control block.
    pub(super) fn enable(
        &mut self,
        dev: &Device,
        shared_section: &SharedSectionInfo,
        csg_idx: usize,
        csg_stride: usize,
    ) -> Result {
        let vmap = &shared_section.vmap;
        let va_range = &shared_section.va_range;

        // Calculate the runtime offset for this CSG's control block.
        // The CSG control blocks start at CSG_GROUP_CONTROL_OFFSET from the GLB control block,
        // with each CSG spaced by csg_stride bytes.
        let csg_control_offset = CSG_GROUP_CONTROL_OFFSET + csg_idx * csg_stride;

        // The CSG control block's MCU virtual address is relative to the shared section start.
        let csg_control_va = va_range.start + csg_control_offset as u64;

        // Create a bounded interface for this CSG's control block at the calculated address.
        let csg_control = FwInterface::<Region<CSG_CONTROL_BLOCK_SIZE>>::new(
            dev,
            vmap,
            va_range,
            csg_control_va,
        )?;

        // Read the input and output VAs from the CSG control block.
        let input_va = csg_control.read(GROUP_INPUT_VA).value().get();
        let csg_input = FwInterface::<FwRegion<CSG_INPUT_BLOCK_SIZE>>::new(
            dev,
            vmap,
            va_range,
            input_va.into(),
        )?;

        let output_va = csg_control.read(GROUP_OUTPUT_VA).value().get();
        let csg_output = FwInterface::<Region<CSG_OUTPUT_BLOCK_SIZE>>::new(
            dev,
            vmap,
            va_range,
            output_va.into(),
        )?;

        // Read the runtime stride between CS control blocks.
        let cs_stride = csg_control.read(GROUP_STREAM_STRIDE).value().get() as usize;

        if cs_stride < CS_CONTROL_BLOCK_SIZE {
            dev_err!(
                dev,
                "CS stride {} is smaller than control block size {}",
                cs_stride,
                CS_CONTROL_BLOCK_SIZE
            );
            return Err(EINVAL);
        }

        // Read how many CS interfaces exist for this CSG.
        let cs_num = csg_control.read(GROUP_STREAM_NUM).value().get();

        // Validate that the hardware doesn't report more CS than we support.
        if cs_num as usize > MAX_CS {
            dev_err!(
                dev,
                "Too many CS: hardware reports {}, max supported {}",
                cs_num,
                MAX_CS
            );
            return Err(EINVAL);
        }

        let enabled = EnabledCsgInterface {
            csg_control,
            csg_input,
            csg_output,
            cs_stride,
            cs_num: cs_num as usize,
            cs: KVec::with_capacity(cs_num as usize, GFP_KERNEL)?,
        };

        self.state = CsgInterfaceState::Enabled(enabled);
        self.init_cs(dev, shared_section, csg_control_offset)?;
        Ok(())
    }

    /// Initialize and discover CS interfaces.
    ///
    /// This uses the previously read CS count to create and enable each CS interface.
    fn init_cs(
        &mut self,
        dev: &Device,
        shared_section: &SharedSectionInfo,
        csg_control_offset: usize,
    ) -> Result {
        let enabled = match &mut self.state {
            CsgInterfaceState::Enabled(e) => e,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        for cs_idx in 0..enabled.cs_num {
            // Create and enable the CS interface.
            let mut cs = CsInterface::new(cs_idx)?;
            cs.enable(
                dev,
                shared_section,
                csg_control_offset,
                cs_idx,
                enabled.cs_stride,
            )?;

            enabled.cs.push(cs, GFP_KERNEL)?;
        }

        Ok(())
    }

    pub(in super::super) fn suspend_buf_sizes(&self) -> Result<(u32, u32)> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(e) => e,
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
            CsgInterfaceState::Enabled(e) => e,
            CsgInterfaceState::Disabled => return None,
        };

        enabled.cs.get(index)
    }

    pub(crate) fn cs_mut(&mut self, index: usize) -> Option<&mut CsInterface> {
        let enabled = match &mut self.state {
            CsgInterfaceState::Enabled(e) => e,
            CsgInterfaceState::Disabled => return None,
        };

        enabled.cs.get_mut(index)
    }

    #[expect(dead_code)]
    pub(in super::super) fn read_input_req(&self) -> Result<CSG_REQ> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(e) => e,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_input.read(CSG_REQ))
    }

    #[expect(dead_code)]
    pub(in super::super) fn write_input_req(&self, req: CSG_REQ) {
        if let CsgInterfaceState::Enabled(enabled) = &self.state {
            enabled.csg_input.write(CSG_REQ, req);
        }
    }

    pub(crate) fn read_input_db_req(&self) -> Result<CSG_DB_REQ> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(e) => e,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_input.read(CSG_DB_REQ))
    }

    pub(crate) fn write_input_db_req(&self, req: CSG_DB_REQ) {
        if let CsgInterfaceState::Enabled(enabled) = &self.state {
            enabled.csg_input.write(CSG_DB_REQ, req);
        }
    }

    pub(crate) fn read_input_irq_ack(&self) -> Result<CSG_IRQ_ACK> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(e) => e,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_input.read(CSG_IRQ_ACK))
    }

    pub(crate) fn write_input_irq_ack(&self, ack: CSG_IRQ_ACK) {
        if let CsgInterfaceState::Enabled(enabled) = &self.state {
            enabled.csg_input.write(CSG_IRQ_ACK, ack);
        }
    }

    #[expect(dead_code)]
    pub(in super::super) fn read_output_ack(&self) -> Result<CSG_ACK> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(e) => e,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_output.read(CSG_ACK))
    }

    pub(crate) fn read_output_db_ack(&self) -> Result<CSG_DB_ACK> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(e) => e,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_output.read(CSG_DB_ACK))
    }

    pub(crate) fn read_output_irq_req(&self) -> Result<CSG_IRQ_REQ> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(e) => e,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.csg_output.read(CSG_IRQ_REQ))
    }

    pub(in super::super) fn cs_slot_count(&self) -> Result<u32> {
        let enabled = match &self.state {
            CsgInterfaceState::Enabled(e) => e,
            CsgInterfaceState::Disabled => return Err(EINVAL),
        };

        Ok(enabled.cs_num as u32)
    }
}
