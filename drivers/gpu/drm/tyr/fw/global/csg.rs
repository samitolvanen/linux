// SPDX-License-Identifier: GPL-2.0 or MIT

//! Command stream group (CSG) code.
//!
//! A CSG is a group of command streams (CS) for a given context. They can be
//! assigned to a single process at a time.
//!
//! A CSG exposes a given number of command streams, these are queues where
//! actual work can be scheduled, provided that all resources for a given
//! workload are available.
//!
//! The group is assigned an AS slot when it is activated. This address space is
//! shared between all CS's in a CSG. Furthermore, all CS's in a group are
//! suspended and resumed together, i.e.: as a single unit.
//!
//! A CSG is usually used to back a UMD queue abstraction, like a VkQueue, for
//! example.
//!
//! Command stream groups are discovered using the global interface's control
//! area.

use kernel::bits::bit_u32;
use kernel::kvec;
use kernel::prelude::*;

use crate::fw::global::cs::CommandStream;
use crate::fw::impl_shared_section_read;
use crate::fw::impl_shared_section_rw;
use crate::fw::GlobalInterface;
use crate::fw::RequestField;
use crate::fw::SharedSectionEntry;
use crate::fw::SharedSectionRange;
use constants::*;

/// Maximum number of command stream groups in all architectures so far.
pub(crate) const MAX_CSGS: u32 = 31;

pub(crate) mod constants {
    #![allow(dead_code)]
    use kernel::bits::bit_u32;
    use kernel::bits::genmask_u32;

    pub(crate) const CSG_STATE_MASK: u32 = genmask_u32(2, 0);
    const CSG_STATE_TERMINATE: u32 = 0;
    const CSG_STATE_START: u32 = 1;
    const CSG_STATE_SUSPEND: u32 = 2;
    const CSG_STATE_RESUME: u32 = 3;

    pub(crate) const CSG_ENDPOINT_CONFIG: u32 = bit_u32(4);
    pub(crate) const CSG_STATUS_UPDATE: u32 = bit_u32(5);

    pub(crate) const CSG_SYNC_UPDATE: u32 = bit_u32(28);
    pub(crate) const CSG_IDLE: u32 = bit_u32(29);
    pub(crate) const CSG_DOORBELL: u32 = bit_u32(30);
    pub(crate) const CSG_PROGRESS_TIMER_EVENT: u32 = bit_u32(31);

    pub(crate) const CSG_REQ_MASK: u32 = CSG_STATE_MASK | CSG_ENDPOINT_CONFIG | CSG_STATUS_UPDATE;
    pub(crate) const CSG_EVT_MASK: u32 = CSG_SYNC_UPDATE | CSG_IDLE | CSG_PROGRESS_TIMER_EVENT;

    pub(crate) const fn csg_ep_req_compute(x: u32) -> u32 {
        x & genmask_u32(7, 0)
    }

    pub(crate) const fn csg_ep_req_fragment(x: u32) -> u32 {
        (x << 8) & genmask_u32(15, 8)
    }

    pub(crate) const fn csg_ep_req_tiler(x: u32) -> u32 {
        (x << 16) & genmask_u32(19, 16)
    }

    pub(crate) const CSG_EP_REQ_EXCL_COMPUTE: u32 = bit_u32(20);
    pub(crate) const CSG_EP_REQ_EXCL_FRAGMENT: u32 = bit_u32(21);

    pub(crate) const fn csg_ep_req_priority(x: u32) -> u32 {
        (x << 28) & genmask_u32(31, 28)
    }

    pub(crate) const CSG_EP_REQ_PRIORITY_MASK: u32 = genmask_u32(31, 28);
}

pub(crate) struct CommandStreamGroup {
    csg_id: usize,

    control_area: SharedSectionRange,
    input_area: SharedSectionRange,
    output_area: SharedSectionRange,

    streams: KVec<CommandStream>,
    state: GroupState,
}

impl CommandStreamGroup {
    pub(crate) fn init(
        glb_iface: &mut GlobalInterface,
        iface_offset: u32,
        csg_id: usize,
    ) -> Result<Self> {
        if iface_offset as usize + core::mem::size_of::<Self>() >= glb_iface.shared_section_size() {
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

        const CSF_STREAM_CONTROL_OFFSET: u32 = 0x40;
        let mut streams: KVec<CommandStream> = kvec![];

        for cs_idx in 0..control.stream_num {
            let iface_offset = iface_offset + CSF_STREAM_CONTROL_OFFSET + (cs_idx * control.stride);
            let cs = CommandStream::init(glb_iface, iface_offset, csg_id, cs_idx as usize)?;

            if let Some(first) = streams.first() {
                let control = cs.read_control()?;
                let first_control = first.read_control()?;

                if control.features != first_control.features {
                    pr_err!("Expecting identical CS slots in a group\n");
                    return Err(EINVAL);
                }
            }

            streams.push(cs, GFP_KERNEL)?;
        }

        Ok(CommandStreamGroup {
            csg_id,
            control_area,
            input_area,
            output_area,
            streams,
            state: GroupState::Terminate,
        })
    }

    pub(super) fn set_group_state(&mut self, state: GroupState) -> Result<()> {
        let req = self.input_request()?;
        req.update_reqs(state as u32, CSG_STATE_MASK)?;

        if let GroupState::Start = state {
            req.toggle_reqs(constants::CSG_ENDPOINT_CONFIG)?;
        }

        self.state = state;
        Ok(())
    }

    pub(super) fn is_identical(&self, other: &CommandStreamGroup) -> Result<bool> {
        let a = self.read_control()?;
        let b = other.read_control()?;

        if a.features != b.features {
            return Ok(false);
        }
        if a.suspend_size != b.suspend_size {
            return Ok(false);
        }
        if a.protm_suspend_size != b.protm_suspend_size {
            return Ok(false);
        }
        if a.stream_num != b.stream_num {
            return Ok(false);
        }

        Ok(true)
    }

    /// Returns the stream of index `idx` in this command stream group.
    pub(crate) fn cs(&self, idx: usize) -> Option<&CommandStream> {
        self.streams.get(idx)
    }

    /// Returns the stream of index `idx` in this command stream group.
    pub(crate) fn cs_mut(&mut self, idx: usize) -> Option<&mut CommandStream> {
        self.streams.get_mut(idx)
    }

    pub(crate) fn csg_id(&self) -> usize {
        self.csg_id
    }
}

impl SharedSectionEntry for CommandStreamGroup {
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

    fn doobell_request(&self) -> Result<RequestField> {
        Ok(RequestField::new(
            &self.input_area,
            core::mem::offset_of!(Input, doorbell_req),
            core::mem::offset_of!(Output, doorbell_ack),
        ))
    }

    fn interrupt_ack(&self) -> Result<RequestField> {
        // Note that the order is reversed, because the roles are switched: this
        // is the CPU answering to CSF.
        Ok(RequestField::new(
            &self.input_area,
            core::mem::offset_of!(Input, irq_ack),
            core::mem::offset_of!(Output, irq_req),
        ))
    }
}

#[repr(C)]
pub(crate) struct Control {
    pub(crate) features: u32,
    pub(crate) input_va: u32,
    pub(crate) output_va: u32,
    pub(crate) suspend_size: u32,
    pub(crate) protm_suspend_size: u32,
    pub(crate) stream_num: u32,
    pub(crate) stride: u32,
}

#[repr(C)]
pub(crate) struct Input {
    pub(crate) req: u32,
    pub(crate) ack_irq_mask: u32,
    pub(crate) doorbell_req: u32,
    pub(crate) irq_ack: u32,
    pub(crate) reserved1: [u32; 4],
    pub(crate) allow_compute: u64,
    pub(crate) allow_fragment: u64,
    pub(crate) allow_other: u32,
    pub(crate) csg_ep_req: u32,
    pub(crate) reserved2: [u32; 2],
    pub(crate) suspend_buf: u64,
    pub(crate) protm_suspend_buf: u64,
    pub(crate) csg_config: u32,
    pub(crate) reserved3: u32,
}

impl Input {
    pub(crate) fn set_endpoint_req(
        &mut self,
        compute: u32,
        fragment: u32,
        tiler: u32,
        priority: Priority,
    ) {
        self.csg_ep_req = constants::csg_ep_req_compute(compute)
            | constants::csg_ep_req_fragment(fragment)
            | constants::csg_ep_req_tiler(tiler)
            | constants::csg_ep_req_priority(priority as u32);
    }
}

#[repr(C)]
pub(crate) struct Output {
    pub(crate) ack: u32,
    pub(crate) reserved1: u32,
    pub(crate) doorbell_ack: u32,
    pub(crate) irq_req: u32,
    pub(crate) status_ep_current: u32,
    pub(crate) status_ep_req: u32,
    pub(crate) status_state: u32,
    pub(crate) resource_dep: u32,
}

impl Output {
    pub(crate) fn is_idle(&self) -> bool {
        self.status_state & bit_u32(0) != 0
    }
}

impl_shared_section_rw!(Control);
impl_shared_section_rw!(Input);
impl_shared_section_read!(Output);

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum GroupState {
    Terminate,
    Start,
    Suspend,
    Resume,
}

/// Represents the priority levels for a Command Stream Group (CSG).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Priority {
    /// Low priority group.
    Low = 0,

    /// Medium priority group.
    Medium = 1,

    /// High priority group.
    High = 2,

    /// Real-time priority group.
    ///
    /// Real-time priority allows preempting the scheduling of other
    /// non-real-time groups. When such a group becomes executable,
    /// it will evict the group with the lowest non-real-time priority
    /// if there's no free group slot available.
    RealTime = 3,
}

impl Priority {
    pub(crate) const fn num_priorities() -> usize {
        4
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
