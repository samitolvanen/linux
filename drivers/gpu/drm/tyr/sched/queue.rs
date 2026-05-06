// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;

use kernel::{
    io::{
        mem::DevresIoMem,
        register::Array,
        Io,
        IoBase, //
    },
    prelude::*,
    sizes::{
        SZ_2M,
        SZ_4K,
        SZ_64K, //
    },
    sync::{
        atomic::{
            Atomic,
            Relaxed, //
        },
        barrier::{
            smp_mb,
            Write, //
        },
        Arc, //
    },
    transmute::FromBytes,
    uapi, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmRegistrationData, //
    },
    gem,
    regs::doorbell_block,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    }, //
};

const UNASSIGNED_DOORBELL_ID: usize = usize::MAX;

#[repr(transparent)]
pub(crate) struct QueueCreate(uapi::drm_panthor_queue_create);

// SAFETY: This wrapper is layout-identical to the UAPI queue-create record
// read from userspace.
unsafe impl FromBytes for QueueCreate {}

impl QueueCreate {
    pub(crate) fn validate(&self) -> Result {
        if self.0.pad != [0; 3] {
            return Err(EINVAL);
        }

        if self.0.priority > 15 {
            return Err(EINVAL);
        }

        if self.0.ringbuf_size < SZ_4K as u32
            || self.0.ringbuf_size > SZ_64K as u32
            || !self.0.ringbuf_size.is_power_of_two()
        {
            return Err(EINVAL);
        }

        Ok(())
    }

    pub(crate) fn priority(&self) -> u8 {
        self.0.priority
    }

    pub(crate) fn ringbuf_size(&self) -> u32 {
        self.0.ringbuf_size
    }
}

struct QueueData {
    #[expect(dead_code)]
    priority: u8,
    ringbuf: Arc<gem::MappedBo>,
    interfaces: Interfaces,
    doorbell_id: Atomic<usize>,
    next_seqno: Atomic<u64>,
    iomem: Arc<DevresIoMem<SZ_2M>>,
}

impl QueueData {
    fn ringbuf_space_for(&self, instr_count: usize) -> Result<RingBufferInput> {
        let ringbuf_input = self.interfaces.read_input()?;
        let size = self.ringbuf.vmap().size();
        let ringbuf_output = self.interfaces.read_output()?;
        let used = ringbuf_input
            .insert
            .checked_sub(ringbuf_output.extract)
            .ok_or(EIO)?;

        if instr_count > size {
            return Err(ENOSPC);
        }

        if used > size as u64 || instr_count as u64 > size as u64 - used {
            return Err(ENOSPC);
        }

        Ok(ringbuf_input)
    }

    fn doorbell_id(&self) -> Option<usize> {
        let doorbell_id = self.doorbell_id.load(Relaxed);

        if doorbell_id == UNASSIGNED_DOORBELL_ID {
            None
        } else {
            Some(doorbell_id)
        }
    }

    fn set_doorbell_id(&self, doorbell_id: Option<usize>) {
        self.doorbell_id
            .store(doorbell_id.unwrap_or(UNASSIGNED_DOORBELL_ID), Relaxed);
    }

    fn can_append(&self, instr_count: usize) -> Result {
        self.ringbuf_space_for(instr_count)?;
        Ok(())
    }

    fn claim_seqno(&self) -> u64 {
        self.next_seqno.fetch_add(1, Relaxed) + 1
    }

    fn append_instrs(&self, instrs: &[u8]) -> Result {
        let mut ringbuf_input = self.ringbuf_space_for(instrs.len())?;

        let ringbuf = self.ringbuf.vmap();
        let size = ringbuf.size();
        let ringbuf_output = self.interfaces.read_output()?;

        let cs_insert = (ringbuf_input.insert & (size as u64 - 1)) as usize;

        let first_chunk = core::cmp::min(size - cs_insert, instrs.len());
        let dst = ringbuf.as_view().as_ptr().cast::<u8>();
        // SAFETY: `dst` is the writable CPU mapping of the ring buffer, valid
        // for `size` bytes, and `instrs` is a separate allocation. The mask
        // puts `cs_insert` below `size`, and `first_chunk` is at most
        // `size - cs_insert`, so the first copy stays inside the mapping. An
        // append larger than the ring is rejected, so the wrapped remainder
        // `instrs.len() - first_chunk` is at most `size`.
        unsafe {
            core::ptr::copy_nonoverlapping(instrs.as_ptr(), dst.add(cs_insert), first_chunk);
            core::ptr::copy_nonoverlapping(
                instrs.as_ptr().add(first_chunk),
                dst,
                instrs.len() - first_chunk,
            );
        }

        smp_mb(Write);

        ringbuf_input.extract_init = ringbuf_output.extract;
        ringbuf_input.insert += instrs.len() as u64;

        self.interfaces.write_input(ringbuf_input)?;
        smp_mb(Write);
        Ok(())
    }

    fn kick(&self) -> Result {
        let io = self.iomem.try_access().ok_or(ENODEV)?;
        let doorbell_reg =
            doorbell_block::DOORBELL::try_at(self.doorbell_id().ok_or(EINVAL)?).ok_or(EINVAL)?;

        io.try_write(
            doorbell_reg,
            doorbell_block::DOORBELL::zeroed().with_ring(true),
        )
    }
}

/// A minimal hardware queue object owned by a scheduling group.
pub(crate) struct Queue {
    data: Arc<QueueData>,
}

impl Queue {
    pub(crate) fn new(
        tdev: &TyrDrmDevice,
        reg_data: &TyrDrmRegistrationData<'_>,
        queue_args: &QueueCreate,
        vm: Arc<Vm>,
    ) -> Result<Self> {
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let ringbuf = gem::new_kernel_object(
            reg_data.pdev.as_ref(),
            tdev,
            &vm,
            queue_args.ringbuf_size() as usize,
            flags,
        )?;
        let iface_mem = reg_data.fw.alloc_queue_mem(tdev)?;
        let interfaces = Interfaces::new(iface_mem)?;

        let data = Arc::new(
            QueueData {
                priority: queue_args.priority(),
                ringbuf,
                interfaces,
                doorbell_id: Atomic::new(UNASSIGNED_DOORBELL_ID),
                next_seqno: Atomic::new(0),
                iomem: reg_data.iomem.clone(),
            },
            GFP_KERNEL,
        )?;

        Ok(Self { data })
    }

    pub(super) fn set_doorbell_id(&self, doorbell_id: Option<usize>) {
        self.data.set_doorbell_id(doorbell_id);
    }

    pub(super) fn can_append(&self, instr_count: usize) -> Result {
        self.data.can_append(instr_count)
    }

    pub(super) fn claim_seqno(&self) -> u64 {
        self.data.claim_seqno()
    }

    pub(crate) fn append_instrs(&self, instrs: &[u8]) -> Result {
        self.data.append_instrs(instrs)
    }

    pub(crate) fn kick(&self) -> Result {
        self.data.kick()
    }
}

/// Firmware layout of the queue input block.
#[repr(C)]
pub(super) struct RingBufferInput {
    insert: u64,
    extract_init: u64,
}

impl RingBufferInput {
    const INSERT: usize = core::mem::offset_of!(Self, insert);
    const EXTRACT_INIT: usize = core::mem::offset_of!(Self, extract_init);
}

/// Firmware layout of the queue output block. It stops at `extract`,
/// since the driver never reads the word that follows.
#[repr(C)]
pub(super) struct RingBufferOutput {
    extract: u64,
}

impl RingBufferOutput {
    const EXTRACT: usize = core::mem::offset_of!(Self, extract);
}

/// The firmware-owned input and output blocks of a single queue.
pub(crate) struct Interfaces {
    mem: Arc<gem::MappedBo>,
    #[expect(dead_code)]
    pub(super) input_va: Range<u64>,
    #[expect(dead_code)]
    pub(super) output_va: Range<u64>,
    input_offset: usize,
    output_offset: usize,
}

impl Interfaces {
    fn new(mem: Arc<gem::MappedBo>) -> Result<Self> {
        let input_va = mem.kernel_va().ok_or(EINVAL)?;
        let output_start = input_va.start + SZ_4K as u64;
        let output_va = output_start..(output_start + SZ_4K as u64);

        Ok(Self {
            mem,
            input_va,
            output_va,
            input_offset: 0,
            output_offset: SZ_4K,
        })
    }

    pub(super) fn read_input(&self) -> Result<RingBufferInput> {
        let vmap = self.mem.vmap();

        Ok(RingBufferInput {
            insert: vmap.try_read64(self.input_offset + RingBufferInput::INSERT)?,
            extract_init: vmap.try_read64(self.input_offset + RingBufferInput::EXTRACT_INIT)?,
        })
    }

    pub(super) fn write_input(&self, value: RingBufferInput) -> Result {
        let vmap = self.mem.vmap();

        vmap.try_write64(
            value.extract_init,
            self.input_offset + RingBufferInput::EXTRACT_INIT,
        )?;
        vmap.try_write64(value.insert, self.input_offset + RingBufferInput::INSERT)
    }

    pub(super) fn read_output(&self) -> Result<RingBufferOutput> {
        Ok(RingBufferOutput {
            extract: self
                .mem
                .vmap()
                .try_read64(self.output_offset + RingBufferOutput::EXTRACT)?,
        })
    }
}
