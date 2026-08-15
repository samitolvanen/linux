// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;

use kernel::{
    io::IoBase,
    prelude::*,
    sizes::SZ_4K,
    sync::Arc, //
};

use crate::{
    driver::{
        TyrDrmDevice,
        TyrDrmRegistrationData, //
    },
    file::QueueCreate,
    gem,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    }, //
};

/// A minimal hardware queue object owned by a scheduling group.
pub(crate) struct Queue {
    #[expect(dead_code)]
    priority: u8,
    #[expect(dead_code)]
    ringbuf: Arc<gem::MappedBo>,
    #[expect(dead_code)]
    interfaces: Interfaces,
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

        Ok(Self {
            priority: queue_args.priority(),
            ringbuf,
            interfaces,
        })
    }
}

#[allow(dead_code)]
#[repr(C)]
pub(super) struct RingBufferInput {
    insert: u64,
    extract_init: u64,
}

#[allow(dead_code)]
#[repr(C)]
pub(super) struct RingBufferOutput {
    extract: u64,
    active: u32,
}

/// The firmware-owned input and output blocks of a single queue.
pub(crate) struct Interfaces {
    mem: Arc<gem::MappedBo>,
    #[expect(dead_code)]
    input_va: Range<u64>,
    #[expect(dead_code)]
    output_va: Range<u64>,
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

    #[expect(dead_code)]
    pub(super) fn read_input(&mut self) -> Result<RingBufferInput> {
        let vmap = self.mem.vmap();
        // SAFETY: `input_offset` selects the queue input structure inside the
        // writable CPU mapping owned by `mem`.
        let input = unsafe {
            vmap.as_view()
                .as_ptr()
                .cast::<u8>()
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .read_volatile()
        };

        Ok(input)
    }

    #[expect(dead_code)]
    pub(super) fn write_input(&mut self, value: RingBufferInput) -> Result {
        let vmap = self.mem.vmap();

        // SAFETY: `input_offset` selects the queue input structure inside the
        // writable CPU mapping owned by `mem`.
        unsafe {
            vmap.as_view()
                .as_ptr()
                .cast::<u8>()
                .add(self.input_offset)
                .cast::<RingBufferInput>()
                .write_volatile(value)
        };

        Ok(())
    }

    #[expect(dead_code)]
    pub(super) fn read_output(&mut self) -> Result<RingBufferOutput> {
        let vmap = self.mem.vmap();
        // SAFETY: `output_offset` selects the queue output structure inside the
        // writable CPU mapping owned by `mem`.
        let output = unsafe {
            vmap.as_view()
                .as_ptr()
                .cast::<u8>()
                .add(self.output_offset)
                .cast::<RingBufferOutput>()
                .read_volatile()
        };

        Ok(output)
    }
}
