// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;

use kernel::{
    io::Io,
    prelude::*,
    sizes::SZ_4K,
    sync::Arc,
};

use crate::{
    driver::TyrDrmDevice,
    file::QueueCreate,
    gem,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags,
    },
};

/// A minimal hardware queue object owned by a scheduling group.
pub(crate) struct Queue {
    _priority: u8,
    _ringbuf: Arc<gem::MappedBo>,
    _interfaces: Interfaces,
}

impl Queue {
    pub(crate) fn new(
        tdev: &TyrDrmDevice,
        queue_args: &QueueCreate,
        vm: Arc<Vm>,
    ) -> Result<Self> {
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let ringbuf =
            gem::new_kernel_object(tdev, &vm, queue_args.ringbuf_size() as usize, flags)?;
        let iface_mem = tdev.fw.alloc_queue_mem(tdev)?;
        let interfaces = Interfaces::new(iface_mem)?;

        Ok(Self {
            _priority: queue_args.priority(),
            _ringbuf: ringbuf,
            _interfaces: interfaces,
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

pub(crate) struct Interfaces {
    _mem: Arc<gem::MappedBo>,
    _input_va: Range<u64>,
    _output_va: Range<u64>,
    _input_offset: usize,
    _output_offset: usize,
}

impl Interfaces {
    fn new(mem: Arc<gem::MappedBo>) -> Result<Self> {
        let input_va = mem.kernel_va().ok_or(EINVAL)?;
        let output_start = input_va.start + SZ_4K as u64;
        let output_va = output_start..(output_start + SZ_4K as u64);

        Ok(Self {
            _mem: mem,
            _input_va: input_va,
            _output_va: output_va,
            _input_offset: 0,
            _output_offset: SZ_4K,
        })
    }

    #[allow(dead_code)]
    pub(super) fn read_input(&mut self) -> Result<RingBufferInput> {
        let vmap = self._mem.vmap();
        // SAFETY: `_input_offset` selects the queue input structure inside the
        // writable CPU mapping owned by `_mem`.
        let input = unsafe {
            (vmap.addr() as *mut u8)
                .add(self._input_offset)
                .cast::<RingBufferInput>()
                .read_volatile()
        };

        Ok(input)
    }

    #[allow(dead_code)]
    pub(super) fn write_input(&mut self, value: RingBufferInput) -> Result {
        let vmap = self._mem.vmap();

        // SAFETY: `_input_offset` selects the queue input structure inside the
        // writable CPU mapping owned by `_mem`.
        unsafe {
            (vmap.addr() as *mut u8)
                .add(self._input_offset)
                .cast::<RingBufferInput>()
                .write_volatile(value)
        };

        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn read_output(&mut self) -> Result<RingBufferOutput> {
        let vmap = self._mem.vmap();
        // SAFETY: `_output_offset` selects the queue output structure inside the
        // writable CPU mapping owned by `_mem`.
        let output = unsafe {
            (vmap.addr() as *mut u8)
                .add(self._output_offset)
                .cast::<RingBufferOutput>()
                .read_volatile()
        };

        Ok(output)
    }
}