// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    prelude::*,
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
    _iface_mem: Arc<gem::MappedBo>,
}

impl Queue {
    pub(crate) fn new(
        tdev: &TyrDrmDevice,
        queue_args: &QueueCreate,
        vm: Arc<Vm>,
    ) -> Result<Self> {
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);
        let ringbuf = gem::new_kernel_object(tdev, &vm, queue_args.ringbuf_size() as usize, flags)?;
        let iface_mem = tdev.fw.alloc_queue_mem(tdev)?;

        Ok(Self {
            _priority: queue_args.priority(),
            _ringbuf: ringbuf,
            _iface_mem: iface_mem,
        })
    }
}