// SPDX-License-Identifier: GPL-2.0 or MIT

use kernel::{
    prelude::*,
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
    iface_mem: Arc<gem::MappedBo>,
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

        Ok(Self {
            priority: queue_args.priority(),
            ringbuf,
            iface_mem,
        })
    }
}
