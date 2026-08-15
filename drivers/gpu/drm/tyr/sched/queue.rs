// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;

use kernel::{
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
    iface_mem: Arc<gem::MappedBo>,
    #[expect(dead_code)]
    iface_input_va: Range<u64>,
    #[expect(dead_code)]
    iface_output_va: Range<u64>,
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
        let iface_input_va = iface_mem.kernel_va().ok_or(EINVAL)?;
        let iface_output_start = iface_input_va.start + SZ_4K as u64;
        let iface_output_va = iface_output_start..(iface_output_start + SZ_4K as u64);

        Ok(Self {
            priority: queue_args.priority(),
            ringbuf,
            iface_mem,
            iface_input_va,
            iface_output_va,
        })
    }
}
