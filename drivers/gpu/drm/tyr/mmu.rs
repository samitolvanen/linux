// SPDX-License-Identifier: GPL-2.0 or MIT

use core::ops::Range;

use as_lock::AsLockToken;
use faults::decode_faults;
use kernel::devres::Devres;
use kernel::dma_fence::DmaFenceWorkqueue;
use kernel::io;
use kernel::io_pgtable;
use kernel::new_mutex;
use kernel::platform;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::time::Delta;
use kernel::types::ForeignOwnable;
use vm::Vm;
use vm::VmLayout;

use crate::driver::IoMem;
use crate::driver::TyrDevice;
use crate::gpu::GpuInfo;
use crate::regs::*;

mod as_lock;
mod faults;
pub(crate) mod irq;
mod slot_allocator;
pub(crate) mod vm;

use self::slot_allocator::SlotAllocator;

pub(crate) struct Mmu {
    /// List containing all VMs.
    vms: KVec<Arc<Mutex<Vm>>>,
    /// Tracks which of the 32 AS slots are free.
    slots: SlotAllocator,
}

impl Mmu {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            vms: KVec::new(),
            slots: SlotAllocator::new(),
        })
    }

    pub(crate) fn create_vm(
        &mut self,
        tdev: &TyrDevice,
        pdev: &platform::Device,
        gpu_info: &GpuInfo,
        for_mcu: bool,
        layout: VmLayout,
        auto_kernel_va: Range<u64>,
        iomem: Arc<Devres<IoMem>>,
        wq: Arc<DmaFenceWorkqueue>,
        /* coherent: bool, */
    ) -> Result<Arc<Mutex<Vm>>> {
        let vm = Vm::create(
            tdev,
            pdev,
            for_mcu,
            gpu_info,
            layout,
            auto_kernel_va,
            iomem,
            wq,
        )?;

        let vm = Arc::pin_init(new_mutex!(vm), GFP_KERNEL)?;
        self.vms.push(vm.clone(), GFP_KERNEL)?;
        Ok(vm)
    }

    fn flush_range(iomem: &Devres<IoMem>, as_nr: usize, range: Range<u64>) -> Result {
        Self::do_as_command(iomem, as_nr, AS_COMMAND_FLUSH_PT, range)
    }

    fn wait_ready(iomem: &Devres<IoMem>, as_nr: usize) -> Result {
        let op = || as_status(as_nr)?.read(iomem);
        let cond = |status: &u32| -> bool { *status & AS_STATUS_ACTIVE == 0 };
        let _ = io::poll::read_poll_timeout(
            op,
            cond,
            Delta::from_millis(0),
            Delta::from_micros(10000),
        )?;

        Ok(())
    }

    fn do_as_command(
        iomem: &Devres<IoMem>,
        as_nr: usize,
        command: u32,
        region: Range<u64>,
    ) -> Result {
        if command == AS_COMMAND_UNLOCK {
            as_command(as_nr)?.write(iomem, command)?;
        } else {
            let _lock = AsLockToken::lock_region(iomem, as_nr, region)?;
            Self::wait_ready(iomem, as_nr)?;
            as_command(as_nr)?.write(iomem, command)?;
            Self::wait_ready(iomem, as_nr)?;
        }

        Ok(())
    }

    pub(crate) fn bind_vm(
        &mut self,
        vm: Arc<Mutex<Vm>>,
        gpu_info: &GpuInfo,
        iomem: &Devres<IoMem>,
    ) -> Result {
        let mut vm = vm.lock();

        // If this VM is already bound to an AS (shared with another group),
        // just increment the refcount and reuse the existing slot. Without
        // this, a second bind_vm() would allocate a fresh AS, overwrite
        // vm.address_space, and silently leak the old slot.
        if vm.binding_count > 0 {
            vm.binding_count += 1;
            return Ok(());
        }

        let va_bits = gpu_info.va_bits();

        // stack_pin_init!(let local_guard = new_mutex!(()));
        // let locked_vm = vm.gpuvm.lock(&mut local_guard.lock());

        let transtab = vm.gpuvm.data().page_table.cfg().ttbr;
        let transcfg = AS_TRANSCFG_PTW_MEMATTR_WB
            | AS_TRANSCFG_PTW_RA
            | AS_TRANSCFG_ADRMODE_AARCH64_4K
            | as_transcfg_ina_bits((55 - va_bits).into());

        let memattr = vm.memattr;
        let as_nr = self.slots.find_slot(vm.for_mcu)?;
        if gpu_info.as_present & (1 << as_nr) == 0 {
            return Err(EBUSY);
        }
        Self::enable_as(iomem, as_nr, transtab, transcfg.into(), memattr)?;
        self.slots.alloc_slot(as_nr);
        vm.address_space = Some(as_nr);
        vm.binding_count = 1;
        Ok(())
    }

    pub(crate) fn unbind_vm(&mut self, vm: &Arc<Mutex<Vm>>, iomem: &Devres<IoMem>) -> Result {
        let mut vm = vm.lock();

        if vm.binding_count == 0 {
            pr_warn!("unbind_vm: called on already-unbound VM, ignoring\n");
            return Ok(());
        }

        vm.binding_count -= 1;

        // Still in use by another group sharing this VM.
        if vm.binding_count > 0 {
            return Ok(());
        }

        let as_nr = vm.address_space.ok_or(EINVAL).inspect_err(|_| {
            pr_warn!("unbind_vm: binding_count reached 0 but address_space is None\n")
        })?;
        Self::disable_as(iomem, as_nr)?;
        vm.address_space = None;
        self.slots.free_slot(as_nr);
        Ok(())
    }

    fn enable_as(
        iomem: &Devres<IoMem>,
        as_nr: usize,
        transtab: u64,
        transcfg: u64,
        memattr: u64,
    ) -> Result {
        let active = as_status(as_nr)?.read(iomem)? & AS_STATUS_ACTIVE != 0;
        if active {
            return Err(EBUSY);
        }

        Self::do_as_command(iomem, as_nr, AS_COMMAND_FLUSH_MEM, 0..u64::MAX)?;

        let transtab_lo = (transtab & 0xffffffff) as u32;
        let transtab_hi = (transtab >> 32) as u32;

        let transcfg_lo = (transcfg & 0xffffffff) as u32;
        let transcfg_hi = (transcfg >> 32) as u32;

        let memattr_lo = (memattr & 0xffffffff) as u32;
        let memattr_hi = (memattr >> 32) as u32;

        as_transtab_lo(as_nr)?.write(iomem, transtab_lo)?;
        as_transtab_hi(as_nr)?.write(iomem, transtab_hi)?;

        as_transcfg_lo(as_nr)?.write(iomem, transcfg_lo)?;
        as_transcfg_hi(as_nr)?.write(iomem, transcfg_hi)?;

        as_memattr_lo(as_nr)?.write(iomem, memattr_lo)?;
        as_memattr_hi(as_nr)?.write(iomem, memattr_hi)?;

        let op = || as_status(as_nr)?.read(iomem);
        let cond = |status: &u32| -> bool { *status & AS_STATUS_ACTIVE == 0 };
        let _ =
            io::poll::read_poll_timeout(op, cond, Delta::from_millis(0), Delta::from_micros(200))?;

        as_command(as_nr)?.write(iomem, AS_COMMAND_UPDATE)?;

        Ok(())
    }

    fn disable_as(iomem: &Devres<IoMem>, as_nr: usize) -> Result {
        Self::do_as_command(iomem, as_nr, AS_COMMAND_FLUSH_MEM, 0..u64::MAX)?;

        as_transtab_lo(as_nr)?.write(iomem, 0)?;
        as_transtab_hi(as_nr)?.write(iomem, 0)?;

        as_memattr_lo(as_nr)?.write(iomem, 0)?;
        as_memattr_hi(as_nr)?.write(iomem, 0)?;

        as_transcfg_lo(as_nr)?.write(iomem, AS_TRANSCFG_ADRMODE_UNMAPPED as u32)?;
        as_transcfg_hi(as_nr)?.write(iomem, 0)?;

        let op = || as_status(as_nr)?.read(iomem);
        let cond = |status: &u32| -> bool { *status & AS_STATUS_ACTIVE == 0 };
        let _ =
            io::poll::read_poll_timeout(op, cond, Delta::from_millis(0), Delta::from_micros(200))?;

        as_command(as_nr)?.write(iomem, AS_COMMAND_UPDATE)?;

        Ok(())
    }
}

/* dummy TLB ops, the real TLB flush happens in panthor_vm_flush_range() */
impl io_pgtable::FlushOps for Mmu {
    type Data = ();

    fn tlb_flush_all(_data: <Self::Data as ForeignOwnable>::Borrowed<'_>) {}
    fn tlb_flush_walk(
        _data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _iova: usize,
        _size: usize,
        _granule: usize,
    ) {
    }
    fn tlb_add_page(
        _data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _iova: usize,
        _granule: usize,
    ) {
    }
}
