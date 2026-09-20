// SPDX-License-Identifier: GPL-2.0 or MIT

//! Address space module.
//!
//! This module handles the hardware interaction for MMU operations through
//! MMIO register access.
//!

use core::ops::Range;

use kernel::{
    device::{
        Bound,
        Device, //
    }, //
    error::Result,
    io::{
        mem::DevresIoMem,
        poll,
        register::Array,
        Io, //
    },
    iommu::pgtable::{
        Config,
        IoPageTable, //
    },
    new_mutex,
    num::Bounded,
    platform,
    prelude::*,
    sizes::{
        SZ_2M,
        SZ_4K, //
    },
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc,
        ArcBorrow,
        LockedBy,
        Mutex,
        MutexGuard, //
    },
    time::Delta, //
};

use crate::{
    mmu::{
        irq::PageFaultMask,
        AsSlotManager,
        Mmu, //
    },
    regs::{
        gpu_control::{
            FlushMode,
            GPU_COMMAND,
            GPU_IRQ_CLEAR,
            GPU_IRQ_RAWSTAT, //
        },
        mmu_control::mmu_as_control,
        mmu_control::mmu_as_control::*,
        MAX_AS, //
    },
    reset::ResetHandle,
    slot::{
        LockedSeat,
        Seat,
        SlotOperations, //
    },
    vm::pt_alloc::{
        DevresPageTable,
        PtAllocator, //
    }, //
};

/// Address space configuration values to be written to MMU registers.
#[derive(Clone, Copy)]
struct AddressSpaceConfig {
    /// Translation configuration. Configures how the MMU walks the page table for this
    /// address space.
    transcfg: u64,

    /// Translation table base address. The address of the page table.
    transtab: u64,

    /// Memory attributes such as cacheability.
    memattr: u64,
}

/// Virtual memory (VM) address space data for use in MMU operations.
#[pin_data]
pub(crate) struct VmAsData {
    /// This address-space seat tracks this VM's binding to a hardware address space slot.
    /// It can only be accessed when holding the `Mmu::as_manager` lock.
    as_seat: LockedSeat<AddressSpaceManager, MAX_AS>,

    /// Number of groups currently bound to a CSG slot that use this VM.
    ///
    /// The AS slot stays pinned (non-reclaimable) while this is non-zero,
    /// and becomes reclaimable once the last group unbinds.
    as_active_users: LockedBy<u32, AsSlotManager>,

    /// Virtual address bits for this address space.
    va_bits: u8,

    /// Set by the MMU IRQ handler when this AS slot took a page fault
    /// the in-kernel handler could not service. The scheduler reads it
    /// during the next tick to terminate any groups bound to this VM.
    pub(crate) unhandled_fault: Atomic<bool>,

    /// Serializes page-table update spans on this VM against hardware
    /// residency changes, so the GPU never translates against a page
    /// table that is being modified.
    #[pin]
    op_lock: Mutex<()>,

    /// Provides the memory backing the page tables of this VM.
    pub(crate) pt_allocator: Arc<PtAllocator>,

    /// The page table which maps GPU virtual addresses to physical addresses for this VM.
    #[pin]
    pub(crate) page_table: DevresPageTable,
}

impl VmAsData {
    /// Creates VM address space data by initializing all of its fields.
    pub(crate) fn new<'a>(
        mmu: &'a Mmu,
        dev: &Device<Bound>,
        va_bits: u32,
        pa_bits: u32,
    ) -> Result<impl pin_init::PinInit<VmAsData, Error> + 'a> {
        let pt_config = Config {
            quirks: 0,
            pgsize_bitmap: SZ_4K | SZ_2M,
            ias: va_bits,
            oas: pa_bits,
            coherent_walk: false,
        };

        let pt_allocator = Arc::pin_init(PtAllocator::new(), GFP_KERNEL)?;
        let page_table_init =
            IoPageTable::new_devres_with_alloc(dev, pt_config, pt_allocator.clone());

        Ok(try_pin_init!(Self {
            as_seat: LockedBy::new(&mmu.as_manager, Seat::NoSeat),
            as_active_users: LockedBy::new(&mmu.as_manager, 0),
            va_bits: va_bits as u8,
            unhandled_fault: Atomic::new(false),
            op_lock <- new_mutex!(()),
            pt_allocator,
            page_table <- page_table_init,
        }? Error))
    }

    /// Acquires the per-VM operation lock that guards page-table update
    /// spans against concurrent hardware residency changes.
    ///
    /// Lock order `{csg_slot_manager or gpuvm_unique} > vm op_lock >
    /// hw_gate read > as_manager`.
    pub(crate) fn lock_ops(&self) -> MutexGuard<'_, ()> {
        self.op_lock.lock()
    }

    /// Computes the hardware configuration for this address space.
    fn as_config(&self) -> Result<AddressSpaceConfig> {
        let pt = self.page_table.try_access().ok_or(ENODEV)?;
        // The hardware computes the valid input address range as:
        //   INA_BITS_VALID = min(HW_INA_BITS, 55 - INA_BITS)
        // To configure our desired va_bits, we solve for INA_BITS:
        //   INA_BITS = 55 - va_bits
        // This assumes HW_INA_BITS (hardware capability) >= va_bits.
        let field = 55u64.checked_sub(self.va_bits.into()).ok_or(EINVAL)?;
        let ina_bits =
            match mmu_as_control::InaBits::try_from(Bounded::try_new(field).ok_or(EINVAL)?)? {
                mmu_as_control::InaBits::Reset => return Err(EINVAL),
                bits => bits,
            };

        let transcfg = mmu_as_control::TRANSCFG::zeroed()
            .with_ptw_memattr(mmu_as_control::PtwMemattr::WriteBack)
            .with_r_allocate(true)
            .with_mode(mmu_as_control::AddressSpaceMode::Aarch64_4K)
            .with_ina_bits(ina_bits)
            .into_raw();

        Ok(AddressSpaceConfig {
            transcfg,
            // SAFETY: The SlotManager holds an `Arc<VmAsData>` as SlotData while this
            // TTBR is programmed and stores that Arc in the active slot before
            // returning. Eviction flushes and disables the slot before releasing
            // the Arc. A failed eviction leaves the slot holding it. The page table
            // is otherwise freed only at unbind, where the driver core drops the
            // driver's private data before releasing devres resources, so
            // `Firmware::drop()` stops the MCU first.
            transtab: unsafe { pt.ttbr() },
            memattr: MEMATTR::from_mair(pt.mair()).into_raw(),
        })
    }
}

/// Coordinates all hardware-level address space operations through MMIO register
/// operations including enabling, disabling, flushing, and updating address spaces.
pub(crate) struct AddressSpaceManager {
    /// Parent device used for logging.
    pdev: ARef<platform::Device>,

    /// Memory-mapped I/O region for GPU register access.
    ///
    /// Access goes through the RCU read-side lock, so a guard is only ever held across register
    /// accesses, never across a command wait.
    iomem: Arc<DevresIoMem<SZ_2M>>,

    /// Bitmask of present address space slots from GPU_AS_PRESENT register.
    as_present: u32,

    /// Live page-fault IRQ mask, shared with the MMU IRQ handler.
    fault_mask: Arc<PageFaultMask>,

    /// Whether hardware AS slot N currently holds a region lock.
    ///
    /// The lock is tracked per slot. Every Lock and Unlock on a slot goes
    /// through `as_start_update`, `as_end_update`, and `as_disable` under the
    /// `as_manager` mutex, so the flag follows whichever VM occupies the slot.
    lock_pending: [bool; MAX_AS],

    /// Whether hardware AS slot N was unprogrammed by the fault
    /// handler while its slot binding was kept. Cleared when the slot
    /// is programmed again.
    faulty: [bool; MAX_AS],

    /// Whether hardware AS slot N stopped completing commands. A command
    /// timeout sets it. A reset releases the slot binding, and the next
    /// activation to land on the slot clears it.
    stuck: [bool; MAX_AS],

    /// Reset handle for escalating stuck AS commands and cache flushes.
    reset: ResetHandle,
}

impl AddressSpaceManager {
    /// Creates a new address space manager.
    ///
    /// Initializes the manager with references to the platform device and
    /// I/O memory region, along with the bitmask of available AS slots.
    pub(super) fn new(
        pdev: &platform::Device<Bound>,
        iomem: Arc<DevresIoMem<SZ_2M>>,
        as_present: u32,
        reset: ResetHandle,
        fault_mask: Arc<PageFaultMask>,
    ) -> Result<AddressSpaceManager> {
        if as_present.trailing_ones() != as_present.count_ones() {
            dev_err!(
                pdev,
                "Sparse AS_PRESENT mask is unsupported: {:#x}",
                as_present
            );
            return Err(EINVAL);
        }

        Ok(Self {
            pdev: pdev.into(),
            iomem,
            as_present,
            fault_mask,
            lock_pending: [false; MAX_AS],
            faulty: [false; MAX_AS],
            stuck: [false; MAX_AS],
            reset,
        })
    }

    /// Validates that an AS slot number is within range and present in hardware.
    ///
    /// Checks that the slot index is less than [`MAX_AS`] and that
    /// the corresponding bit is set in the `as_present` mask read from the GPU.
    ///
    /// Returns [`EINVAL`] if the slot is out of range or not present in hardware.
    fn validate_as_slot(&self, as_nr: usize) -> Result {
        if as_nr >= MAX_AS {
            dev_err!(
                &self.pdev,
                "AS slot {} out of valid range (max {})",
                as_nr,
                MAX_AS
            );
            return Err(EINVAL);
        }

        if (self.as_present & (1 << as_nr)) == 0 {
            dev_err!(
                &self.pdev,
                "AS slot {} not present in hardware (AS_PRESENT={:#x})",
                as_nr,
                self.as_present
            );
            return Err(EINVAL);
        }
        Ok(())
    }

    /// Waits for an AS slot to become ready (not active).
    ///
    /// Returns an error if the slot is invalid, if polling times out, or if
    /// register access fails. A slot already known to be stuck fails without
    /// polling.
    fn as_wait_ready(&mut self, as_nr: usize) -> Result {
        self.validate_as_slot(as_nr)?;

        if self.stuck[as_nr] {
            return Err(ETIMEDOUT);
        }

        let op = || {
            let io = self.iomem.try_access().ok_or(ENODEV)?;
            let status_reg = STATUS::try_at(as_nr).ok_or(EINVAL)?;
            Ok(io.read(status_reg))
        };
        let cond = |status: &STATUS| -> bool { !status.active_ext() };
        let res =
            poll::read_poll_timeout(op, cond, Delta::from_micros(50), Delta::from_millis(100));
        if matches!(res, Err(e) if e == ETIMEDOUT) {
            // A stuck AS_ACTIVE bit only clears with a GPU reset.
            dev_err!(&self.pdev, "AS_ACTIVE bit stuck\n");
            self.reset.schedule();
            self.stuck[as_nr] = true;
        }

        res.map(|_| ())
    }

    /// Sends a command to an AS slot.
    ///
    /// Returns an error if waiting for ready times out or if register write fails.
    fn as_send_cmd(&mut self, as_nr: usize, cmd: MmuCommand) -> Result {
        self.as_wait_ready(as_nr)?;
        let io = self.iomem.try_access().ok_or(ENODEV)?;
        let command_reg = COMMAND::try_at(as_nr).ok_or(EINVAL)?;
        io.write(command_reg, COMMAND::zeroed().with_command(cmd));
        Ok(())
    }

    /// Sends a command to an AS slot and waits for completion.
    ///
    /// Returns an error if sending the command fails or if waiting for completion times out.
    fn as_send_cmd_and_wait(&mut self, as_nr: usize, cmd: MmuCommand) -> Result {
        self.as_send_cmd(as_nr, cmd)?;
        self.as_wait_ready(as_nr)?;
        Ok(())
    }

    /// Enables an AS slot with the provided configuration.
    ///
    /// Returns an error if the slot is invalid or if register writes/commands fail.
    fn as_enable(&mut self, as_nr: usize, as_config: &AddressSpaceConfig) -> Result {
        self.validate_as_slot(as_nr)?;

        {
            let io = self.iomem.try_access().ok_or(ENODEV)?;

            self.fault_mask.unmask_slot(&io, as_nr);

            let transtab = as_config.transtab;
            io.write(
                TRANSTAB_LO::try_at(as_nr).ok_or(EINVAL)?,
                TRANSTAB_LO::from_raw(transtab as u32),
            );
            io.write(
                TRANSTAB_HI::try_at(as_nr).ok_or(EINVAL)?,
                TRANSTAB_HI::from_raw((transtab >> 32) as u32),
            );

            let transcfg = as_config.transcfg;
            io.write(
                TRANSCFG_LO::try_at(as_nr).ok_or(EINVAL)?,
                TRANSCFG_LO::from_raw(transcfg as u32),
            );
            io.write(
                TRANSCFG_HI::try_at(as_nr).ok_or(EINVAL)?,
                TRANSCFG_HI::from_raw((transcfg >> 32) as u32),
            );

            let memattr = as_config.memattr;
            io.write(
                MEMATTR_LO::try_at(as_nr).ok_or(EINVAL)?,
                MEMATTR_LO::from_raw(memattr as u32),
            );
            io.write(
                MEMATTR_HI::try_at(as_nr).ok_or(EINVAL)?,
                MEMATTR_HI::from_raw((memattr >> 32) as u32),
            );
        }

        // Cleared before the command because `as_wait_ready` would
        // otherwise fail it.
        self.stuck[as_nr] = false;
        self.as_send_cmd_and_wait(as_nr, MmuCommand::Update)?;
        self.faulty[as_nr] = false;

        Ok(())
    }

    /// Disables an AS slot and clears its configuration.
    ///
    /// Returns an error if the slot is invalid or if register writes/commands fail.
    fn as_disable(&mut self, as_nr: usize) -> Result {
        self.validate_as_slot(as_nr)?;

        {
            let io = self.iomem.try_access().ok_or(ENODEV)?;

            self.fault_mask.mask_slot(&io, as_nr);
        }

        self.gpu_flush_caches(
            FlushMode::CleanInvalidate,
            FlushMode::CleanInvalidate,
            FlushMode::Invalidate,
        )?;

        // Reclaiming a slot mid-update leaves the region lock from
        // `as_start_update` unbalanced. Release it before the slot is reused.
        if self.lock_pending[as_nr] {
            self.as_send_cmd_and_wait(as_nr, MmuCommand::Unlock)?;
        }
        self.lock_pending[as_nr] = false;

        {
            let io = self.iomem.try_access().ok_or(ENODEV)?;

            io.write(
                TRANSTAB_LO::try_at(as_nr).ok_or(EINVAL)?,
                TRANSTAB_LO::from_raw(0),
            );
            io.write(
                TRANSTAB_HI::try_at(as_nr).ok_or(EINVAL)?,
                TRANSTAB_HI::from_raw(0),
            );

            io.write(
                MEMATTR_LO::try_at(as_nr).ok_or(EINVAL)?,
                MEMATTR_LO::from_raw(0),
            );
            io.write(
                MEMATTR_HI::try_at(as_nr).ok_or(EINVAL)?,
                MEMATTR_HI::from_raw(0),
            );

            let transcfg = TRANSCFG::zeroed()
                .with_mode(AddressSpaceMode::Unmapped)
                .into_raw();

            io.write(
                TRANSCFG_LO::try_at(as_nr).ok_or(EINVAL)?,
                TRANSCFG_LO::from_raw(transcfg as u32),
            );
            io.write(
                TRANSCFG_HI::try_at(as_nr).ok_or(EINVAL)?,
                TRANSCFG_HI::from_raw((transcfg >> 32) as u32),
            );
        }

        self.as_send_cmd_and_wait(as_nr, MmuCommand::Update)?;

        Ok(())
    }

    /// Locks a region of the translation tables for an atomic update.
    ///
    /// Programs the MMU [`LOCKADDR`] register for the given address space and issues
    /// the lock command. The hardware rounds the requested range up to a
    /// power-of-two region aligned to its size.
    ///
    /// Returns an error if the slot is invalid or if register writes/commands fail.
    fn as_start_update(&mut self, as_nr: usize, region: &Range<u64>) -> Result {
        self.validate_as_slot(as_nr)?;

        // An empty region locks nothing. `region.end - 1` below would
        // underflow.
        if region.is_empty() {
            return Ok(());
        }

        // The lock operates on full 64-byte cache lines of translation table entries.
        // Since each translation table entry (TTE) is 8 bytes, a cache line has 8 TTEs.
        // Since each TTE maps one page, the minimum locked region size will be 8 pages.
        //
        // With 4KiB pages (Aarch64_4K mode), the minimum locked region is 32KiB.
        let lock_region_min_size: u64 = 4096 * 8;

        // Count the number of trailing zero bits (zeros at the right/least-significant
        // end of the binary representation). For a power-of-two value, this equals the
        // base-2 exponent (e.g., 32 KiB = 2^15 → 15).
        let lock_region_min_size_log2 = lock_region_min_size.trailing_zeros() as u8;

        // XOR the first and last addresses to identify which bits differ between them.
        // The highest set bit in the result determines the exponent of the smallest
        // power-of-two region that can contain both addresses.
        //
        // Example:
        //   addr_xor = 0x1000 ^ 0x2FFF = 0x3FFF
        //   highest set bit in 0x3FFF is bit 13
        //   minimum region size = 2^(13 + 1) = 16 KiB
        let addr_xor = region.start ^ (region.end - 1);
        let region_size_log2 = 64 - addr_xor.leading_zeros() as u8;

        let lock_region_log2 = core::cmp::max(region_size_log2, lock_region_min_size_log2);

        let lock_region_size = 1u64.checked_shl(lock_region_log2.into()).ok_or(EINVAL)?;
        // Align the LOCKADDR base address down to the lock region size (1 << lock_region_log2).
        //
        // The MMU ignores the low lock_region_log2 bits of LOCKADDR base, so ensure
        // they are cleared in software to avoid ambiguity.
        //
        // Example:
        //   lock_region_log2 = 14 (16 KiB)
        //   region.start = 0x1000
        //   lockaddr_base = 0x1000 & ~(0x3FFF) = 0x0000
        let lockaddr_base = region.start & !(lock_region_size - 1);

        // The LOCKADDR size field encodes the lock region size as log2(size) - 1,
        // per the hardware definition. For example, a 32 KiB region is encoded as 14
        // because log2(32 KiB) = 15.
        let lockaddr_size = lock_region_log2 - 1;

        // The LOCKADDR base field stores address bits 63:12, so remove the low 12 bits
        // before passing this value to the register macro helper.
        // These bits are guaranteed to be zero anyway because of the minimum
        // size of the locked region.
        let lockaddr_base_field = lockaddr_base >> 12;
        let lockaddr_val = LOCKADDR::zeroed()
            .try_with_size(lockaddr_size)?
            .try_with_base(lockaddr_base_field)?
            .into_raw();

        {
            let io = self.iomem.try_access().ok_or(ENODEV)?;

            io.write(
                LOCKADDR_LO::try_at(as_nr).ok_or(EINVAL)?,
                LOCKADDR_LO::from_raw(lockaddr_val as u32),
            );
            io.write(
                LOCKADDR_HI::try_at(as_nr).ok_or(EINVAL)?,
                LOCKADDR_HI::from_raw((lockaddr_val >> 32) as u32),
            );
        }

        self.as_send_cmd_and_wait(as_nr, MmuCommand::Lock)?;
        self.lock_pending[as_nr] = true;
        Ok(())
    }

    /// Completes an atomic translation table update.
    ///
    /// The flush must complete before the Unlock so the GPU never resumes
    /// against stale translations.
    fn as_end_update(&mut self, as_nr: usize) -> Result {
        self.validate_as_slot(as_nr)?;
        self.gpu_flush_caches(
            FlushMode::CleanInvalidate,
            FlushMode::CleanInvalidate,
            FlushMode::Invalidate,
        )?;
        self.as_send_cmd_and_wait(as_nr, MmuCommand::Unlock)?;
        self.lock_pending[as_nr] = false;
        Ok(())
    }

    /// Issues the GPU-side `flush_caches` command and waits for completion.
    ///
    /// The completion bit is cleared before and after polling so each call
    /// observes only its own completion event. This affects all GPU caches
    /// globally. It does not touch MMU AS lock state.
    pub(super) fn gpu_flush_caches(
        &self,
        l2: FlushMode,
        lsc: FlushMode,
        other: FlushMode,
    ) -> Result {
        {
            let io = self.iomem.try_access().ok_or(ENODEV)?;

            let gpu_cmd = GPU_COMMAND::flush_caches(l2, lsc, other);

            io.write(
                GPU_IRQ_CLEAR,
                GPU_IRQ_CLEAR::zeroed().with_clean_caches_completed(true),
            );

            io.write_reg(gpu_cmd);
        }

        let op = || {
            let io = self.iomem.try_access().ok_or(ENODEV)?;
            Ok(io.read(GPU_IRQ_RAWSTAT))
        };
        let cond = |status: &GPU_IRQ_RAWSTAT| -> bool { status.clean_caches_completed() };
        let res =
            poll::read_poll_timeout(op, cond, Delta::from_micros(10), Delta::from_millis(100));

        // Always clear the bit, even on timeout, to leave the next caller
        // in a known state.
        {
            let io = self.iomem.try_access().ok_or(ENODEV)?;

            io.write(
                GPU_IRQ_CLEAR,
                GPU_IRQ_CLEAR::zeroed().with_clean_caches_completed(true),
            );
        }

        if res.is_err() {
            // The GPU stopped acknowledging cache maintenance. Only a
            // reset unblocks the situation.
            dev_err!(&self.pdev, "Flush caches timeout\n");
            self.reset.schedule();
        }

        res.map(|_| ())
    }
}

impl SlotOperations<MAX_AS> for AddressSpaceManager {
    /// VM address space data associated with a hardware slot.
    type SlotData = Arc<VmAsData>;

    fn seat(slot_data: &Self::SlotData) -> &LockedSeat<Self, MAX_AS> {
        &slot_data.as_seat
    }

    /// Activates a VM in a hardware slot.
    fn activate(&mut self, slot_idx: usize, slot_data: &Self::SlotData) -> Result {
        let as_config = slot_data.as_config()?;
        self.as_enable(slot_idx, &as_config)
    }

    /// Evicts a VM from a hardware slot.
    fn evict(&mut self, slot_idx: usize, _slot_data: &Self::SlotData) -> Result {
        // The reset may have been scheduled for a stuck AS command, and it
        // leaves the slot unprogrammed anyway, so release only the bookkeeping.
        if self.reset.in_progress() {
            return Ok(());
        }
        self.as_disable(slot_idx)?;
        Ok(())
    }
}

impl AsSlotManager {
    /// Locks a region for translation table updates if the VM is resident.
    ///
    /// An idle VM keeps its slot programmed in hardware, so the lock covers
    /// idle-resident VMs as well as active ones.
    pub(super) fn start_vm_update(&mut self, vm_as_data: &VmAsData, region: &Range<u64>) -> Result {
        if region.is_empty() {
            return Ok(());
        }

        match self.resident_slot(&vm_as_data.as_seat) {
            Some(slot) => self.as_start_update(slot as usize, region),
            None => Ok(()),
        }
    }

    /// Widens the active lock to cover a larger region.
    ///
    /// Re-issues the LOCKADDR and Lock command over `region`, which the
    /// caller has computed as the union of the currently locked region and
    /// the wider range it is about to rebuild. The hardware lock is replaced
    /// in place, so `region` must contain the previously locked range to keep
    /// the GPU stalled over it.
    ///
    /// An idle VM keeps its slot programmed in hardware, so the lock covers
    /// idle-resident VMs as well as active ones.
    ///
    /// If the region is empty or the VM is not resident in a hardware slot,
    /// this is a no-op.
    pub(super) fn extend_vm_update(
        &mut self,
        vm_as_data: &VmAsData,
        region: &Range<u64>,
    ) -> Result {
        if region.is_empty() {
            return Ok(());
        }

        match self.resident_slot(&vm_as_data.as_seat) {
            Some(slot) => self.as_start_update(slot as usize, region),
            None => Ok(()),
        }
    }

    /// Completes translation table updates and unlocks the region.
    ///
    /// An idle VM keeps its slot programmed in hardware, so the flush covers
    /// idle-resident VMs as well as active ones.
    pub(super) fn end_vm_update(&mut self, vm_as_data: &VmAsData, region: &Range<u64>) -> Result {
        if region.is_empty() {
            return Ok(());
        }

        match self.resident_slot(&vm_as_data.as_seat) {
            Some(slot) => self.as_end_update(slot as usize),
            None => Ok(()),
        }
    }

    /// Bumps an already-resident VM's active-user count.
    ///
    /// A non-zero count means the VM is bound to a hardware slot, so an extra
    /// user needs no residency change or hardware programming.
    pub(super) fn bump_resident_vm_users(&mut self, vm_as_data: &VmAsData) -> bool {
        let users = vm_as_data.as_active_users.access_mut(self);
        if *users == 0 {
            return false;
        }
        *users += 1;
        true
    }

    /// Activates a VM by assigning it to a hardware slot.
    pub(super) fn activate_vm(&mut self, vm_as_data: ArcBorrow<'_, VmAsData>) -> Result {
        if *vm_as_data.as_active_users.access(self) == 0 {
            // A slot disabled by the fault handler keeps its binding
            // but not its hardware programming. Evict so activation
            // programs the hardware again.
            if let Some(slot) = self.resident_slot(&vm_as_data.as_seat) {
                if self.faulty[slot as usize] {
                    self.evict(&vm_as_data.as_seat)?;
                }
            }
            self.activate(vm_as_data.into())?;
            vm_as_data.unhandled_fault.store(false, Relaxed);
        }
        *vm_as_data.as_active_users.access_mut(self) += 1;
        Ok(())
    }

    /// Drops one of the VM's bound users, flagging the slot idle once the
    /// last one drops. The slot stays pinned and programmed while any user
    /// remains, then is reclaimed and evicted lazily.
    ///
    /// A drop when no users remain is a no-op, so it safely follows a
    /// `deactivate_vm` that already reset the count.
    pub(super) fn idle_vm(&mut self, vm_as_data: &VmAsData) -> Result {
        let users = vm_as_data.as_active_users.access_mut(self);
        if *users == 0 {
            return Ok(());
        }
        *users -= 1;
        if *users == 0 {
            self.idle(&vm_as_data.as_seat)?;
        }
        Ok(())
    }

    /// Deactivates a VM by evicting it from its hardware slot.
    ///
    /// Resets the user count, so it evicts even while groups are still
    /// bound.
    pub(super) fn deactivate_vm(&mut self, vm_as_data: &VmAsData) -> Result {
        *vm_as_data.as_active_users.access_mut(self) = 0;
        self.evict(&vm_as_data.as_seat)
    }

    /// Disables a faulted VM's hardware address space while keeping
    /// the slot bound to the VM.
    ///
    /// The user count is untouched, so the slot cannot be handed to
    /// another VM while bound groups still name it through their CSG
    /// JASID. Evicting those groups drops the users, after which the
    /// slot is reclaimed through the normal idle path.
    ///
    /// A no-op if the VM is not resident or its slot is already
    /// marked faulty.
    pub(super) fn disable_vm(&mut self, vm_as_data: &VmAsData) -> Result {
        let Some(slot) = self.resident_slot(&vm_as_data.as_seat) else {
            return Ok(());
        };
        let slot = slot as usize;
        if self.faulty[slot] {
            return Ok(());
        }
        // Set the flag before disabling, so a disable that fails on a
        // wedged address space is not retried on every repeat fault.
        self.faulty[slot] = true;
        self.as_disable(slot)
    }

    /// Returns the AS slot index the VM is currently assigned to, or `None`
    /// if the VM has no bound users.
    ///
    /// An idle VM reports `None` even though its slot stays programmed
    /// until it is reclaimed.
    ///
    /// The slot binding is only stable for as long as the caller holds
    /// the AS slot manager mutex. Once dropped, another caller may
    /// evict the VM.
    pub(super) fn vm_as_slot(&self, vm_as_data: &VmAsData) -> Option<u8> {
        vm_as_data.as_seat.access(self).slot()
    }

    /// Evicts every resident VM from its hardware AS slot.
    pub(super) fn suspend(&mut self) {
        for slot_idx in 0..self.slot_count() {
            let Some(vm) = self.slot_data(slot_idx).cloned() else {
                continue;
            };
            // The power cycle clears the slot. Reset the count so the next
            // `activate_vm` reprograms it instead of treating the VM as still
            // bound.
            *vm.as_active_users.access_mut(self) = 0;
            if let Err(e) = self.evict_forced(&vm.as_seat) {
                dev_err!(
                    &self.pdev,
                    "AS slot {} suspend evict failed: {}\n",
                    slot_idx,
                    e.to_errno()
                );
            }
        }
    }
}
