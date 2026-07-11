// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU address space management and hardware operations.
//!
//! This module manages GPU hardware address spaces (AS), including configuration,
//! command submission, and page table update regions. It handles the hardware
//! interaction for MMU operations through MMIO register access.
//!
//! The [`AddressSpaceManager`] implements [`SlotOperations`] to integrate with
//! the slot management system, enabling and configuring address spaces in the
//! hardware slots as needed.
//!
//! [`SlotOperations`]: crate::slot::SlotOperations

use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

use kernel::{
    device::{
        Bound,
        Device, //
    },
    devres::Devres,
    error::Result,
    io::{
        poll,
        register::Array,
        Io, //
    },
    iommu::pgtable::{
        Config,
        IoPageTable, //
    },
    new_mutex,
    platform,
    prelude::*,
    sizes::{
        SZ_2M,
        SZ_4K, //
    },
    sync::{
        aref::ARef,
        Arc,
        ArcBorrow,
        LockedBy,
        Mutex,
        MutexGuard, //
    },
    time::Delta, //
};

use crate::{
    driver::IoMem,
    mmu::{
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
        Seat,
        SlotOperations, //
    },
    vm::pt_alloc::{
        PageTable,
        PtAllocator, //
    }, //
};

/// Hardware address space configuration registers.
///
/// Contains register values for configuring a GPU MMU address space.
#[derive(Clone, Copy)]
struct AddressSpaceConfig {
    /// Translation configuration.
    ///
    /// Controls address translation mode, address range restrictions, translation table
    /// walk attributes, and access permission settings for this address space.
    transcfg: u64,

    /// Translation table base address.
    ///
    /// The address of the top level of a translation table structure.
    transtab: u64,

    /// Memory attributes.
    ///
    /// Defines memory attribute indirection entries that control cacheability
    /// and other memory access properties for the address space.
    memattr: u64,
}

/// Virtual memory (VM) address space data for GPU MMU operations.
///
/// Contains all resources and information needed by the [`AddressSpaceManager`]
/// to activate a VM in a hardware address space slot.
///
/// On activation, we will pass an [`Arc`]<[`VmAsData`]> that will be stored in
/// the slot to make sure the page table and the underlying resources
/// (pages) used by the AS slot won't go away while the MMU points to
/// those.
///
/// The `as_seat` field uses [`LockedBy`] to ensure safe concurrent access to
/// the slot assignment state, protected by the [`AsSlotManager`] lock.
#[pin_data]
pub(crate) struct VmAsData {
    /// Tracks this VM's binding to a hardware address space slot.
    as_seat: LockedBy<Seat, AsSlotManager>,

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
    pub(crate) unhandled_fault: AtomicBool,

    /// Serializes page-table update spans on this VM against hardware
    /// residency changes, so the GPU never translates against a page
    /// table that is being modified.
    #[pin]
    op_lock: Mutex<()>,

    /// Provides the memory backing the page tables of this VM.
    pub(crate) pt_allocator: Arc<PtAllocator>,

    /// Page table.
    ///
    /// Managed by devres to ensure proper cleanup. The page table maps
    /// GPU virtual addresses to physical addresses for this VM.
    #[pin]
    pub(crate) page_table: Devres<PageTable>,
}

impl VmAsData {
    /// Creates a new VM address space data structure.
    ///
    /// Initializes the page table for the address space.
    pub(crate) fn new<'a>(
        mmu: &'a Mmu,
        pdev: &'a platform::Device,
        va_bits: u32,
        pa_bits: u32,
    ) -> Result<impl pin_init::PinInit<VmAsData, Error> + 'a> {
        // SAFETY: pdev is a bound device.
        let dev = unsafe { pdev.as_ref().as_bound() };

        let pt_config = Config {
            quirks: 0,
            pgsize_bitmap: SZ_4K | SZ_2M,
            ias: va_bits,
            oas: pa_bits,
            coherent_walk: false,
        };

        let pt_allocator = Arc::pin_init(PtAllocator::new(), GFP_KERNEL)?;
        let page_table_init = IoPageTable::new_with_alloc(dev, pt_config, pt_allocator.clone());

        Ok(try_pin_init!(Self {
            as_seat: LockedBy::new(&mmu.as_manager, Seat::NoSeat),
            as_active_users: LockedBy::new(&mmu.as_manager, 0),
            va_bits: va_bits as u8,
            unhandled_fault: AtomicBool::new(false),
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
    ///
    /// The caller must ensure that the address space is evicted and cleaned up
    /// before the `VmAsData` is dropped.
    fn as_config(&self, dev: &Device<Bound>) -> Result<AddressSpaceConfig> {
        let pt = self.page_table.access(dev)?;

        // The hardware computes the valid input address range as:
        //   INA_BITS_VALID = min(HW_INA_BITS, 55 - INA_BITS)
        // To configure our desired va_bits, we solve for INA_BITS:
        //   INA_BITS = 55 - va_bits
        // This assumes HW_INA_BITS (hardware capability) >= va_bits.
        let ina_bits_field_value = 55 - self.va_bits;
        let ina_bits = match ina_bits_field_value {
            7 => mmu_as_control::InaBits::Bits48,
            8 => mmu_as_control::InaBits::Bits47,
            9 => mmu_as_control::InaBits::Bits46,
            10 => mmu_as_control::InaBits::Bits45,
            11 => mmu_as_control::InaBits::Bits44,
            12 => mmu_as_control::InaBits::Bits43,
            13 => mmu_as_control::InaBits::Bits42,
            14 => mmu_as_control::InaBits::Bits41,
            15 => mmu_as_control::InaBits::Bits40,
            16 => mmu_as_control::InaBits::Bits39,
            17 => mmu_as_control::InaBits::Bits38,
            18 => mmu_as_control::InaBits::Bits37,
            19 => mmu_as_control::InaBits::Bits36,
            20 => mmu_as_control::InaBits::Bits35,
            21 => mmu_as_control::InaBits::Bits34,
            22 => mmu_as_control::InaBits::Bits33,
            23 => mmu_as_control::InaBits::Bits32,
            24 => mmu_as_control::InaBits::Bits31,
            25 => mmu_as_control::InaBits::Bits30,
            26 => mmu_as_control::InaBits::Bits29,
            27 => mmu_as_control::InaBits::Bits28,
            28 => mmu_as_control::InaBits::Bits27,
            29 => mmu_as_control::InaBits::Bits26,
            30 => mmu_as_control::InaBits::Bits25,
            _ => return Err(EINVAL),
        };

        let transcfg = mmu_as_control::TRANSCFG::zeroed()
            .with_ptw_memattr(mmu_as_control::PtwMemattr::WriteBack)
            .with_r_allocate(true)
            .with_mode(mmu_as_control::AddressSpaceMode::Aarch64_4K)
            .with_ina_bits(ina_bits)
            .into_raw();

        Ok(AddressSpaceConfig {
            transcfg,
            // SAFETY: Caller ensures proper cleanup.
            transtab: unsafe { pt.ttbr() },
            memattr: MEMATTR::from_mair(pt.mair()).into_raw(),
        })
    }
}

/// Manages GPU hardware address spaces via MMIO register operations.
///
/// Coordinates all hardware-level address space operations including enabling,
/// disabling, flushing, and updating address spaces. Implements [`SlotOperations`]
/// to integrate with the generic slot management system.
///
/// [`SlotOperations`]: crate::slot::SlotOperations
pub(crate) struct AddressSpaceManager {
    /// Platform device reference for DMA and device operations.
    pdev: ARef<platform::Device>,

    /// Memory-mapped I/O region for GPU register access.
    iomem: Arc<Devres<IoMem>>,

    /// Bitmask of available address space slots from GPU_AS_PRESENT register.
    as_present: u32,

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

    /// Reset handle for escalating stuck AS commands and cache flushes.
    reset: ResetHandle,
}

impl SlotOperations for AddressSpaceManager {
    /// VM address space data stored in each hardware slot.
    type SlotData = Arc<VmAsData>;

    type Context = ();

    /// Activates an address space in a hardware slot.
    fn activate(
        &mut self,
        slot_idx: usize,
        slot_data: &Self::SlotData,
        _ctx: &mut Self::Context,
    ) -> Result {
        let as_config = slot_data.as_config(self.dev())?;
        self.as_enable(slot_idx, &as_config)
    }

    /// Evicts an address space from a hardware slot.
    fn evict(
        &mut self,
        slot_idx: usize,
        _slot_data: &Self::SlotData,
        _ctx: &mut Self::Context,
    ) -> Result {
        // The reset may have been scheduled for a stuck AS command, and it
        // leaves the slot unprogrammed anyway, so release only the bookkeeping.
        if self.reset.in_progress() {
            return Ok(());
        }
        if self.iomem.try_access().is_some() {
            self.as_disable(slot_idx)?;
        }
        Ok(())
    }
}

impl AddressSpaceManager {
    /// Creates a new address space manager.
    ///
    /// Initializes the manager with references to the platform device and
    /// I/O memory region, along with the bitmask of available AS slots.
    pub(super) fn new(
        pdev: &platform::Device,
        iomem: ArcBorrow<'_, Devres<IoMem>>,
        as_present: u32,
        reset: ResetHandle,
    ) -> Result<AddressSpaceManager> {
        Ok(Self {
            pdev: pdev.into(),
            iomem: iomem.into(),
            as_present,
            lock_pending: [false; MAX_AS],
            faulty: [false; MAX_AS],
            reset,
        })
    }

    /// Returns a reference to the bound device.
    fn dev(&self) -> &Device<Bound> {
        // SAFETY: pdev is a bound device.
        unsafe { self.pdev.as_ref().as_bound() }
    }

    /// Validates that an AS slot number is within range and present in hardware.
    ///
    /// Checks that the slot index is less than [`MAX_AS`] and that
    /// the corresponding bit is set in the `as_present` mask read from the GPU.
    ///
    /// Returns [`EINVAL`] if the slot is out of range or not present in hardware.
    fn validate_as_slot(&self, as_nr: usize) -> Result {
        if as_nr >= MAX_AS {
            pr_err!("AS slot {} out of valid range (max {})\n", as_nr, MAX_AS);
            return Err(EINVAL);
        }

        if (self.as_present & (1 << as_nr)) == 0 {
            pr_err!(
                "AS slot {} not present in hardware (AS_PRESENT={:#x})\n",
                as_nr,
                self.as_present
            );
            return Err(EINVAL);
        }

        Ok(())
    }

    /// Waits for an AS slot to become ready (not active).
    ///
    /// Returns an error if polling times out or if register access fails.
    fn as_wait_ready(&self, as_nr: usize) -> Result {
        let dev = self.dev();
        let io = self.iomem.access(dev)?;
        let op = || {
            let status_reg = STATUS::try_at(as_nr).ok_or(EINVAL)?;
            Ok(io.read(status_reg))
        };
        let cond = |status: &STATUS| -> bool { !status.active_ext() };
        poll::read_poll_timeout(op, cond, Delta::from_micros(10), Delta::from_millis(100))
            .inspect_err(|e| {
                // A stuck AS_ACTIVE bit only clears with a GPU reset.
                if *e == ETIMEDOUT {
                    dev_err!(dev, "AS_ACTIVE bit stuck\n");
                    self.reset.schedule();
                }
            })?;

        Ok(())
    }

    /// Sends a command to an AS slot.
    ///
    /// Returns an error if waiting for ready times out or if register write fails.
    fn as_send_cmd(&mut self, as_nr: usize, cmd: MmuCommand) -> Result {
        self.as_wait_ready(as_nr)?;
        let dev = self.dev();
        let io = self.iomem.access(dev)?;
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

        let dev = self.dev();
        let io = self.iomem.access(dev)?;

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

        self.as_send_cmd_and_wait(as_nr, MmuCommand::Update)?;
        self.faulty[as_nr] = false;

        Ok(())
    }

    /// Disables an AS slot and clears its configuration.
    ///
    /// Returns an error if the slot is invalid or if register writes/commands fail.
    fn as_disable(&mut self, as_nr: usize) -> Result {
        self.validate_as_slot(as_nr)?;

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

        let dev = self.dev();
        let io = self.iomem.access(dev)?;

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

        self.as_send_cmd_and_wait(as_nr, MmuCommand::Update)?;

        Ok(())
    }

    /// Locks a region of the translation tables for an atomic update.
    ///
    /// Programs the MMU LOCKADDR register for the given address space and issues
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
        let lock_region_min_size: u64 = 32 * 1024;

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

        // Align the LOCKADDR base address down to the lock region size (1 << lock_region_log2).
        //
        // The MMU ignores the low lock_region_log2 bits of LOCKADDR base, so ensure
        // they are cleared in software to avoid ambiguity.
        let lockaddr_base = region.start & !((1u64 << lock_region_log2) - 1);

        // The LOCKADDR size field encodes the lock region size as log2(size) - 1,
        // per the hardware definition. For example, a 32 KiB region is encoded as 14
        // because log2(32 KiB) = 15.
        let lockaddr_size = lock_region_log2 - 1;

        let dev = self.dev();
        let io = self.iomem.access(dev)?;

        let lockaddr_val = LOCKADDR::zeroed()
            .try_with_size(lockaddr_size)?
            .try_with_base(lockaddr_base)?
            .into_raw();

        io.write(
            LOCKADDR_LO::try_at(as_nr).ok_or(EINVAL)?,
            LOCKADDR_LO::from_raw(lockaddr_val as u32),
        );
        io.write(
            LOCKADDR_HI::try_at(as_nr).ok_or(EINVAL)?,
            LOCKADDR_HI::from_raw((lockaddr_val >> 32) as u32),
        );

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
        let dev = self.dev();
        let io = self.iomem.access(dev)?;

        let gpu_cmd = GPU_COMMAND::flush_caches(l2, lsc, other);

        io.write(
            GPU_IRQ_CLEAR,
            GPU_IRQ_CLEAR::zeroed().with_clean_caches_completed(true),
        );

        io.write_reg(gpu_cmd);

        let op = || Ok(io.read(GPU_IRQ_RAWSTAT));
        let cond = |status: &GPU_IRQ_RAWSTAT| -> bool { status.clean_caches_completed() };
        let res =
            poll::read_poll_timeout(op, cond, Delta::from_micros(10), Delta::from_millis(100));

        // Always clear the bit, even on timeout, to leave the next caller
        // in a known state.
        io.write(
            GPU_IRQ_CLEAR,
            GPU_IRQ_CLEAR::zeroed().with_clean_caches_completed(true),
        );

        if res.is_err() {
            // The GPU stopped acknowledging cache maintenance. Only a
            // reset unblocks the situation.
            dev_err!(dev, "Flush caches timeout\n");
            self.reset.schedule();
        }

        res.map(|_| ())
    }
}

impl AsSlotManager {
    /// Locks a region for translation table updates if the VM is resident.
    ///
    /// If the VM is currently assigned to a hardware slot, locks the specified
    /// memory region to make translation table updates atomic. GPU accesses to the
    /// region will be blocked until [`end_vm_update`] is called.
    ///
    /// An idle VM keeps its slot programmed in hardware, so the lock covers
    /// idle-resident VMs as well as active ones.
    ///
    /// If the region is empty or the VM is not resident in a hardware slot,
    /// this is a no-op.
    pub(super) fn start_vm_update(&mut self, vm: &VmAsData, region: &Range<u64>) -> Result {
        if region.is_empty() {
            return Ok(());
        }

        match self.resident_slot(&vm.as_seat) {
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
    pub(super) fn extend_vm_update(&mut self, vm: &VmAsData, region: &Range<u64>) -> Result {
        if region.is_empty() {
            return Ok(());
        }

        match self.resident_slot(&vm.as_seat) {
            Some(slot) => self.as_start_update(slot as usize, region),
            None => Ok(()),
        }
    }

    /// Completes translation table updates and unlocks the region.
    ///
    /// If the VM is currently assigned to a hardware slot, flushes the translation
    /// table cache and unlocks the region that was locked by [`start_vm_update`],
    /// allowing GPU accesses to proceed with the updated translation tables.
    ///
    /// An idle VM keeps its slot programmed in hardware, so the flush covers
    /// idle-resident VMs as well as active ones.
    ///
    /// If the region is empty or the VM is not resident in a hardware slot,
    /// this is a no-op.
    pub(super) fn end_vm_update(&mut self, vm: &VmAsData, region: &Range<u64>) -> Result {
        if region.is_empty() {
            return Ok(());
        }

        match self.resident_slot(&vm.as_seat) {
            Some(slot) => self.as_end_update(slot as usize),
            None => Ok(()),
        }
    }

    /// Bumps an already-resident VM's active-user count.
    ///
    /// A non-zero count means the VM is bound to a hardware slot, so an extra
    /// user needs no residency change or hardware programming.
    pub(super) fn bump_resident_vm_users(&mut self, vm: &VmAsData) -> bool {
        let users = vm.as_active_users.access_mut(self);
        if *users == 0 {
            return false;
        }
        *users += 1;
        true
    }

    /// Activates a VM by assigning it to a hardware slot.
    ///
    /// Allocates a hardware address space slot for the VM and configures
    /// it with the VM's translation table and memory attributes.
    pub(super) fn activate_vm(&mut self, vm: ArcBorrow<'_, VmAsData>) -> Result {
        if *vm.as_active_users.access(self) == 0 {
            // A slot disabled by the fault handler keeps its binding
            // but not its hardware programming. Evict so activation
            // programs the hardware again.
            if let Some(slot) = self.resident_slot(&vm.as_seat) {
                if self.faulty[slot as usize] {
                    self.evict(&vm.as_seat, &mut ())?;
                }
            }
            self.activate(&vm.as_seat, vm.into(), &mut ())?;
            vm.unhandled_fault.store(false, Ordering::Relaxed);
        }
        *vm.as_active_users.access_mut(self) += 1;
        Ok(())
    }

    /// Drops one of the VM's bound users, flagging the slot idle once the
    /// last one drops. The slot stays pinned and programmed while any user
    /// remains, then is reclaimed and evicted lazily.
    ///
    /// A drop when no users remain is a no-op, so it safely follows a
    /// `deactivate_vm` that already reset the count.
    pub(super) fn idle_vm(&mut self, vm: &VmAsData) -> Result {
        let users = vm.as_active_users.access_mut(self);
        if *users == 0 {
            return Ok(());
        }
        *users -= 1;
        if *users == 0 {
            self.idle(&vm.as_seat)?;
        }
        Ok(())
    }

    /// Deactivates a VM by evicting it from its hardware slot.
    ///
    /// Flushes any pending operations and clears the hardware slot's
    /// configuration, freeing the slot for use by other VMs. Resets the
    /// user count, so it evicts even while groups are still bound.
    pub(super) fn deactivate_vm(&mut self, vm: &VmAsData) -> Result {
        *vm.as_active_users.access_mut(self) = 0;
        self.evict(&vm.as_seat, &mut ())
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
    pub(super) fn disable_vm(&mut self, vm: &VmAsData) -> Result {
        let Some(slot) = self.resident_slot(&vm.as_seat) else {
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

    /// Returns the AS slot index `vm` is currently assigned to, or `None`
    /// if the VM is not resident.
    ///
    /// The slot binding is only stable for as long as the caller holds
    /// the AS slot manager mutex; once dropped, another caller may
    /// evict the VM.
    pub(super) fn vm_as_slot(&self, vm: &VmAsData) -> Option<u8> {
        vm.as_seat.access(self).slot()
    }

    /// Evicts every resident VM from its hardware AS slot.
    pub(super) fn suspend(&mut self) {
        for slot_idx in 0..self.slot_count() {
            let Some(vm) = self.slot_data(slot_idx).cloned() else {
                continue;
            };
            // On a flush timeout the slot is freed anyway so the clocks can
            // gate with nothing programmed, and the reset on resume reprograms
            // it. Keeping it would fault the next VM bound there.
            *vm.as_active_users.access_mut(self) = 0;
            if let Err(e) = self.evict_forced(&vm.as_seat, &mut ()) {
                pr_err!(
                    "AS slot {} suspend evict failed: {}\n",
                    slot_idx,
                    e.to_errno()
                );
            }
        }
    }
}
