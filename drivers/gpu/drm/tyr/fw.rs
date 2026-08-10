// SPDX-License-Identifier: GPL-2.0 or MIT

//! Firmware loading and management for Mali CSF GPU.
//!
//! This module handles loading the Mali GPU firmware binary, parsing it into sections,
//! and mapping those sections into the MCU's virtual address space. Each firmware section
//! has specific properties (read/write/execute permissions, cache modes) and must be loaded
//! at specific virtual addresses expected by the MCU.
//!
//! See [`Firmware`] for the main firmware management interface and [`Section`] for
//! individual firmware sections.
//!
//! [`Firmware`]: crate::fw::Firmware
//! [`Section`]: crate::fw::Section

use kernel::{
    device::{
        Bound,
        Device, //
    },
    devres::Devres,
    drm::{
        gem::{
            shmem::VMapOwned,
            BaseObject, //
        },
        Uninit, //
    },
    firmware,
    io::{
        poll,
        Io, //
    },
    platform,
    prelude::*,
    sizes::{
        SZ_1M,
        SZ_8K, //
    },
    str::CString,
    sync::{
        aref::ARef,
        atomic::{
            Acquire,
            Atomic,
            Release, //
        },
        Arc,
        ArcBorrow, //
    },
    time, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice,
        TyrDrmDeviceData, //
    },
    fw::{
        global::{
            GlbProbe,
            GlobalInterface, //
        },
        parser::{
            FwParser,
            ParsedSection,
            SectionFlag,
            SectionFlags, //
        },
    },
    gem,
    gem::{
        BoData,
        KernelBo,
        KernelBoVaAlloc, //
    },
    gpu::GpuInfo,
    mmu::Mmu,
    regs::gpu_control::{
        McuControlMode,
        McuStatus,
        GPU_ID,
        MCU_CONTROL,
        MCU_STATUS, //
    },
    vm::{Vm, VmFlag, VmMapFlags}, //
};

pub(crate) mod global;
mod interfaces;
pub(crate) mod irq;
mod parser;

// Re-exports of firmware-interface bitfield types and enums that the
// scheduler needs to construct CSG_INPUT writes from outside the
// firmware module. The bitfield definitions themselves stay private
// to `crate::fw`; the apply path only depends on these typed views.
pub(crate) use interfaces::{
    CsBlockedReason,
    CsFatalExceptionType,
    CsFaultExceptionType,
    CsWaitCondition,
    CsgExecutionState,
    CSG_CONFIG,
    CSG_EP_REQ,
    CSG_REQ, //
};

/// Maximum number of CSG interfaces supported by hardware.
pub(crate) const MAX_CSG: usize = 16;

/// Bitmap over CSG slot indices in `[0, MAX_CSG)`.
///
/// Each bit at position `i` indicates that CSG slot `i` is part of the
/// set. Used to drive per-tick batch operations (apply, doorbell-ring,
/// timeout tracking) without ambiguity against `CSG_REQ`, which is a
/// register-bitfield value within one slot's `CSG_REQ` word.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) struct CsgSlotMask(u32);

impl CsgSlotMask {
    pub(crate) const fn empty() -> Self {
        Self(0)
    }

    #[expect(dead_code)]
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) const fn into_raw(self) -> u32 {
        self.0
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) const fn contains(self, csg_idx: usize) -> bool {
        (self.0 & (1u32 << csg_idx)) != 0
    }

    pub(crate) fn insert(&mut self, csg_idx: usize) {
        debug_assert!(csg_idx < MAX_CSG);
        self.0 |= 1u32 << csg_idx;
    }

    #[expect(dead_code)]
    pub(crate) fn iter(self) -> impl Iterator<Item = usize> {
        (0..MAX_CSG).filter(move |&csg_id| (self.0 & (1u32 << csg_id)) != 0)
    }
}

/// Bitmap over CS indices within a CSG, in `[0, MAX_CS_PER_GROUP)`.
///
/// Each bit at position `i` indicates that CS `i` within a CSG slot has
/// a pending per-CS doorbell ring request.
///
/// Distinct from `CsgSlotMask`, whose bits are CSG slot indices in
/// `[0, MAX_CSG)`. Both are 32-bit bitmaps but the bit positions mean
/// different things.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) struct CsDbMask(u32);

impl CsDbMask {
    pub(crate) const fn empty() -> Self {
        Self(0)
    }

    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) const fn into_raw(self) -> u32 {
        self.0
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[expect(dead_code)]
    pub(crate) const fn contains(self, cs_idx: usize) -> bool {
        (self.0 & (1u32 << cs_idx)) != 0
    }

    pub(crate) fn insert(&mut self, cs_idx: usize) {
        debug_assert!(cs_idx < crate::sched::group::MAX_CS_PER_GROUP);
        self.0 |= 1u32 << cs_idx;
    }

    #[expect(dead_code)]
    pub(crate) fn iter(self) -> impl Iterator<Item = usize> {
        (0..crate::sched::group::MAX_CS_PER_GROUP)
            .filter(move |&cs_idx| (self.0 & (1u32 << cs_idx)) != 0)
    }
}

/// Maximum number of CS interfaces supported by hardware.
const MAX_CS: usize = 16;

/// MCU virtual address where the CSF shared memory region starts.
///
/// This region contains the firmware interface structures for communication between
/// the CPU driver and MCU firmware, including the GLB_CONTROL_BLOCK at this base address.
/// The firmware binary contains a section marked to be loaded at this address.
pub(super) const CSF_MCU_SHARED_REGION_START: u32 = 0x04000000;

/// Size of the MCU CSF shared memory region.
pub(super) const CSF_MCU_SHARED_REGION_SIZE: u32 = 0x04000000;

/// A parsed section of the firmware binary.
pub(crate) struct Section {
    // Raw firmware section data for reset purposes
    data: KVec<u8>,

    // Section flags, retained so a reset reload reproduces the zero
    // tail of the initial load.
    section_flags: SectionFlags,

    // CPU mapping of the section, retained so the reset path can
    // rewrite the section without allocating a fresh vmap.
    vmap: VMapOwned<BoData>,

    // Keep the BO backing this firmware section so that both the
    // GPU mapping and CPU mapping remain valid until the Section is dropped.
    mem: gem::KernelBo,
}

/// Loaded firmware with sections mapped into MCU VM.
#[pin_data(PinnedDrop)]
pub(crate) struct Firmware {
    /// Platform device reference (needed to access the MCU JOB_IRQ registers).
    pdev: ARef<platform::Device>,

    /// Iomem need to access registers.
    iomem: Arc<Devres<IoMem>>,

    /// MCU VM.
    vm: Arc<Vm>,

    /// List of firmware sections.
    sections: KVec<Section>,

    /// Firmware IRQ state, including readiness and event wait objects.
    irq_state: irq::JobIrqState,

    /// Set when the MCU was disabled without reaching the halted state.
    /// The resident sections may only be reused after a clean halt, so the
    /// next boot reloads them. Cleared once `post_reset` completes, so a
    /// reload that fails part way keeps it set.
    unclean_stop: Atomic<bool>,

    /// The global FW interface.
    #[pin]
    global_iface: GlobalInterface,
}

#[pinned_drop]
impl PinnedDrop for Firmware {
    fn drop(self: Pin<&mut Self>) {
        // AS slots retain a VM ref, we need to kill the circular ref manually.
        self.vm.kill();
    }
}

/// Why the MCU did not reach a requested `MCU_STATUS` value.
enum McuWaitError {
    /// The poll gave up with the MCU in this state.
    Timeout(McuStatus),

    /// The request or the read failed, so no state is reported.
    Failed(Error),
}

impl From<McuWaitError> for Error {
    fn from(e: McuWaitError) -> Self {
        match e {
            McuWaitError::Timeout(_) => ETIMEDOUT,
            McuWaitError::Failed(e) => e,
        }
    }
}

impl Firmware {
    fn find_shared_section(sections: &KVec<Section>) -> Result<&Section> {
        sections
            .iter()
            .find(|section| section.mem.va_range().start == u64::from(CSF_MCU_SHARED_REGION_START))
            .ok_or_else(|| {
                pr_err!(
                    "CSF shared section not found at 0x{:08x}\n",
                    CSF_MCU_SHARED_REGION_START
                );
                EINVAL
            })
    }

    fn init_section_mem(vmap: &VMapOwned<BoData>, data: &KVec<u8>, flags: SectionFlags) -> Result {
        let zero_tail = flags.contains(SectionFlag::Zero);

        if data.is_empty() && !zero_tail {
            return Ok(());
        }

        let size = vmap.owner().size();

        if data.len() > size {
            pr_err!("fw section {} bigger than BO {}\n", data.len(), size);
            return Err(EINVAL);
        }

        for (i, &byte) in data.iter().enumerate() {
            vmap.try_write8(byte, i)?;
        }

        if zero_tail {
            for i in data.len()..size {
                vmap.try_write8(0, i)?;
            }
        }

        Ok(())
    }

    fn request(
        ddev: &TyrDrmDevice<Uninit>,
        gpu_info: &GpuInfo,
    ) -> Result<kernel::firmware::Firmware> {
        let gpu_id = GPU_ID::from_raw(gpu_info.gpu_id);

        let path = CString::try_from_fmt(fmt!(
            "arm/mali/arch{}.{}/mali_csffw.bin",
            gpu_id.arch_major().get(),
            gpu_id.arch_minor().get()
        ))?;

        kernel::firmware::Firmware::request(&path, ddev.as_ref())
    }

    fn load(ddev: &TyrDrmDevice<Uninit>, gpu_info: &GpuInfo) -> Result<KVec<ParsedSection>> {
        let fw = Self::request(ddev, gpu_info)?;
        let mut parser = FwParser::new(fw.data());

        parser.parse()
    }

    /// Load firmware and map sections into MCU VM.
    pub(crate) fn new(
        pdev: &platform::Device,
        iomem: Arc<Devres<IoMem>>,
        ddev: &TyrDrmDevice<Uninit>,
        mmu: ArcBorrow<'_, Mmu>,
        gpu_info: &GpuInfo,
        coherent: bool,
        cleanup_wq: Arc<crate::driver::CleanupQueue>,
    ) -> Result<Arc<Firmware>> {
        let vm = Vm::new_fw(
            pdev,
            ddev,
            mmu,
            gpu_info,
            u64::from(CSF_MCU_SHARED_REGION_START),
            u64::from(CSF_MCU_SHARED_REGION_SIZE),
            coherent,
            cleanup_wq.clone(),
        )?;

        let parsed_sections = Self::load(ddev, gpu_info)?;

        vm.activate()?;

        let mut sections = KVec::new();
        for parsed in parsed_sections {
            let ParsedSection {
                data,
                va,
                vm_map_flags,
                section_flags,
            } = parsed;
            let size = (va.end - va.start) as usize;
            let va = u64::from(va.start);
            let end = va + size as u64;

            let mem = KernelBo::new(
                ddev,
                vm.as_arc_borrow(),
                size.try_into().unwrap(),
                KernelBoVaAlloc::Explicit(va),
                vm_map_flags,
                coherent,
                cleanup_wq.clone(),
            )?;

            let auto_va_start = u64::from(CSF_MCU_SHARED_REGION_START);
            let auto_va_end = auto_va_start + u64::from(CSF_MCU_SHARED_REGION_SIZE);
            if end > auto_va_start && va < auto_va_end {
                vm.reserve_kernel_range(va.max(auto_va_start), end.min(auto_va_end))?;
            }

            let vmap = mem.bo.owned_vmap::<0>()?;
            Self::init_section_mem(&vmap, &data, section_flags)?;

            sections.push(
                Section {
                    data,
                    section_flags,
                    vmap,
                    mem,
                },
                GFP_KERNEL,
            )?;
        }

        // Downstream-only debug aid; not for upstream.
        vm.pad_kernel_range(SZ_1M)?;

        let irq_state = irq::JobIrqState::new()?;
        let shared_section = Self::find_shared_section(&sections)?;
        let user_as_slot_count = mmu.as_slot_count().saturating_sub(1);
        let global_iface = GlobalInterface::new(
            pdev,
            iomem.clone(),
            shared_section,
            *gpu_info,
            &irq_state,
            user_as_slot_count,
        )?;

        let firmware = Arc::pin_init(
            try_pin_init!(Firmware {
                pdev: pdev.into(),
                iomem,
                vm,
                sections,
                irq_state,
                unclean_stop: Atomic::new(false),
                global_iface <- global_iface,
            }),
            GFP_KERNEL,
        )?;

        Ok(firmware)
    }

    /// Polls `MCU_STATUS` until it reaches `target` or the timeout elapses.
    ///
    /// The MMIO guard is re-acquired for each read so it is never held
    /// across the poll sleep, which would sleep under the RCU read lock.
    fn wait_for_mcu_status(
        iomem: &Devres<IoMem>,
        target: McuStatus,
        interval: time::Delta,
        timeout: time::Delta,
    ) -> Result<(), McuWaitError> {
        let mut last = None;

        poll::read_poll_timeout(
            || {
                iomem
                    .try_access()
                    .ok_or(ENODEV)
                    .map(|io| io.read(MCU_STATUS))
            },
            |status| {
                last = Some(status.value());
                status.value() == target
            },
            interval,
            timeout,
        )
        .map(|_| ())
        .map_err(|e| match last {
            Some(status) if e == ETIMEDOUT => McuWaitError::Timeout(status),
            _ => McuWaitError::Failed(e),
        })
    }

    pub(crate) fn boot(&self) -> Result {
        {
            let io = self.iomem.try_access().ok_or(ENODEV)?;
            io.write_reg(MCU_CONTROL::zeroed().with_req(McuControlMode::Auto));
        }

        if let Err(e) = Self::wait_for_mcu_status(
            &self.iomem,
            McuStatus::Enabled,
            time::Delta::from_millis(1),
            time::Delta::from_millis(100),
        ) {
            if let McuWaitError::Timeout(status) = e {
                pr_err!("MCU failed to boot, status: {:?}\n", status);
            }
            return Err(e.into());
        }
        Ok(())
    }

    fn halt_mcu(&self) -> Result<(), McuWaitError> {
        self.global_iface.halt_mcu().map_err(McuWaitError::Failed)?;

        Self::wait_for_mcu_status(
            &self.iomem,
            McuStatus::Halt,
            time::Delta::from_micros(10),
            time::Delta::from_millis(1000),
        )
    }

    fn stop_mcu(&self) {
        {
            let Some(io) = self.iomem.try_access() else {
                return;
            };
            io.write_reg(MCU_CONTROL::zeroed().with_req(McuControlMode::Disable));
        }

        if Self::wait_for_mcu_status(
            &self.iomem,
            McuStatus::Disabled,
            time::Delta::from_micros(10),
            time::Delta::from_millis(100),
        )
        .is_err()
        {
            dev_err!(self.pdev.as_ref(), "Failed to stop MCU\n");
        }
    }

    /// Returns whether the next boot has to reload the firmware sections.
    pub(crate) fn needs_reload(&self) -> bool {
        self.unclean_stop.load(Acquire)
    }

    /// Halts and stops the MCU for runtime suspend, releasing the firmware AS
    /// slot for resume to reprogram.
    pub(crate) fn suspend(&self, tdev: &TyrDrmDevice, dev: &Device<Bound>) {
        if let Err(e) = self.halt_mcu() {
            match e {
                McuWaitError::Timeout(status) => dev_warn!(
                    self.pdev.as_ref(),
                    "Failed to cleanly halt the MCU, status: {:?}\n",
                    status
                ),
                McuWaitError::Failed(e) => dev_warn!(
                    self.pdev.as_ref(),
                    "Failed to cleanly halt the MCU: {:?}\n",
                    e
                ),
            }
            self.unclean_stop.store(true, Release);
        }

        self.stop_mcu();
        tdev.job_irq.quiesce(dev, &self.iomem, irq::job_irq_disable);
        self.global_iface.suspend();
        let _ = self.vm.deactivate();
    }

    /// Stops the firmware for a GPU reset.
    ///
    /// The reset runs because the firmware stopped responding, so it
    /// is force-stopped and the subsequent `post_reset` does a
    /// full reload.
    ///
    /// The firmware VM is left resident so page-table updates on it keep
    /// issuing cache and TLB maintenance up to the soft reset. It is released
    /// after the soft reset by `mmu::post_reset`, together with the user VMs.
    pub(crate) fn pre_reset(&self, tdev: &TyrDrmDevice) {
        tdev.job_irq
            .reset_suspend(&self.iomem, irq::job_irq_disable);

        self.stop_mcu();
        self.global_iface.suspend();
    }

    /// Reboots the MCU after a GPU reset.
    ///
    /// The hang may have corrupted firmware memory, so every section is
    /// rewritten from the data retained at load time before the MCU
    /// restarts. The reload also clears the halt request in the global
    /// input block, so no explicit `set_mcu_active` is needed.
    pub(crate) fn post_reset(&self, tdev: &TyrDrmDevice) -> Result {
        tdev.job_irq.clear_suspended();

        self.vm.activate()?;
        self.reload_sections()?;
        self.irq_state.clear_ready();

        {
            let io = self.iomem.try_access().ok_or(ENODEV)?;
            irq::job_irq_enable(&io);
        }

        self.boot()?;
        self.wait_ready(1000).inspect_err(|_| {
            dev_err!(
                self.pdev.as_ref(),
                "Timed out waiting for firmware to be ready after reset.\n"
            )
        })?;

        self.reenable_global_interface(tdev)?;
        self.unclean_stop.store(false, Release);

        Ok(())
    }

    /// Cold-boots the firmware from the retained sections after a power
    /// cycle or wedge. The stop step forces the interface through the
    /// suspended state so bring-up starts from a known point.
    pub(crate) fn reload(&self, tdev: &TyrDrmDevice) -> Result {
        self.pre_reset(tdev);
        self.post_reset(tdev)
    }

    /// Rewrites every firmware section from the data retained at load
    /// time.
    ///
    /// Writes go through the vmaps retained in `Section`, so the reset
    /// path neither allocates nor takes BO locks.
    fn reload_sections(&self) -> Result {
        for section in self.sections.iter() {
            Self::init_section_mem(&section.vmap, &section.data, section.section_flags)?;
        }
        Ok(())
    }

    /// Boots the MCU from the resident firmware sections after a runtime
    /// suspend.
    ///
    /// The sections live in system RAM and survive the suspend, so they are
    /// not reloaded. Only valid while `needs_reload` returns false.
    pub(crate) fn resume(&self, tdev: &TyrDrmDevice) -> Result {
        tdev.job_irq.clear_suspended();

        self.vm.activate()?;
        self.irq_state.clear_ready();

        {
            let io = self.iomem.try_access().ok_or(ENODEV)?;
            irq::job_irq_enable(&io);
        }
        self.global_iface.set_mcu_active()?;

        self.boot()?;
        self.wait_ready(1000).inspect_err(|_| {
            dev_err!(
                self.pdev.as_ref(),
                "Timed out waiting for firmware to be ready.\n"
            )
        })?;

        self.reenable_global_interface(tdev)
    }

    /// Waits until the firmware signals readiness via the GLB IRQ bit.
    pub(crate) fn wait_ready(&self, timeout_ms: u32) -> Result {
        self.irq_state.wait_ready(timeout_ms)
    }

    pub(crate) fn irq_state(&self) -> irq::JobIrqState {
        self.irq_state.clone()
    }

    /// Acknowledges pending global interface events.
    ///
    /// Returns whether an idle event was pending.
    pub(super) fn process_global_irq(&self) -> Result<bool> {
        self.global_iface.process_global_irq()
    }

    /// Pings the firmware and waits up to `timeout_ms` for the ack.
    ///
    /// Returns `Err` if the firmware does not respond in time. The caller
    /// must only ping while the device is powered and no reset owns the
    /// firmware interface.
    pub(crate) fn ping(&self, timeout_ms: u32) -> Result {
        self.global_iface.ping(timeout_ms)
    }

    /// Probes global-interface liveness with a single ping.
    ///
    /// Returns the raw `GLB_REQ`/`GLB_ACK` words sampled around the ping
    /// together with the raw `MCU_STATUS` read once the ping wait is over,
    /// or `u32::MAX` if the registers went away with the device. Callers
    /// that already saw a CSG request go unacked use this to tell a
    /// stopped MCU from a stuck CSG state machine.
    ///
    /// Downstream-only debug aid. Not for upstream.
    pub(crate) fn probe_liveness(&self, timeout_ms: u32) -> Result<(GlbProbe, u32)> {
        let probe = self.global_iface.probe_liveness(timeout_ms)?;
        let mcu_status = self
            .iomem
            .try_access()
            .map_or(u32::MAX, |io| io.read(MCU_STATUS).into_raw());

        Ok((probe, mcu_status))
    }

    /// Enable the global interface.
    pub(crate) fn enable_global_interface(&self, tdev: &TyrDrmDevice) -> Result {
        let core_clk_rate = tdev.with_locked_core_clk(|core_clk| core_clk.rate().as_hz() as u64);
        self.global_iface.enable(core_clk_rate)?;
        TyrDrmDeviceData::arm_fw_ping(&tdev.into());
        Ok(())
    }

    /// Re-enables the global interface after a runtime resume or a GPU
    /// reset.
    fn reenable_global_interface(&self, tdev: &TyrDrmDevice) -> Result {
        let core_clk_rate = tdev.with_locked_core_clk(|core_clk| core_clk.rate().as_hz() as u64);
        self.global_iface.reenable(core_clk_rate)?;
        TyrDrmDeviceData::arm_fw_ping(&tdev.into());
        Ok(())
    }

    pub(crate) fn csif_info_counts(&self) -> Result<(u32, u32, u32, u32)> {
        self.global_iface.csif_info_counts()
    }

    pub(crate) fn group_suspend_buf_sizes(&self) -> Result<(u32, u32)> {
        self.global_iface.group_suspend_buf_sizes()
    }

    pub(crate) fn with_csg_mut<F, R>(&self, csg_idx: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut global::CsgInterface) -> Result<R>,
    {
        self.global_iface.with_csg_mut(csg_idx, f)
    }

    /// Toggles the per-CSG doorbells for every slot set in `csg_mask`
    /// and rings the global doorbell to make the firmware re-evaluate
    /// the requested slots.
    pub(crate) fn ring_csg_doorbells(&self, csg_mask: CsgSlotMask) -> Result {
        self.global_iface.ring_csg_doorbells(csg_mask)
    }

    /// Like `with_csg_mut` followed by `ring_csg_doorbells` for the same
    /// slot, but holds the firmware interface lock across `f` and the
    /// doorbell-request toggle. `f` must not sleep or take the scheduler
    /// or `csg_slot_manager` mutexes.
    pub(crate) fn with_csg_mut_ring_doorbell<F, R>(&self, csg_idx: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut global::CsgInterface) -> Result<R>,
    {
        self.global_iface.with_csg_mut_ring_doorbell(csg_idx, f)
    }

    /// Waits for the firmware to acknowledge every bit in `mask` for the
    /// `CSG_REQ` word at `csg_idx`.
    ///
    /// Returns the bits that the firmware has actually acknowledged
    /// (`!(req ^ ack) & mask`). The 3-bit `CSG_REQ::state` field is
    /// reported atomically: a partial state ack is reported as
    /// "not acked" and the corresponding bits are cleared from the
    /// returned mask. Other CSG_REQ bits are independent and reported
    /// per-bit.
    ///
    /// See `GlobalInterface::wait_csg_acks` for the locking
    /// constraints. In short: the caller must not hold the
    /// `csg_slot_manager` mutex (the per-slot IRQ path takes it via
    /// `process_csg_irqs` and would otherwise be blocked behind this
    /// wait), and the wait predicate must not re-take the firmware
    /// `inner` mutex (the snapshot pattern inside the helper handles
    /// this). The scheduler mutex may be held across the wait.
    pub(crate) fn wait_csg_acks(
        &self,
        csg_idx: usize,
        mask: CSG_REQ,
        timeout_ms: u32,
    ) -> Result<CSG_REQ> {
        self.global_iface.wait_csg_acks(csg_idx, mask, timeout_ms)
    }

    /// The firmware MCU VM.
    pub(crate) fn vm(&self) -> &Vm {
        &self.vm
    }

    /// Allocate a CS ring-buffer interface in the FW VM (AS0).
    pub(crate) fn alloc_queue_mem(&self, tdev: &TyrDrmDevice) -> Result<Arc<gem::MappedBo>> {
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);

        let mem = gem::new_kernel_object(
            tdev,
            &self.vm,
            SZ_8K,
            flags,
            tdev.coherent,
            tdev.cleanup_wq.clone(),
        )?;

        let vmap = mem.vmap();
        let size = vmap.owner().size();
        // SAFETY: `vmap` owns a writable CPU mapping for the BO and `size`
        // matches the mapped object size.
        let bytes = unsafe { core::slice::from_raw_parts_mut(vmap.addr() as *mut u8, size) };
        bytes.fill(0);

        Ok(mem)
    }

    pub(crate) fn alloc_suspend_buf(
        &self,
        tdev: &TyrDrmDevice,
        suspend_size: usize,
    ) -> Result<gem::KernelBo> {
        let flags = VmMapFlags::from(VmFlag::Noexec);

        gem::new_kernel_object_no_vmap(
            tdev,
            &self.vm,
            suspend_size,
            flags,
            tdev.coherent,
            tdev.cleanup_wq.clone(),
        )
        .inspect_err(|e| {
            dev_warn!(
                self.pdev.as_ref(),
                "Failed to allocate {} bytes for a suspend buffer in the firmware VM: {:?}\n",
                suspend_size,
                e
            );
        })
    }
}

/// Add modinfo entries for the firmware blobs needed by Tyr.
pub(crate) struct ModInfoBuilder<const N: usize>(firmware::ModInfoBuilder<N>);

impl<const N: usize> ModInfoBuilder<N> {
    const FILES: &'static [&'static str] = &["arm/mali/arch10.8/mali_csffw.bin"];

    pub(crate) const fn create(
        module_name: &'static kernel::str::CStr,
    ) -> kernel::firmware::ModInfoBuilder<N> {
        let mut builder = kernel::firmware::ModInfoBuilder::new(module_name);
        let mut index = 0;

        while index < Self::FILES.len() {
            builder = builder.new_entry().push(Self::FILES[index]);
            index += 1;
        }

        builder
    }
}
