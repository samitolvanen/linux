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
    drm::gem::{
        shmem::VMapOwned,
        BaseObject, //
    },
    firmware,
    io::{
        mem::DevresIoMem,
        poll,
        Io,
        IoBase, //
    },
    platform,
    prelude::*,
    sizes::{
        SZ_2M,
        SZ_8K, //
    },
    str::CString,
    sync::{
        Arc,
        ArcBorrow, //
    },
    time, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice, //
    },
    fw::{
        global::GlobalInterface,
        parser::{
            FwParser,
            ParsedSection,
            SectionFlags, //
        }, //
    },
    gem,
    gem::{
        BoData,
        KernelBo,
        KernelBoVaAlloc, //
    },
    gpu::GpuInfo,
    irq::{
        clear_suspended,
        quiesce, //
    },
    mmu::Mmu,
    regs::gpu_control::{
        McuControlMode,
        McuStatus,
        GPU_ID,
        MCU_CONTROL,
        MCU_STATUS, //
    },
    sched::group::MAX_CS_PER_GROUP,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    }, //
};

pub(crate) mod global;
mod interfaces;
pub(crate) mod irq;
mod parser;
mod region;

// Re-exports of firmware-interface bitfield types and enums that the
// scheduler needs to construct CSG_INPUT writes from outside the
// firmware module. The bitfield definitions themselves stay private
// to `crate::fw`. The apply path only depends on these typed views.
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
        debug_assert!(cs_idx < MAX_CS_PER_GROUP);
        self.0 |= 1u32 << cs_idx;
    }

    #[expect(dead_code)]
    pub(crate) fn iter(self) -> impl Iterator<Item = usize> {
        (0..MAX_CS_PER_GROUP).filter(move |&cs_idx| (self.0 & (1u32 << cs_idx)) != 0)
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
pub(crate) struct Firmware<'drm> {
    /// The bound device the firmware sections are mapped for.
    dev: &'drm platform::Device<Bound>,

    /// Device-managed handle to the GPU MMIO register mapping, held so
    /// `Drop` can stop the MCU.
    iomem: Arc<DevresIoMem<SZ_2M>>,

    /// MCU VM.
    vm: Arc<Vm>,

    /// Firmware sections, held to keep their mappings alive while the MCU runs.
    sections: KVec<Section>,

    /// Firmware IRQ state, including readiness and event wait objects.
    irq_state: irq::JobIrqState,

    /// The global FW interface.
    global_iface: Arc<GlobalInterface<'drm>>,
}

impl<'drm> Drop for Firmware<'drm> {
    fn drop(&mut self) {
        // Stop the MCU before releasing its firmware mappings and memory.
        if let Ok(io) = self.iomem.access(self.dev.as_ref()) {
            let _ = self.stop(io);
        }

        // AS slots retain a VM ref, we need to kill the circular ref manually.
        self.vm.kill();
    }
}

impl<'drm> Firmware<'drm> {
    fn find_shared_section<'a>(dev: &Device, sections: &'a KVec<Section>) -> Result<&'a Section> {
        sections
            .iter()
            .find(|section| section.mem.va_range().start == u64::from(CSF_MCU_SHARED_REGION_START))
            .ok_or_else(|| {
                dev_err!(
                    dev,
                    "CSF shared section not found at 0x{:08x}",
                    CSF_MCU_SHARED_REGION_START
                );
                EINVAL
            })
    }

    fn init_section_mem(
        dev: &Device,
        vmap: &VMapOwned<BoData>,
        data: &KVec<u8>,
        flags: SectionFlags,
    ) -> Result {
        let zero_tail = flags.zero();

        if data.is_empty() && !zero_tail {
            return Ok(());
        }

        let size = vmap.owner().size();

        if data.len() > size {
            dev_err!(dev, "fw section {} bigger than BO {}", data.len(), size);
            return Err(EINVAL);
        }

        let dst = vmap.as_view().as_ptr().cast::<u8>();
        // SAFETY: `dst` is the section BO's writable CPU mapping, valid for
        // `size` bytes, and the check above bounds `data.len()` by `size`.
        // `data` is a separate allocation.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };

        if zero_tail {
            // SAFETY: `dst` is valid for `size` bytes and the check above bounds
            // `data.len()` by `size`, so the tail ends at `size`.
            unsafe { core::ptr::write_bytes(dst.add(data.len()), 0, size - data.len()) };
        }

        Ok(())
    }

    fn request(ddev: &TyrDrmDevice, gpu_info: &GpuInfo) -> Result<kernel::firmware::Firmware> {
        let gpu_id = GPU_ID::from_raw(gpu_info.gpu_id);

        let path = CString::try_from_fmt(fmt!(
            "arm/mali/arch{}.{}/mali_csffw.bin",
            gpu_id.arch_major().get(),
            gpu_id.arch_minor().get()
        ))?;

        kernel::firmware::Firmware::request(&path, ddev.as_ref().as_ref())
    }

    fn load(dev: &Device, ddev: &TyrDrmDevice, gpu_info: &GpuInfo) -> Result<KVec<ParsedSection>> {
        let fw = Self::request(ddev, gpu_info)?;
        let mut parser = FwParser::new(dev, fw.data());

        parser.parse()
    }

    /// Load firmware and map sections into MCU VM.
    pub(crate) fn new(
        pdev: &'drm platform::Device<Bound>,
        iomem: Arc<DevresIoMem<SZ_2M>>,
        ddev: &TyrDrmDevice,
        mmu: ArcBorrow<'_, Mmu>,
        gpu_info: &GpuInfo,
        coherent: bool,
    ) -> Result<Firmware<'drm>> {
        let dev = pdev.as_ref();
        let vm = Vm::new_fw(
            pdev,
            ddev,
            mmu,
            gpu_info,
            u64::from(CSF_MCU_SHARED_REGION_START),
            u64::from(CSF_MCU_SHARED_REGION_SIZE),
            coherent,
        )?;
        vm.activate()?;

        let result = (|| {
            let parsed_sections = Self::load(dev, ddev, gpu_info)?;
            let mut sections = KVec::new();
            for parsed in parsed_sections {
                let ParsedSection {
                    data,
                    va,
                    vm_map_flags,
                    section_flags,
                } = parsed;
                let size = u64::from(va.end.checked_sub(va.start).ok_or(EINVAL)?);

                let va = u64::from(va.start);
                let end = va + size;

                let mem = KernelBo::new(
                    dev,
                    ddev,
                    vm.clone(),
                    size,
                    KernelBoVaAlloc::Explicit(va),
                    vm_map_flags,
                    coherent,
                )?;

                let auto_va_start = u64::from(CSF_MCU_SHARED_REGION_START);
                let auto_va_end = auto_va_start + u64::from(CSF_MCU_SHARED_REGION_SIZE);
                if end > auto_va_start && va < auto_va_end {
                    vm.reserve_kernel_range(va.max(auto_va_start), end.min(auto_va_end))?;
                }

                let vmap = mem.bo().owned_vmap::<0>()?;
                Self::init_section_mem(dev, &vmap, &data, section_flags)?;

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

            let irq_state = irq::JobIrqState::new()?;
            let user_as_slot_count = mmu.as_slot_count().saturating_sub(1);
            let shared_section = Self::find_shared_section(dev, &sections)?;
            let global_iface = Arc::pin_init(
                GlobalInterface::new(
                    pdev.as_ref(),
                    iomem.clone(),
                    shared_section,
                    *gpu_info,
                    &irq_state,
                    user_as_slot_count,
                )?,
                GFP_KERNEL,
            )?;

            Ok(Firmware {
                dev: pdev,
                iomem,
                vm: vm.clone(),
                sections,
                irq_state,
                global_iface,
            })
        })();

        if result.is_err() {
            vm.kill();
        }

        result
    }

    /// Polls `MCU_STATUS` until it reaches `target` or the timeout elapses.
    fn wait_for_mcu_status(
        io: &IoMem<'_>,
        target: McuStatus,
        interval: time::Delta,
        timeout: time::Delta,
    ) -> Result {
        poll::read_poll_timeout(
            || Ok(io.read(MCU_STATUS)),
            |status| status.value() == target,
            interval,
            timeout,
        )
        .map(|_| ())
    }

    pub(crate) fn boot(&self, io: &IoMem<'_>) -> Result {
        io.write_reg(MCU_CONTROL::zeroed().with_req(McuControlMode::Auto));

        if let Err(e) = Self::wait_for_mcu_status(
            io,
            McuStatus::Enabled,
            time::Delta::from_millis(1),
            time::Delta::from_millis(100),
        ) {
            let status = io.read(MCU_STATUS);
            dev_err!(self.dev, "MCU failed to boot, status: {:?}", status.value());
            return Err(e);
        }

        Ok(())
    }

    fn stop(&self, io: &IoMem<'_>) -> Result {
        io.write_reg(MCU_CONTROL::zeroed().with_req(McuControlMode::Disable));

        if let Err(e) = Self::wait_for_mcu_status(
            io,
            McuStatus::Disabled,
            time::Delta::from_micros(10),
            time::Delta::from_millis(100),
        ) {
            let status = io.read(MCU_STATUS);
            dev_err!(self.dev, "MCU failed to stop, status: {:?}", status.value());
            return Err(e);
        }

        Ok(())
    }

    fn halt_mcu(&self, io: &IoMem<'_>) -> Result {
        self.global_iface.halt_mcu()?;

        Self::wait_for_mcu_status(
            io,
            McuStatus::Halt,
            time::Delta::from_micros(10),
            time::Delta::from_millis(1000),
        )
    }

    /// Halts and stops the MCU for runtime suspend, releasing the firmware AS
    /// slot for resume to reprogram.
    pub(crate) fn suspend(&self, job_irq: &irq::JobIrqRegistration<'_>, io: &IoMem<'_>) {
        if let Err(e) = self.halt_mcu(io) {
            dev_warn!(self.dev, "Failed to cleanly halt the MCU: {:?}\n", e);
        }

        let _ = self.stop(io);
        quiesce(job_irq, io, irq::job_irq_disable);
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
    pub(crate) fn pre_reset(&self, job_irq: &irq::JobIrqRegistration<'_>, io: &IoMem<'_>) {
        quiesce(job_irq, io, irq::job_irq_disable);

        let _ = self.stop(io);
        self.global_iface.suspend();
    }

    /// Reboots the MCU after a GPU reset.
    ///
    /// The hang may have corrupted firmware memory, so every section is
    /// rewritten from the data retained at load time before the MCU
    /// restarts. The reload also clears the halt request in the global
    /// input block, so no explicit `set_mcu_active` is needed.
    pub(crate) fn post_reset(
        &self,
        job_irq: &irq::JobIrqRegistration<'_>,
        core_clk_rate: u64,
        io: &IoMem<'_>,
    ) -> Result {
        clear_suspended(job_irq);

        self.vm.activate()?;
        self.reload_sections()?;
        self.irq_state.clear_ready();

        irq::job_irq_enable(io);

        self.boot(io)?;
        self.wait_ready(1000).inspect_err(|_| {
            dev_err!(
                self.dev,
                "Timed out waiting for firmware to be ready after reset.\n"
            )
        })?;

        self.reenable_global_interface(core_clk_rate, io)
    }

    /// Cold-boots the firmware from the retained sections after a power
    /// cycle or wedge. The stop step forces the interface through the
    /// suspended state so bring-up starts from a known point.
    pub(crate) fn reload(
        &self,
        job_irq: &irq::JobIrqRegistration<'_>,
        core_clk_rate: u64,
        io: &IoMem<'_>,
    ) -> Result {
        self.pre_reset(job_irq, io);
        self.post_reset(job_irq, core_clk_rate, io)
    }

    /// Rewrites every firmware section from the data retained at load
    /// time.
    ///
    /// Writes go through the vmaps retained in `Section`, so the reset
    /// path neither allocates nor takes BO locks.
    fn reload_sections(&self) -> Result {
        for section in self.sections.iter() {
            Self::init_section_mem(
                self.vm.dev(),
                &section.vmap,
                &section.data,
                section.section_flags,
            )?;
        }
        Ok(())
    }

    /// Boots the MCU from the resident firmware sections after a runtime
    /// suspend.
    ///
    /// The sections live in system RAM and survive the suspend, so they are
    /// not reloaded.
    pub(crate) fn resume(
        &self,
        job_irq: &irq::JobIrqRegistration<'_>,
        core_clk_rate: u64,
        io: &IoMem<'_>,
    ) -> Result {
        clear_suspended(job_irq);

        self.vm.activate()?;
        self.irq_state.clear_ready();

        irq::job_irq_enable(io);
        self.global_iface.set_mcu_active()?;

        self.boot(io)?;
        self.wait_ready(1000)
            .inspect_err(|_| dev_err!(self.dev, "Timed out waiting for firmware to be ready.\n"))?;

        self.reenable_global_interface(core_clk_rate, io)
    }

    /// Waits until the firmware signals readiness via the GLB IRQ bit.
    pub(crate) fn wait_ready(&self, timeout_ms: u32) -> Result {
        self.irq_state.wait_ready(timeout_ms)
    }

    pub(crate) fn irq_state(&self) -> irq::JobIrqState {
        self.irq_state.clone()
    }

    pub(crate) fn global_iface(&self) -> Arc<GlobalInterface<'drm>> {
        self.global_iface.clone()
    }

    /// Enable the global interface.
    pub(crate) fn enable_global_interface(&self, core_clk_rate: u64, io: &IoMem<'_>) -> Result {
        self.global_iface.enable(core_clk_rate, io)
    }

    /// Re-enables the global interface after a runtime resume or a GPU
    /// reset.
    fn reenable_global_interface(&self, core_clk_rate: u64, io: &IoMem<'_>) -> Result {
        self.global_iface.reenable(core_clk_rate, io)
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
    /// reported atomically. A partial state ack is reported as
    /// "not acked" and the corresponding bits are cleared from the
    /// returned mask. Other CSG_REQ bits are independent and reported
    /// per-bit.
    ///
    /// See `GlobalInterface::wait_csg_acks` for the locking
    /// constraints. The caller must not hold the
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

    /// Allocate a CS ring-buffer interface in the FW VM (AS0).
    pub(crate) fn alloc_queue_mem(&self, ddev: &TyrDrmDevice) -> Result<Arc<gem::MappedBo>> {
        let dev = self.dev.as_ref();
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);

        let mem = gem::new_kernel_object(dev, ddev, &self.vm, SZ_8K, flags, ddev.coherent)?;

        let vmap = mem.vmap();
        let size = vmap.owner().size();
        // SAFETY: `vmap` owns a writable CPU mapping for the BO and `size`
        // matches the mapped object size.
        unsafe { core::ptr::write_bytes(vmap.as_view().as_ptr().cast::<u8>(), 0, size) };

        Ok(mem)
    }

    pub(crate) fn alloc_suspend_buf(
        &self,
        ddev: &TyrDrmDevice,
        suspend_size: usize,
    ) -> Result<gem::KernelBo> {
        let dev = self.dev.as_ref();
        let flags = VmMapFlags::from(VmFlag::Noexec);

        gem::new_kernel_object_no_vmap(dev, ddev, &self.vm, suspend_size, flags, ddev.coherent)
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
