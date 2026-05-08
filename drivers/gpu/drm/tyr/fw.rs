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
    devres::Devres,
    drm::{
        gem::BaseObject,
        Uninit, //
    },
    firmware,
    io::{
        poll,
        Io, //
    },
    platform,
    prelude::*,
    sizes::SZ_8K,
    str::CString,
    sync::{aref::ARef, Arc, ArcBorrow},
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
            ParsedSection, //
        },
    },
    gem,
    gem::{
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

/// A parsed section of the firmware binary.
pub(crate) struct Section {
    // Raw firmware section data for reset purposes
    #[expect(dead_code)]
    data: KVec<u8>,

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

    fn init_section_mem(mem: &mut KernelBo, data: &KVec<u8>) -> Result {
        if data.is_empty() {
            return Ok(());
        }

        let vmap = mem.bo.vmap::<0>()?;
        let size = mem.bo.size();

        if data.len() > size {
            pr_err!("fw section {} bigger than BO {}\n", data.len(), size);
            return Err(EINVAL);
        }

        for (i, &byte) in data.iter().enumerate() {
            vmap.try_write8(byte, i)?;
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
    ) -> Result<Arc<Firmware>> {
        let vm = Vm::new(pdev, ddev, mmu, gpu_info)?;

        let parsed_sections = Self::load(ddev, gpu_info)?;

        vm.activate()?;

        let mut sections = KVec::new();
        for parsed in parsed_sections {
            let ParsedSection {
                data,
                va,
                vm_map_flags,
            } = parsed;
            let size = (va.end - va.start) as usize;
            let va = u64::from(va.start);

            let mut mem = KernelBo::new(
                ddev,
                vm.as_arc_borrow(),
                size.try_into().unwrap(),
                KernelBoVaAlloc::Explicit(va),
                vm_map_flags,
            )?;

            Self::init_section_mem(&mut mem, &data)?;

            sections.push(Section { data, mem }, GFP_KERNEL)?;
        }

        let irq_state = irq::JobIrqState::new()?;
        let shared_section = Self::find_shared_section(&sections)?;
        let global_iface =
            GlobalInterface::new(pdev, iomem.clone(), shared_section, *gpu_info, &irq_state)?;

        let firmware = Arc::pin_init(
            try_pin_init!(Firmware {
                pdev: pdev.into(),
                iomem,
                vm,
                sections,
                irq_state,
                global_iface <- global_iface,
            }),
            GFP_KERNEL,
        )?;

        Ok(firmware)
    }

    pub(crate) fn boot(&self) -> Result {
        // SAFETY: Boot is currently only called in the probe path, so we're sure we have a bound
        // device.
        let dev = unsafe { self.pdev.as_ref().as_bound() };
        let io = (self.iomem).access(dev)?;
        io.write_reg(MCU_CONTROL::zeroed().with_req(McuControlMode::Auto));

        if let Err(e) = poll::read_poll_timeout(
            || Ok(io.read(MCU_STATUS)),
            |status| status.value() == McuStatus::Enabled,
            time::Delta::from_millis(1),
            time::Delta::from_millis(100),
        ) {
            let status = io.read(MCU_STATUS);
            pr_err!("MCU failed to boot, status: {:?}", status.value());
            return Err(e);
        }
        Ok(())
    }

    /// Waits until the firmware signals readiness via the GLB IRQ bit.
    pub(crate) fn wait_ready(&self, timeout_ms: u32) -> Result {
        self.irq_state.wait_ready(timeout_ms)
    }

    pub(crate) fn irq_state(&self) -> irq::JobIrqState {
        self.irq_state.clone()
    }

    pub(super) fn process_global_irq(&self) -> Result {
        self.global_iface.process_global_irq()
    }

    /// Enable the global interface.
    pub(crate) fn enable_global_interface(&self, tdev: &TyrDrmDevice) -> Result {
        // Drop the clks lock before enable(), which can block on
        // firmware ack waits for up to a second.
        let core_clk_rate = tdev.with_locked_core_clk(|core_clk| core_clk.rate().as_hz() as u64);
        self.global_iface.enable(core_clk_rate)
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

    pub(crate) fn ring_csg_doorbell(&self, csg_idx: usize) -> Result {
        self.global_iface.ring_csg_doorbell(csg_idx)
    }

    /// Toggles the per-CSG doorbells for every slot set in `csg_mask`
    /// and rings the global doorbell to make the firmware re-evaluate
    /// the requested slots.
    pub(crate) fn ring_csg_doorbells(&self, csg_mask: CsgSlotMask) -> Result {
        self.global_iface.ring_csg_doorbells(csg_mask)
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
    /// See [`GlobalInterface::wait_csg_acks`] for the locking
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

    /// Allocate a CS ring-buffer interface in the FW VM (AS0).
    pub(crate) fn alloc_queue_mem(&self, tdev: &TyrDrmDevice) -> Result<Arc<gem::MappedBo>> {
        let flags = VmMapFlags::from(VmFlag::Noexec) | VmMapFlags::from(VmFlag::Uncached);

        gem::new_kernel_object(tdev, &self.vm, SZ_8K, flags)
    }

    pub(crate) fn alloc_suspend_buf(
        &self,
        tdev: &TyrDrmDevice,
        suspend_size: usize,
    ) -> Result<Arc<gem::MappedBo>> {
        let flags = VmMapFlags::from(VmFlag::Noexec);

        gem::new_kernel_object(tdev, &self.vm, suspend_size, flags)
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
