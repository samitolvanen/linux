// SPDX-License-Identifier: GPL-2.0 or MIT

//! Global CSF firmware interface implementation.
//!
//! This module owns the GLB-side firmware runtime state and configuration
//! path. It keeps the global request/ack protocol and CSG discovery together,
//! while leaving shared register definitions and low-level interface helpers in
//! fw/interfaces.rs.

mod cs;
mod csg;

use core::ops::Range;

use crate::{
	driver::IoMem,
	fw::{
		interfaces::{
			FwInterface,
			GLB_ACK,
			GLB_ACK_IRQ_MASK,
			GLB_ALLOC_EN,
			GLB_CONTROL_BLOCK_SIZE,
			GLB_GROUP_NUM,
			GLB_GROUP_STRIDE,
			GLB_IDLE_TIMER,
			GLB_INPUT_BLOCK_SIZE,
			GLB_INPUT_VA,
			GLB_OUTPUT_BLOCK_SIZE,
			GLB_OUTPUT_VA,
			GLB_PROGRESS_TIMER,
			GLB_PWROFF_TIMER,
			GLB_REQ,
			GLB_VERSION,
			CSG_CONTROL_BLOCK_SIZE,
		},
		irq::JobIrqState,
		Section,
		MAX_CSG,
	},
	gem::BoData,
	gpu::GpuInfo,
	regs::doorbell_block::DOORBELL,
	wait::Wait,
};
use kernel::{
	bindings::SZ_1K,
	clk::Clk,
	devres::Devres,
	drm::gem::shmem::VMapOwned,
	io::{
		register::Array,
		Io,
	},
	new_mutex,
	num::Bounded,
	platform,
	prelude::*,
	sync::{
		aref::ARef,
		Arc,
		Mutex,
	},
	time::arch_timer_get_rate,
};

pub(super) use self::csg::CsgInterface;

use crate::wait::WaitResult;

/// Encodes a GLB timer timeout and selects the backing time source.
pub(super) fn conv_timeout(core_clk: &Clk, timeout_us: u32) -> Result<(u32, Bounded<u32, 1>)> {
	// The max timeout is determined by the 31 bit size of the timeout field.
	let max_timeout = (1u32 << 31) - 1;
	let core_rate = core_clk.rate().as_hz() as u64;

	let (timer_rate, timer_source) = match arch_timer_get_rate() {
		Some(rate) => (u64::from(rate), Bounded::try_new(0).unwrap()),
		_ if core_rate != 0 => (core_rate, Bounded::try_new(1).unwrap()),
		_ => return Err(EINVAL),
	};

	let timeout_in_cycles = u64::from(timeout_us) * timer_rate;

	// The hardware stores the represented timeout value with a shr(10) to save space.
	let timeout_shift = u64::from(SZ_1K);
	let us_per_second = 1_000_000u64;

	let timeout_val = timeout_in_cycles.div_ceil(us_per_second * timeout_shift);
	let timeout_val = timeout_val.min(u64::from(max_timeout)) as u32;

	Ok((timeout_val, timer_source))
}

struct GlobalInterfaceRequests<'a> {
	input: &'a FwInterface<GLB_INPUT_BLOCK_SIZE>,
	output: &'a FwInterface<GLB_OUTPUT_BLOCK_SIZE>,
}

impl<'a> GlobalInterfaceRequests<'a> {
	fn new(
		input: &'a FwInterface<GLB_INPUT_BLOCK_SIZE>,
		output: &'a FwInterface<GLB_OUTPUT_BLOCK_SIZE>,
	) -> Self {
		Self { input, output }
	}

	fn wait_acks(&self, reqs_mask: GLB_REQ, event_wait: &Wait, timeout_ms: u32) -> Result {
		let mask = reqs_mask.into_raw();

		event_wait.wait_interruptible_timeout(timeout_ms, || {
			let req = self.input.read(GLB_REQ).into_raw() & mask;
			let ack = self.output.read(GLB_ACK).into_raw() & mask;
			if req == ack {
				Ok(WaitResult::Done)
			} else {
				Ok(WaitResult::Retry)
			}
		})
	}

	fn toggle_requests(&self, reqs_mask: GLB_REQ) -> Result {
		let reqs_mask_val = reqs_mask.into_raw();
		let cur_ack_val = self.output.read(GLB_ACK).into_raw();
		let toggled_bits = (cur_ack_val ^ reqs_mask_val) & reqs_mask_val;

		let cur_req_val = self.input.read(GLB_REQ).into_raw();
		let preserved_bits = cur_req_val & !reqs_mask_val;
		let new_val = toggled_bits | preserved_bits;

		self.input.write(GLB_REQ, GLB_REQ::from_raw(new_val));
		Ok(())
	}
}

enum GlobalInterfaceState {
	Disabled,
	Enabled(EnabledGlobalInterface),
}

#[expect(dead_code)]
struct EnabledGlobalInterface {
	glb_control: FwInterface<GLB_CONTROL_BLOCK_SIZE>,
	glb_input: FwInterface<GLB_INPUT_BLOCK_SIZE>,
	glb_output: FwInterface<GLB_OUTPUT_BLOCK_SIZE>,
	csg_stride: usize,
	csg_num: usize,
	csg: KVec<CsgInterface>,
}

struct InnerGlobalInterface {
	state: GlobalInterfaceState,
}

struct SharedSectionInfo {
	vmap: VMapOwned<BoData>,
	va_range: Range<u64>,
}

impl SharedSectionInfo {
	fn new(shared_section: &Section) -> Result<Self> {
		Ok(Self {
			vmap: shared_section.mem.bo.owned_vmap::<0>()?,
			va_range: shared_section.mem.va_range(),
		})
	}
}

#[pin_data]
pub(crate) struct GlobalInterface {
	pdev: ARef<platform::Device>,
	iomem: Arc<Devres<IoMem>>,
	shared_section: SharedSectionInfo,
	gpu_info: GpuInfo,
	event_wait: Arc<Wait>,
	#[pin]
	inner: Mutex<InnerGlobalInterface>,
}

impl GlobalInterface {
	pub(crate) fn new(
		pdev: &platform::Device,
		iomem: Arc<Devres<IoMem>>,
		shared_section: &Section,
		gpu_info: GpuInfo,
		irq_state: &JobIrqState,
	) -> Result<impl PinInit<Self, Error>> {
		let inner = InnerGlobalInterface::new();
		let pdev: ARef<platform::Device> = pdev.into();
		let shared_section = SharedSectionInfo::new(shared_section)?;
		let event_wait = irq_state.event_wait_arc();

		Ok(try_pin_init!(Self {
			pdev,
			iomem,
			shared_section,
			gpu_info,
			event_wait,
			inner <- new_mutex!(inner),
		}))
	}

	pub(crate) fn enable(&self, core_clk: &Clk) -> Result {
		let mut inner = self.inner.lock();
		inner.enable(
			&self.pdev,
			self.iomem.as_ref(),
			&self.shared_section,
			self.gpu_info,
			core_clk,
			self.event_wait.as_ref(),
		)
	}

	pub(crate) fn csif_info_counts(&self) -> Result<(u32, u32, u32, u32)> {
		let inner = self.inner.lock();
		inner.csif_info_counts()
	}

	pub(crate) fn group_suspend_buf_sizes(&self) -> Result<(u32, u32)> {
		let inner = self.inner.lock();
		inner.group_suspend_buf_sizes()
	}

	pub(super) fn process_global_irq(&self) -> Result {
		let mut inner = self.inner.lock();
		inner.process_global_irq(&self.event_wait)
	}

	#[allow(dead_code)]
	pub(super) fn with_csg_mut<F, R>(&self, csg_idx: usize, f: F) -> Result<R>
	where
		F: FnOnce(&mut csg::CsgInterface) -> Result<R>,
	{
		let mut inner = self.inner.lock();
		let csg = inner.csg_mut(csg_idx).ok_or(EINVAL)?;
		f(csg)
	}

	#[allow(dead_code)]
	pub(super) fn ring_csg_doorbell(&self, csg_idx: usize) -> Result {
		self.ring_doorbell(csg_idx + 1)
	}

	fn ring_doorbell(&self, doorbell_id: usize) -> Result {
		// SAFETY: Firmware global interface access only happens after the device is bound.
		let dev = unsafe { self.pdev.as_ref().as_bound() };
		let io = self.iomem.access(dev)?;
		let doorbell = Array::try_at(doorbell_id).ok_or(EINVAL)?;
		io.try_write(doorbell, DOORBELL::zeroed().with_ring(true))
	}
}

impl InnerGlobalInterface {
	fn new() -> Self {
		Self {
			state: GlobalInterfaceState::Disabled,
		}
	}

	fn enable(
		&mut self,
		pdev: &platform::Device,
		iomem: &Devres<IoMem>,
		shared_section: &SharedSectionInfo,
		gpu_info: GpuInfo,
		core_clk: &Clk,
		event_wait: &Wait,
	) -> Result {
		let glb_control =
			FwInterface::<GLB_CONTROL_BLOCK_SIZE>::new(
				&shared_section.vmap,
				&shared_section.va_range,
				shared_section.va_range.start,
			)?;

		let version = glb_control.read(GLB_VERSION);
		if version.major().get() == 0 {
			pr_err!("CSF interface version is 0. Firmware may have failed to boot.\n");
			return Err(EINVAL);
		}
		pr_info!(
			"CSF interface version: {}.{}.{}\n",
			version.major().get(),
			version.minor().get(),
			version.patch().get()
		);

		let input_va = glb_control.read(GLB_INPUT_VA);
		let glb_input = FwInterface::<GLB_INPUT_BLOCK_SIZE>::new(
			&shared_section.vmap,
			&shared_section.va_range,
			input_va.value().get().into(),
		)?;

		let output_va = glb_control.read(GLB_OUTPUT_VA);
		let glb_output = FwInterface::<GLB_OUTPUT_BLOCK_SIZE>::new(
			&shared_section.vmap,
			&shared_section.va_range,
			output_va.value().get().into(),
		)?;

		Self::configure_glb_input(&glb_input, &gpu_info, core_clk)?;
		let ack_mask = Self::configure_glb_requests(&glb_input, &glb_output)?;

		// SAFETY: Called during probe after the device has been successfully bound,
		// so it is valid to access it as a bound device.
		let dev = unsafe { pdev.as_ref().as_bound() };
		let io = iomem.access(dev)?;
		io.write(Array::at(0), DOORBELL::zeroed().with_ring(true));

		let request_field = GlobalInterfaceRequests::new(&glb_input, &glb_output);
		if let Err(e) = request_field.wait_acks(ack_mask, event_wait, 1000) {
			pr_err!("CSF firmware failed to ACK initial GLB config\n");
			return Err(e);
		}

		let csg_num = glb_control.read(GLB_GROUP_NUM).value().get();
		let csg_stride = glb_control.read(GLB_GROUP_STRIDE).value().get() as usize;

		if csg_stride < CSG_CONTROL_BLOCK_SIZE {
			pr_err!(
				"CSG stride {} is smaller than control block size {}\n",
				csg_stride,
				CSG_CONTROL_BLOCK_SIZE
			);
			return Err(EINVAL);
		}

		if csg_num as usize > MAX_CSG {
			pr_err!(
				"Too many CSGs: hardware reports {}, max supported {}\n",
				csg_num,
				MAX_CSG
			);
			return Err(EINVAL);
		}

		self.state = GlobalInterfaceState::Enabled(EnabledGlobalInterface {
			glb_control,
			glb_input,
			glb_output,
			csg_stride,
			csg_num: csg_num as usize,
			csg: KVec::with_capacity(csg_num as usize, GFP_KERNEL)?,
		});

		self.init_csg(shared_section)
	}

	fn configure_glb_input(
		glb_input: &FwInterface<GLB_INPUT_BLOCK_SIZE>,
		gpu_info: &GpuInfo,
		core_clk: &Clk,
	) -> Result {
		glb_input.write(
			GLB_ALLOC_EN,
			GLB_ALLOC_EN::zeroed().with_mask(gpu_info.shader_present),
		);

		const PWROFF_HYSTERESIS_US: u32 = 10_000;
		let (pwroff_timeout, pwroff_source) = conv_timeout(core_clk, PWROFF_HYSTERESIS_US)?;
		let pwroff_timeout = Bounded::<u32, 31>::try_new(pwroff_timeout).ok_or(EINVAL)?;
		glb_input.write(
			GLB_PWROFF_TIMER,
			GLB_PWROFF_TIMER::zeroed()
				.with_timeout(pwroff_timeout)
				.with_timer_source(pwroff_source.into()),
		);

		const PROGRESS_TIMEOUT_CYCLES: u32 = 5 * 500 * 1024 * 1024;
		const PROGRESS_TIMEOUT_SCALE_SHIFT: u32 = 10;
		let progress_timeout = PROGRESS_TIMEOUT_CYCLES >> PROGRESS_TIMEOUT_SCALE_SHIFT;
		glb_input.write(
			GLB_PROGRESS_TIMER,
			GLB_PROGRESS_TIMER::zeroed().with_timeout(progress_timeout),
		);

		const IDLE_HYSTERESIS_US: u32 = 800;
		let (idle_timeout, idle_source) = conv_timeout(core_clk, IDLE_HYSTERESIS_US)?;
		let idle_timeout = Bounded::<u32, 31>::try_new(idle_timeout).ok_or(EINVAL)?;
		glb_input.write(
			GLB_IDLE_TIMER,
			GLB_IDLE_TIMER::zeroed()
				.with_timeout(idle_timeout)
				.with_timer_source(idle_source.into()),
		);

		Ok(())
	}

	fn configure_glb_requests(
		glb_input: &FwInterface<GLB_INPUT_BLOCK_SIZE>,
		glb_output: &FwInterface<GLB_OUTPUT_BLOCK_SIZE>,
	) -> Result<GLB_REQ> {
		glb_input.write(
			GLB_ACK_IRQ_MASK,
			GLB_ACK_IRQ_MASK::zeroed()
				.with_cfg_progress_timer(true)
				.with_cfg_alloc_en(true)
				.with_cfg_pwroff_timer(true)
				.with_idle_enable(true)
				.with_idle_event(true)
				.with_counter_enable(true),
		);

		let cur_req = glb_input.read(GLB_REQ);
		glb_input.write(
			GLB_REQ,
			cur_req.with_idle_enable(true).with_counter_enable(true),
		);

		let request_field = GlobalInterfaceRequests::new(glb_input, glb_output);
		let toggle_mask = GLB_REQ::zeroed()
			.with_cfg_progress_timer(true)
			.with_cfg_alloc_en(true)
			.with_cfg_pwroff_timer(true);
		request_field.toggle_requests(toggle_mask)?;

		Ok(GLB_REQ::zeroed()
			.with_cfg_progress_timer(true)
			.with_cfg_alloc_en(true)
			.with_cfg_pwroff_timer(true)
			.with_idle_enable(true)
			.with_counter_enable(true))
	}

	fn init_csg(&mut self, shared_section: &SharedSectionInfo) -> Result {
		let enabled = match &mut self.state {
			GlobalInterfaceState::Enabled(enabled) => enabled,
			GlobalInterfaceState::Disabled => return Err(EINVAL),
		};

		for csg_idx in 0..enabled.csg_num {
			let mut csg = CsgInterface::new(csg_idx)?;
			csg.enable(shared_section, csg_idx, enabled.csg_stride)?;
			enabled.csg.push(csg, GFP_KERNEL)?;
		}

		Ok(())
	}

	fn csg(&self, index: usize) -> Option<&CsgInterface> {
		let enabled = match &self.state {
			GlobalInterfaceState::Enabled(enabled) => enabled,
			GlobalInterfaceState::Disabled => return None,
		};

		enabled.csg.get(index)
	}

	fn csg_mut(&mut self, index: usize) -> Option<&mut CsgInterface> {
		let enabled = match &mut self.state {
			GlobalInterfaceState::Enabled(enabled) => enabled,
			GlobalInterfaceState::Disabled => return None,
		};

		enabled.csg.get_mut(index)
	}

	fn process_global_irq(&mut self, event_wait: &Wait) -> Result {
		let enabled = match &self.state {
			GlobalInterfaceState::Enabled(enabled) => enabled,
			GlobalInterfaceState::Disabled => return Ok(()),
		};

		let request_field = GlobalInterfaceRequests::new(&enabled.glb_input, &enabled.glb_output);
		let req = enabled.glb_input.read(GLB_REQ);
		let ack = enabled.glb_output.read(GLB_ACK);
		let pending_idle = req.idle_event() ^ ack.idle_event();

		if pending_idle {
			let idle_mask = GLB_REQ::zeroed().with_idle_event(true);
			request_field.toggle_requests(idle_mask)?;
			request_field.wait_acks(idle_mask, event_wait, 1000)?;
		}

		Ok(())
	}

	fn csg_slot_count(&self) -> Result<u32> {
		let enabled = match &self.state {
			GlobalInterfaceState::Enabled(enabled) => enabled,
			GlobalInterfaceState::Disabled => return Err(EINVAL),
		};

		Ok(enabled.csg_num as u32)
	}

	fn csif_info_counts(&self) -> Result<(u32, u32, u32, u32)> {
		let csg = self.csg(0).ok_or(EINVAL)?;
		let cs = csg.cs(0).ok_or(EINVAL)?;

		Ok((
			self.csg_slot_count()?,
			csg.cs_slot_count()?,
			cs.work_regs()?,
			cs.scoreboards()?,
		))
	}

	fn group_suspend_buf_sizes(&self) -> Result<(u32, u32)> {
		let csg = self.csg(0).ok_or(EINVAL)?;

		csg.suspend_buf_sizes()
	}
}
