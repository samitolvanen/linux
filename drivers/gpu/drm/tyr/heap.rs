// SPDX-License-Identifier: GPL-2.0 or MIT

//! The heap management implementation.
//!
//! Mali GPUs are [tiled
//! renderers](https://en.wikipedia.org/wiki/Tiled_rendering). This means that
//! the hardware tiler units do not know upfront how much memory a scene will
//! take and instead emit OOM events when they run out of memory. The driver is
//! reponsible for allocating more memory when this happens.
//!
//! This file contains the implementations for two driver ioctls:
//!
//! - DRM_PANTHOR_HEAP_CREATE: Create a tiler heap.
//! - DRM_PANTHOR_HEAP_DESTROY: Destroy a tiler heap.
//!
//! As well as the logic to dynamically grow the heap on OOM events.
//!

use core::sync::atomic::AtomicUsize;

use kernel::alloc::KVec;
use kernel::bits::genmask_u64;
use kernel::devres::Devres;
use kernel::io::mem::IoMem;
use kernel::kvec;
use kernel::new_mutex;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::uapi::SZ_128K;
use kernel::uapi::SZ_8M;
use kernel::xarray;
use kernel::xarray::XArray;

use crate::driver::TyrDevice;
use crate::gem;
use crate::mmu::vm::Vm;
use crate::mmu::vm::WithLockedVm;

const MAX_HEAPS_PER_POOL: u32 = 128;
const MAX_CONTEXT_SIZE: u32 = 32;

pub(crate) struct ChunkHeader {
    /// A GPU VA pointing to the next chunk in the list.
    next: u64,

    /// Other hardware-specific fields. MBZ.
    unknown: [u32; 14],
}

impl ChunkHeader {
    /// Reads a heap chunk header at a given offset.
    ///
    /// Note that the area pointed to by `ptr` is shared with the GPU, so we
    /// cannot simply parse it or cast it to &Self.
    ///
    /// Merely taking a reference to it would be UB, as the GPU can change the
    /// underlying memory at any time, as it is a core running on its own.
    pub(super) fn read(mem: &mut gem::ObjectRef, offset: usize) -> Result<Self> {
        if offset > mem.size() {
            return Err(EINVAL);
        }

        let vmap = mem.vmap()?;
        let ptr = unsafe { vmap.as_mut_ptr().add(offset).cast::<Self>() };
        // SAFETY: we know that this pointer is aligned and valid for reads for
        // at least size_of::<Self>() bytes.
        Ok(unsafe { core::ptr::read_volatile(ptr) })
    }

    /// Writes a heap chunk header at a given offset.
    ///
    /// Note that the area pointed to by `ptr` is shared with the GPU, so we
    /// cannot simply parse it or cast it to &Self.
    ///
    /// Merely taking a reference to it would be UB, as the GPU can change the
    /// underlying memory at any time, as it is a core running on its own.
    pub(super) fn write(mem: &mut gem::ObjectRef, offset: usize, value: Self) -> Result {
        if offset > mem.size() {
            return Err(EINVAL);
        }

        let vmap = mem.vmap()?;
        let ptr = unsafe { vmap.as_mut_ptr().add(offset).cast::<Self>() };
        // SAFETY: we know that this pointer is aligned and valid for writes for
        // at least size_of::<Self>() bytes.
        unsafe { core::ptr::write_volatile(ptr, value) };

        Ok(())
    }
}

pub(crate) struct ContextCreateArgs {
    pub(crate) initial_chunk_count: u32,
    pub(crate) chunk_size: u32,
    pub(crate) max_chunks: u32,
    pub(crate) target_in_flight: u32,
}

pub(crate) struct CreatedContext {
    pub(crate) context_id: usize,
    pub(crate) context_gpu_va: u64,
    pub(crate) first_chunk_gpu_va: u64,
}

pub(crate) struct ContextGrowArgs {
    pub(crate) heap_gpu_va: u64,
    pub(crate) renderpasses_in_flight: u32,
    pub(crate) pending_frag_count: u32,
}

pub(crate) struct Context {
    /// The VM this heap is bound to.
    vm: Arc<Mutex<Vm>>,
    chunks: KVec<gem::ObjectRef>,
    chunk_size: u32,
    max_chunks: u32,
    target_in_flight: u32,
}

impl Context {
    fn alloc_chunk(&mut self, tdev: &TyrDevice) -> Result {
        let chunk_bo = {
            let mut chunk_bo = self.vm.with_lock_taken(|vm| {
                pr_info!("Allocating heap chunk for context\n");
                gem::new_kernel_object(
                    tdev,
                    tdev.iomem.clone(),
                    vm,
                    gem::KernelVaPlacement::Auto {
                        size: self.chunk_size as usize,
                    },
                    crate::mmu::vm::map_flags::NOEXEC.into(),
                )
            })?;

            let vmap = chunk_bo.vmap()?;
            let mem = vmap.as_mut_slice();
            mem.fill(0);

            chunk_bo
        };

        // Chain the new chunk to the end of the list.
        if let Some(last) = self.chunks.last_mut() {
            let mut last_hdr = ChunkHeader::read(last, 0)?;
            last_hdr.next = (chunk_bo.kernel_va().ok_or(EINVAL)?.start & genmask_u64(12..=63))
                | (chunk_bo.size() as u64 >> 12);
            ChunkHeader::write(last, 0, last_hdr)?;
        }

        self.chunks.push(chunk_bo, GFP_KERNEL)?;
        Ok(())
    }
}

pub(crate) struct Pool {
    /// The VM this pool is bound to.
    vm: Arc<Mutex<Vm>>,

    gpu_contexts: Pin<KBox<Mutex<gem::ObjectRef>>>,
    pool_total_size: AtomicUsize,

    xa: Pin<KBox<XArray<KBox<Context>>>>,
    free_index: AtomicUsize,
}

impl Pool {
    pub(crate) fn create(
        tdev: &TyrDevice,
        iomem: Arc<Devres<IoMem>>,
        vm: Arc<Mutex<Vm>>,
    ) -> Result<Self> {
        let stride = tdev.gpu_info.heap_context_stride();

        let bo_size = MAX_HEAPS_PER_POOL * stride;
        let bo_size = bo_size.next_multiple_of(4096) as usize;

        let gpu_contexts = vm.with_lock_taken(|vm| {
            gem::new_kernel_object(
                tdev,
                iomem,
                vm,
                gem::KernelVaPlacement::Auto { size: bo_size },
                crate::mmu::vm::map_flags::NOEXEC.into(),
            )
        })?;

        let gpu_contexts = KBox::pin_init(new_mutex!(gpu_contexts), GFP_KERNEL)?;

        let pool_total_size = AtomicUsize::new(bo_size);

        let xa = KBox::pin_init(XArray::new(xarray::AllocKind::Alloc1), GFP_KERNEL)?;
        let free_index = AtomicUsize::new(1);

        Ok(Self {
            vm,
            gpu_contexts,
            pool_total_size,
            xa,
            free_index,
        })
    }

    pub(crate) fn create_heap_context(
        &self,
        tdev: &TyrDevice,
        mut args: ContextCreateArgs,
    ) -> Result<CreatedContext> {
        if args.initial_chunk_count == 0 {
            return Err(EINVAL);
        }

        if args.initial_chunk_count > args.max_chunks {
            return Err(EINVAL);
        }

        if args.chunk_size != args.chunk_size.next_multiple_of(4096) {
            return Err(EINVAL);
        }

        if args.chunk_size < SZ_128K || args.chunk_size > SZ_8M {
            return Err(EINVAL);
        }

        // Force 8MB chunks for now, as our TILER_OOM impl does not work.
        args.chunk_size = SZ_8M;

        let mut heap_ctx = KBox::new(
            Context {
                vm: self.vm.clone(),
                chunks: kvec![],
                chunk_size: args.chunk_size,
                max_chunks: args.max_chunks,
                target_in_flight: 0,
            },
            GFP_KERNEL,
        )?;

        pr_info!("Creating heap context: initial_chunks={}, chunk_size={:#x}, max_chunks={}, target_in_flight={}\n",
            args.initial_chunk_count,
            args.chunk_size,
            args.max_chunks,
            args.target_in_flight,
        );

        for _ in 0..args.initial_chunk_count {
            heap_ctx.alloc_chunk(tdev)?;
        }

        let first_chunk_gpu_va = heap_ctx
            .chunks
            .first()
            .and_then(|bo| bo.kernel_va())
            .ok_or(EINVAL)?
            .start;

        let context_gpu_va = self.gpu_contexts.lock().kernel_va().ok_or(EINVAL)?.start
            + (self.free_index.load(core::sync::atomic::Ordering::Relaxed) as u64
                * u64::from(tdev.gpu_info.heap_context_stride()));

        let index = self
            .free_index
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        let xa = self.xa.as_ref();
        let mut guard = xa.lock();
        guard
            .store(index, heap_ctx, GFP_KERNEL)
            .map_err(|_| EINVAL)?;

        Ok(CreatedContext {
            context_id: index,
            context_gpu_va,
            first_chunk_gpu_va,
        })
    }

    pub(crate) fn destroy_heap_context(&self, context_id: usize) -> Option<KBox<Context>> {
        let xa = self.xa.as_ref();
        let mut guard = xa.lock();
        guard.remove(context_id)
    }

    pub(crate) fn grow_heap_context(
        &mut self,
        tdev: &TyrDevice,
        args: ContextGrowArgs,
    ) -> Result<u64> {
        let offset = args.heap_gpu_va - self.gpu_contexts.lock().kernel_va().ok_or(EINVAL)?.start;

        let offset = u32::try_from(offset).map_err(|_| EINVAL)?;
        let index = offset / tdev.gpu_info.heap_context_stride();

        let xa = self.xa.as_ref();
        let mut guard = xa.lock();
        let heap_ctx = guard.get_mut(index as usize).ok_or(EINVAL)?;

        // if args.renderpasses_in_flight > heap_ctx.target_in_flight
        //     || heap_ctx.chunks.len() >= heap_ctx.max_chunks as usize
        // {
        //     return Err(ENOMEM);
        // }

        heap_ctx.alloc_chunk(tdev)?;

        let chunk_bo = heap_ctx.chunks.last().ok_or(EINVAL)?;
        let chunk_start = chunk_bo.kernel_va().ok_or(EINVAL)?.start;

        let new_chunk_gpu_va =
            (chunk_start & genmask_u64(12..=63)) | (chunk_bo.size() as u64 >> 12);

        Ok(new_chunk_gpu_va)
    }
}
