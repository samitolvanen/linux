// SPDX-License-Identifier: GPL-2.0 or MIT

//! Tiler heap management.

use core::sync::atomic::{AtomicUsize, Ordering};

use kernel::{
    alloc::KVec,
    drm::gem::BaseObject,
    io::Io,
    kvec,
    prelude::*,
    sync::Arc,
    uapi,
    uapi::{SZ_128K, SZ_8M},
    xarray,
    xarray::XArray,
};

use crate::{
    driver::TyrDrmDevice,
    gem,
    vm::{Vm, VmFlag, VmMapFlags},
};

const MAX_HEAPS_PER_POOL: u32 = 128;
const CHUNK_SIZE_MASK: u64 = !((1u64 << 12) - 1);

#[repr(C)]
pub(crate) struct ChunkHeader {
    // Written to GPU-visible memory through `write`; never read back.
    #[allow(dead_code)]
    next: u64,
    _unknown: [u32; 14],
}

impl ChunkHeader {
    fn write(mem: &gem::MappedBo, offset: usize, value: Self) -> Result {
        mem.check_offset::<Self>(offset)?;

        let vmap = mem.vmap();
        // SAFETY: `check_offset` verified bounds and alignment for `Self` at `offset`.
        let ptr = unsafe { (vmap.addr() as *mut u8).add(offset).cast::<Self>() };

        // SAFETY: `ptr` is aligned, in-bounds (see above), and shared with the GPU.
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

#[allow(dead_code)]
pub(crate) struct ContextGrowArgs {
    pub(crate) heap_gpu_va: u64,
    pub(crate) renderpasses_in_flight: u32,
    pub(crate) pending_frag_count: u32,
}

pub(crate) struct Pools {
    entries: Pin<KBox<XArray<Arc<Pool>>>>,
}

impl Pools {
    pub(crate) fn create() -> Result<Self> {
        let entries = KBox::pin_init(XArray::new(xarray::AllocKind::Alloc1), GFP_KERNEL)?;

        Ok(Self { entries })
    }

    pub(crate) fn get_pool(&self, vm_id: usize) -> Option<Arc<Pool>> {
        let xa = self.entries.as_ref();
        let guard = xa.lock();
        let pool = guard.get(vm_id)?;

        Some(pool.into())
    }

    fn get_or_create_pool(
        &self,
        tdev: &TyrDrmDevice,
        vm_id: usize,
        vm: Arc<Vm>,
    ) -> Result<Arc<Pool>> {
        if let Some(pool) = self.get_pool(vm_id) {
            return Ok(pool);
        }

        let pool = Arc::new(Pool::create(tdev, vm)?, GFP_KERNEL)?;
        let xa = self.entries.as_ref();
        let mut guard = xa.lock();
        guard
            .store(vm_id, pool.clone(), GFP_KERNEL)
            .map_err(|_| EINVAL)?;

        Ok(pool)
    }

    pub(crate) fn create_context(
        &self,
        tdev: &TyrDrmDevice,
        vm_id: usize,
        vm: Arc<Vm>,
        heapcreate: &mut uapi::drm_panthor_tiler_heap_create,
    ) -> Result<Arc<Pool>> {
        let args = ContextCreateArgs {
            initial_chunk_count: heapcreate.initial_chunk_count,
            chunk_size: heapcreate.chunk_size,
            max_chunks: heapcreate.max_chunks,
            target_in_flight: heapcreate.target_in_flight,
        };

        let pool = self.get_or_create_pool(tdev, vm_id, vm)?;
        let created_context = pool.create_heap_context(tdev, args)?;

        heapcreate.handle = heapcreate.vm_id << 16 | created_context.context_id as u32;
        heapcreate.tiler_heap_ctx_gpu_va = created_context.context_gpu_va;
        heapcreate.first_heap_chunk_gpu_va = created_context.first_chunk_gpu_va;

        Ok(pool)
    }

    pub(crate) fn destroy_context(
        &self,
        heapdestroy: &uapi::drm_panthor_tiler_heap_destroy,
    ) -> Result {
        if heapdestroy.pad != 0 {
            return Err(EINVAL);
        }

        let vm_id = (heapdestroy.handle >> 16) as usize;
        let heap_idx = (heapdestroy.handle & 0xffff) as usize;
        let pool = self.get_pool(vm_id).ok_or(EINVAL)?;

        pool.destroy_heap_context(heap_idx)
    }
}

struct Context {
    vm: Arc<Vm>,
    chunks: KVec<Arc<gem::MappedBo>>,
    chunk_size: u32,
    max_chunks: u32,
    target_in_flight: u32,
}

fn alloc_chunk_bo(
    tdev: &TyrDrmDevice,
    vm: &Arc<Vm>,
    chunk_size: u32,
) -> Result<Arc<gem::MappedBo>> {
    let flags = VmMapFlags::from(VmFlag::Noexec);
    let chunk_bo = gem::new_kernel_object(
        tdev,
        vm,
        chunk_size as usize,
        flags,
        tdev.coherent,
        tdev.cleanup_wq.clone(),
    )?;

    let vmap = chunk_bo.vmap();
    let size = vmap.owner().size();
    // SAFETY: `vmap` owns a writable CPU mapping for the BO and `size`
    // matches the mapped object size.
    let mem = unsafe { core::slice::from_raw_parts_mut(vmap.addr() as *mut u8, size) };
    mem.fill(0);

    Ok(chunk_bo)
}

impl Context {
    fn push_chunk(&mut self, chunk_bo: Arc<gem::MappedBo>) -> Result {
        self.chunks.reserve(1, GFP_KERNEL)?;
        self.chunks
            .insert_within_capacity(0, chunk_bo)
            .map_err(|_| ENOMEM)?;
        Ok(())
    }

    fn alloc_initial_chunk(&mut self, tdev: &TyrDrmDevice) -> Result {
        let chunk_bo = alloc_chunk_bo(tdev, &self.vm, self.chunk_size)?;

        if let Some(prev) = self.chunks.first() {
            let next = (prev.kernel_va().ok_or(EINVAL)?.start & CHUNK_SIZE_MASK)
                | (u64::from(self.chunk_size) >> 12);
            ChunkHeader::write(
                &chunk_bo,
                0,
                ChunkHeader {
                    next,
                    _unknown: [0; 14],
                },
            )?;
        }

        self.push_chunk(chunk_bo)
    }
}

pub(crate) struct Pool {
    vm: Arc<Vm>,
    gpu_contexts: Arc<gem::MappedBo>,
    xa: Pin<KBox<XArray<KBox<Context>>>>,
    free_index: AtomicUsize,
}

impl Pool {
    pub(crate) fn create(tdev: &TyrDrmDevice, vm: Arc<Vm>) -> Result<Self> {
        let stride = tdev.gpu_info.heap_context_stride();
        let bo_size = (MAX_HEAPS_PER_POOL * stride).next_multiple_of(4096) as usize;

        let flags = VmMapFlags::from(VmFlag::Noexec);
        let gpu_contexts = gem::new_kernel_object(
            tdev,
            &vm,
            bo_size,
            flags,
            tdev.coherent,
            tdev.cleanup_wq.clone(),
        )?;
        let xa = KBox::pin_init(XArray::new(xarray::AllocKind::Alloc1), GFP_KERNEL)?;

        Ok(Self {
            vm,
            gpu_contexts,
            xa,
            free_index: AtomicUsize::new(1),
        })
    }

    pub(crate) fn create_heap_context(
        &self,
        tdev: &TyrDrmDevice,
        args: ContextCreateArgs,
    ) -> Result<CreatedContext> {
        if args.initial_chunk_count == 0 {
            return Err(EINVAL);
        }

        if args.initial_chunk_count > args.max_chunks {
            return Err(EINVAL);
        }

        let aligned = args
            .chunk_size
            .checked_next_multiple_of(4096)
            .ok_or(EINVAL)?;
        if args.chunk_size != aligned {
            return Err(EINVAL);
        }

        if args.chunk_size < SZ_128K || args.chunk_size > SZ_8M {
            return Err(EINVAL);
        }

        let mut heap_ctx = KBox::new(
            Context {
                vm: self.vm.clone(),
                chunks: kvec![],
                chunk_size: args.chunk_size,
                max_chunks: args.max_chunks,
                target_in_flight: args.target_in_flight,
            },
            GFP_KERNEL,
        )?;

        for _ in 0..args.initial_chunk_count {
            heap_ctx.alloc_initial_chunk(tdev)?;
        }

        // `alloc_initial_chunk` prepends, so `chunks.first()` is the
        // most-recently allocated chunk and the head of the chain.
        let first_chunk_gpu_va = heap_ctx
            .chunks
            .first()
            .and_then(|bo| bo.kernel_va())
            .ok_or(EINVAL)?
            .start;

        let index = self.free_index.fetch_add(1, Ordering::Relaxed);
        let context_gpu_va = self.gpu_contexts.kernel_va().ok_or(EINVAL)?.start
            + index as u64 * u64::from(tdev.gpu_info.heap_context_stride());

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

    pub(crate) fn destroy_heap_context(&self, context_id: usize) -> Result {
        let xa = self.xa.as_ref();
        let heap_ctx = {
            let mut guard = xa.lock();
            guard.remove(context_id).ok_or(EINVAL)?
        };

        drop(heap_ctx);

        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn grow_heap_context(
        &self,
        tdev: &TyrDrmDevice,
        args: ContextGrowArgs,
    ) -> Result<u64> {
        let _ = args.pending_frag_count;

        let offset = args.heap_gpu_va - self.gpu_contexts.kernel_va().ok_or(EINVAL)?.start;
        let offset = u32::try_from(offset).map_err(|_| EINVAL)?;
        let index = offset / tdev.gpu_info.heap_context_stride();

        let xa = self.xa.as_ref();

        // TODO: holding each Context behind its own mutex (XArray<Arc<Mutex<Context>>>)
        // would let the whole grow run under one sleeping lock and drop this
        // snapshot-then-recheck dance; the XArray spinlock would only guard the lookup.
        let (vm, chunk_size, max_chunks) = {
            let guard = xa.lock();
            let heap_ctx = guard.get(index as usize).ok_or(EINVAL)?;

            if args.renderpasses_in_flight > heap_ctx.target_in_flight
                || heap_ctx.chunks.len() >= heap_ctx.max_chunks as usize
            {
                return Err(ENOMEM);
            }

            (
                heap_ctx.vm.clone(),
                heap_ctx.chunk_size,
                heap_ctx.max_chunks,
            )
        };

        // Allocate outside the XArray spinlock: the BO allocation takes the
        // kernel-VA range mutex and uses GFP_KERNEL, neither of which is
        // permitted while holding a spinlock.
        let chunk_bo = alloc_chunk_bo(tdev, &vm, chunk_size)?;

        let mut guard = xa.lock();
        let heap_ctx = guard.get_mut(index as usize).ok_or(EINVAL)?;

        if heap_ctx.chunks.len() >= max_chunks as usize {
            return Err(ENOMEM);
        }

        // Grow under the XArray spinlock with GFP_NOWAIT: a sleeping
        // GFP_KERNEL reclaim is not allowed here.
        heap_ctx.chunks.reserve(1, GFP_NOWAIT)?;
        heap_ctx
            .chunks
            .insert_within_capacity(0, chunk_bo)
            .map_err(|_| ENOMEM)?;

        let chunk_bo = heap_ctx.chunks.first().ok_or(EINVAL)?;
        let chunk_start = chunk_bo.kernel_va().ok_or(EINVAL)?.start;

        Ok((chunk_start & CHUNK_SIZE_MASK) | (chunk_bo.size() as u64 >> 12))
    }
}
