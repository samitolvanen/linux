// SPDX-License-Identifier: GPL-2.0 or MIT

//! Tiler heap management.

use core::ops::Deref;

use kernel::{
    alloc::KVec,
    drm::gem::BaseObject,
    io::Io,
    kvec,
    new_spinlock,
    prelude::*,
    sync::{
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc,
        SpinLock, //
    },
    time::{
        Instant,
        Monotonic, //
    },
    uapi::{
        self,
        SZ_128K,
        SZ_8M, //
    },
    xarray::{
        self,
        XArray, //
    }, //
};

use crate::{
    driver::TyrDrmDevice,
    gem, trace,
    vm::{
        Vm,
        VmFlag,
        VmMapFlags, //
    },
};

const MAX_HEAPS_PER_POOL: u32 = 128;
const CHUNK_SIZE_MASK: u64 = !((1u64 << 12) - 1);

/// Chunk lifetimes a pool keeps in its `ChunkLedger`.
const CHUNK_LEDGER_ENTRIES: usize = 64;

/// The lifetime of one tiler-heap chunk, as recorded by `ChunkLedger`.
#[derive(Clone, Copy)]
pub(crate) struct ChunkRecord {
    pub(crate) va: u64,
    pub(crate) size: u64,
    /// `None` when the allocation of this chunk has aged out of the
    /// ring and only its release was recorded.
    pub(crate) alloc: Option<Instant<Monotonic>>,
    /// `None` while a heap still owns the chunk.
    pub(crate) free: Option<Instant<Monotonic>>,
}

impl ChunkRecord {
    const EMPTY: Self = Self {
        va: 0,
        size: 0,
        alloc: None,
        free: None,
    };

    fn covers(&self, va: u64) -> bool {
        self.size != 0 && va >= self.va && va - self.va < self.size
    }
}

struct LedgerRing {
    records: [ChunkRecord; CHUNK_LEDGER_ENTRIES],
    /// Records ever appended. The ring keeps the last
    /// `CHUNK_LEDGER_ENTRIES` of them.
    appended: usize,
}

impl LedgerRing {
    fn push(&mut self, record: ChunkRecord) {
        let index = self.appended % CHUNK_LEDGER_ENTRIES;
        self.records[index] = record;
        self.appended += 1;
    }
}

/// Ring of recent chunk lifetimes for one heap pool, so an address that
/// no longer resolves to a mapping can still be attributed to a chunk
/// the pool has since released.
///
/// Downstream-only debug aid; not for upstream.
#[pin_data]
struct ChunkLedger {
    #[pin]
    ring: SpinLock<LedgerRing>,
}

impl ChunkLedger {
    fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            ring <- new_spinlock!(LedgerRing {
                records: [ChunkRecord::EMPTY; CHUNK_LEDGER_ENTRIES],
                appended: 0,
            }),
        })
    }

    /// Records an allocation and returns the generation the caller
    /// passes back to `record_free`.
    fn record_alloc(&self, va: u64, size: u64) -> usize {
        let mut ring = self.ring.lock();
        let generation = ring.appended;
        ring.push(ChunkRecord {
            va,
            size,
            alloc: Some(Instant::now()),
            free: None,
        });

        generation
    }

    fn record_free(&self, generation: usize, va: u64, size: u64) {
        let now = Instant::now();
        let mut ring = self.ring.lock();
        // The slot still holds this chunk's record until
        // `CHUNK_LEDGER_ENTRIES` later appends have overwritten it.
        if generation + CHUNK_LEDGER_ENTRIES > ring.appended {
            ring.records[generation % CHUNK_LEDGER_ENTRIES].free = Some(now);
            return;
        }

        ring.push(ChunkRecord {
            va,
            size,
            alloc: None,
            free: Some(now),
        });
    }

    /// Returns the newest recorded chunk covering `va`.
    fn lookup(&self, va: u64) -> Option<ChunkRecord> {
        let ring = self.ring.lock();
        let count = ring.appended.min(CHUNK_LEDGER_ENTRIES);
        (1..=count)
            .map(|back| ring.records[(ring.appended - back) % CHUNK_LEDGER_ENTRIES])
            .find(|record| record.covers(va))
    }
}

/// A chunk owned by a heap context, whose allocation and release are
/// recorded in the owning pool's `ChunkLedger`.
struct Chunk {
    bo: Arc<gem::MappedBo>,
    ledger: Arc<ChunkLedger>,
    recorded_va: u64,
    recorded_size: u64,
    generation: usize,
}

impl Chunk {
    fn new(bo: Arc<gem::MappedBo>, ledger: Arc<ChunkLedger>) -> Self {
        // A chunk with no VA is recorded with size 0, which
        // `ChunkRecord::covers` never matches.
        let (recorded_va, recorded_size) = match bo.kernel_va() {
            Some(range) => (range.start, bo.size() as u64),
            None => (0, 0),
        };
        let generation = ledger.record_alloc(recorded_va, recorded_size);

        Self {
            bo,
            ledger,
            recorded_va,
            recorded_size,
            generation,
        }
    }
}

impl Deref for Chunk {
    type Target = gem::MappedBo;

    fn deref(&self) -> &Self::Target {
        &self.bo
    }
}

impl Drop for Chunk {
    fn drop(&mut self) {
        self.ledger
            .record_free(self.generation, self.recorded_va, self.recorded_size);
    }
}

/// Chunk headers an event-driven dump reads per heap. The chunk BOs are
/// write-combine mapped on a non-coherent device, so an uncapped chain
/// walk would cost hundreds of microseconds of uncached reads on the
/// tiler-OOM answer path.
const EVENT_DUMP_MAX_CHUNKS: usize = 4;

/// Links a chunk-chain walk follows from the heap context head. Each
/// link costs one uncached read of a write-combine mapping on the
/// tiler-OOM answer path, so the walk reports a prefix of a long chain
/// rather than paying for all of it.
const CHAIN_WALK_MAX_LINKS: u32 = 16;

/// Heaps a log dump reports, and chunk addresses per heap. The dump
/// runs on an unhandled MMU fault, where walking every heap would push
/// the rest of the fault report out of the log buffer.
const LOG_DUMP_MAX_HEAPS: usize = 4;
const LOG_DUMP_MAX_CHUNK_VAS: usize = 8;

/// One heap's state, taken under the heap XArray lock so that
/// `Pool::dump_for_log` writes to the log with the lock released.
#[derive(Clone, Copy)]
struct HeapLogEntry {
    index: usize,
    ctx_va: u64,
    chunk_count: usize,
    head: [u8; 32],
    chain: [u64; LOG_DUMP_MAX_CHUNK_VAS],
    /// Entries of `chain` that were filled in.
    listed: usize,
}

impl HeapLogEntry {
    const EMPTY: Self = Self {
        index: 0,
        ctx_va: 0,
        chunk_count: 0,
        head: [0; 32],
        chain: [0; LOG_DUMP_MAX_CHUNK_VAS],
        listed: 0,
    };
}

/// Reads the first 32 bytes of the heap context at `ctx_off`, or
/// `None` when that range does not fit in `ctx_size`.
///
/// # Safety
///
/// `ctx_addr` must be the base of a CPU mapping of at least `ctx_size`
/// bytes that stays valid for reads across the call.
unsafe fn read_heap_head(ctx_addr: *const u8, ctx_size: usize, ctx_off: usize) -> Option<[u8; 32]> {
    if ctx_off.saturating_add(32) > ctx_size {
        return None;
    }

    let mut head = [0u8; 32];
    // SAFETY: the bounds check above confirms `ctx_off..ctx_off + 32`
    // lies in the caller's mapping, the bytes are aligned for `u8`, and
    // the mapping is shared with the GPU (volatile read).
    unsafe {
        let src = ctx_addr.add(ctx_off);
        for (i, slot) in head.iter_mut().enumerate() {
            *slot = core::ptr::read_volatile(src.add(i));
        }
    }

    Some(head)
}

/// Reads the link word at the start of a chunk header, or `None` when
/// the chunk's mapping cannot hold one.
fn read_chunk_link(chunk: &Chunk) -> Option<u64> {
    chunk.check_offset::<u64>(0).ok()?;

    let vmap = chunk.vmap();
    // SAFETY: `check_offset::<u64>` above verified that the first eight
    // bytes are in bounds of the vmap, whose base is page-aligned and so
    // aligned for `u64`. The mapping is shared with the GPU (volatile
    // read).
    Some(unsafe { core::ptr::read_volatile(vmap.addr() as *const u64) })
}

/// Classifies one chain link against the live chunks of `heap_ctx`,
/// returning the chunk the link addresses along with its position in
/// the chunk list.
fn classify_link<'a>(
    heap_ctx: &'a Context,
    raw: u64,
    prev_va: Option<u64>,
) -> (trace::HeapChainClass, Option<(usize, &'a Chunk)>) {
    let va = raw & CHUNK_SIZE_MASK;
    if raw == 0 {
        return (trace::HeapChainClass::Null, None);
    }
    if prev_va == Some(va) {
        return (trace::HeapChainClass::SelfLink, None);
    }

    let listed =
        heap_ctx.chunks.iter().enumerate().find(|(_, chunk)| {
            chunk.recorded_size != 0 && chunk.recorded_va & CHUNK_SIZE_MASK == va
        });

    match listed {
        None => (trace::HeapChainClass::Unlisted, None),
        Some((_, chunk)) if raw & !CHUNK_SIZE_MASK != chunk.recorded_size >> 12 => {
            (trace::HeapChainClass::BadSize, listed)
        }
        Some(_) => (trace::HeapChainClass::Ok, listed),
    }
}

/// Walks the chunk chain of `heap_ctx` from the head pointer the
/// firmware reads, reporting each link through `tyr_heap_chain_link`
/// and closing with `tyr_heap_chain_summary`. A chunk header is read
/// only for a link already matched to a live chunk of this context, and
/// the walk stops on the first link that is not `Ok` or after
/// `CHAIN_WALK_MAX_LINKS`.
///
/// Runs under the caller's heap XArray guard, so it takes no lock and
/// does no allocation. Per link it scans the chunk list once and reads
/// eight bytes of the matched chunk.
///
/// Downstream-only debug aid; not for upstream.
fn walk_chunk_chain(
    heap_ctx: &Context,
    trigger: trace::HeapDumpTrigger,
    group_id: u64,
    group_uid: u64,
    cs_id: u32,
    heap_index: u32,
    content: &[u8; 32],
) {
    let head_raw = u64::from_le_bytes([
        content[0], content[1], content[2], content[3], content[4], content[5], content[6],
        content[7],
    ]);

    let mut raw = head_raw;
    let mut prev_va = None;
    let mut links = 0;
    let mut terminal = trace::HeapChainClass::Null;

    for depth in 0..CHAIN_WALK_MAX_LINKS {
        let va = raw & CHUNK_SIZE_MASK;
        let (class, listed) = classify_link(heap_ctx, raw, prev_va);

        let next = match (class, listed) {
            (trace::HeapChainClass::Ok, Some((_, chunk))) => read_chunk_link(chunk),
            _ => None,
        };

        trace::heap_chain_link(
            trigger,
            group_id,
            group_uid,
            cs_id,
            heap_index,
            depth,
            raw,
            va,
            next.unwrap_or(0),
            listed.map_or(u32::MAX, |(list_index, _)| list_index as u32),
            class,
        );

        links = depth + 1;
        terminal = class;

        let Some(next) = next else {
            break;
        };
        prev_va = Some(va);
        raw = next;
    }

    trace::heap_chain_summary(
        trigger,
        group_id,
        group_uid,
        cs_id,
        heap_index,
        head_raw,
        links,
        terminal,
        u32::try_from(heap_ctx.chunks.len()).unwrap_or(u32::MAX),
    );
}

/// Recognizable base pattern for the canary in a chunk header.
const CHUNK_CANARY_MAGIC: u32 = 0x4352_5954;

/// Byte offset of the reserved region of a chunk header.
const CHUNK_CANARY_OFFSET: usize = 8;

/// First word of that region the canary fills. From it up the words are
/// software-defined, which the hardware neither reads nor writes.
const CHUNK_CANARY_FIRST_WORD: usize = 12;

/// Canary word for word `index` of the reserved region of the header of
/// the chunk at `chunk_va`. Mixing in the address and the index means a
/// header copied from another chunk, or shifted within this one, does
/// not read back as intact.
///
/// Downstream-only debug aid; not for upstream.
fn canary_word(chunk_va: u64, index: usize) -> u32 {
    CHUNK_CANARY_MAGIC ^ (chunk_va as u32) ^ (index as u32)
}

/// Compares the software-defined words of a chunk header against the
/// canary written at allocation and reports the first that differs,
/// along with a mask of every word that does.
///
/// Downstream-only debug aid; not for upstream.
fn check_chunk_canary(
    group_id: u64,
    group_uid: u64,
    heap_index: u32,
    chunk_index: u32,
    chunk_va: u64,
    header: &[u8; 64],
) {
    let Some(reserved) = header.get(CHUNK_CANARY_OFFSET..) else {
        return;
    };

    let mut first_bad = None;
    let mut bad_mask = 0;
    for (index, word) in reserved
        .chunks_exact(4)
        .enumerate()
        .skip(CHUNK_CANARY_FIRST_WORD)
    {
        let Ok(bytes) = <[u8; 4]>::try_from(word) else {
            continue;
        };

        let found = u32::from_le_bytes(bytes);
        let expected = canary_word(chunk_va, index);
        if found == expected {
            continue;
        }

        bad_mask |= 1u32 << index;
        first_bad.get_or_insert((index, expected, found));
    }

    let Some((index, expected, found)) = first_bad else {
        return;
    };

    trace::heap_chunk_canary(
        group_id,
        group_uid,
        heap_index,
        chunk_index,
        chunk_va,
        (CHUNK_CANARY_OFFSET + index * 4) as u32,
        expected,
        found,
        bad_mask,
    );
}

#[repr(C)]
pub(crate) struct ChunkHeader {
    // Written to GPU-visible memory through `write`; never read back.
    #[allow(dead_code)]
    next: u64,
    _unknown: [u32; 14],
}

impl ChunkHeader {
    /// Header for the chunk at `chunk_va`, with the software-defined
    /// words carrying that chunk's canary.
    fn new(next: u64, chunk_va: u64) -> Self {
        let mut header = Self {
            next,
            _unknown: [0; 14],
        };
        for (index, word) in header
            ._unknown
            .iter_mut()
            .enumerate()
            .skip(CHUNK_CANARY_FIRST_WORD)
        {
            *word = canary_word(chunk_va, index);
        }

        header
    }

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
    /// Identity of the group whose CS raised the OOM, carried for the
    /// `tyr_heap_grow_decision` tracepoint.
    pub(crate) group_uid: u64,
    /// Index of the CS within that group.
    pub(crate) cs_id: u32,
    pub(crate) vt_start: u32,
    pub(crate) vt_end: u32,
    pub(crate) frag_end: u32,
}

/// Per-heap state observed while deciding whether a grow can proceed,
/// reported by `Pool::grow_heap_context` through the
/// `tyr_heap_grow_decision` tracepoint.
#[derive(Default)]
struct GrowState {
    chunk_count: u32,
    max_chunks: u32,
    target_in_flight: u32,
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
        if let Some(existing_pool) = guard.get(vm_id) {
            return Ok(existing_pool.into());
        }
        if let Some(existing) = guard.store(vm_id, pool.clone(), GFP_KERNEL)? {
            // The XArray lock can be dropped while `store` allocates a node,
            // so a concurrent creator may have stored its pool first. Keep
            // that pool and discard ours. The slot already holds a node, so
            // this GFP_NOWAIT store allocates nothing and cannot fail.
            guard.store(vm_id, existing.clone(), GFP_NOWAIT)?;
            return Ok(existing);
        }

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
    chunks: KVec<Chunk>,
    chunk_size: u32,
    max_chunks: u32,
    target_in_flight: u32,
    /// Identity of this context, distinguishing it from a later context
    /// allocated at the same recycled index.
    cookie: u64,
}

fn alloc_chunk(
    tdev: &TyrDrmDevice,
    vm: &Arc<Vm>,
    chunk_size: u32,
    ledger: &Arc<ChunkLedger>,
) -> Result<Chunk> {
    let flags = VmMapFlags::from(VmFlag::Noexec);
    let chunk_bo = gem::new_kernel_object(
        tdev,
        vm,
        chunk_size as usize,
        flags,
        tdev.coherent,
        tdev.cleanup_wq.clone(),
    )?;

    let chunk_va = chunk_bo.kernel_va().ok_or(EINVAL)?.start;
    ChunkHeader::write(&chunk_bo, 0, ChunkHeader::new(0, chunk_va))?;

    Ok(Chunk::new(chunk_bo, ledger.clone()))
}

impl Context {
    fn push_chunk(&mut self, chunk_bo: Chunk) -> Result {
        self.chunks.reserve(1, GFP_KERNEL)?;
        self.chunks
            .insert_within_capacity(0, chunk_bo)
            .map_err(|_| ENOMEM)?;
        Ok(())
    }

    fn alloc_initial_chunk(&mut self, tdev: &TyrDrmDevice, ledger: &Arc<ChunkLedger>) -> Result {
        let chunk_bo = alloc_chunk(tdev, &self.vm, self.chunk_size, ledger)?;

        if let Some(prev) = self.chunks.first() {
            let next = (prev.kernel_va().ok_or(EINVAL)?.start & CHUNK_SIZE_MASK)
                | (u64::from(self.chunk_size) >> 12);
            let chunk_va = chunk_bo.kernel_va().ok_or(EINVAL)?.start;
            ChunkHeader::write(&chunk_bo, 0, ChunkHeader::new(next, chunk_va))?;
        }

        self.push_chunk(chunk_bo)
    }
}

pub(crate) struct Pool {
    vm: Arc<Vm>,
    gpu_contexts: Arc<gem::MappedBo>,
    xa: Pin<KBox<XArray<KBox<Context>>>>,
    next_id: Atomic<u32>,
    /// Ever-incrementing source of context cookies. Unlike `next_id`, it
    /// never wraps or recycles, so each context gets a unique identity.
    next_cookie: Atomic<u64>,
    /// Recent chunk lifetimes of every heap in this pool.
    chunk_ledger: Arc<ChunkLedger>,
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
        let xa = KBox::pin_init(XArray::new(xarray::AllocKind::Alloc), GFP_KERNEL)?;
        let chunk_ledger = Arc::pin_init(ChunkLedger::new(), GFP_KERNEL)?;

        Ok(Self {
            vm,
            gpu_contexts,
            xa,
            next_id: Atomic::new(0),
            next_cookie: Atomic::new(0),
            chunk_ledger,
        })
    }

    /// Returns the newest recorded lifetime of a chunk covering `va`.
    pub(crate) fn lookup_chunk_va(&self, va: u64) -> Option<ChunkRecord> {
        self.chunk_ledger.lookup(va)
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
                cookie: self.next_cookie.fetch_add(1, Relaxed),
            },
            GFP_KERNEL,
        )?;

        for _ in 0..args.initial_chunk_count {
            heap_ctx.alloc_initial_chunk(tdev, &self.chunk_ledger)?;
        }

        // `alloc_initial_chunk` prepends, so `chunks.first()` is the
        // most-recently allocated chunk and the head of the chain.
        let first_chunk_gpu_va = heap_ctx
            .chunks
            .first()
            .and_then(|bo| bo.kernel_va())
            .ok_or(EINVAL)?
            .start;

        let stride = tdev.gpu_info.heap_context_stride() as usize;
        let contexts_va = self.gpu_contexts.kernel_va().ok_or(EINVAL)?.start;

        let xa = self.xa.as_ref();
        let mut guard = xa.lock();

        let mut next = self.next_id.load(Relaxed);
        let index = match guard.alloc_cyclic(
            heap_ctx,
            xarray::XaLimit::new(0, MAX_HEAPS_PER_POOL - 1),
            &mut next,
            GFP_KERNEL,
        ) {
            Err(e) => {
                // Drop the guard before dropping the heap_ctx that fails to allocate,
                // as dropping the Context might take the VM mutex.
                drop(guard);
                return Err(e.error);
            }
            Ok(index) => index,
        };
        self.next_id.store(next, Relaxed);

        let offset = index * stride;

        let vmap = self.gpu_contexts.vmap();
        // SAFETY: `index` is allocated cyclically within `0..MAX_HEAPS_PER_POOL`.
        // The contexts buffer is sized to fit `MAX_HEAPS_PER_POOL * stride`, so the
        // write range `offset..offset + stride` is always within the mapping. The
        // index is allocated in the XArray and the guard is held across this fill,
        // so no concurrent create or destroy can touch this slot range.
        let slot = unsafe {
            core::slice::from_raw_parts_mut((vmap.addr() as *mut u8).add(offset), stride)
        };
        slot.fill(0);

        let context_gpu_va = contexts_va + offset as u64;

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

    fn heap_va_to_index(&self, tdev: &TyrDrmDevice, heap_gpu_va: u64) -> Result<usize> {
        let contexts_va = self.gpu_contexts.kernel_va().ok_or(EINVAL)?.start;
        let offset = heap_gpu_va.checked_sub(contexts_va).ok_or(EINVAL)?;
        let offset = u32::try_from(offset).map_err(|_| EINVAL)?;
        Ok((offset / tdev.gpu_info.heap_context_stride()) as usize)
    }

    #[allow(dead_code)]
    pub(crate) fn grow_heap_context(
        &self,
        tdev: &TyrDrmDevice,
        args: ContextGrowArgs,
    ) -> Result<(u64, u64)> {
        let mut state = GrowState::default();
        let result = self.try_grow_heap_context(tdev, &args, &mut state);

        // Mirrors the outcome the caller derives from the same error
        // codes in `sched::events`.
        let outcome = match &result {
            Ok(_) => trace::HeapGrowOutcome::Grown,
            Err(e) if *e == ENOMEM => trace::HeapGrowOutcome::Reclaim,
            Err(_) => trace::HeapGrowOutcome::Fatal,
        };
        trace::heap_grow_decision(
            args.group_uid,
            args.cs_id,
            args.heap_gpu_va,
            state.chunk_count,
            state.max_chunks,
            args.renderpasses_in_flight,
            state.target_in_flight,
            args.pending_frag_count,
            args.vt_start,
            args.vt_end,
            args.frag_end,
            outcome,
        );

        result
    }

    /// Links one more chunk into the heap context addressed by
    /// `args.heap_gpu_va`, recording the state the decision was taken on
    /// in `state` so the caller can trace refusals.
    fn try_grow_heap_context(
        &self,
        tdev: &TyrDrmDevice,
        args: &ContextGrowArgs,
        state: &mut GrowState,
    ) -> Result<(u64, u64)> {
        let index = self.heap_va_to_index(tdev, args.heap_gpu_va)?;

        let xa = self.xa.as_ref();

        // TODO: holding each Context behind its own mutex (XArray<Arc<Mutex<Context>>>)
        // would let the whole grow run under one sleeping lock and drop this
        // snapshot-then-recheck dance; the XArray spinlock would only guard the lookup.
        let (vm, chunk_size, max_chunks, cookie) = {
            let guard = xa.lock();
            let heap_ctx = guard.get(index).ok_or(EINVAL)?;

            state.chunk_count = u32::try_from(heap_ctx.chunks.len()).unwrap_or(u32::MAX);
            state.max_chunks = heap_ctx.max_chunks;
            state.target_in_flight = heap_ctx.target_in_flight;

            if args.renderpasses_in_flight > heap_ctx.target_in_flight
                || heap_ctx.chunks.len() >= heap_ctx.max_chunks as usize
            {
                return Err(ENOMEM);
            }

            (
                heap_ctx.vm.clone(),
                heap_ctx.chunk_size,
                heap_ctx.max_chunks,
                heap_ctx.cookie,
            )
        };

        // Allocate outside the XArray spinlock: the BO allocation takes the
        // kernel-VA range mutex and uses GFP_KERNEL, neither of which is
        // permitted while holding a spinlock.
        let chunk_bo = alloc_chunk(tdev, &vm, chunk_size, &self.chunk_ledger)?;

        let mut guard = xa.lock();
        let heap_ctx = guard.get_mut(index).ok_or(EINVAL)?;

        // While the lock was dropped the original context may have been
        // destroyed and a new one allocated at the same recycled index.
        // The cookie identifies the original; reject the grow if it changed.
        if heap_ctx.cookie != cookie {
            return Err(EINVAL);
        }

        // Chunks may have been added while the lock was dropped, so refresh
        // the count the refusal below is taken on.
        state.chunk_count = u32::try_from(heap_ctx.chunks.len()).unwrap_or(u32::MAX);

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

        Ok((
            (chunk_start & CHUNK_SIZE_MASK) | (chunk_bo.size() as u64 >> 12),
            cookie,
        ))
    }

    pub(crate) fn return_chunk(
        &self,
        tdev: &TyrDrmDevice,
        heap_gpu_va: u64,
        chunk_gpu_va: u64,
        cookie: u64,
    ) -> Result {
        let index = self.heap_va_to_index(tdev, heap_gpu_va)?;

        let xa = self.xa.as_ref();
        let removed = {
            let mut guard = xa.lock();
            let heap_ctx = guard.get_mut(index).ok_or(EINVAL)?;

            // The slot-manager lock was dropped between growing the chunk
            // and returning it, so this index may now hold a different
            // context. The cookie identifies the original, so we bail
            // rather than remove a chunk from the wrong context.
            if heap_ctx.cookie != cookie {
                return Err(EINVAL);
            }

            let pos = heap_ctx
                .chunks
                .iter()
                .position(|bo| {
                    bo.kernel_va()
                        .map(|va| va.start & CHUNK_SIZE_MASK == chunk_gpu_va & CHUNK_SIZE_MASK)
                        .unwrap_or(false)
                })
                .ok_or(EINVAL)?;
            heap_ctx.chunks.remove(pos).map_err(|_| EINVAL)?
        };

        // Drop the removed chunk after the XArray spinlock is released,
        // because dropping the BO may run cleanup that takes the VM mutex.
        drop(removed);

        Ok(())
    }

    /// Best-effort dump of every heap-context entry and chunk-header in
    /// this pool to the `tyr_heap_context_dump` / `tyr_heap_chunk_dump`
    /// tracepoints. Called from the CS_FAULT / CS_FATAL event path in
    /// dma-fence signalling context and from the periodic 1Hz heap-dump
    /// worker (which passes `cs_id = 0`). A `Some(trigger)` caller gets
    /// the event-driven tracepoints instead, narrowed to the heap at
    /// `heap_gpu_va` if one is given and to `EVENT_DUMP_MAX_CHUNKS`
    /// headers per heap. Such a caller also gets `walk_chunk_chain` run
    /// on each heap it covers, gated on that walk's own tracepoints so a
    /// capture can take the chain without the header dumps. Each part
    /// only runs while the tracepoints it would emit to are enabled.
    /// When enabled, the dump:
    ///
    /// * uses `try_lock` on the heap XArray (a spinlock-backed lock)
    ///   and silently skips the dump when the lock is contended;
    /// * does no allocation;
    /// * touches only already-mapped kernel vmaps via raw byte reads;
    /// * is bounded by [`MAX_HEAPS_PER_POOL`] and by each heap's chunk
    ///   chain length.
    ///
    /// This is a downstream-only debug aid and never returns an error.
    pub(crate) fn dump_for_trace(
        &self,
        tdev: &TyrDrmDevice,
        group_id: u64,
        group_uid: u64,
        cs_id: u32,
        heap_gpu_va: Option<u64>,
        trigger: Option<trace::HeapDumpTrigger>,
    ) {
        let dump = match trigger {
            Some(_) => trace::heap_event_dump_enabled(),
            None => trace::heap_dump_enabled(),
        };
        let walk = trigger.filter(|_| trace::heap_chain_walk_enabled());
        if !dump && walk.is_none() {
            return;
        }

        let indices = match heap_gpu_va {
            Some(va) => match self.heap_va_to_index(tdev, va) {
                Ok(index) => index..index + 1,
                Err(_) => return,
            },
            None => 0..MAX_HEAPS_PER_POOL as usize,
        };
        let chunk_limit = match trigger {
            Some(_) => EVENT_DUMP_MAX_CHUNKS,
            None => usize::MAX,
        };

        let stride = tdev.gpu_info.heap_context_stride() as usize;
        let Some(ctx_base) = self.gpu_contexts.kernel_va().map(|r| r.start) else {
            return;
        };
        let ctx_vmap = self.gpu_contexts.vmap();
        let ctx_size = ctx_vmap.owner().size();
        let ctx_addr = ctx_vmap.addr() as *const u8;

        let xa = self.xa.as_ref();
        let Some(guard) = xa.try_lock() else {
            return;
        };

        for index in indices {
            let Some(heap_ctx) = guard.get(index) else {
                continue;
            };

            let ctx_off = index.saturating_mul(stride);
            // SAFETY: `ctx_addr` is the base of the heap-context BO's CPU
            // mapping, which `ctx_vmap` keeps alive for `ctx_size` bytes.
            let Some(content) = (unsafe { read_heap_head(ctx_addr, ctx_size, ctx_off) }) else {
                continue;
            };

            if let Some(trigger) = walk {
                walk_chunk_chain(
                    heap_ctx,
                    trigger,
                    group_id,
                    group_uid,
                    cs_id,
                    index as u32,
                    &content,
                );
            }

            if !dump {
                continue;
            }

            let ctx_va = ctx_base + (index as u64) * (stride as u64);
            let chunk_count = u32::try_from(heap_ctx.chunks.len()).unwrap_or(u32::MAX);
            trace::heap_context_dump(
                trigger,
                group_id,
                group_uid,
                cs_id,
                index as u32,
                ctx_va,
                chunk_count,
                &content,
            );

            for (chunk_index, chunk_bo) in heap_ctx.chunks.iter().enumerate().take(chunk_limit) {
                let chunk_vmap = chunk_bo.vmap();
                let chunk_size = chunk_vmap.owner().size();
                if chunk_size < 64 {
                    continue;
                }
                let chunk_va = match chunk_bo.kernel_va() {
                    Some(r) => r.start,
                    None => continue,
                };

                let mut header = [0u8; 64];
                // SAFETY: `chunk_vmap.addr()` is the base of the chunk
                // BO's CPU mapping of size `chunk_size >= 64`; reads
                // are within bounds, aligned for `u8`, and the mapping
                // is shared with the GPU (volatile read).
                unsafe {
                    let src = chunk_vmap.addr() as *const u8;
                    for (i, slot) in header.iter_mut().enumerate() {
                        *slot = core::ptr::read_volatile(src.add(i));
                    }
                }

                trace::heap_chunk_dump(
                    trigger,
                    group_id,
                    group_uid,
                    cs_id,
                    index as u32,
                    chunk_index as u32,
                    chunk_va,
                    &header,
                );

                check_chunk_canary(
                    group_id,
                    group_uid,
                    index as u32,
                    chunk_index as u32,
                    chunk_va,
                    &header,
                );
            }
        }
    }

    /// Logs the head of each heap context in this pool and the start of
    /// its chunk chain, bounded to `LOG_DUMP_MAX_HEAPS` heaps and
    /// `LOG_DUMP_MAX_CHUNK_VAS` addresses per heap.
    pub(crate) fn dump_for_log(&self, tdev: &TyrDrmDevice) {
        let stride = tdev.gpu_info.heap_context_stride() as usize;
        let Some(ctx_base) = self.gpu_contexts.kernel_va().map(|r| r.start) else {
            return;
        };
        let ctx_vmap = self.gpu_contexts.vmap();
        let ctx_size = ctx_vmap.owner().size();
        let ctx_addr = ctx_vmap.addr() as *const u8;

        let mut entries = [HeapLogEntry::EMPTY; LOG_DUMP_MAX_HEAPS];
        let mut dumped = 0;
        {
            let xa = self.xa.as_ref();
            let Some(guard) = xa.try_lock() else {
                pr_err!("heap dump: heap XArray contended\n");
                return;
            };

            for index in 0..MAX_HEAPS_PER_POOL as usize {
                if dumped == LOG_DUMP_MAX_HEAPS {
                    break;
                }
                let Some(heap_ctx) = guard.get(index) else {
                    continue;
                };

                let ctx_off = index.saturating_mul(stride);
                // SAFETY: `ctx_addr` is the base of the heap-context BO's CPU
                // mapping, which `ctx_vmap` keeps alive for `ctx_size` bytes.
                let Some(head) = (unsafe { read_heap_head(ctx_addr, ctx_size, ctx_off) }) else {
                    continue;
                };

                let entry = &mut entries[dumped];
                entry.index = index;
                entry.ctx_va = ctx_base + (index as u64) * (stride as u64);
                entry.chunk_count = heap_ctx.chunks.len();
                entry.listed = heap_ctx.chunks.len().min(LOG_DUMP_MAX_CHUNK_VAS);
                entry.head = head;
                dumped += 1;

                for (slot, chunk) in entry.chain.iter_mut().zip(heap_ctx.chunks.iter()) {
                    *slot = chunk.kernel_va().map_or(0, |r| r.start);
                }
            }
        }

        for entry in &entries[..dumped] {
            pr_err!(
                "heap {} ctx 0x{:016X} chunks {}: head {:02X?}\n",
                entry.index,
                entry.ctx_va,
                entry.chunk_count,
                &entry.head[..],
            );
            pr_err!("  chain: {:X?}\n", &entry.chain[..entry.listed]);
        }
    }
}
