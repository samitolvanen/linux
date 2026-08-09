// SPDX-License-Identifier: GPL-2.0 or MIT

//! Range allocator.
//!
//! This module allows Tyr to reserve unused GPU virtual address ranges for
//! kernel-owned objects such as queue ring buffers and firmware-visible state.

use core::ops::Range;

use kernel::{
    alloc::Flags,
    maple_tree::MapleTreeAlloc,
    new_mutex,
    prelude::*,
    ptr::{
        Alignable,
        Alignment,
        //
    },
    sync::{Arc, Mutex},
};

#[pin_data]
struct RangeAllocInner {
    #[pin]
    maple: MapleTreeAlloc<()>,
    #[pin]
    lock: Mutex<()>,
    range: Range<u64>,
}

// SAFETY: `RangeAllocInner` can be sent between threads because all access to
// the underlying maple tree is serialized by `lock`.
unsafe impl Send for RangeAllocInner {}

// SAFETY: `RangeAllocInner` is `Sync` because every maple-tree mutation goes
// through `lock`, preventing concurrent unsynchronized access.
unsafe impl Sync for RangeAllocInner {}

pub(crate) struct RangeAlloc {
    inner: Arc<RangeAllocInner>,
}

pub(crate) struct LiveRange {
    inner: Arc<RangeAllocInner>,
    offset: u64,
    size: usize,
}

impl RangeAlloc {
    pub(crate) fn new(start: u64, end: u64, gfp: Flags) -> Result<Self> {
        if end < start {
            return Err(EINVAL);
        }

        #[cfg(target_pointer_width = "32")]
        if end - start > u32::MAX as u64 {
            return Err(EINVAL);
        }

        let inner = Arc::pin_init(
            try_pin_init!(RangeAllocInner {
                maple <- MapleTreeAlloc::new(),
                lock <- new_mutex!(()),
                range: start..end,
            }),
            gfp,
        )?;

        Ok(Self { inner })
    }

    /// Reserves `size` bytes at an address aligned to `align`, or at the
    /// first free address when no wider gap exists.
    pub(crate) fn allocate(&self, size: usize, align: Alignment, gfp: Flags) -> Result<LiveRange> {
        let _guard = self.inner.lock.lock();
        let offset = self.inner.alloc_aligned(size, align, gfp)?;

        Ok(LiveRange {
            inner: self.inner.clone(),
            offset,
            size,
        })
    }

    pub(crate) fn insert(&self, start: u64, end: u64, gfp: Flags) -> Result<LiveRange> {
        if end <= start {
            return Err(EINVAL);
        }

        let _guard = self.inner.lock.lock();

        #[cfg(target_pointer_width = "32")]
        {
            if let Some(range) = self.inner.maple_range(start, end) {
                self.inner.maple.insert_range(range, (), gfp)?;
            }
        }

        #[cfg(target_pointer_width = "64")]
        {
            self.inner
                .maple
                .insert_range(start as usize..end as usize, (), gfp)?;
        }

        Ok(LiveRange {
            inner: self.inner.clone(),
            offset: start,
            size: (end - start) as usize,
        })
    }
}

impl RangeAllocInner {
    /// The address that tree index zero maps to.
    fn base(&self) -> u64 {
        #[cfg(target_pointer_width = "32")]
        {
            self.range.start
        }

        #[cfg(target_pointer_width = "64")]
        {
            0
        }
    }

    /// Reserves `size` bytes, preferring an address aligned to `align`, and
    /// returns the address.
    ///
    /// # Locking
    ///
    /// The reservation is built in several tree operations, so the caller
    /// must hold `lock` across the call.
    fn alloc_aligned(&self, size: usize, align: Alignment, gfp: Flags) -> Result<u64> {
        let base = self.base();
        let window = (self.range.start - base) as usize..(self.range.end - base) as usize;
        let span = size.checked_add(align.as_usize() - 1).ok_or(EINVAL)?;

        let index = self.maple.alloc_range(size, (), window.clone(), gfp)?;
        let addr = base + index as u64;
        if addr.align_down(align) == addr {
            return Ok(addr);
        }

        self.maple.erase(index);

        // The span only locates a gap. The aligned block inside it is
        // reserved.
        let span_index = match self.maple.alloc_range(span, (), window, gfp) {
            Ok(span_index) => span_index,
            Err(_) => {
                self.maple.insert_range(index..index + size, (), gfp)?;
                return Ok(addr);
            }
        };

        self.maple.erase(span_index);

        let span_addr = base + span_index as u64;
        let aligned_addr = span_addr.align_up(align).ok_or(EINVAL)?;
        let aligned_index = span_index + (aligned_addr - span_addr) as usize;
        self.maple
            .insert_range(aligned_index..aligned_index + size, (), gfp)?;

        Ok(aligned_addr)
    }
}

#[cfg(target_pointer_width = "32")]
impl RangeAllocInner {
    fn maple_range(&self, start: u64, end: u64) -> Option<Range<usize>> {
        let range_start = u64::max(start, self.range.start);
        let range_end = u64::min(end, self.range.end);

        if range_start != range_end {
            let maple_start = (range_start - self.range.start) as usize;
            let maple_end = (range_end - self.range.start) as usize;
            Some(maple_start..maple_end)
        } else {
            None
        }
    }
}

impl LiveRange {
    pub(crate) fn start(&self) -> u64 {
        self.offset
    }

    pub(crate) fn end(&self) -> u64 {
        self.offset + self.size as u64
    }

    pub(crate) fn range(&self) -> Range<u64> {
        self.start()..self.end()
    }
}

impl Drop for LiveRange {
    #[cfg(target_pointer_width = "32")]
    fn drop(&mut self) {
        let _guard = self.inner.lock.lock();

        if let Some(range) = self.inner.maple_range(self.start(), self.end()) {
            self.inner.maple.erase(range.start);
        }
    }

    #[cfg(target_pointer_width = "64")]
    fn drop(&mut self) {
        let _guard = self.inner.lock.lock();
        self.inner.maple.erase(self.offset as usize);
    }
}
