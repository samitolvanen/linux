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

    pub(crate) fn allocate(&self, size: usize, gfp: Flags) -> Result<LiveRange> {
        let _guard = self.inner.lock.lock();

        #[cfg(target_pointer_width = "32")]
        {
            let range = &self.inner.range;
            let total_size = (range.end - range.start) as usize;
            let offset = self.inner.maple.alloc_range(size, (), 0..total_size, gfp)?;

            Ok(LiveRange {
                inner: self.inner.clone(),
                offset: range.start + offset as u64,
                size,
            })
        }

        #[cfg(target_pointer_width = "64")]
        {
            let maple_start = self.inner.range.start as usize;
            let maple_end = self.inner.range.end as usize;
            let offset = self
                .inner
                .maple
                .alloc_range(size, (), maple_start..maple_end, gfp)?;

            Ok(LiveRange {
                inner: self.inner.clone(),
                offset: offset as u64,
                size,
            })
        }
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
