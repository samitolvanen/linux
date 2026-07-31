// SPDX-License-Identifier: GPL-2.0

//! DMA buffer abstractions.
//!
//! Rust abstractions for the kernel's DMA buffer subsystem (drivers/dma-buf/).

pub mod dma_fence;

use crate::bindings;

/// How the fences of a `dma_resv` are used.
///
/// The usages are ordered `Kernel` < `Write` < `Read` < `Bookkeep`. A query for
/// one usage also returns the fences of every usage below it, so asking for
/// `Write` fences returns the `Kernel` fences as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DmaResvUsage {
    /// For in kernel memory management only, such as copying or clearing
    /// memory with a DMA engine.
    ///
    /// A driver must wait for these fences before it touches the resource,
    /// unless the resource is pinned in place.
    Kernel = bindings::dma_resv_usage_DMA_RESV_USAGE_KERNEL,
    /// Implicit write synchronization, for userspace command submissions that
    /// add an implicit write dependency.
    Write = bindings::dma_resv_usage_DMA_RESV_USAGE_WRITE,
    /// Implicit read synchronization, for userspace command submissions that
    /// add an implicit read dependency.
    Read = bindings::dma_resv_usage_DMA_RESV_USAGE_READ,
    /// No implicit sync, for submissions that take no part in implicit
    /// synchronization, such as preemption fences, page table updates and TLB
    /// flushes.
    Bookkeep = bindings::dma_resv_usage_DMA_RESV_USAGE_BOOKKEEP,
}
