// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DRM MM range allocator.
//!
//! The range allocator is frequently used to manage GPU memory. To do so,
//! drivers have to insert nodes into the allocator. The presence of a node in
//! the allocator indicates that the range it represents is currently taken.
//!
//! See [`DRM MM Range Allocator`](https://docs.kernel.org/gpu/drm-mm.html#drm-mm-range-allocator)
//! for more information.
//!
//! C header: [`include/drm/drm_mm.h`](srctree/include/drm/drm_mm.h)

use crate::{
    alloc::flags::*,
    bindings, container_of,
    error::{to_result, Result},
    new_mutex,
    prelude::*,
    sync::{Arc, Mutex, UniqueArc},
    types::Opaque,
};

use crate::init::InPlaceInit;
use crate::prelude::KBox;

use core::{
    marker::{PhantomData, PhantomPinned},
    ops::{ControlFlow, Deref},
    pin::Pin,
};

/// Type alias representing a DRM MM node.
pub type Node<A, T> = Pin<KBox<NodeData<A, T>>>;

/// Trait which must be implemented by the inner allocator state type provided by the user.
pub trait AllocInner<T> {
    /// Notification that a node was dropped from the allocator.
    fn drop_object(&mut self, _start: u64, _size: u64, _color: usize, _object: &mut T) {}
}

impl<T> AllocInner<T> for () {}

/// Wrapper type for a `struct drm_mm` plus user AllocInner object.
///
/// # Invariants
/// The `drm_mm` struct is valid and initialized.
struct MmInner<A: AllocInner<T>, T>(Opaque<bindings::drm_mm>, A, PhantomData<T>);

/// Represents a single allocated node in the MM allocator
///
/// # Invariants
///
/// - `node` points to a valid `drm_mm_node` struct, which is initialized when
///   the node is inserted in the allocator, and inserting a node is the only way
///   to create a `NodeData`, therefore `node` is always valid.
#[repr(C)]
pub struct NodeData<A: AllocInner<T>, T> {
    node: Opaque<bindings::drm_mm_node>,
    mm: Arc<Mutex<MmInner<A, T>>>,
    valid: bool,
    /// A drm_mm_node needs to be pinned because nodes reference each other in a linked list.
    _pin: PhantomPinned,
    inner: T,
}

impl<A: AllocInner<T>, T> NodeData<A, T> {
    /// Resets the raw `drm_mm_node` field to zero from a `Pin`.
    ///
    /// This is safe because the `node` field is not structural to the pinning.
    pub fn reset_node(self: Pin<&mut Self>) {
        // SAFETY: We are not moving the data out of the `Pin`. The `node` field is not
        //         structural to the pinning, so mutating it is safe.
        unsafe { self.get_unchecked_mut().node = core::mem::zeroed() };
    }

    /// Returns the color of the node (an opaque value)
    #[inline]
    pub fn color(&self) -> usize {
        // SAFETY: Safe as per the type invariants of `NodeData`.
        unsafe { *self.node.get() }.color
    }

    /// Returns the start address of the node
    #[inline]
    pub fn start(&self) -> u64 {
        // SAFETY: Safe as per the type invariants of `NodeData`.
        unsafe { *self.node.get() }.start
    }

    /// Returns the size of the node in bytes
    #[inline]
    pub fn size(&self) -> u64 {
        // SAFETY: Safe as per the type invariants of `NodeData`.
        unsafe { *self.node.get() }.size
    }

    /// Operate on the user `AllocInner<T>` implementation associated with this node's allocator.
    pub fn with_inner<RetVal>(&self, cb: impl FnOnce(&mut A) -> RetVal) -> RetVal {
        let mut l = self.mm.lock();
        cb(&mut l.1)
    }

    /// Return a clonable, detached reference to the allocator inner data.
    pub fn alloc_ref(&self) -> InnerRef<A, T> {
        InnerRef(self.mm.clone())
    }

    /// Return a mutable reference to the inner data.
    pub fn inner_mut(self: Pin<&mut Self>) -> &mut T {
        // SAFETY: This is okay because inner is not structural
        unsafe { &mut self.get_unchecked_mut().inner }
    }
}

impl<A: AllocInner<T>, T> Deref for NodeData<A, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<A: AllocInner<T>, T> Drop for NodeData<A, T> {
    fn drop(&mut self) {
        if self.valid {
            let mut guard = self.mm.lock();

            // Inform the user allocator that a node is being dropped.
            guard
                .1
                .drop_object(self.start(), self.size(), self.color(), &mut self.inner);
            // SAFETY: The MM lock is still taken, so we can safely remove the node.
            unsafe { bindings::drm_mm_remove_node(self.node.get()) };
        }
    }
}

// SAFETY: Allocator ops take the mutex, and there are no mutable actions on the node.
unsafe impl<A: Send + AllocInner<T>, T: Send> Send for NodeData<A, T> {}
// SAFETY: Allocator ops take the mutex, and there are no mutable actions on the node.
unsafe impl<A: Send + AllocInner<T>, T: Sync> Sync for NodeData<A, T> {}

/// Available MM node insertion modes
#[repr(u32)]
pub enum InsertMode {
    /// Search for the smallest hole (within the search range) that fits the desired node.
    ///
    /// Allocates the node from the bottom of the found hole.
    Best = bindings::drm_mm_insert_mode_DRM_MM_INSERT_BEST,

    /// Search for the lowest hole (address closest to 0, within the search range) that fits the
    /// desired node.
    ///
    /// Allocates the node from the bottom of the found hole.
    Low = bindings::drm_mm_insert_mode_DRM_MM_INSERT_LOW,

    /// Search for the highest hole (address closest to U64_MAX, within the search range) that fits
    /// the desired node.
    ///
    /// Allocates the node from the top of the found hole. The specified alignment for the node is
    /// applied to the base of the node (`Node.start()`).
    High = bindings::drm_mm_insert_mode_DRM_MM_INSERT_HIGH,

    /// Search for the most recently evicted hole (within the search range) that fits the desired
    /// node. This is appropriate for use immediately after performing an eviction scan and removing
    /// the selected nodes to form a hole.
    ///
    /// Allocates the node from the bottom of the found hole.
    Evict = bindings::drm_mm_insert_mode_DRM_MM_INSERT_EVICT,
}

/// A clonable, interlocked reference to the allocator state.
///
/// This is useful to perform actions on the user-supplied `AllocInner<T>` type given just a Node,
/// without immediately taking the lock.
#[derive(Clone)]
pub struct InnerRef<A: AllocInner<T>, T>(Arc<Mutex<MmInner<A, T>>>);

impl<A: AllocInner<T>, T> InnerRef<A, T> {
    /// Operate on the user `AllocInner<T>` implementation, taking the lock.
    pub fn with<RetVal>(&self, cb: impl FnOnce(&mut A) -> RetVal) -> RetVal {
        let mut l = self.0.lock();
        cb(&mut l.1)
    }
}

/// An instance of a DRM MM range allocator.
pub struct Allocator<A: AllocInner<T>, T> {
    mm: Arc<Mutex<MmInner<A, T>>>,
    _p: PhantomData<T>,
}

impl<A: AllocInner<T>, T> Allocator<A, T> {
    /// Create a new range allocator for the given start and size range of addresses.
    ///
    /// The user may optionally provide an inner object representing allocator state, which will
    /// be protected by the same lock. If not required, `()` can be used.
    #[track_caller]
    pub fn new(start: u64, size: u64, inner: A) -> Result<Allocator<A, T>> {
        let mm = UniqueArc::pin_init(
            new_mutex!(MmInner(Opaque::uninit(), inner, PhantomData)),
            GFP_KERNEL,
        )?;

        // SAFETY: The Opaque instance provides a valid pointer, and it is initialized after
        // this call.
        unsafe {
            bindings::drm_mm_init(mm.lock().0.get(), start, size);
        }

        Ok(Allocator {
            mm: mm.into(),
            _p: PhantomData,
        })
    }

    /// Insert a new node into the allocator of a given size.
    ///
    /// `node` is the user `T` type data to store into the node.
    pub fn insert_node(&mut self, node: T, size: u64) -> Result<Node<A, T>> {
        self.insert_node_generic(node, size, 0, 0, InsertMode::Best)
    }

    /// Insert a new node into the allocator of a given size, with configurable alignment,
    /// color, and insertion mode.
    ///
    /// `node` is the user `T` type data to store into the node.
    pub fn insert_node_generic(
        &mut self,
        node: T,
        size: u64,
        alignment: u64,
        color: usize,
        mode: InsertMode,
    ) -> Result<Node<A, T>> {
        self.insert_node_in_range(node, size, alignment, color, 0, u64::MAX, mode)
    }

    /// Insert a new node into the allocator of a given size, with configurable alignment,
    /// color, insertion mode, and sub-range to allocate from.
    ///
    /// `node` is the user `T` type data to store into the node.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_node_in_range(
        &mut self,
        node: T,
        size: u64,
        alignment: u64,
        color: usize,
        start: u64,
        end: u64,
        mode: InsertMode,
    ) -> Result<Node<A, T>> {
        let mut mm_node = self.allocate_node_data(node)?;

        let guard = self.mm.lock();
        // SAFETY: We hold the lock and all pointers are valid.
        to_result(unsafe {
            bindings::drm_mm_insert_node_in_range(
                guard.0.get(),
                mm_node.node.get(),
                size,
                alignment,
                color,
                start,
                end,
                mode as u32,
            )
        })?;

        mm_node.valid = true;

        Ok(Pin::from(mm_node))
    }

    /// Insert a node into the allocator at a fixed start address.
    ///
    /// `node` is the user `T` type data to store into the node.
    pub fn reserve_node(
        &mut self,
        node: T,
        start: u64,
        size: u64,
        color: usize,
    ) -> Result<Node<A, T>> {
        let mm_node = Pin::from(self.allocate_node_data(node)?);
        self.reserve_node_from_node_data(mm_node, start, size, color)
            .map_err(|(e, _)| e)
    }

    /// Allocates the data for a new node, but does not insert it into the allocator.
    ///
    /// This is useful when the caller needs to prepare a node but defer its insertion, for example,
    /// when using `reserve_node_from_node_data`.
    ///
    /// `inner` is the user `T` type data to store into the node.
    pub fn allocate_node_data(&self, node: T) -> Result<KBox<NodeData<A, T>>> {
        Ok(KBox::new(
            NodeData {
                // SAFETY: This C struct should be zero-initialized.
                node: unsafe { core::mem::zeroed() },
                valid: false,
                inner: node,
                mm: self.mm.clone(),
                _pin: PhantomPinned,
            },
            GFP_KERNEL,
        )?)
    }

    /// Insert a pre-allocated node into the allocator at a fixed start address.
    ///
    /// `mm_node` is a `Node<A, T>` that has been allocated via `allocate_node_data`.
    pub fn reserve_node_from_node_data(
        &self,
        mut mm_node: Node<A, T>,
        start: u64,
        size: u64,
        color: usize,
    ) -> Result<Node<A, T>, (Error, Node<A, T>)> {
        {
            // SAFETY: We don't move the pinned data.
            let node_ref = unsafe { mm_node.as_mut().get_unchecked_mut() };
            node_ref.valid = false;

            // SAFETY: It is safe to fabricate a &mut reference here.
            let drm_node = unsafe { &mut *node_ref.node.get() };
            drm_node.start = start;
            drm_node.size = size;
            drm_node.color = color;
        }

        let guard = self.mm.lock();
        // SAFETY: We hold the lock and all pointers are valid.
        match to_result(unsafe { bindings::drm_mm_reserve_node(guard.0.get(), mm_node.node.get()) })
        {
            Ok(_) => {
                // SAFETY: We don't move the pinned data.
                unsafe { mm_node.as_mut().get_unchecked_mut() }.valid = true;
                Ok(mm_node)
            }
            Err(e) => Err((e, mm_node)),
        }
    }

    /// Removes a node from the allocator.
    ///
    /// This is equivalent to `NodeData::drop`, but allows the caller to retain ownership of the
    /// Node<A, T> memory. The node is marked as invalid after this call, so `drop` will become
    /// a no-op.
    pub fn remove_node(&self, node: &mut Node<A, T>) {
        // SAFETY: `remove_node` does not move the pinned data.
        let node_mut = unsafe { node.as_mut().get_unchecked_mut() };
        if !node_mut.valid {
            return;
        }

        let mut guard = self.mm.lock();

        // Inform the user allocator that a node is being dropped.
        guard.1.drop_object(
            node_mut.start(),
            node_mut.size(),
            node_mut.color(),
            &mut node_mut.inner,
        );
        // SAFETY: The MM lock is still taken, so we can safely remove the node.
        unsafe { bindings::drm_mm_remove_node(node_mut.node.get()) };

        node_mut.valid = false;
    }

    /// Iterate over all nodes that overlap with the given range.
    ///
    /// The lock on the allocator is held during the iteration.
    pub fn for_each_node_in_range<F>(&self, start: u64, end: u64, mut f: F)
    where
        F: FnMut(&NodeData<A, T>) -> ControlFlow<()>,
    {
        let guard = self.mm.lock();
        let mm_ptr = guard.0.get();

        // SAFETY: `mm_ptr` is valid and we hold the lock.
        let mut node_ptr = unsafe { bindings::drm_mm_first_node_in_range(mm_ptr, start, end) };

        while !node_ptr.is_null() {
            // SAFETY: The pointer is guaranteed to be valid while the allocator lock is held.
            // We can safely cast it to a `NodeData` reference.
            let node_data = unsafe {
                let node_data_ptr = container_of!(
                    node_ptr as *mut Opaque<bindings::drm_mm_node>,
                    NodeData<A, T>,
                    node
                );
                &*node_data_ptr
            };

            if f(node_data).is_break() {
                break;
            }

            // SAFETY: `node_ptr` is valid and we hold the lock.
            node_ptr = unsafe { bindings::drm_mm_next_node_in_range(node_ptr, end) };
        }
    }

    /// Operate on the inner user type `A`, taking the allocator lock
    pub fn with_inner<RetVal>(&self, cb: impl FnOnce(&mut A) -> RetVal) -> RetVal {
        let mut guard = self.mm.lock();
        cb(&mut guard.1)
    }
}

impl<A: AllocInner<T>, T> Drop for MmInner<A, T> {
    fn drop(&mut self) {
        // SAFETY: If the MmInner is dropped then all nodes are gone (since they hold references),
        // so it is safe to tear down the allocator.
        unsafe {
            bindings::drm_mm_takedown(self.0.get());
        }
    }
}

// SAFETY: MmInner is safely Send if the AllocInner user type is Send.
unsafe impl<A: Send + AllocInner<T>, T> Send for MmInner<A, T> {}
