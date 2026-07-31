// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DRM execution contexts.
//!
//! An execution context locks the reservations of a set of GEM objects and
//! reserves slots in them for the fences an operation adds later. Taking
//! several reservations at once can deadlock, so the context backs off when it
//! finds one held by another task. It then drops every lock it took and asks
//! the caller to select the set again. The reservation it backed off for is
//! taken first on the next attempt, so the retry can finish.
//!
//! C header: [`include/drm/drm_exec.h`](srctree/include/drm/drm_exec.h)

use crate::{
    bindings,
    dma_buf::{
        dma_fence::PublicDmaFence,
        DmaResvUsage, //
    },
    drm::gem::IntoGEMObject,
    error::to_result,
    impl_flags,
    pr_warn_once,
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
    types::Opaque, //
};

/// Hands out the identity carried by [`Prepared`], so a receipt is only ever
/// accepted by the [`Exec`] that issued it.
static NEXT_EXEC_ID: Atomic<u64> = Atomic::new(0);

impl_flags!(
    /// Flags controlling how an [`Exec`] takes its locks.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct ExecFlags(u32);

    /// An individual flag in [`ExecFlags`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ExecFlag {
        /// Wait for a reservation lock interruptibly, so a signal aborts the
        /// wait and fails the prepare call with `EINTR`.
        InterruptibleWait = bindings::DRM_EXEC_INTERRUPTIBLE_WAIT,

        /// Accept an object whose reservation the round already holds, instead
        /// of failing with `EALREADY`.
        ///
        /// Objects private to a GPUVM all share the GPUVM's own reservation,
        /// and a caller may select the same object twice. The duplicate does
        /// not enter the context's object list.
        IgnoreDuplicates = bindings::DRM_EXEC_IGNORE_DUPLICATES,
    }
);

/// Proof that the [`Exec`] that issued it holds a reservation lock and has
/// reserved the fence slots asked for on it.
///
/// [`ExecCtx::prepare_obj`] issues one per object, and [`Exec::resv_add_fence`]
/// requires one. A reservation an execution context holds cannot be reached any
/// other way. A receipt carries the identity of its own context, because two
/// contexts can be locked at once and would otherwise accept each other's
/// receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prepared {
    exec_id: u64,
    index: usize,
    resv: *mut bindings::dma_resv,
}

/// An execution context holding the reservations of a completed round.
///
/// The locks belong to the task that took them, so this type is neither
/// [`Send`] nor [`Sync`].
///
/// # Invariants
///
/// The context is initialized by `drm_exec_init()` and finalized exactly once,
/// by [`Drop`]. `id` comes from a counter that hands out each value once, so no
/// two contexts share one. Every reservation in `resvs` was prepared by the
/// round that completed, and stays locked and valid for as long as this value
/// lives.
pub struct Exec {
    exec: Pin<KBox<Opaque<bindings::drm_exec>>>,
    resvs: KVec<*mut bindings::dma_resv>,
    id: u64,
}

impl Exec {
    /// Locks every object `prepare` selects and reserves the fence slots it
    /// asks for.
    ///
    /// `prepare` runs once per attempt, and runs again after the context backs
    /// off, so it has to select the same objects every time. The value it
    /// returns from the attempt that completed is returned here with the
    /// context, and the values of earlier attempts are dropped.
    ///
    /// `nr_objects` sizes the initial object table. Zero leaves the C code to
    /// pick a default, and the table grows on demand either way.
    ///
    /// Wraps `drm_exec_init()` and the `drm_exec_until_all_locked()` loop.
    pub fn lock<P>(
        flags: ExecFlags,
        nr_objects: u32,
        prepare: impl Fn(&mut ExecCtx<'_>) -> Result<P>,
    ) -> Result<(Self, P)> {
        // INVARIANT: `drm_exec_init()` initializes the context, and from here
        // on `Drop` is the only caller of `drm_exec_fini()` for it.
        let mut this = Self {
            exec: KBox::pin_init(
                // SAFETY: `drm_exec_init()` initializes the context it is
                // given. It leaves the object table empty when it cannot
                // allocate one, which the C code handles on first use.
                Opaque::ffi_init(|slot| unsafe {
                    bindings::drm_exec_init(slot, flags.into(), nr_objects)
                }),
                GFP_KERNEL,
            )?,
            resvs: KVec::new(),
            id: NEXT_EXEC_ID.fetch_add(1, Relaxed),
        };

        let mut prepared = None;

        loop {
            // `drm_exec_cleanup()` is the loop condition of
            // `drm_exec_until_all_locked()`. It arms the ww ticket on the
            // first call, drops the locks of a round that backed off on a
            // later one, and returns false once a round has taken every lock.
            //
            // SAFETY: By the type invariant the context is initialized.
            if !unsafe { bindings::drm_exec_cleanup(this.raw()) } {
                return Ok((this, prepared.ok_or(EINVAL)?));
            }

            this.resvs.clear();

            let result = prepare(&mut ExecCtx {
                exec: &mut this,
                contended: false,
            });

            // SAFETY: By the type invariant the context is initialized.
            if !unsafe { bindings::drm_exec_is_contended(this.raw()) } {
                prepared = Some(result?);
            }
        }
    }

    /// Adds `fence` to the reservation `prepared` names, with `usage`.
    ///
    /// Ignores `prepared` unless it names a reservation this context prepared,
    /// so a fence only ever reaches a reservation this context holds. Neither
    /// allocates nor fails, so it may be called from a region that has already
    /// published a fence.
    ///
    /// The caller has to keep the fences it adds for one object within the
    /// slots reserved for it. The wrapper cannot count them, because
    /// `dma_resv_add_fence()` may replace an entry instead of taking a slot.
    /// Overrunning the reservation hits a `BUG_ON()` in
    /// `dma_resv_add_fence()`.
    pub fn resv_add_fence(
        &mut self,
        prepared: Prepared,
        fence: &PublicDmaFence,
        usage: DmaResvUsage,
    ) {
        if prepared.exec_id != self.id || self.resvs.get(prepared.index) != Some(&prepared.resv) {
            pr_warn_once!("drm_exec: dropping a fence for an unprepared reservation\n");
            return;
        }

        // SAFETY: By the type invariant the reservation is locked for as long
        // as `self` lives, and `fence` is live for the call.
        unsafe { bindings::dma_resv_add_fence(prepared.resv, fence.raw(), usage as u32) };
    }

    /// The raw context, for `rust/kernel` wrappers of C functions taking a
    /// `struct drm_exec *`.
    ///
    /// Such a wrapper must not change the lock set, for instance with
    /// `drm_exec_unlock_obj()`. A receipt names a reservation by its position
    /// in this context's own list, so unlocking behind that list would leave
    /// [`Exec::resv_add_fence`] adding to a reservation the context no longer
    /// holds.
    #[inline]
    pub(crate) fn raw(&self) -> *mut bindings::drm_exec {
        self.exec.get()
    }
}

impl Drop for Exec {
    fn drop(&mut self) {
        // SAFETY: By the type invariant the context is initialized and has not
        // been finalized yet.
        unsafe { bindings::drm_exec_fini(self.raw()) };
    }
}

/// One locking round of an [`Exec`].
///
/// [`Exec::lock`] hands this to its `prepare` closure, which uses it to select
/// the objects the round has to cover.
pub struct ExecCtx<'a> {
    exec: &'a mut Exec,
    contended: bool,
}

impl ExecCtx<'_> {
    /// Locks `obj`'s reservation and reserves `num_fences` fence slots on
    /// it.
    ///
    /// Fails the round with `EDEADLK` when another task holds the reservation,
    /// which [`Exec::lock`] turns into another attempt. Every further call in
    /// a round that has backed off fails with `EDEADLK` without touching
    /// `obj`.
    ///
    /// Rejects a `num_fences` of zero, which `dma_resv_reserve_fences()`
    /// warns about and refuses.
    ///
    /// Wraps `drm_exec_prepare_obj()`.
    pub fn prepare_obj<T: IntoGEMObject>(&mut self, obj: &T, num_fences: u32) -> Result<Prepared> {
        if num_fences == 0 {
            return Err(EINVAL);
        }

        let obj = obj.as_raw();
        let prepare = |exec: *mut bindings::drm_exec| {
            // SAFETY: `prepare_with` passes an initialized context that stays
            // valid for the call, and `obj` points at a live GEM object.
            to_result(unsafe { bindings::drm_exec_prepare_obj(exec, obj, num_fences) })
        };

        // SAFETY: `drm_exec_prepare_obj()` is a single locking call. On
        // success it locks `obj`'s reservation in this round, and on failure
        // it only drops `obj` from the lock set. `obj` is live, so reading its
        // `resv` is valid, and the round holds a reference to the object that
        // owns that reservation, either `obj` or the one it shares the
        // reservation with, so the reservation outlives the context.
        unsafe { self.prepare_with(prepare, (*obj).resv) }
    }

    /// Runs one prepare call of this round and issues the receipt for the
    /// reservation it locked.
    ///
    /// Returns `EDEADLK` without running `prepare` once the round has backed
    /// off, because the next prepare call would wait for the contended
    /// reservation while the round still holds its other locks.
    ///
    /// `prepare` is given a pointer to an initialized context that stays valid
    /// for the call. A failing `prepare` invalidates every receipt of this
    /// round.
    ///
    /// # Safety
    ///
    /// `prepare` must make exactly one `drm_exec` locking call on the context
    /// it is given and must not change the lock set in any other way, except
    /// that a failing call may unlock objects the round already holds. On
    /// success that call must have locked `resv` in this round, and `resv`
    /// must stay valid for as long as the [`Exec`] lives.
    pub(crate) unsafe fn prepare_with(
        &mut self,
        prepare: impl FnOnce(*mut bindings::drm_exec) -> Result,
        resv: *mut bindings::dma_resv,
    ) -> Result<Prepared> {
        if self.contended {
            return Err(EDEADLK);
        }

        if let Err(e) = prepare(self.exec.raw()) {
            if e == EDEADLK {
                self.contended = true;
            }

            // The failing call may have dropped an object the round was
            // already holding, so no receipt of this round can be trusted.
            self.exec.resvs.clear();

            return Err(e);
        }

        let index = self.exec.resvs.len();
        self.exec.resvs.push(resv, GFP_KERNEL)?;

        Ok(Prepared {
            exec_id: self.exec.id,
            index,
            resv,
        })
    }
}
