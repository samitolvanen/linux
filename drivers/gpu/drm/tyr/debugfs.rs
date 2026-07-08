// SPDX-License-Identifier: GPL-2.0 or MIT

//! Debugfs knobs for exercising the GPU reset machinery. Local debugging
//! aid.

use kernel::{
    debugfs::{
        Dir,
        File, //
    },
    prelude::*,
    sync::aref::ARef,
    uaccess::UserSliceReader, //
};

use crate::driver::TyrDrmDevice;

/// Owns the debugfs entries. Dropped with the platform driver data at
/// unbind, which removes the files before the reset controller is torn
/// down.
pub(crate) struct TyrDebugfs {
    _reset: Pin<KBox<File<ARef<TyrDrmDevice>>>>,
    _dir: Dir,
}

impl TyrDebugfs {
    /// Creates the `tyr` debugfs directory and its entries.
    pub(crate) fn new(tdev: ARef<TyrDrmDevice>) -> Result<Self> {
        let dir = Dir::new(c"tyr");
        let reset = KBox::pin_init(
            dir.write_callback_file(c"reset", tdev, &reset_write),
            GFP_KERNEL,
        )?;
        Ok(Self {
            _reset: reset,
            _dir: dir,
        })
    }
}

/// Schedules an asynchronous GPU reset on any write to `tyr/reset`.
fn reset_write(tdev: &ARef<TyrDrmDevice>, _reader: &mut UserSliceReader) -> Result {
    dev_info!(tdev.pdev.as_ref(), "debug: scheduling a GPU reset\n");
    tdev.reset.schedule();
    Ok(())
}
