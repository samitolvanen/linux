// SPDX-License-Identifier: GPL-2.0 or MIT

//! Debugfs knobs for exercising the GPU reset machinery. Local debugging
//! aid.

use core::sync::atomic::Ordering;

use kernel::{
    debugfs::{
        Dir,
        File, //
    },
    fmt,
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
    _fail_ping: Pin<KBox<File<ARef<TyrDrmDevice>>>>,
    _fw_va: Pin<KBox<File<ARef<TyrDrmDevice>>>>,
    _dir: Dir,
}

impl TyrDebugfs {
    /// Creates the `tyr` debugfs directory and its entries.
    pub(crate) fn new(tdev: ARef<TyrDrmDevice>) -> Result<Self> {
        let dir = Dir::new(c"tyr");
        let fail_ping = KBox::pin_init(
            dir.read_write_callback_file(
                c"fail_ping",
                tdev.clone(),
                &fail_ping_read,
                &fail_ping_write,
            ),
            GFP_KERNEL,
        )?;
        let fw_va = KBox::pin_init(
            dir.read_callback_file(c"fw_va", tdev.clone(), &fw_va_read),
            GFP_KERNEL,
        )?;
        let reset = KBox::pin_init(
            dir.write_callback_file(c"reset", tdev, &reset_write),
            GFP_KERNEL,
        )?;
        Ok(Self {
            _reset: reset,
            _fail_ping: fail_ping,
            _fw_va: fw_va,
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

/// Reports the remaining number of armed ping failures.
fn fail_ping_read(tdev: &ARef<TyrDrmDevice>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(f, "{}", tdev.fail_ping_count.load(Ordering::Relaxed))
}

/// Arms ping fault injection for the next N watchdog pings.
fn fail_ping_write(tdev: &ARef<TyrDrmDevice>, reader: &mut UserSliceReader) -> Result {
    let mut buf = [0u8; 16];
    if reader.len() > buf.len() {
        return Err(EINVAL);
    }
    let n = reader.len();
    reader.read_slice(&mut buf[..n])?;
    let s = core::str::from_utf8(&buf[..n]).map_err(|_| EINVAL)?;
    let count = s.trim().parse::<u32>().map_err(|_| EINVAL)?;
    tdev.fail_ping_count.store(count, Ordering::Relaxed);
    Ok(())
}

/// Reports the firmware VM kernel-VA window as "<used> <total>" bytes,
/// for watching suspend-buffer VA growth across reset storms.
fn fw_va_read(tdev: &ARef<TyrDrmDevice>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (used, total) = tdev.fw.vm().kernel_va_occupancy();
    writeln!(f, "{} {}", used, total)
}
