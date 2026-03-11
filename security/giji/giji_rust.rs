#![allow(missing_docs)]

use kernel::prelude::*;
use kernel::bindings;

// LOG_PREFIX for pr_info! macro
const __LOG_PREFIX: &[u8] = b"GIJI\0";

/*
 * Implementing the handler that will be called from the C code
 * returns 0 if permission is granted
 * otherwise denies, options can be seen at
 *     linux/include/uapi/asm-generic/errno-base.h
 *
 * To test callback is being received specifically on
 * inode_handler, do any file relate operations in the kernel,
 * such as `ls`, `cat file`, which should print the `inode_handler call` log
 *
 * TODO: This is unsafe
 * `kernel::bindings` should not be used here,
 * instead a safe/sound wrapper should be written in
 *     linux/rust/kernel/
 *
 */

#[unsafe(no_mangle)]
unsafe extern "C" fn rust_inode_handler(
    _inode: *mut bindings::inode,
    _mask: core::ffi::c_int,
) -> i32 {
    pr_info!("inode_handler call\n");
    0
        // -(bindings::EPERM as i32)
}


