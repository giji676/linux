#![allow(missing_docs)]

use kernel::prelude::*;
use kernel::bindings;

const __LOG_PREFIX: &[u8] = b"GIJI\0";

#[unsafe(no_mangle)]
unsafe extern "C" fn rust_inode_handler(
    _inode: *mut bindings::inode,
    _mask: core::ffi::c_int,
) -> i32 {
    pr_info!("inode_handler call\n");
    0
    // -(bindings::EPERM as i32)
}

