use kernel::prelude::*;
use kernel::bindings;
use core::ffi;
use core::ptr::addr_of;
use core::mem::offset_of;
use kernel::sync::rcu::Guard;

// LOG_PREFIX for pr_info! macro
const __LOG_PREFIX: &[u8] = b"YAMA_RUST\0";

/// Kernel C functions in Rust.
/// Should be moved to srctree/linux/rust/ and rewritten as
/// proper, safe abstractions.
#[macro_export]
macro_rules! list_for_each_entry_rcu {
    ($pos:ident, $head:expr, $container:ty, $member:ident, $body:block) => {{
        unsafe {
            let mut __cursor: *mut $container =
                list_entry_rcu!((*$head).next, $container, $member);
            loop {
                if addr_of!((*__cursor).$member) == $head {
                    break;
                }
                let $pos = __cursor;
                __cursor = list_entry_rcu!(
                    (*$pos).$member.next,
                    $container,
                    $member
                );
                $body
            }
        }
    }};
}

#[inline(always)]
fn assert_same_type<T>(_: *const T, _: *const T) {}

#[macro_export]
macro_rules! container_of {
    ($ptr:expr, $container:ty, $field:ident) => {{
        let __ptr = $ptr;

        // Checks if a field is a member of the given container
        // if it isn't compiler will complain
        let __field_ptr =
            addr_of!(
                (*core::ptr::NonNull::<$container>::dangling().as_ptr()).$field
            );

        assert_same_type(__ptr as *const _, __field_ptr);

        (__ptr as *const u8)
            .sub(offset_of!($container, $field))
            as *mut $container
    }};
}

#[macro_export]
macro_rules! list_entry_rcu {
    ($_ptr:expr, $_type:ty, $_member:ident) => {{
        container_of!(
            bindings::rust_read_once($_ptr),
            $_type,
            $_member)
    }};
}

/// yama_ptracer_del written in Rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_yama_ptracer_del(
    tracer: *mut bindings::task_struct,
    tracee: *mut bindings::task_struct,
) {
    // pr_info!("rust_yama_ptracer_del\n");

    let mut marked = false;

    let guard = Guard::new();
    let relations = unsafe { bindings::rust_ptracer_relations() };

    list_for_each_entry_rcu!(
        pos,
        relations,
        bindings::ptrace_relation,
        node,
        {
            if (*pos).invalid {
                continue;
            }

            if (*pos).tracee == tracee
                || (!tracer.is_null() && (*pos).tracer == tracer)
            {
                (*pos).invalid = true;
                marked = true;
            }
        }
    );

    guard.unlock();

    unsafe {
        if marked {
            bindings::rust_schedule_work(
                bindings::rust_yama_relation_work(),
            );
        }
    }
}

fn has_ns_capability(
    t: *mut bindings::task_struct,
    ns: *mut bindings::user_namespace,
    cap: ffi::c_int,
) -> bool {
    let ret: ffi::c_int;
    let guard = Guard::new();
    unsafe {
        ret = bindings::security_capable(
            bindings::rust_task_cred(t),
            ns,
            cap,
            bindings::CAP_OPT_NONE,
        );
    }
    guard.unlock();
    ret == 0
}

/// yama_ptrace_traceme written in Rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_yama_ptrace_traceme(
    parent: *mut bindings::task_struct,
    ptrace_scope: ffi::c_int
) -> ffi::c_int {
    match ptrace_scope {
        val if val == bindings::YAMA_SCOPE_CAPABILITY as ffi::c_int => {
            unsafe {
                if !has_ns_capability(
                    parent,
                    bindings::rust_current_user_ns(),
                    bindings::CAP_SYS_PTRACE as ffi::c_int,
                ) {
                    return -(bindings::EPERM as c_int);
                }
            }
        }
        val if val == bindings::YAMA_SCOPE_NO_ATTACH as ffi::c_int => {
            return -(bindings::EPERM as c_int);
        }
        _ => {
        }
    }
    0
}
