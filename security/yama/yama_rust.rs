use kernel::prelude::*;
use kernel::bindings;
use core::mem::offset_of;
use kernel::sync::rcu::Guard;

// LOG_PREFIX for pr_info! macro
const __LOG_PREFIX: &[u8] = b"YAMA_RUST\0";

/// Kernel C functions in Rust.
/// Should be moved to srctree/linux/rust/ and rewritten as
/// proper, safe abstractions.
pub unsafe fn list_for_each_entry_rcu<F>(
    head: *mut bindings::list_head,
    mut f: F,
)
where
    F: FnMut(*mut bindings::ptrace_relation),
{
    unsafe {
        let mut rel = list_entry_rcu!((*head).next, bindings::ptrace_relation, node);

        while core::ptr::addr_of!((*rel).node) != head {
            f(rel);

            let mut rel = list_entry_rcu!((*rel).node.next, bindings::ptrace_relation, node);
        }
    }
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
            core::ptr::addr_of!(
                (*core::ptr::NonNull::<$container>::dangling().as_ptr()).$field
            );

        assert_same_type(__ptr, __field_ptr);

        unsafe {
            (__ptr as *const u8)
                .sub(core::mem::offset_of!($container, $field))
                as *mut $container
        }
    }};
}

#[macro_export]
macro_rules! list_entry_rcu {
    ($_ptr:expr, $_type:ty, $_member:ident) => {{
        unsafe {
            container_of!(bindings::rust_read_once_list_next($_ptr), $_type, $_member)
        }
    }};
}

/// yama_pracer_del written in Rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_yama_ptracer_del(
    tracer: *mut bindings::task_struct,
    tracee: *mut bindings::task_struct,
) {
    pr_info!("rust_yama_ptracer_del\n");

    let mut marked = false;

    let guard = Guard::new();

    unsafe {
        list_for_each_entry_rcu(
            bindings::rust_ptracer_relations(),
            |relation| {
                pr_info!(
                    "tracer pid = {}\n",
                    bindings::rust_task_pid_nr(tracer)
                );
                pr_info!(
                    "tracee pid = {}\n",
                    bindings::rust_task_pid_nr(tracee)
                );

                if (*relation).invalid {
                    return;
                }

                if (*relation).tracee == tracee
                    || (!tracer.is_null() && (*relation).tracer == tracer)
                {
                    (*relation).invalid = true;
                    marked = true;
                }
            },
        );
    }

    guard.unlock();

    unsafe {
        if marked {
            bindings::rust_schedule_work(
                bindings::rust_yama_relation_work(),
            );
        }
    }

}
