use kernel::prelude::*;
use kernel::bindings;
use core::mem::offset_of;

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
    let offset = offset_of!(bindings::ptrace_relation, node);

    unsafe {
        let mut rel = list_entry_rcu::<bindings::ptrace_relation>(
            (*head).next,
            offset,
        );

        while core::ptr::addr_of!((*rel).node) != head {
            f(rel);

            rel = list_entry_rcu::<bindings::ptrace_relation>(
                (*rel).node.next,
                offset,
            );
        }
    }
}

#[inline(always)]
pub const fn list_check_rcu() {}

#[inline(always)]
pub unsafe fn container_of<T>(
    ptr: *const u8,
    offset: usize,
) -> *mut T {
    unsafe {
        ptr.sub(offset) as *mut T
    }
}

#[inline(always)]
pub unsafe fn list_entry_rcu<T>(
    ptr: *mut bindings::list_head,
    offset: usize,
) -> *mut T {
    
    unsafe {
        let ptr = bindings::rust_read_once_list_next(ptr);
        container_of::<T>(ptr as *const u8, offset) as *mut T
    }
}

/// yama_pracer_del written in Rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_yama_ptracer_del(
    tracer: *mut bindings::task_struct,
    tracee: *mut bindings::task_struct,
) {
    pr_info!("rust_yama_ptracer_del\n");

    let mut marked = false;

    unsafe {
        bindings::rcu_read_lock();

        list_for_each_entry_rcu(
            bindings::rust_ptracer_relations(),
            |relation| {
                unsafe {
                    pr_info!(
                        "tracer pid = {}\n",
                        bindings::rust_task_pid_nr(tracer)
                    );
                    pr_info!(
                        "tracee pid = {}\n",
                        bindings::rust_task_pid_nr(tracee)
                    );
                }

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

        bindings::rcu_read_unlock();

        if marked {
            bindings::rust_schedule_work(
                bindings::rust_yama_relation_work(),
            );
        }
    }
}
