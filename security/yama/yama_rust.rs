use kernel::prelude::*;
use kernel::bindings;
use core::ffi;
use core::ptr::addr_of;
use core::mem::offset_of;
use kernel::sync::rcu::Guard;

// LOG_PREFIX for pr_info! macro
const __LOG_PREFIX: &[u8] = b"YAMA_RUST\0";

/// Kernel C functions in Rust.
///
/// # Safety requirements
///
/// - `$head` must be a valid, non-null pointer to a `list_head` that is
///   either the sentinel head of a circular doubly-linked list, or reachable
///   as such - i.e. traversing `->next` repeatedly must eventually reach
///   `$head` again.
/// - Every node in the list (other than `$head` itself) must be embedded in
///   a live `$container` at field `$member`, consistent with how the list
///   was populated.
/// - The list must be RCU-protected, and this macro must be invoked from
///   within an RCU read-side critical section (`rcu_read_lock()` held) for
///   the whole duration of the loop - the underlying `READ_ONCE` in
///   `list_entry_rcu!` only gives you a *consistent* pointer read, not
///   protection against the pointed-to node being freed concurrently.
/// - `$body` must not free, unlink, or otherwise invalidate the *current*
///   node in a way that a later `pos.$member.next` read (already captured
///   into `__cursor` before `$body` runs) would dereference freed memory -
///   note the cursor is captured *before* `$body` runs specifically so that
///   `continue` inside `$body` cannot skip the advance (see earlier bug fix).
#[macro_export]
macro_rules! list_for_each_entry_rcu {
    ($pos:ident, $head:expr, $container:ty, $member:ident, $body:block) => {{
        // SAFETY: the caller of this macro is responsible for upholding all
        // of the invariants documented above (RCU lock held, `$head`/list
        // validity, correct `$container`/`$member` pairing).
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

/// # Safety requirements
///
/// - `$ptr` must be a valid, non-null pointer to the `$field` member of some
///   live `$container` value (i.e. it must actually point *inside* such a
///   struct at the right offset, not just be any valid pointer of the same
///   type).
/// - Must be invoked from an `unsafe` context - the pointer arithmetic
///   (`.sub()`) inside is itself unsafe and is not independently wrapped
///   here, so callers get no compiler enforcement beyond what surrounds the
///   macro invocation.
#[macro_export]
macro_rules! container_of {
    ($ptr:expr, $container:ty, $field:ident) => {{
        let __ptr = $ptr;

        // Compile-time-only check: confirms `$field` is actually a member of
        // `$container` with a matching type. This doesn't touch the pointer
        // in `__ptr` at all - `NonNull::dangling()` is never dereferenced,
        // only used to compute a field pointer's *type* for comparison.
        let __field_ptr =
            addr_of!(
                (*core::ptr::NonNull::<$container>::dangling().as_ptr()).$field
            );

        assert_same_type(__ptr as *const _, __field_ptr);

        // SAFETY: caller guarantees `__ptr` points at the `$field` member of
        // a live `$container`, per this macro's documented requirements -
        // `offset_of!` gives the exact byte offset of that field, so
        // subtracting it recovers a valid pointer to the start of the
        // enclosing `$container`.
        (__ptr as *const u8)
            .sub(offset_of!($container, $field))
            as *mut $container
    }};
}
///
/// # Safety requirements
///
/// - `$_ptr` must be a valid pointer to read via `READ_ONCE` (i.e. valid for
///   reads of a pointer-sized value at this point in time - the RCU-critical-
///   section requirement for what it *points to* is the caller's
///   responsibility, not this macro's).
/// - The value read from `$_ptr` must satisfy `container_of!`'s requirements
///   above (point at the `$_member` field of a live `$_type`).
#[macro_export]
macro_rules! list_entry_rcu {
    ($_ptr:expr, $_type:ty, $_member:ident) => {{
        container_of!(
            // SAFETY: caller guarantees `$_ptr` is valid for a `READ_ONCE`
            // read of a `list_head *`, per this macro's documented requirements.
            unsafe { bindings::rust_read_once($_ptr) },
            $_type,
            $_member)
    }};
}

/// yama_ptracer_del written in Rust.
///
/// # Safety
///
/// - `tracer` must be either null or a valid, non-dangling `task_struct` pointer.
/// - `tracee` must be a valid, non-dangling `task_struct` pointer.
/// - Both pointers must remain valid for the duration of this call (guaranteed
///   by the C caller holding an appropriate reference/lock, same as the
///   original C `yama_ptracer_del`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_yama_ptracer_del(
    tracer: *mut bindings::task_struct,
    tracee: *mut bindings::task_struct,
) {
    let mut marked = false;

    let guard = Guard::new();

    // SAFETY: `relations` points at the static `ptracer_relations` list head,
    // which is always initialized for the lifetime of the module.
    let relations = unsafe { bindings::rust_ptracer_relations() };

    // SAFETY: we're inside an RCU read-side critical section (see `Guard::new()`
    // below), and `relations` is a valid, permanently-live list head, satisfying
    // the traversal macro's requirements.
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

/// Checks whether task `t` has `cap` in namespace `ns`.
///
/// # Safety
///
/// - `t` must be a valid, non-null `task_struct` pointer, valid for the
///   duration of this call (its `cred` is read via RCU-protected access
///   internally by `rust_task_cred`).
/// - `ns` must be a valid, non-null `user_namespace` pointer, valid for the
///   duration of this call.
unsafe fn has_ns_capability(
    t: *mut bindings::task_struct,
    ns: *mut bindings::user_namespace,
    cap: ffi::c_int,
) -> bool {
    let ret: ffi::c_int;
    let guard = Guard::new();

    // SAFETY: `t` and `ns` are valid per this function's own safety
    // contract. `rust_task_cred(t)` returns a `cred` pointer that's only
    // valid for the duration of the current RCU read-side critical section
    // (held here via `guard`), which `security_capable()` is called within
    // before the guard is dropped - satisfying `__task_cred()`'s usual
    // requirement of being read under `rcu_read_lock()`.
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

/// yama_ptrace_traceme written in Rust.
///
/// # Safety
///
/// `parent` must be a valid, non-null `task_struct` pointer that remains
/// valid for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_yama_ptrace_traceme(
    parent: *mut bindings::task_struct,
    ptrace_scope: ffi::c_int
) -> ffi::c_int {
    match ptrace_scope {
        val if val == bindings::YAMA_SCOPE_CAPABILITY as ffi::c_int => {
            // SAFETY: `parent` is valid per this function's own safety
            // contract. `rust_current_user_ns()` always returns a valid,
            // non-null `user_namespace` for the currently running task, so
            // both of `has_ns_capability`'s pointer requirements are met.
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
