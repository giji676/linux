// SPDX-License-Identifier: GPL-2.0

//! Rust port of the Yama LSM's ptrace-scope enforcement logic.
//!
//! C source: [`security/yama/yama_lsm.c`](srctree/security/yama/yama_lsm.c).

use kernel::prelude::*;
use kernel::bindings;
use core::ffi;
use core::ptr::addr_of;
use core::ptr::addr_of_mut;
use core::mem::offset_of;
use kernel::sync::rcu::read_lock;

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
            bindings::rust_read_once($_ptr),
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

    // let guard = Guard::new();
    let guard = read_lock();

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
    // let guard = Guard::new();
    let guard = read_lock();

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
    let mut rc: ffi::c_int = 0;

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
                    rc = -(bindings::EPERM as ffi::c_int);
                }
            }
        }
        val if val == bindings::YAMA_SCOPE_NO_ATTACH as ffi::c_int => {
            rc = -(bindings::EPERM as ffi::c_int);
        }
        _ => {}
    }

    if rc != 0 {
        let current = current!();

        // SAFETY: `current.as_ptr()` is the currently running task, valid for
        // the duration of this scope.
        let _guard = unsafe { TaskLockGuard::new(current.as_ptr()) };

        // SAFETY: `c"traceme"` is `'static`. `current.as_ptr()` is valid and
        // its `alloc_lock` is held via `_guard` for the duration of this call,
        // satisfying `rust_report_access`'s locking requirement. `parent` is
        // valid per this function's own safety contract.
        unsafe {
            rust_report_access(
                c"traceme".as_ptr().cast::<u8>(),
                current.as_ptr(),
                parent,
            )
        };
        // alloc_lock released here via `_guard`'s Drop
    }

    rc
}

/// report_access written in Rust.
///
/// # Safety
///
/// - `access` must be a valid, nul-terminated C string pointer with
///   `'static` storage duration. It may be stored inside a heap-allocated
///   `access_report_info` and read later, after this function returns, from
///   the deferred `__report_access` task_work callback - so it must outlive
///   this call, not just be valid during it.
/// - `target` and `agent` must be valid, non-null `task_struct` pointers
///   that remain valid for the duration of this call.
/// - The caller must hold `target->alloc_lock` for the duration of this
///   call (matches the C original's `assert_spin_locked(&target->alloc_lock)`
///   comment: "for target->comm").
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_report_access(
    access: *const u8,
    target: *mut bindings::task_struct,
    agent: *mut bindings::task_struct,
) {
    // SAFETY: `target` is valid and its `alloc_lock` is held by the caller,
    // per this function's own safety contract.
    unsafe {
        bindings::rust_assert_spin_locked(addr_of_mut!((*target).alloc_lock));
    }

    let current = current!();
    let current_ptr = current.as_ptr();

    // SAFETY: `current_ptr` is the currently running task, always valid.
    // `flags` is a plain field read with no aliasing concerns.
    let flags = unsafe { (*current_ptr).flags };

    if flags & bindings::PF_KTHREAD != 0 {
        // SAFETY: `access` is valid and `'static` per this function's
        // safety contract. `target` and `agent` are valid per this
        // function's safety contract, so `target->comm`/`agent->comm` are
        // valid nul-terminated buffers to read, and `rust_task_pid_nr` is
        // safe to call on both.
        unsafe {
            bindings::rust_report_access_ratelimited(
                access,
                addr_of!((*target).comm).cast(),
                bindings::rust_task_pid_nr(target),
                addr_of!((*agent).comm).cast(),
                bindings::rust_task_pid_nr(agent),
            );
        }
        return;
    }

    // SAFETY: `rust_kmalloc_access_report_info` has no preconditions; it
    // may return null on allocation failure, which is checked immediately
    // below before the pointer is dereferenced.
    let info: *mut bindings::access_report_info = unsafe {
        bindings::rust_kmalloc_access_report_info()
    };

    if info.is_null() {
        return;
    }

    // SAFETY: `info` was just allocated above and confirmed non-null, so
    // it's valid to write its fields. `bindings::__report_access` is a
    // valid, non-null function pointer with the signature `task_work_add`
    // expects. `target` and `agent` are valid per this function's safety
    // contract, and `get_task_struct` is safe to call on any valid,
    // non-null task pointer - this takes the reference that `agent`/
    // `target` will be held under until the deferred callback (or the
    // failure-path cleanup below) releases it.
    unsafe {
        (*info).work.func = Some(bindings::__report_access);
        (*info).access = access;
        (*info).target = target;
        (*info).agent = agent;

        bindings::get_task_struct(target);
        bindings::get_task_struct(agent);
    }

    // SAFETY: `current_ptr` is the currently running task. `info->work` was
    // just initialized above via the write to `.func`, and `info` remains
    // valid (not yet freed) at this point.
    let ret = unsafe {
        bindings::task_work_add(
            current_ptr,
            addr_of_mut!((*info).work),
            bindings::task_work_notify_mode_TWA_RESUME
        )
    };

    if ret == 0 {
        return;
    }

    kernel::pr_warn!("report_access called from exiting task\n");

    // SAFETY: `task_work_add` failed, so `info->work` was never enqueued
    // and nothing else holds a reference to `info`, `target`, or `agent`
    // beyond what was taken above - undoing exactly those: the two
    // `get_task_struct` calls and the `rust_kmalloc_access_report_info`
    // allocation, all performed earlier in this same call.
    unsafe {
        bindings::put_task_struct(target);
        bindings::put_task_struct(agent);
        bindings::kfree(info.cast());
    }
}

/// RAII guard around `task_lock()`/`task_unlock()` (i.e. `spin_lock`/
/// `spin_unlock` on `task_struct::alloc_lock`).
///
/// Holding this guard is equivalent to having called `task_lock(task)`;
/// dropping it calls `task_unlock(task)`.
struct TaskLockGuard {
    task: *mut bindings::task_struct,
}

impl TaskLockGuard {
    /// Acquires `task->alloc_lock`.
    ///
    /// # Safety
    ///
    /// `task` must be a valid, non-null `task_struct` pointer that remains
    /// valid for the entire lifetime of the returned guard.
    unsafe fn new(task: *mut bindings::task_struct) -> Self {
        // SAFETY: caller guarantees `task` is valid, per this function's
        // own safety contract. `rust_task_lock` is safe to call on any
        // valid, non-null task pointer.
        unsafe { bindings::rust_task_lock(task) };
        Self { task }
    }
}

impl Drop for TaskLockGuard {
    fn drop(&mut self) {
        // SAFETY: `self.task->alloc_lock` was locked in `new()` and the
        // task pointer is guaranteed valid for the guard's whole lifetime,
        // per `new()`'s safety contract.
        unsafe { bindings::rust_task_unlock(self.task) };
    }
}

/// pid_alive written in Rust.
///
/// # Safety
///
/// `p` must be a valid, non-null `task_struct` pointer, valid for the
/// duration of this call.
unsafe fn pid_alive(p: *const bindings::task_struct) -> bool {
    // SAFETY: caller guarantees `p` is valid, per this function's own
    // safety contract. `thread_pid` is a plain field read.
    unsafe { !(*p).thread_pid.is_null() }
}

unsafe fn thread_group_leader(
    p: *const bindings::task_struct
) -> bool {
    unsafe { (*p).exit_signal >= 0 }
}

unsafe fn task_is_descendant(
    mut parent: *mut bindings::task_struct,
    child: *mut bindings::task_struct
) -> bool {
    let mut walker = child;

    if parent.is_null() || child.is_null() {
        return false;
    }

    let _guard = read_lock();

    unsafe {
        if !thread_group_leader(parent) {
            parent = bindings::rust_rcu_dereference_task((*parent).group_leader);
        }
    }

    unsafe {
        while (*walker).pid > 0 {
            if !thread_group_leader(walker) {
                walker = bindings::rust_rcu_dereference_task((*walker).group_leader);
            }
            if walker == parent {
                return true;
            }
            walker = bindings::rust_rcu_dereference_task((*walker).real_parent);
        }
    }

    false
}

unsafe fn same_thread_group(
    p1: *const bindings::task_struct,
    p2: *const bindings::task_struct
) -> bool {
    unsafe { (*p1).signal == (*p2).signal }
}

unsafe fn ptrace_parent(
    task: *const bindings::task_struct
) -> *mut bindings::task_struct {
    unsafe {
        // NOTE: `unlikly` branch prediction hint is omitted from the original C code
        if (*task).ptrace != 0 {
            bindings::rust_rcu_dereference_task((*task).parent)
        } else {
            core::ptr::null_mut()
        }
    }
}

unsafe extern "C" fn ptracer_exception_found(
    tracer: *mut bindings::task_struct,
    mut tracee: *mut bindings::task_struct,
) -> bool {
    let _guard = read_lock();

	let mut parent = unsafe { ptrace_parent(tracee) };

	if !parent.is_null() &&
        unsafe { same_thread_group(parent, tracer) } {
        return true;
	}

    unsafe {
        if !thread_group_leader(tracee) {
            tracee = bindings::rust_rcu_dereference_task((*tracee).group_leader);
        }
    }

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

        if (*pos).tracee == tracee {
            parent = (*pos).tracer;
            break;
        }
    }
    );

    if  parent.is_null() || unsafe { task_is_descendant(parent, tracer) } {
        true
    } else {
        false
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_yama_ptrace_access_check(
    child: *mut bindings::task_struct,
    mode: ffi::c_uint,
    ptrace_scope: ffi::c_int
) -> ffi::c_int {
    let mut rc: ffi::c_int = 0;

    let current = current!();
    let current_ptr = current.as_ptr();

    if mode & bindings::PTRACE_MODE_ATTACH != 0 {
        match ptrace_scope {
            val if val == bindings::YAMA_SCOPE_DISABLED as ffi::c_int => {
            }
            val if val == bindings::YAMA_SCOPE_RELATIONAL as ffi::c_int => {
                let _guard = read_lock();
                unsafe {
                    if !pid_alive(child) {
                        rc = -(bindings::EPERM as ffi::c_int);
                    }

                    if rc == 0 && !task_is_descendant(current_ptr, child) &&
                        !ptracer_exception_found(current_ptr, child) &&
                        !bindings::ns_capable(
                            (*bindings::rust_task_cred(child)).user_ns,
                            bindings::CAP_SYS_PTRACE as i32) {

                        rc = -(bindings::EPERM as ffi::c_int);
                    }
                }
            }
            val if val == bindings::YAMA_SCOPE_CAPABILITY as ffi::c_int => {
                let _guard = read_lock();
                unsafe {
                    if !bindings::ns_capable(
                        (*bindings::rust_task_cred(child)).user_ns,
                        bindings::CAP_SYS_PTRACE as i32) {
                        rc = -(bindings::EPERM as ffi::c_int);
                    }
                }
            }
            val if val == bindings::YAMA_SCOPE_NO_ATTACH as ffi::c_int => {
                rc = -(bindings::EPERM as ffi::c_int);
            }
            _ => {
                rc = -(bindings::EPERM as ffi::c_int);
            }
        }
    }

    if rc != 0 && (mode & bindings::PTRACE_MODE_NOAUDIT) == 0 {
        // SAFETY: `child` valid per this function's contract, `_guard`
        // holds `child->alloc_lock` for the duration of this call.
        let _guard = unsafe { TaskLockGuard::new(child) };
        unsafe {
            rust_report_access(
                c"attach".as_ptr().cast::<u8>(),
                child,
                current_ptr
            );
        }
    }

	rc
}
