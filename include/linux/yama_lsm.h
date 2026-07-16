#ifndef _YAMA_LSM_H
#define _YAMA_LSM_H

#include "linux/types.h"
#include <linux/list.h>
#include <linux/spinlock.h>

#define YAMA_SCOPE_DISABLED	0
#define YAMA_SCOPE_RELATIONAL	1
#define YAMA_SCOPE_CAPABILITY	2
#define YAMA_SCOPE_NO_ATTACH	3

/* describe a ptrace relationship for potential exception */
struct ptrace_relation {
	struct task_struct *tracer;
	struct task_struct *tracee;
	bool invalid;
	struct list_head node;
	struct rcu_head rcu;
};

struct access_report_info {
	struct callback_head work;
	const char *access;
	struct task_struct *target;
	struct task_struct *agent;
};

struct list_head *rust_read_once_list_next(const struct list_head *node);
struct list_head *rust_read_once(struct list_head *ptr);
bool rust_read_once_bool(bool *p);
struct task_struct *rust_read_once_task(struct task_struct **p);
struct list_head *rust_ptracer_relations(void);
struct work_struct *rust_yama_relation_work(void);
void rust_schedule_work(struct work_struct *work);
int rust_task_pid_nr(struct task_struct *task);
const struct cred *rust_task_cred(struct task_struct *task);
struct user_namespace *rust_current_user_ns(void);
void rust_task_lock(struct task_struct *task);
void rust_task_unlock(struct task_struct *task);
struct access_report_info *rust_kmalloc_access_report_info(void);
void __report_access(struct callback_head *work);
void rust_assert_spin_locked(spinlock_t *lock);
void rust_report_access_ratelimited(const char *access,
				     const char *target_comm, int target_pid,
				     const char *agent_comm, int agent_pid);
struct task_struct *rust_rcu_dereference_task(struct task_struct *const *field);

#endif
