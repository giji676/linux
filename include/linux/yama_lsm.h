#ifndef _YAMA_LSM_H
#define _YAMA_LSM_H

#include "linux/types.h"
#include <linux/list.h>

/* describe a ptrace relationship for potential exception */
struct ptrace_relation {
	struct task_struct *tracer;
	struct task_struct *tracee;
	bool invalid;
	struct list_head node;
	struct rcu_head rcu;
};

struct list_head *rust_read_once(struct list_head *ptr);
bool rust_read_once_bool(bool *p);
struct task_struct *rust_read_once_task(struct task_struct **p);
struct list_head *rust_ptracer_relations(void);
struct work_struct *rust_yama_relation_work(void);
void rust_schedule_work(struct work_struct *work);
int rust_task_pid_nr(struct task_struct *task);

#endif
