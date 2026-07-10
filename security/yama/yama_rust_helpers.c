#include <linux/yama_lsm.h>
#include "yama_lsm.c"

struct list_head *rust_read_once_list_next(const struct list_head *node)
{
	return READ_ONCE(node->next);
}

struct list_head *rust_read_once(struct list_head *ptr)
{
	return READ_ONCE(ptr);
}

bool rust_read_once_bool(bool *p)
{
	return READ_ONCE(*p);
}

struct task_struct *rust_read_once_task(struct task_struct **p)
{
	return READ_ONCE(*p);
}

struct list_head *rust_ptracer_relations(void)
{
	return &ptracer_relations;
}

struct work_struct *rust_yama_relation_work(void)
{
	return &yama_relation_work;
}

void rust_schedule_work(struct work_struct *work)
{
	schedule_work(work);
}

int rust_task_pid_nr(struct task_struct *task)
{
	return task_pid_nr(task);
}

const struct cred *rust_task_cred(struct task_struct *task)
{
	return __task_cred(task);
}

struct user_namespace *rust_current_user_ns(void)
{
	return current_user_ns();
}

struct access_report_info *rust_kmalloc_access_report_info(void)
{
	return kmalloc(sizeof(struct access_report_info), GFP_ATOMIC);
}

void rust_assert_spin_locked(spinlock_t *lock)
{
	assert_spin_locked(lock);
}

void rust_report_access_ratelimited(const char *access,
				     const char *target_comm, int target_pid,
				     const char *agent_comm, int agent_pid)
{
	pr_notice_ratelimited(
	    "ptrace %s of \"%s\"[%d] was attempted by \"%s\"[%d]\n",
	    access, target_comm, target_pid, agent_comm, agent_pid);
}
