#include <linux/lsm_hooks.h>

extern int rust_inode_handler(struct inode *inode, int mask);

static int giji_inode_permission(struct inode *inode, int mask) {
    return rust_inode_handler(inode, mask);
}

static struct security_hook_list giji_hooks[] __ro_after_init = {
    LSM_HOOK_INIT(inode_permission, giji_inode_permission),
};

static const struct lsm_id giji_lsmid = {
	.name = "giji",
	.id = LSM_ID_GIJI,
};

static int __init giji_init(void)
{
	pr_info("GIJI: C init\n");
	security_add_hooks(giji_hooks, ARRAY_SIZE(giji_hooks), &giji_lsmid);
	return 0;
}

DEFINE_LSM(giji) = {
	.id = &giji_lsmid,
	.init = giji_init,
};
