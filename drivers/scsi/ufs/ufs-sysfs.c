/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 *
 * UFS sysfs nodes for userspace access
 *   /sys/ufs/ufsid  -> UFS device serial number
 */

#define pr_fmt(fmt) "ufs-sysfs: " fmt

#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/module.h>

#include "ufshcd.h"

static struct kobject *ufs_kobj;

/* Hardcoded UFS serial - 32 hex chars */
static const char g_ufsid[] = "00000000000000000000000000000000";

static ssize_t ufsid_show(struct kobject *kobj,
			  struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", g_ufsid);
}

static struct kobj_attribute ufsid_attr = __ATTR_RO(ufsid);

static struct attribute *ufs_attrs[] = {
	&ufsid_attr.attr,
	NULL,
};

static struct attribute_group ufs_attr_group = {
	.attrs = ufs_attrs,
};

void ufs_sysfs_set_hba(struct ufs_hba *hba)
{
	/* no-op: using hardcoded UFS ID */
}
EXPORT_SYMBOL_GPL(ufs_sysfs_set_hba);

void ufs_sysfs_clear_hba(void)
{
	/* no-op */
}
EXPORT_SYMBOL_GPL(ufs_sysfs_clear_hba);

int ufs_sysfs_init(void)
{
	int ret;

	if (ufs_kobj)
		return 0;

	ufs_kobj = kobject_create_and_add("ufs", NULL);
	if (!ufs_kobj) {
		pr_err("Failed to create /sys/ufs kobject\n");
		return -ENOMEM;
	}

	/* Make the ufs directory world-readable */
	ret = sysfs_create_group(ufs_kobj, &ufs_attr_group);
	if (ret) {
		pr_err("Failed to create /sys/ufs sysfs group: %d\n", ret);
		kobject_put(ufs_kobj);
		ufs_kobj = NULL;
		return ret;
	}

	pr_info("/sys/ufs/ufsid created (hardcoded: %s)\n", g_ufsid);
	return 0;
}

void ufs_sysfs_exit(void)
{
	if (ufs_kobj) {
		sysfs_remove_group(ufs_kobj, &ufs_attr_group);
		kobject_put(ufs_kobj);
		ufs_kobj = NULL;
	}
}
