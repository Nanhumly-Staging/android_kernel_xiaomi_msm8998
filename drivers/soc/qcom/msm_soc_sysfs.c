/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * MSM SoC sysfs nodes
 *
 * Exports the following fixed sysfs nodes under /sys/devices/soc1/:
 *   cpu_freq      - CPU frequency (fixed: 245)
 *   core_num      - Number of CPU cores (fixed: 8)
 *   cpu_type      - CPU type string (fixed: "msm8998")
 *   user_cpu_freq - User CPU frequency (fixed: 245)
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/sysfs.h>

static struct device *soc1_dev;

static ssize_t cpu_freq_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", 245);
}

static ssize_t core_num_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", 8);
}

static ssize_t cpu_type_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", "msm8998");
}

static ssize_t user_cpu_freq_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", 245);
}

static DEVICE_ATTR_RO(cpu_freq);
static DEVICE_ATTR_RO(core_num);
static DEVICE_ATTR_RO(cpu_type);
static DEVICE_ATTR_RO(user_cpu_freq);

static struct attribute *soc1_attrs[] = {
	&dev_attr_cpu_freq.attr,
	&dev_attr_core_num.attr,
	&dev_attr_cpu_type.attr,
	&dev_attr_user_cpu_freq.attr,
	NULL,
};

static const struct attribute_group soc1_attr_group = {
	.attrs = soc1_attrs,
};

static int __init soc1_sysfs_init(void)
{
	int ret;

	soc1_dev = root_device_register("soc1");
	if (IS_ERR(soc1_dev)) {
		ret = PTR_ERR(soc1_dev);
		pr_err("Failed to register root device: %d\n", ret);
		return ret;
	}

	ret = sysfs_create_group(&soc1_dev->kobj, &soc1_attr_group);
	if (ret) {
		pr_err("Failed to create sysfs group: %d\n", ret);
		root_device_unregister(soc1_dev);
		return ret;
	}

	pr_info("soc1 sysfs nodes registered at /sys/devices/soc1/\n");
	return 0;
}

static void __exit soc1_sysfs_exit(void)
{
	sysfs_remove_group(&soc1_dev->kobj, &soc1_attr_group);
	root_device_unregister(soc1_dev);
	pr_info("soc1 sysfs nodes unregistered\n");
}

module_init(soc1_sysfs_init);
module_exit(soc1_sysfs_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("MSM SoC sysfs attributes for soc1");