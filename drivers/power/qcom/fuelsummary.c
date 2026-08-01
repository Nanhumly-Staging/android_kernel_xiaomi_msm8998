/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 *
 * Fuel summary sysfs class
 *
 * Maps battery power_supply properties to a simplified interface:
 *   /sys/class/fuelsummary/cycle  -> cycle_count
 *   /sys/class/fuelsummary/soh    -> charge_full
 */

#define pr_fmt(fmt) "fuelsummary: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/power_supply.h>

static struct class *fuelsummary_class;

static struct power_supply *battery_psy;

static ssize_t cycle_show(struct class *cls,
			  struct class_attribute *attr, char *buf)
{
	union power_supply_propval val;
	int ret;

	battery_psy = power_supply_get_by_name("battery");
	if (!battery_psy)
		return -ENODEV;

	ret = power_supply_get_property(battery_psy,
					POWER_SUPPLY_PROP_CYCLE_COUNT, &val);
	power_supply_put(battery_psy);

	if (ret < 0)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", val.intval);
}

static ssize_t soh_show(struct class *cls,
			struct class_attribute *attr, char *buf)
{
	union power_supply_propval val;
	int ret;

	battery_psy = power_supply_get_by_name("battery");
	if (!battery_psy)
		return -ENODEV;

	ret = power_supply_get_property(battery_psy,
					POWER_SUPPLY_PROP_CHARGE_FULL, &val);
	power_supply_put(battery_psy);

	if (ret < 0)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", val.intval);
}

static CLASS_ATTR_RO(cycle);
static CLASS_ATTR_RO(soh);

static int __init fuelsummary_init(void)
{
	int ret;

	fuelsummary_class = class_create(THIS_MODULE, "fuelsummary");
	if (IS_ERR(fuelsummary_class)) {
		ret = PTR_ERR(fuelsummary_class);
		pr_err("Failed to create class: %d\n", ret);
		return ret;
	}

	ret = class_create_file(fuelsummary_class, &class_attr_cycle);
	if (ret) {
		pr_err("Failed to create cycle node: %d\n", ret);
		class_destroy(fuelsummary_class);
		return ret;
	}

	ret = class_create_file(fuelsummary_class, &class_attr_soh);
	if (ret) {
		pr_err("Failed to create soh node: %d\n", ret);
		class_remove_file(fuelsummary_class, &class_attr_cycle);
		class_destroy(fuelsummary_class);
		return ret;
	}

	pr_info("registered: /sys/class/fuelsummary/{cycle,soh}\n");
	return 0;
}

static void __exit fuelsummary_exit(void)
{
	class_remove_file(fuelsummary_class, &class_attr_soh);
	class_remove_file(fuelsummary_class, &class_attr_cycle);
	class_destroy(fuelsummary_class);
	pr_info("unregistered\n");
}

module_init(fuelsummary_init);
module_exit(fuelsummary_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Fuel Summary sysfs class");