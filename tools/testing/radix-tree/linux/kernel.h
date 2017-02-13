#ifndef _KERNEL_H
#define _KERNEL_H

#include "../../include/linux/kernel.h"
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "../../include/linux/compiler.h"
#include "../../include/linux/err.h"
#include "../../../include/linux/kconfig.h"

#define printk printf
#define pr_debug printk
#define pr_cont printk

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif /* _KERNEL_H */
