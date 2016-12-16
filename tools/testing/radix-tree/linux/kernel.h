#ifndef _KERNEL_H
#define _KERNEL_H

#include "../../include/linux/kernel.h"
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "../../include/linux/compiler.h"
#include "../../include/linux/err.h"
#include "../../../include/linux/kconfig.h"

#ifdef BENCHMARK
#define RADIX_TREE_MAP_SHIFT	6
#else
#define RADIX_TREE_MAP_SHIFT	3
#endif

#define printk printf
#define pr_debug printk

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define xchg(ptr, x)	uatomic_xchg(ptr, x)

#endif /* _KERNEL_H */
