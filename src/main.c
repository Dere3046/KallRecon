// SPDX-License-Identifier: GPL-2.0-only
/*
 * main.c
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <linux/errno.h>

#include "../lib/core.h"
#include "verify.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KallRecon ARM64 probe");

static int __init probe_init(void)
{
	pr_info("[kallrecon] init\n");

	find_kallsyms_base();
	dump_kallsyms_layout();

	if (!kloffs_addr) {
		pr_info("[kallrecon] discovery failed\n");
		return -ENODATA;
	}

	verify_kallsyms();

	return 0;
}

static void __exit probe_exit(void)
{
	pr_info("[kallrecon] exit\n");
}

module_init(probe_init);
module_exit(probe_exit);
