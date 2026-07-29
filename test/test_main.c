// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <linux/errno.h>
#include "../lib/core.h"

MODULE_LICENSE("GPL");

extern char sprint_symbol;

static int __init test_probe_init(void)
{
	sprint_addr = (unsigned long)&sprint_symbol;
	kernel_base = sprint_addr & ~0x1FFFFFULL;

	find_kallsyms_base();

	if (!klnum_val || !kallrecon_klp) {
		pr_info("[test] bootstrap incomplete\n");
		return -ENODATA;
	}

	unsigned long addr = kallrecon_klp("_printk");
	pr_info("[test] _printk @ 0x%lx (%u symbols)\n",
		addr, klnum_val);

	return 0;
}

static void __exit test_probe_exit(void)
{
	pr_info("[test] exit\n");
}

module_init(test_probe_init);
module_exit(test_probe_exit);
