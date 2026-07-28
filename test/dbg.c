// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include "../lib/core.h"

static unsigned int dbg_buf[16 * 1024];

static int dbg_safe_read(void *dst, const void *src, size_t sz)
{
	return copy_from_kernel_nofault(dst, src, sz);
}

static int dbg_check_ti(unsigned short *ti, unsigned long addr)
{
	if (ti[0] != 0) {
		pr_info("[dbg] ti@0x%lx reject ti[0]=%u\n", addr, ti[0]);
		return 0;
	}
	for (int i = 1; i < 256; i++) {
		if (ti[i] <= ti[i - 1]) {
			pr_info("[dbg] ti@0x%lx reject !mono i=%d %u->%u\n",
				addr, i, ti[i - 1], ti[i]);
			return 0;
		}
	}
	int da = ti['b'] - ti['a'];
	int dz = ti['z'] - ti['a'];
	if (da != 2 || dz != 50) {
		pr_info("[dbg] ti@0x%lx reject az ti[a]=%u ti[b]=%u ti[z]=%u da=%d dz=%d\n",
			addr, ti['a'], ti['b'], ti['z'], da, dz);
		return 0;
	}
	pr_info("[dbg] ti HIT @ 0x%lx\n", addr);
	return 1;
}

static void dbg_probe_page(unsigned long pg)
{
	unsigned char probe[4];
	if (dbg_safe_read(probe, (void *)pg, sizeof(probe)))
		pr_info("[dbg]   page 0x%lx DEAD\n", pg);
	else
		pr_info("[dbg]   page 0x%lx live\n", pg);
}

void dbg_scan(void)
{
	unsigned long start = sprint_addr & ~0xFFFULL;
	unsigned long pg, ti_hit = 0;
	int blocks = 0, total_cands = 0;

	pr_info("[dbg] sprint=0x%lx kernel_base=0x%lx start=0x%lx\n",
		sprint_addr, kernel_base, start);

	pr_info("[dbg] 8 pages below start:\n");
	for (pg = start - 8 * 0x1000; pg < start; pg += 0x1000)
		dbg_probe_page(pg);

	pr_info("[dbg] scanning up from 0x%lx...\n", start);
	for (pg = start; ; pg += 16 * 0x1000) {
		blocks++;

		if (dbg_safe_read(dbg_buf, (void *)pg, 16 * 0x1000)) {
			pr_info("[dbg] BLOCK %d pg=0x%lx FAILED\n", blocks, pg);
			pr_info("[dbg] probing 16 pages in failed block:\n");
			for (int i = 0; i < 16; i++)
				dbg_probe_page(pg + i * 0x1000);
			break;
		}

		for (int pi = 0; pi < 16; pi++) {
			unsigned int *buf = &dbg_buf[pi * 1024];
			unsigned long base = pg + pi * 0x1000;

			for (int off = 512; off < 0x1000 + 512; off += 4) {
				if (off >= 0x1000 && pi == 15)
					break;
				unsigned short *ti =
					(unsigned short *)((unsigned char *)buf +
						off - 512);
				if (dbg_check_ti(ti, base + off - 512)) {
					ti_hit = base + off - 512;
					goto done;
				}
				total_cands++;
			}
		}
	}

done:
	pr_info("[dbg] total: %d blocks %d candidates ti=0x%lx\n",
		blocks, total_cands, ti_hit);
}
