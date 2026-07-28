// SPDX-License-Identifier: GPL-2.0-only
/*
 * sct.c
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <asm/compiler.h>
#ifndef ptrauth_strip_kernel_insn_pac
#define ptrauth_strip_kernel_insn_pac(x) (x)
#endif
#include "core.h"
#include "sct.h"

unsigned long sys_call_table_addr;
unsigned long b_target_found;

static unsigned int adrp_buf[MAX_SCAN];

unsigned long read_fp(void)
{
	unsigned long fp;
	asm volatile("mov %0, x29\n" : "=r"(fp));
	return fp;
}

int is_ktxt(unsigned long addr)
{
	unsigned long v;
	if (addr < 0xFFFF800000000000ULL)
		return 0;
	return read_val(addr, &v);
}

int read_val(unsigned long addr, unsigned long *val)
{
	return !safe_read(val, (void *)addr, sizeof(*val));
}

int walk_stack(struct fp_ret *out, int max)
{
	unsigned long fp = read_fp();
	unsigned long tmp;
	int n = 0;

	for (int i = 0; i < max; i++) {
		if (!fp)
			break;
		if (safe_read(&tmp, (void *)(fp + 8), sizeof(tmp)))
			break;
		out[n].addr = ptrauth_strip_kernel_insn_pac(tmp);
		n++;
		if (safe_read(&fp, (void *)fp, sizeof(fp)))
			break;
	}
	return n;
}

void dump_frames(struct fp_ret *frames, int n)
{
	pr_info("[sct] x29 stack (%d frames):\n", n);
	for (int i = 0; i < n; i++)
		pr_info("  [%2d] 0x%lx\n", i, frames[i].addr);
}

int scan_adrp_add(unsigned long base, int ninst,
		  struct adrp_entry *out, int max)
{
	int found = 0;

	if (ninst > MAX_SCAN)
		ninst = MAX_SCAN;
	if (safe_read(adrp_buf, (void *)base, ninst * 4))
		return 0;

	for (int i = 0; i < ninst - 2 && found < max; i++) {
		unsigned int adrp = adrp_buf[i];
		if ((adrp & 0x9F000000) != 0x90000000)
			continue;

		int rd = adrp & 0x1F;
		unsigned int nxt = adrp_buf[i + 1];
		unsigned long imm12;
		int valid = 0;

		if ((nxt & 0xFFC00000) == 0x91000000)
			valid = ((nxt >> 5) & 0x1F) == rd &&
				(nxt & 0x1F) == rd;
		if (!valid && (nxt & 0xFFC00000) == 0xF9400000)
			valid = ((nxt >> 5) & 0x1F) == rd &&
				(nxt & 0x1F) == rd;
		if (!valid)
			continue;

		imm12 = (nxt >> 10) & 0xFFF;
		unsigned long immhi = (adrp >> 5) & 0x7FFFF;
		unsigned long immlo = (adrp >> 29) & 3;
		unsigned long imm = (immhi << 2) | immlo;
		unsigned long pc = base + i * 4;

		out[found].pc = pc;
		out[found].target = (pc & ~0xFFF) + (imm << 12) + imm12;
		out[found].rd = rd;
		out[found].has_b = 0;
		out[found].b_target = 0;

		unsigned int bop = adrp_buf[i + 2];
		if ((bop & 0xFC000000) == 0x14000000) {
			long imm26 = bop & 0x3FFFFFF;
			if (imm26 & 0x2000000)
				imm26 |= ~0x3FFFFFF;
			out[found].has_b = 1;
			out[found].b_target = pc + 2 * 4 + imm26 * 4;
		} else if ((bop & 0xFC000000) == 0x94000000) {
			long imm26 = bop & 0x3FFFFFF;
			if (imm26 & 0x2000000)
				imm26 |= ~0x3FFFFFF;
			out[found].has_b = 2;
			out[found].b_target = pc + 2 * 4 + imm26 * 4;
		}

		found++;
	}
	return found;
}

static int check_sct(unsigned long addr)
{
	unsigned long v;
	for (int i = 0; i < 20; i++) {
		if (!read_val(addr + i * 8, &v))
			return 0;
		if (!is_ktxt(v))
			return 0;
	}
	return 1;
}

unsigned long find_sct(struct fp_ret *frames, int nf)
{
	struct adrp_entry adrps[MAX_ADRP];
	int na;
	unsigned long best = 0;

	pr_info("[sct] scanning frames for do_el0_svc:\n");

	for (int i = nf - 1; i >= 0; i--) {
		unsigned long addr = frames[i].addr;
		if (addr < 0xFFFF800000000000ULL)
			continue;
		unsigned long base = addr - 128;
		na = scan_adrp_add(base, MAX_SCAN, adrps, MAX_ADRP);
		if (!na)
			continue;

		for (int j = 0; j < na; j++) {
			if (!adrps[j].has_b)
				continue;
			unsigned long sct = adrps[j].target;
			if (!check_sct(sct))
				continue;
			pr_info("[sct] SCT candidate @ 0x%lx\n", sct);
			if (!best) {
				best = sct;
				sys_call_table_addr = sct;
				b_target_found = adrps[j].b_target;
			}
		}
	}

	if (!best)
		pr_info("[sct] SCT not found\n");
	return best;
}

void dump_sct(void)
{
	unsigned long v;
	pr_info("[sct] sys_call_table entries:\n");
	for (int i = 0; i < 8; i++)
		if (read_val(sys_call_table_addr + i * 8, &v))
			pr_info("  [%3d] 0x%lx\n", i, v);
}
