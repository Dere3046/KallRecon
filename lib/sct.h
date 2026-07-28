// SPDX-License-Identifier: GPL-2.0-only
/*
 * sct.h
 *
 * Copyright (C) 2026 dere3046
 */

#ifndef SCT_H
#define SCT_H

#include <linux/types.h>

#define MAX_FP 48
#define MAX_SCAN 128
#define MAX_ADRP 32

struct fp_ret {
	unsigned long addr;
};

struct adrp_entry {
	unsigned long target;
	unsigned long pc;
	unsigned long b_target;
	int rd;
	int has_b;
};

extern unsigned long sys_call_table_addr;
extern unsigned long b_target_found;

unsigned long read_fp(void);
int is_ktxt(unsigned long addr);
int read_val(unsigned long addr, unsigned long *val);
int walk_stack(struct fp_ret *out, int max);
void dump_frames(struct fp_ret *frames, int n);
int scan_adrp_add(unsigned long base, int ninst, struct adrp_entry *out, int max);
unsigned long find_sct(struct fp_ret *frames, int nf);
void dump_sct(void);

#endif
