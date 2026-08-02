// SPDX-License-Identifier: GPL-2.0-only
/*
 * core.h
 *
 * Copyright (C) 2026 dere3046
 */

#ifndef CORE_H
#define CORE_H

#include <linux/types.h>

int safe_read(void *dst, const void *src, size_t sz);

extern unsigned long sprint_addr;
extern unsigned long kernel_base;
extern unsigned long klbase_addr;
extern unsigned long klbase_val;
extern unsigned long kloffs_addr;
extern unsigned long klindex_addr;
extern unsigned long klseqs_addr;
extern unsigned int  klnum_val;
extern unsigned long klmarks_addr;
extern unsigned long kltable_addr;
extern unsigned long klnames_addr;
extern unsigned long klnum_addr;

extern int is_v1_layout;

extern unsigned long (*kallrecon_klp)(const char *name);
#ifdef KALLRECON_MODULE_LOOKUP
extern unsigned long (*kallrecon_module_klp)(const char *name); /* experimental, may be unstable */
#endif

void find_kallsyms_base(void);
void kallrecon_set_cleanup(int (*cb)(char *s)); /* NULL detaches user cleanup hook */
unsigned long sym_addr(int idx);
int expand_sym(unsigned int off, char *buf, int max);
unsigned int get_sym_seq(int idx);
unsigned int get_sym_offset(unsigned int seq);
unsigned long kallsyms_name_to_addr(const char *name);
int sym_name_at(unsigned long addr, char *buf, int max);

#endif
