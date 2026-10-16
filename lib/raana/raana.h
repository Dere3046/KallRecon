// SPDX-License-Identifier: GPL-2.0-only
/*
 * raana.h
 *
 * Copyright (C) 2026 dere3046
 */

#ifndef RAANA_H
#define RAANA_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/completion.h>

#include "../slide.h"

#define RAANA_MAX_WORKERS	8
#define RAANA_TOKEN_RANGE	(32UL * 1024 * 1024)
#define RAANA_MAX_TI		4
#define RAANA_CROSS_PAD		0x1000

/* keep in sync with discover.c */
#define RAANA_RUN_MIN		5000
#define RAANA_2M_MASK		0x1FFFFFULL
#define RAANA_PAGE_MASK		0xFFFULL
#define RAANA_SCAN_BACK		0x400000
#define RAANA_SCAN_FWD		0x200000
#define RAANA_FALLBACK_OFF	0x1000

struct raana_ctx {
	unsigned long start;
	unsigned long end;
	int next;
	int stop;
	spinlock_t lock;
	unsigned long ti_hits[RAANA_MAX_TI];
	int nti;
	unsigned long hit_cand;
	int hit_len;
	int hit_ok;
	int pri_idx;
	int pri_cnt;
	int nchunks;
	unsigned long rlo;
	unsigned long rhi;
	unsigned long sback;
	unsigned long sfwd;
	int range_active;
	int first_hit;
};

struct raana_worker {
	struct raana_ctx *ctx;
	int id;
	struct completion done;
};

struct kallrecon_hint;

/* verifiers owned by discover.c */
int kr_check_ti_strong(unsigned short *ti);
int kr_commit_offsets(unsigned long cand, int len,
		      unsigned long *best_cand, int *best_len);
int kr_commit_selfrel(unsigned long cand, int len,
		      unsigned long *best_cand, int *best_len);
unsigned long kr_find_token_table(unsigned long ti_addr, unsigned short ti255);
int kr_hint_commit_offsets(const struct kallrecon_hint *h,
			   unsigned long *best_cand, int *best_len);

/* executor battery */
int raana_run(struct raana_ctx *ctx);

int raana_token_worker(struct raana_worker *wk);
void raana_offsets_phase(struct raana_ctx *ctx, unsigned long ti,
			 unsigned long kltable);
int kr_raana_discover(void);

#endif
