// SPDX-License-Identifier: GPL-2.0-only
/*
 * core.c
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include "core.h"
#include "slide.h"

#ifdef KALLRECON_DEBUG
#define ks_dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
#define ks_dbg(fmt, ...) do {} while (0)
#endif

int safe_read(void *dst, const void *src, size_t sz)
{
	return copy_from_kernel_nofault(dst, src, sz);
}

unsigned long sprint_addr;
unsigned long kernel_base;
unsigned long klbase_addr;
unsigned long klbase_val;
unsigned long kloffs_addr;
unsigned long klindex_addr;
unsigned long klseqs_addr;
unsigned int  klnum_val;
unsigned long klmarks_addr;
unsigned long kltable_addr;
unsigned long klnames_addr;
unsigned long klnum_addr;

int is_v1_layout;
unsigned long (*kallrecon_klp)(const char *name);
#ifdef KALLRECON_MODULE_LOOKUP
unsigned long (*kallrecon_module_klp)(const char *name); /* experimental, may be unstable */
#endif

static unsigned int bigbuf[16 * 1024];

/* strip LTO suffix like kernel cleanup_symbol_name()
 * 5.10/5.15 (no seqs): '$', 6.1+ (seqs): ".llvm."
 */
static int ks_cleanup_name(char *s)
{
	char *res;

	if (klseqs_addr)
		res = strstr(s, ".llvm.");
	else
		res = strrchr(s, '$');
	if (!res)
		return 0;
	*res = '\0';
	return 1;
}

static int (*kallrecon_user_cleanup)(char *s);

static int ks_cleanup_name_chain(char *s)
{
	int r = ks_cleanup_name(s);
	if (kallrecon_user_cleanup)
		r |= kallrecon_user_cleanup(s) ? 1 : 0;
	return r;
}

void kallrecon_set_cleanup(int (*cb)(char *s))
{
	kallrecon_user_cleanup = cb;
}

static int check_token_index(unsigned short *ti)
{
	if (ti[0] != 0)
		return 0;
	for (int i = 1; i < 256; i++)
		if (ti[i] <= ti[i - 1])
			return 0;
	return 1;
}


static int check_ti_strong(unsigned short *ti)
{
	if (ti[0] != 0)
		return 0;
	for (int i = 1; i < 256; i++)
		if (ti[i] <= ti[i - 1])
			return 0;
	return ti['b'] - ti['a'] == 2 && ti['z'] - ti['a'] == 50;
}
static int verify_offsets_rb(unsigned long cand, int len,
			      unsigned long *rb_out, unsigned long *rb_addr_out)
{
	int skip = 0;
	for (skip = 0; skip < 20; skip++) {
		u32 zv;
		if (safe_read(&zv, (void *)(cand + skip * 4), 4))
			break;
		if (zv != 0)
			break;
	}

	unsigned long real_cand = cand + skip * 4;
	int real_len = len - skip;

	unsigned long base_rb = (cand + len * 4 + 7) & ~7ULL;
	for (int delta = 0; delta < 4096; delta += 8) {
		for (int sgn = 0; sgn < 2; sgn++) {
			unsigned long rb_addr;
			unsigned long rb;

			if (delta == 0 && sgn == 1)
				continue;
			rb_addr = sgn ? base_rb + delta : base_rb - delta;
			if (safe_read(&rb, (void *)rb_addr, 8))
				continue;
			if (rb_addr >= real_cand &&
			    rb_addr + 8 <= real_cand + real_len * 4)
				continue;
			{
				unsigned long check = (rb_addr + 8 + 7) & ~7ULL;
				int ok = 0;
				unsigned int ns;
				if (!safe_read(&ns, (void *)check, 4) &&
				    (ns == (unsigned int)len ||
				     ns == (unsigned int)(len - 1)))
					ok = 1;
				if (!ok) {
					ok = 1;
					for (int i = 0; i < 5 && ok; i++) {
						unsigned char b[3];
						unsigned int s;
						if (safe_read(b, (void *)(check + i * 3), 3))
							ok = 0;
						else {
							s = (b[0] << 16) | (b[1] << 8) | b[2];
							if (s >= (unsigned int)len)
								ok = 0;
						}
					}
				}
				if (!ok)
					continue;
			}

			int vok = 1;
			for (int i = 0; i < 3 && vok; i++) {
				u32 o;
				if (safe_read(&o, (void *)(real_cand + i * 4), 4))
					break;
				char name[KSYM_SYMBOL_LEN];
				sprint_symbol(name, rb + o);
				if (name[0] == '0' && name[1] == 'x') {
					sprint_symbol(name, (u64)o);
					if (name[0] == '0' && name[1] == 'x') {
						sprint_symbol(name,
							kernel_base + o);
						if (name[0] == '0' &&
						    name[1] == 'x')
							vok = 0;
					}
				}
			}
			if (!vok)
				continue;

			if (rb_out)
				*rb_out = rb;
			if (rb_addr_out)
				*rb_addr_out = rb_addr;
			return 1;
		}
	}

	return 0;
}

static int scan_zerou32(unsigned long start, unsigned long end,
			 unsigned long *best_cand, int *best_len)
{
	int found = 0;
	struct slide_win w;

	if (slide_init(&w, start, 64 * 1024, 512))
		return 0;

	for (;;) {
		u32 v;
		unsigned long addr = slide_addr(&w);
		if (addr >= end)
			break;

		v = *(u32 *)slide_ptr(&w, slide_buf);
		if (v != 0) {
			if (slide_advance(&w, 4))
				break;
			continue;
		}

		unsigned long cand = addr;
		int len = 0, prev = -1;

		for (;;) {
			unsigned long ext_addr = slide_addr(&w);
			if (ext_addr >= end || len >= 500000)
				break;
			v = *(u32 *)slide_ptr(&w, slide_buf);
			if ((int)v < prev)
				break;
			prev = (int)v;
			len++;
			if (slide_advance(&w, 4))
				break;
		}

		if (len >= 5000 && len > *best_len) {
			ks_dbg("[kallrecon] cand@0x%lx len=%d prev=0x%x\n",
				cand, len, prev);

			if (prev != 0 && (prev & 0x1FFFFF) == 0)
				len--;

			unsigned long rb, rb_addr;
			if (verify_offsets_rb(cand, len, &rb, &rb_addr)) {
				*best_cand = cand;
				*best_len = len;
				kloffs_addr = cand;
				klnum_val = len;
				klbase_addr = rb_addr;
				klbase_val = rb;
				found = 1;
				ks_dbg("[kallrecon] hit pg=0x%lx sorted=%d\n",
					(unsigned long)(cand & ~0xFFFULL), len);
			} else if (len > 5000 &&
				verify_offsets_rb(cand, len - 1,
						  &rb, &rb_addr)) {
				len--;
				*best_cand = cand;
				*best_len = len;
				kloffs_addr = cand;
				klnum_val = len;
				klbase_addr = rb_addr;
				klbase_val = rb;
				found = 1;
				ks_dbg("[kallrecon] hit pg=0x%lx sorted=%d (len-1)\n",
					(unsigned long)(cand & ~0xFFFULL),
					len);
			} else {
				ks_dbg("[kallrecon] cand REJECT\n");
			}
		}

		if (slide_init(&w, cand + 4, 64 * 1024, 512))
			break;
	}

	return found;
}

static int discover_kallsyms(unsigned long ti_addr)
{
	unsigned long best_cand = 0;
	int best_len = 0;
	unsigned short ti255;
	unsigned long scan_start, scan_end;

	if (safe_read(&ti255, (void *)(ti_addr + 255 * 2), 2))
		return 0;

	{
		unsigned long pos = ti_addr - 1;
		unsigned char c;
		while (pos > kernel_base) {
			if (safe_read(&c, (void *)pos, 1) || c != 0)
				break;
			pos--;
		}
		while (pos > kernel_base) {
			if (safe_read(&c, (void *)pos, 1))
				break;
			if (c == 0)
				break;
			pos--;
		}
		if (pos + 1 > ti255)
			kltable_addr = pos + 1 - ti255;
		else
			kltable_addr = ti_addr - 0x1000;
	}
	scan_start = kltable_addr > 0x400000 ?
		(kltable_addr - 0x400000) & ~0xFFFULL : kernel_base;
	scan_end = (ti_addr + 0x200000 + 0xFFF) & ~0xFFFULL;

	ks_dbg("[kallrecon] scan 0x%lx-0x%lx kltable=0x%lx\n",
		scan_start, scan_end, kltable_addr);

	if (scan_zerou32(scan_start, scan_end, &best_cand, &best_len))
		goto found;

	ks_dbg("[kallrecon] no offsets found\n");
	return 0;

found:
	klindex_addr = ti_addr;
	is_v1_layout = (kloffs_addr < ti_addr) ? 1 : 0;
	ks_dbg("[kallrecon] discovered: sorted=%u v%d\n",
		klnum_val, is_v1_layout ? 1 : 2);
	return 1;
}

static unsigned long find_token_index(unsigned long start)
{
	struct slide_win w;

	if (slide_init(&w, start, 64 * 1024, 512))
		return 0;

	for (;;) {
		unsigned short *ti = (unsigned short *)slide_ptr(&w, slide_buf);
		if (check_ti_strong(ti))
			return slide_addr(&w);
		if (slide_advance(&w, 4))
			break;
	}
	return 0;
}

static unsigned long detect_seqs(unsigned long cand, unsigned int n)
{
	if (!cand || !n)
		return 0;

	int points[] = {0, 1, 2, n/4, n/4+1, n/4+2, n/2, n/2+1, n/2+2,
			3*n/4, 3*n/4+1, 3*n/4+2, n-3, n-2, n-1};
	int np = sizeof(points) / sizeof(points[0]);

	for (int i = 0; i < np; i++) {
		int idx = points[i];
		if (idx < 0 || idx >= (int)n)
			return 0;
		unsigned char buf[3];
		unsigned int seq;
		if (safe_read(buf, (void *)(cand + idx * 3), 3))
			return 0;
		seq = (buf[0] << 16) | (buf[1] << 8) | buf[2];
		if (seq >= n)
			return 0;
	}
	return cand;
}

void find_kallsyms_base(void)
{
	sprint_addr = (unsigned long)&sprint_symbol;
	kernel_base = sprint_addr & ~0x1FFFFFULL;
	klbase_val = kernel_base;

ks_dbg("[kallrecon] sprint=0x%lx kernel_base=0x%lx\n",
		sprint_addr, kernel_base);

	unsigned long ti_addr = find_token_index(sprint_addr & ~0xFFFULL);
	if (!ti_addr) {
ks_dbg("[kallrecon] token_index not found\n");
		return;
	}
ks_dbg("[kallrecon] ti=0x%lx\n", ti_addr);
	klindex_addr = ti_addr;
	if (!discover_kallsyms(ti_addr)) {
ks_dbg("[kallrecon] layout: offsets not found\n");
		return;
	}

	if (is_v1_layout) {
		klnum_addr = (klbase_addr + 8 + 7) & ~7ULL;
		{
			u32 ns;
			if (safe_read(&ns, (void *)klnum_addr, 4) ||
			    (ns != klnum_val && ns != klnum_val - 1))
				klnum_addr = 0;
		}
		klnames_addr = (klnum_addr + 4 + 7) & ~7ULL;

		if (klindex_addr && klnum_val) {
			unsigned short ti255;
			if (!safe_read(&ti255, (void *)(klindex_addr + 255 * 2), 2)) {
				unsigned long pos = klindex_addr - 1;
				unsigned char c;
				while (pos > 0) {
					if (safe_read(&c, (void *)pos, 1) || c != 0)
						break;
					pos--;
				}
				while (pos > 0) {
					if (safe_read(&c, (void *)pos, 1))
						break;
					if (c == 0)
						break;
					pos--;
				}
					if (pos + 1 > ti255)
					kltable_addr = pos + 1 - ti255;
			}
		}

		unsigned int markers_cnt = (klnum_val + 255) / 256;
		unsigned long marks_size = markers_cnt * 4;

		unsigned long seqs_cand = kltable_addr ? (kltable_addr - klnum_val * 3) & ~7ULL : 0;
		klseqs_addr = detect_seqs(seqs_cand, klnum_val);
		if (klseqs_addr)
			klmarks_addr = (klseqs_addr - marks_size) & ~7ULL;
		else
			klmarks_addr = (kltable_addr - marks_size) & ~7ULL;
	} else {
		klseqs_addr = detect_seqs(klbase_addr + 8, klnum_val);

		if (klindex_addr && klnum_val) {
			unsigned short ti255;
			if (!safe_read(&ti255, (void *)(klindex_addr + 255 * 2), 2)) {
				unsigned long pos = klindex_addr - 1;
				unsigned char c;
				while (pos > 0) {
					if (safe_read(&c, (void *)pos, 1) || c != 0)
						break;
					pos--;
				}
				while (pos > 0) {
					if (safe_read(&c, (void *)pos, 1))
						break;
					if (c == 0)
						break;
					pos--;
				}
					if (pos + 1 > ti255)
					kltable_addr = pos + 1 - ti255;
			}
		}

		if (kltable_addr && klnum_val) {
			unsigned int markers_cnt = (klnum_val + 255) / 256;
			unsigned long marks_size = markers_cnt * 4;
			unsigned long marks_end = (kltable_addr + 7) & ~7ULL;
			klmarks_addr = marks_end - marks_size;
		}

		if (klmarks_addr && klnum_val) {
			unsigned long end_addr = klmarks_addr > 0x300000 ?
				klmarks_addr - 0x300000 : kernel_base;
			end_addr &= ~3ULL;
			for (unsigned long addr = klmarks_addr & ~3ULL;
			     addr >= end_addr; addr -= 4) {
				unsigned int v32;
				if (safe_read(&v32, (void *)addr, 4))
					continue;
				if (v32 == klnum_val || v32 == klnum_val - 1) {
					klnum_addr = addr;
					break;
				}
			}
		}

		if (klnum_addr)
			klnames_addr = (klnum_addr + 4 + 7) & ~7ULL;
	}

	/*
	 * sorted-run cand may sit on a leading zero u32 before
	 * kallsyms_offsets, shifting sym_addr() by one entry.
	 * recompute offsets start from kallsyms_num_syms.
	 */
	if (klbase_addr && klnum_addr) {
		u32 ns;
		if (!safe_read(&ns, (void *)klnum_addr, 4) && ns) {
			kloffs_addr =
				(klbase_addr - (unsigned long)ns * 4) & ~7ULL;
			klnum_val = ns;
		}
	}

ks_dbg("[kallrecon] kallsyms data:\n");
ks_dbg("  klbase  @ 0x%lx = 0x%lx\n", klbase_addr, klbase_val);
ks_dbg("  kloffs  @ 0x%lx\n", kloffs_addr);
ks_dbg("  klnum   @ 0x%lx = %u\n", klnum_addr, klnum_val);
ks_dbg("  klindex @ 0x%lx\n", klindex_addr);
ks_dbg("  klseqs  @ 0x%lx\n", klseqs_addr);
ks_dbg("  kltable @ 0x%lx\n", kltable_addr);
ks_dbg("  klmarks @ 0x%lx\n", klmarks_addr);
ks_dbg("  klnames @ 0x%lx\n", klnames_addr);
	ks_dbg("  layout  v%d\n", is_v1_layout ? 1 : 2);

#ifdef KALLRECON_CHECK
	if (kltable_addr && klindex_addr) {
		unsigned short off0;
		unsigned char c;
		if (!safe_read(&off0, (void *)(klindex_addr + '0' * 2), 2) &&
		    !safe_read(&c, (void *)(kltable_addr + off0), 1) &&
		    c == '0')
			ks_dbg("  tbl verify: '0' match\n");
		else
			ks_dbg("  tbl verify: MISMATCH\n");
	}
	if (klmarks_addr && klnum_val) {
		unsigned int m0, m1;
		int mok = !safe_read(&m0, (void *)klmarks_addr, 4) && m0 == 0;
		if (mok && (klnum_val + 255) / 256 > 1)
			mok = !safe_read(&m1, (void *)(klmarks_addr + 4), 4)
				&& m1 >= 256;
		ks_dbg("  markers verify: %s\n", mok ? "OK" : "MISMATCH");
	}
	if (klnames_addr && klmarks_addr && klnum_val) {
		unsigned int markers_cnt = (klnum_val + 255) / 256;
		unsigned int end_off;
		if (!safe_read(&end_off, (void *)(klmarks_addr +
			(markers_cnt - 1) * 4), 4)) {
			unsigned int count = 0;
			for (unsigned long p = klnames_addr;
			     p < klnames_addr + end_off + 1024; ) {
				unsigned char lb;
				unsigned int elen;
				if (safe_read(&lb, (void *)p, 1))
					break;
				if (lb & 0x80) {
					unsigned char lb2;
					if (safe_read(&lb2, (void *)(p + 1), 1))
						break;
					elen = (lb & 0x7F) | (lb2 << 7);
					p += 2;
				} else {
					if (lb == 0)
						break;
					elen = lb;
					p += 1;
				}
				p += elen;
				count++;
			}
			ks_dbg("  names count: dp=%u vs sort=%u %s\n",
				count, klnum_val,
				count == klnum_val ? "MATCH" : "MISMATCH");
		}
	}
#endif

	if (klbase_addr && kloffs_addr) {
		unsigned long addr = kallsyms_name_to_addr("kallsyms_lookup_name");
		if (addr)
			kallrecon_klp = (unsigned long (*)(const char *))addr;

#ifdef KALLRECON_MODULE_LOOKUP
		unsigned long maddr = kallsyms_name_to_addr("module_kallsyms_lookup_name");
		if (maddr)
			kallrecon_module_klp =
				(unsigned long (*)(const char *))maddr;
#endif
	}
}

unsigned long sym_addr(int idx)
{
	u32 off;
	if (safe_read(&off, (void *)(kloffs_addr + idx * 4), 4))
		return 0;
	return klbase_val + off;
}

int expand_sym(unsigned int off, char *buf, int max)
{
	unsigned char lb;
	unsigned int len;
	if (safe_read(&lb, (const void *)(klnames_addr + off), 1))
		return 0;
	len = lb;
	unsigned int off1 = off + 1;

	if (len & 0x80) {
		if (safe_read(&lb, (const void *)(klnames_addr + off1), 1))
			return 0;
		len = (len & 0x7F) | (lb << 7);
		off1++;
	}

	int skipped = 0;
	for (unsigned int i = 0; i < len && max > 1; i++) {
		unsigned char c;
		if (safe_read(&c, (const void *)(klnames_addr + off1 + i), 1))
			return 0;
		unsigned short ti;
		if (safe_read(&ti, (const void *)(klindex_addr + c * 2), 2))
			return 0;
		unsigned int ti_idx = ti;
		{
			unsigned long tp = kltable_addr + ti_idx;
			for (;;) {
				unsigned char ch;
				if (safe_read(&ch, (const void *)tp, 1))
					break;
				if (!ch)
					break;
				if (skipped) {
					if (max <= 1)
						break;
					*buf++ = ch;
					max--;
				} else {
					skipped = 1;
				}
				tp++;
			}
		}
	}
	if (max)
		*buf = '\0';
	return (int)(off1 + len - off);
}

unsigned int get_sym_seq(int idx)
{
	unsigned int i, seq = 0;

	if (klseqs_addr) {
		unsigned char buf[3];
		if (safe_read(buf, (const void *)(klseqs_addr + idx * 3), 3))
			return (unsigned int)idx;
		for (i = 0; i < 3; i++)
			seq = (seq << 8) | buf[i];
		return seq;
	}
	return (unsigned int)idx;
}

unsigned int get_sym_offset(unsigned int seq)
{
	const u8 *p = (const u8 *)klnames_addr;
	unsigned char lb;
	for (unsigned int i = 0; i < seq; i++) {
		if (safe_read(&lb, (void *)p, 1))
			return 0;
		int len = lb;
		if (len & 0x80) {
			if (safe_read(&lb, (void *)(p + 1), 1))
				return 0;
			len = ((len & 0x7F) | (lb << 7)) + 1;
		}
		p = p + len + 1;
	}
	return p - (const u8 *)klnames_addr;
}

static unsigned short ti_buf[256];
static unsigned char tt_buf[2048];

static int expand_sym_buf(unsigned short *ti, unsigned char *tt,
			  const unsigned char *enc, char *buf, int max)
{
	unsigned int len = *enc++;
	if (len & 0x80)
		len = (len & 0x7F) | (*enc++ << 7);
	if (len > 256U)
		return 0;

	int skipped = 0;
	for (unsigned int i = 0; i < len && max > 1; i++) {
		unsigned char c = *enc++;
		if (c >= 256U || ti[c] >= sizeof(tt_buf))
			return 0;
		const char *tp = (const char *)tt + ti[c];
		while (*tp) {
			if ((const unsigned char *)tp - tt >= sizeof(tt_buf))
				return 0;
			if (skipped) {
				if (max <= 1)
					return 0;
				*buf++ = *tp;
				max--;
			} else {
				skipped = 1;
			}
			tp++;
		}
	}
	if (max)
		*buf = '\0';
	return 1;
}

static unsigned long name_to_addr_linear(const char *name)
{
	unsigned short *ti = ti_buf;
	unsigned char *tt = tt_buf;
	char nbuf[256];
	int idx, hit = 0, decoded = 0;
	struct slide_win w;

	ks_dbg("[kallrecon] linear: search '%s' n=%u\n", name, klnum_val);

	if (safe_read(ti, (void *)klindex_addr, sizeof(ti_buf))) {
		ks_dbg("[kallrecon] linear: ti load FAIL\n");
		return 0;
	}
	if (safe_read(tt, (void *)kltable_addr, sizeof(tt_buf))) {
		ks_dbg("[kallrecon] linear: tt load FAIL\n");
		return 0;
	}

	if (slide_init(&w, klnames_addr, 64 * 1024, 512)) {
		ks_dbg("[kallrecon] linear: slide init FAIL\n");
		return 0;
	}

	for (idx = 0; idx < (int)klnum_val; idx++) {
		const unsigned char *name_start = slide_ptr(&w, slide_buf);
		int lb = *name_start;
		int elen = lb;
		int hdr = 1;
		if (lb & 0x80) {
			elen = (lb & 0x7F) | (name_start[1] << 7);
			hdr = 2;
		}
		if ((unsigned int)(hdr + elen) > 256U ||
		    w.off + hdr + elen > w.chunksz + w.margin) {
			ks_dbg("[kallrecon] linear: boundary fail idx=%d hdr=%d elen=%d\n",
				idx, hdr, elen);
			break;
		}

		decoded++;
		expand_sym_buf(ti, tt, name_start, nbuf, sizeof(nbuf));
		{
			int sample = 0;
			if (idx < 5)
				sample = 1;
			else if (idx == (int)klnum_val / 2)
				sample = 1;
			else if (idx >= (int)klnum_val - 5)
				sample = 1;
			else if (nbuf[0] == 'k' && nbuf[1] == 'a')
				sample = 1;
			if (sample)
				ks_dbg("[kallrecon] linear: [%d] '%s'\n", idx, nbuf);
		}
		if (strcmp(nbuf, name) == 0) {
			hit = 1;
			ks_dbg("[kallrecon] linear: HIT idx=%d\n", idx);
			return sym_addr(idx);
		}
		if (ks_cleanup_name_chain(nbuf) && strcmp(nbuf, name) == 0) {
			hit = 1;
			ks_dbg("[kallrecon] linear: HIT(cln) idx=%d\n", idx);
			return sym_addr(idx);
		}

		if (slide_advance(&w, hdr + elen)) {
			ks_dbg("[kallrecon] linear: slide fail idx=%d\n", idx);
			break;
		}
	}

	ks_dbg("[kallrecon] linear: done idx=%d decoded=%d hit=%d\n", idx, decoded, hit);
#ifdef KALLRECON_MODULE_LOOKUP
	if (kallrecon_module_klp)
		return kallrecon_module_klp(name);
#endif
	return 0;
}

unsigned long kallsyms_name_to_addr(const char *name)
{
	if (!klseqs_addr) {
#ifdef KALLRECON_MODULE_LOOKUP
		unsigned long addr = name_to_addr_linear(name);
		if (addr || !kallrecon_module_klp)
			return addr;
		return kallrecon_module_klp(name);
#else
		return name_to_addr_linear(name);
#endif
	}

	int low = 0, high = (int)klnum_val - 1;
	char nbuf[256];

	while (low <= high) {
		int mid = low + (high - low) / 2;
		unsigned int seq = get_sym_seq(mid);
		unsigned int off = get_sym_offset(seq);
		expand_sym(off, nbuf, sizeof(nbuf));
		ks_cleanup_name_chain(nbuf);

		int r = strcmp(name, nbuf);
		if (r > 0)
			low = mid + 1;
		else if (r < 0)
			high = mid - 1;
		else {
			/* walk left to first matching entry, same cleaned
			 * name resolves to smallest address */
			unsigned int first = mid;
			while (first > 0) {
				unsigned int pseq = get_sym_seq(first - 1);
				unsigned int poff = get_sym_offset(pseq);
				expand_sym(poff, nbuf, sizeof(nbuf));
				ks_cleanup_name_chain(nbuf);
				if (strcmp(name, nbuf))
					break;
				first--;
			}
			return sym_addr(get_sym_seq(first));
		}
	}
#ifdef KALLRECON_MODULE_LOOKUP
	if (kallrecon_module_klp)
		return kallrecon_module_klp(name);
#endif
	return 0;
}

int sym_name_at(unsigned long addr, char *buf, int max)
{
	int low = 0, high = (int)klnum_val;

	while (high - low > 1) {
		int mid = low + (high - low) / 2;
		if (sym_addr(mid) <= addr)
			low = mid;
		else
			high = mid;
	}

	unsigned int off = get_sym_offset(low);
	expand_sym(off, buf, max);
	ks_cleanup_name_chain(buf);
	return low;
}
