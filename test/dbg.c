// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include "../lib/core.h"

void sprint_symbol(char *buf, unsigned long addr);

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
	pr_info("[dbg] ti HIT @ 0x%lx ti255=%u\n", addr, ti[255]);
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

static unsigned long dbg_detect_seqs(unsigned long cand, unsigned int n)
{
	if (!cand || !n)
		return 0;
	int points[] = {0, 1, 2, (int)n/4, (int)n/4+1, (int)n/4+2, (int)n/2, (int)n/2+1, (int)n/2+2,
			3*(int)n/4, 3*(int)n/4+1, 3*(int)n/4+2, (int)n-3, (int)n-2, (int)n-1};
	int np = sizeof(points) / sizeof(points[0]);
	for (int i = 0; i < np; i++) {
		int idx = points[i];
		if (idx < 0 || idx >= (int)n)
			return 0;
		unsigned char buf[3];
		unsigned int seq;
		if (dbg_safe_read(buf, (void *)(cand + idx * 3), 3))
			return 0;
		seq = (buf[0] << 16) | (buf[1] << 8) | buf[2];
		if (seq >= n)
			return 0;
	}
	return cand;
}

/* --- step 2: discover kallsyms layout --- */

static void dbg_discover(unsigned long ti_addr)
{
	unsigned short ti255;
	unsigned long scan_start, scan_end;

	pr_info("[dbg] === discover_kallsyms ===\n");

	if (dbg_safe_read(&ti255, (void *)(ti_addr + 255 * 2), 2)) {
		pr_info("[dbg] FAIL read ti[255]\n");
		return;
	}
	pr_info("[dbg] ti[255]=%u\n", ti255);

	/* backward walk to find token_table end */
	{
		unsigned long pos = ti_addr - 1;
		unsigned char c;
		int nz = 0;
		while (pos > kernel_base) {
			if (dbg_safe_read(&c, (void *)pos, 1) || c != 0)
				break;
			nz++;
			pos--;
		}
		pr_info("[dbg] null run behind ti: %d bytes (to 0x%lx)\n", nz, pos + 1);
		while (pos > kernel_base) {
			if (dbg_safe_read(&c, (void *)pos, 1))
				break;
			if (c == 0)
				break;
			pos--;
		}
		unsigned long tk_end = pos + 1;
		pr_info("[dbg] token_table end candidate: 0x%lx (bytes into tt: %lu)\n",
			tk_end, ti_addr - tk_end);
		if (pos + 1 > ti255)
			kltable_addr = pos + 1 - ti255;
		else
			kltable_addr = ti_addr - 0x1000;
		pr_info("[dbg] kltable_addr computed: 0x%lx (delta from ti: %ld)\n",
			kltable_addr, (long)(ti_addr - kltable_addr));
	}

	scan_start = kltable_addr > 0x400000 ?
		(kltable_addr - 0x400000) & ~0xFFFULL : kernel_base;
	scan_end = (ti_addr + 0x200000 + 0xFFF) & ~0xFFFULL;
	pr_info("[dbg] scan range: 0x%lx - 0x%lx (%luKB)\n",
		scan_start, scan_end, (scan_end - scan_start) / 1024);

	/* scan for sorted zero-u32 runs */
	{
		unsigned long best_cand = 0;
		int best_len = 0;

		for (unsigned long pg = scan_start; pg < scan_end; pg += 16 * 0x1000) {
			if (dbg_safe_read(dbg_buf, (void *)pg, 16 * 0x1000))
				continue;

			for (int pi = 0; pi < 16; pi++) {
				unsigned int *buf = &dbg_buf[pi * 1024];
				unsigned long base = pg + pi * 0x1000;

				for (int off = 0; off < 0x1000; off += 4) {
					if (buf[off / 4] != 0)
						continue;

					unsigned long cand = base + off;
					int len = 0, prev = -1;
					int max_i = (4096 - off) / 4;
					for (int i = 0; i < max_i; i++) {
						unsigned int v = buf[(off + i * 4) / 4];
						if ((int)v < prev) {
							len = i;
							goto count_done2;
						}
						prev = (int)v;
					}
					len = max_i;

					for (int chunk = pi + 1; chunk < 16 && len < 500000; chunk++) {
						unsigned int *pbuf = &dbg_buf[chunk * 1024];
						for (int i = 0; i < 1024 && len < 500000; i++) {
							unsigned int v = pbuf[i];
							if ((int)v < prev)
								goto count_done2;
							prev = (int)v;
							len++;
						}
					}

					for (unsigned long pg2 = base + (16 - pi) * 0x1000;
					     len < 500000; pg2 += 16 * 0x1000) {
						if (dbg_safe_read(dbg_buf, (void *)pg2, 16 * 0x1000))
							break;
						for (int chunk = 0; chunk < 16 && len < 500000; chunk++) {
							unsigned int *pbuf = &dbg_buf[chunk * 1024];
							for (int i = 0; i < 1024 && len < 500000; i++) {
								unsigned int v = pbuf[i];
								if ((int)v < prev)
									goto count_done2;
								prev = (int)v;
								len++;
							}
						}
					}
				count_done2:
					if (len < 5000 || len <= best_len)
						continue;

					unsigned long kbase_hi = kernel_base & 0xFFFFFFFF00000000ULL;
					if ((prev | kbase_hi) == kernel_base)
						len--;

					pr_info("[dbg] sorted run @ 0x%lx len=%d last_u32=0x%x\n",
						cand, len, prev);

					/* verify rb */
					unsigned long base_rb = (cand + len * 4 + 7) & ~7ULL;

					int dbskip = 0;
					for (dbskip = 0; dbskip < 20; dbskip++) {
						u32 zv;
						if (dbg_safe_read(&zv, (void *)(cand + dbskip * 4), 4))
							break;
						if (zv != 0)
							break;
					}
					unsigned long real_cand = cand + dbskip * 4;
					int real_len = len - dbskip;

					unsigned long rb, rb_addr;
					int rb_ok = 0;
					for (int delta = 0; delta < 4096 && !rb_ok; delta += 8) {
						for (int sgn = 0; sgn < 2 && !rb_ok; sgn++) {
							if (delta == 0 && sgn == 1)
								continue;
							rb_addr = sgn ? base_rb + delta : base_rb - delta;

							int rd = dbg_safe_read(&rb, (void *)rb_addr, 8);
							if (rd) {
								pr_info("[dbg]   rb@0x%lx d=%d s=%d safe_read FAIL\n",
									rb_addr, delta, sgn);
								continue;
							}

							if (rb_addr >= real_cand &&
							    rb_addr + 8 <= real_cand + real_len * 4) {
								pr_info("[dbg]   rb@0x%lx=0x%lx d=%d RANGE skip\n",
									rb_addr, rb, delta);
								continue;
							}

							unsigned long check = (rb_addr + 8 + 7) & ~7ULL;
							int ns_ok = 0;
							unsigned int ns = 0;
							if (!dbg_safe_read(&ns, (void *)check, 4)) {
								if (ns == (unsigned int)len || ns == (unsigned int)(len - 1))
									ns_ok = 1;
							}
							if (!ns_ok) {
								ns_ok = 1;
								for (int i = 0; i < 5 && ns_ok; i++) {
									unsigned char b[3];
									unsigned int s;
									if (dbg_safe_read(b, (void *)(check + i * 3), 3))
										ns_ok = 0;
									else {
										s = (b[0] << 16) | (b[1] << 8) | b[2];
										if (s >= (unsigned int)len)
											ns_ok = 0;
									}
								}
							}
							if (!ns_ok) {
								pr_info("[dbg]   rb@0x%lx=0x%lx d=%d ns@0x%lx=%u len=%d ns/seqs FAIL\n",
									rb_addr, rb, delta, check, ns, len);
								continue;
							}

							int vok = 1;
							for (int i = 0; i < 3 && vok; i++) {
								u32 o;
								if (dbg_safe_read(&o, (void *)(real_cand + i * 4), 4))
									break;
								char name[64];
								name[0] = 0;
								sprint_symbol(name, rb + o);
								if (name[0] == '0' && name[1] == 'x') {
									sprint_symbol(name, (u64)o);
									if (name[0] == '0' && name[1] == 'x')
										vok = 0;
								}
								pr_info("[dbg]   rb@0x%lx=0x%lx d=%d samp[%d] o=0x%x '%s' %s\n",
									rb_addr, rb, delta, i, o, name,
									vok ? "ok" : "REJECT");
							}
							if (!vok) {
								pr_info("[dbg]   rb@0x%lx=0x%lx d=%d sprint FAIL\n",
									rb_addr, rb, delta);
								continue;
							}

							pr_info("[dbg]   rb@0x%lx=0x%lx d=%d VERIFIED\n",
								rb_addr, rb, delta);
							rb_ok = 1;
						}
					}

					if (!rb_ok) {
						pr_info("[dbg]   sorted %d @ 0x%lx: RB NOT FOUND\n",
							len, cand);
						continue;
					}

					if (len > best_len) {
						best_cand = cand;
						best_len = len;
						kloffs_addr = cand;
						klnum_val = len;
						klbase_addr = rb_addr;
						klbase_val = rb;
						pr_info("[dbg]   BEST so far: sorted=%u klbase=0x%lx\n",
							len, rb);
					}
				}
			}
		}

		pr_info("[dbg] final: sorted=%u kloffs=0x%lx klbase=0x%lx=0x%lx\n",
			best_len, best_cand, klbase_addr, klbase_val);

		if (!best_len) {
			pr_info("[dbg] discover FAIL: no valid sorted run found\n");
			return;
		}

		klindex_addr = ti_addr;
		is_v1_layout = (kloffs_addr < ti_addr) ? 1 : 0;
		pr_info("[dbg] layout v%d (kloffs %s ti)\n",
			is_v1_layout ? 1 : 2,
			is_v1_layout ? "<" : ">");
	}

	/* --- step 3: post-processing --- */
	pr_info("[dbg] === post-processing ===\n");

	if (is_v1_layout) {
		klnum_addr = (klbase_addr + 8 + 7) & ~7ULL;
		{
			u32 ns;
			if (dbg_safe_read(&ns, (void *)klnum_addr, 4) || ns != klnum_val) {
				pr_info("[dbg] v1 klnum@0x%lx MISMATCH (got %u vs %u)\n",
					klnum_addr, ns, klnum_val);
				klnum_addr = 0;
			} else {
				pr_info("[dbg] v1 klnum@0x%lx=%u MATCH\n", klnum_addr, ns);
			}
		}
		klnames_addr = (klnum_addr + 4 + 7) & ~7ULL;
		pr_info("[dbg] v1 klnames@0x%lx\n", klnames_addr);

		/* kltable_addr refinement */
		if (klindex_addr && klnum_val) {
			unsigned short ti255b;
			if (!dbg_safe_read(&ti255b, (void *)(klindex_addr + 255 * 2), 2)) {
				unsigned long pos = klindex_addr - 1;
				unsigned char c;
				while (pos > 0) {
					if (dbg_safe_read(&c, (void *)pos, 1) || c != 0)
						break;
					pos--;
				}
				while (pos > 0) {
					if (dbg_safe_read(&c, (void *)pos, 1))
						break;
					if (c == 0)
						break;
					pos--;
				}
				if (pos + 1 > ti255b)
					kltable_addr = pos + 1 - ti255b;
			}
		}
		pr_info("[dbg] v1 kltable refined: 0x%lx\n", kltable_addr);

		unsigned int markers_cnt = (klnum_val + 255) / 256;
		unsigned long marks_size = markers_cnt * 4;
		unsigned long seqs_cand = kltable_addr ? (kltable_addr - klnum_val * 3) & ~7ULL : 0;
		klseqs_addr = dbg_detect_seqs(seqs_cand, klnum_val);
		if (klseqs_addr) {
			klmarks_addr = (klseqs_addr - marks_size) & ~7ULL;
			pr_info("[dbg] v1 seqs@0x%lx marks@0x%lx\n", klseqs_addr, klmarks_addr);
		} else {
			klmarks_addr = (kltable_addr - marks_size) & ~7ULL;
			pr_info("[dbg] v1 seqs NOT FOUND, marks fallback@0x%lx\n", klmarks_addr);
		}
	} else {
		klseqs_addr = dbg_detect_seqs(klbase_addr + 8, klnum_val);
		pr_info("[dbg] v2 seqs@0x%lx (cand=0x%lx)\n", klseqs_addr, klbase_addr + 8);

		if (klindex_addr && klnum_val) {
			unsigned short ti255b;
			if (!dbg_safe_read(&ti255b, (void *)(klindex_addr + 255 * 2), 2)) {
				unsigned long pos = klindex_addr - 1;
				unsigned char c;
				while (pos > 0) {
					if (dbg_safe_read(&c, (void *)pos, 1) || c != 0)
						break;
					pos--;
				}
				while (pos > 0) {
					if (dbg_safe_read(&c, (void *)pos, 1))
						break;
					if (c == 0)
						break;
					pos--;
				}
				if (pos + 1 > ti255b)
					kltable_addr = pos + 1 - ti255b;
			}
		}
		pr_info("[dbg] v2 kltable refined: 0x%lx\n", kltable_addr);

		if (kltable_addr && klnum_val) {
			unsigned int markers_cnt = (klnum_val + 255) / 256;
			unsigned long marks_size = markers_cnt * 4;
			unsigned long marks_end = (kltable_addr + 7) & ~7ULL;
			klmarks_addr = marks_end - marks_size;
			pr_info("[dbg] v2 marks@0x%lx (cnt=%u size=%lu end=0x%lx)\n",
				klmarks_addr, markers_cnt, marks_size, marks_end);
		}

		if (klmarks_addr && klnum_val) {
			unsigned long end_addr = klmarks_addr > 0x300000 ?
				klmarks_addr - 0x300000 : kernel_base;
			end_addr &= ~3ULL;
			int found_ns = 0;
			for (unsigned long addr = klmarks_addr & ~3ULL;
			     addr >= end_addr; addr -= 4) {
				unsigned int v32;
				if (dbg_safe_read(&v32, (void *)addr, 4))
					continue;
				if (v32 == klnum_val) {
					klnum_addr = addr;
					pr_info("[dbg] v2 klnum@0x%lx=%u MATCH\n", addr, v32);
					found_ns = 1;
					break;
				}
			}
			if (!found_ns)
			pr_info("[dbg] v2 klnum NOT FOUND (scanned %lu-%lu)\n",
				(unsigned long)(klmarks_addr & ~3ULL),
				(unsigned long)end_addr);
		}

		if (klnum_addr) {
			klnames_addr = (klnum_addr + 4 + 7) & ~7ULL;
			pr_info("[dbg] v2 klnames@0x%lx\n", klnames_addr);
		}
	}

	/* --- step 4: markers verify --- */
	pr_info("[dbg] === markers verify ===\n");
	if (klmarks_addr && klnum_val) {
		unsigned int m0, m1;
		int mok = !dbg_safe_read(&m0, (void *)klmarks_addr, 4) && m0 == 0;
		m1 = 0;
		if (mok && (klnum_val + 255) / 256 > 1)
			mok = !dbg_safe_read(&m1, (void *)(klmarks_addr + 4), 4)
				&& m1 >= 256;
		pr_info("[dbg] markers: m0=%u m1=%u -> %s\n",
			m0, m1, mok ? "OK" : "MISMATCH");
	}

	/* --- step 5: table verify --- */
	if (kltable_addr && klindex_addr) {
		unsigned short off0;
		unsigned char c;
		if (!dbg_safe_read(&off0, (void *)(klindex_addr + '0' * 2), 2) &&
		    !dbg_safe_read(&c, (void *)(kltable_addr + off0), 1) &&
		    c == '0')
			pr_info("[dbg] tbl '0' verify: MATCH (off=%u c=%c)\n", off0, c);
		else
			pr_info("[dbg] tbl '0' verify: MISMATCH\n");
	}

	/* --- step 6: bootstrap --- */
	pr_info("[dbg] === bootstrap ===\n");
	if (klbase_addr && kloffs_addr) {
		unsigned long addr = kallsyms_name_to_addr("kallsyms_lookup_name");
		pr_info("[dbg] kallsyms_lookup_name @ 0x%lx\n", addr);
		if (addr) {
			ksymless_klp = (unsigned long (*)(const char *))addr;

			unsigned long klp_addr = ksymless_klp("_printk");
			pr_info("[dbg] _printk @ 0x%lx\n", klp_addr);

			unsigned long sct_addr = ksymless_klp("sprint_symbol");
			pr_info("[dbg] sprint_symbol @ 0x%lx (self=0x%lx delta=%ld)\n",
				sct_addr, sprint_addr, (long)(sct_addr - sprint_addr));
		}
	}

	pr_info("[dbg] === summary ===\n");
	pr_info("[dbg] klbase  @ 0x%lx = 0x%lx\n", klbase_addr, klbase_val);
	pr_info("[dbg] kloffs  @ 0x%lx  sorted=%u\n", kloffs_addr, klnum_val);
	pr_info("[dbg] klnum   @ 0x%lx\n", klnum_addr);
	pr_info("[dbg] klindex @ 0x%lx\n", klindex_addr);
	pr_info("[dbg] klseqs  @ 0x%lx\n", klseqs_addr);
	pr_info("[dbg] kltable @ 0x%lx\n", kltable_addr);
	pr_info("[dbg] klmarks @ 0x%lx\n", klmarks_addr);
	pr_info("[dbg] klnames @ 0x%lx\n", klnames_addr);
	pr_info("[dbg] layout  v%d\n", is_v1_layout ? 1 : 2);
	pr_info("[dbg] klp     %ps\n", ksymless_klp);
}

/* --- step 1: find token_index --- */

void dbg_scan(void)
{
	unsigned long start = sprint_addr & ~0xFFFULL;
	unsigned long pg, ti_hit = 0;
	int blocks = 0, total_cands = 0;

	pr_info("[dbg] === find_token_index ===\n");
	pr_info("[dbg] sprint=0x%lx kernel_base=0x%lx start=0x%lx\n",
		sprint_addr, kernel_base, start);

	pr_info("[dbg] 8 pages below start:\n");
	for (pg = start - 8 * 0x1000; pg < start; pg += 0x1000)
		dbg_probe_page(pg);

	pr_info("[dbg] scanning up from 0x%lx...\n", start);
	for (pg = start; ; pg += 16 * 0x1000) {
		blocks++;

		if (dbg_safe_read(dbg_buf, (void *)pg, 16 * 0x1000)) {
			pr_info("[dbg] BLOCK %d pg=0x%lx FAILED, probing pages:\n", blocks, pg);
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
					goto found_ti;
				}
				total_cands++;
			}
		}
	}

found_ti:
	pr_info("[dbg] total: %d blocks %d candidates ti=0x%lx\n",
		blocks, total_cands, ti_hit);

	if (ti_hit)
		dbg_discover(ti_hit);
}
