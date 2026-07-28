// SPDX-License-Identifier: GPL-2.0-only
#include <linux/types.h>
#include <linux/printk.h>
#include "core.h"
#include "slide.h"

#ifdef KSYMLESS_DEBUG
#define slide_dbg(fmt, ...) pr_info("[slide] " fmt, ##__VA_ARGS__)
#else
#define slide_dbg(fmt, ...) do {} while (0)
#endif

#define SLIDE_BUF_WORDS (18 * 1024)
unsigned int slide_buf[SLIDE_BUF_WORDS];

int slide_init(struct slide_win *w, unsigned long pos,
	       unsigned int chunksz, unsigned int margin)
{
	w->chunksz = chunksz;
	w->margin = margin;
	w->addr = pos;

	slide_dbg("init pos=0x%lx chunksz=%u margin=%u\n", pos, chunksz, margin);

	if (safe_read(slide_buf, (void *)w->addr, chunksz + margin)) {
		slide_dbg("init FAIL read @ 0x%lx\n", w->addr);
		return -1;
	}

	w->off = 0;
	slide_dbg("init ok addr=0x%lx off=%u\n", w->addr, w->off);
	return 0;
}

int slide_advance(struct slide_win *w, unsigned int n)
{
	w->off += n;

	if (w->off >= w->chunksz) {
		unsigned long cursor = w->addr + w->off;
		unsigned long new_addr = (cursor - w->margin) & ~0xFFFULL;

		slide_dbg("slide cursor=0x%lx old=0x%lx new=0x%lx\n",
			  cursor, w->addr, new_addr);

		w->addr = new_addr;

		if (safe_read(slide_buf, (void *)w->addr, w->chunksz + w->margin)) {
			slide_dbg("slide FAIL read @ 0x%lx\n", w->addr);
			return -1;
		}

		w->off = cursor - w->addr;
		slide_dbg("slide ok addr=0x%lx off=%u\n", w->addr, w->off);
	}

	return 0;
}
