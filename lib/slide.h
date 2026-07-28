// SPDX-License-Identifier: GPL-2.0-only
#ifndef SLIDE_H
#define SLIDE_H

#include <linux/types.h>

extern unsigned int slide_buf[];

struct slide_win {
	unsigned long addr;
	unsigned int  chunksz;
	unsigned int  margin;
	unsigned int  off;
};

int slide_init(struct slide_win *w, unsigned long pos,
	       unsigned int chunksz, unsigned int margin);
int slide_advance(struct slide_win *w, unsigned int n);

static inline void *slide_ptr(struct slide_win *w, const void *buf)
{
	return (unsigned char *)buf + w->off;
}

#endif
