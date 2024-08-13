/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Based on scripts/genksyms/genksyms.c, which has the following
 * notice:
 *
 * Generate kernel symbol version hashes.
 * Copyright 1996, 1997 Linux International.
 *
 * New implementation contributed by Richard Henderson <rth@tamu.edu>
 * Based on original work by Bjorn Ekwall <bj0rn@blox.se>
 *
 * This file was part of the Linux modutils 2.4.22: moved back into the
 * kernel sources by Rusty Russell/Kai Germaschewski.
 */

#ifndef __CRC32_H
#define __CRC32_H

extern const unsigned int crctab32[];

static inline unsigned long partial_crc32_one(unsigned char c,
					      unsigned long crc)
{
	return crctab32[(crc ^ c) & 0xff] ^ (crc >> 8);
}

static inline unsigned long partial_crc32(const char *s, unsigned long crc)
{
	while (*s)
		crc = partial_crc32_one(*s++, crc);
	return crc;
}

#endif /* __CRC32_H */
