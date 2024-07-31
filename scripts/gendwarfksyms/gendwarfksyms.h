/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 Google LLC
 */

#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef __GENDWARFKSYMS_H
#define __GENDWARFKSYMS_H

/*
 * Options -- in gendwarfksyms.c
 */
extern bool debug;

#define MAX_INPUT_FILES 128

/*
 * Output helpers
 */
#define __PREFIX "gendwarfksyms: "
#define __println(prefix, format, ...)                                \
	fprintf(stderr, prefix __PREFIX "%s: " format "\n", __func__, \
		##__VA_ARGS__)

#define debug(format, ...)                                    \
	do {                                                  \
		if (debug)                                    \
			__println("", format, ##__VA_ARGS__); \
	} while (0)

#define warn(format, ...) __println("warning: ", format, ##__VA_ARGS__)
#define error(format, ...) __println("error: ", format, ##__VA_ARGS__)

/*
 * Error handling helpers
 */
#define __check(expr, test, rv)                                 \
	({                                                      \
		int __res = expr;                               \
		if (test) {                                     \
			error("`%s` failed: %d", #expr, __res); \
			return rv;                              \
		}                                               \
		__res;                                          \
	})

/* Error == non-zero values */
#define check(expr) __check(expr, __res, -1)
/* Error == negative values */
#define checkp(expr) __check(expr, __res < 0, __res)

/*
 * symbols.c
 */

/* See symbols.c:is_symbol_ptr */
#define SYMBOL_PTR_PREFIX "__gendwarfksyms_ptr_"
#define SYMBOL_PTR_PREFIX_LEN (sizeof(SYMBOL_PTR_PREFIX) - 1)

struct symbol_addr {
	uint32_t section;
	Elf64_Addr address;
};

static inline u32 name_hash(const char *name)
{
	return jhash(name, strlen(name), 0);
}

struct symbol {
	const char *name;
	struct symbol_addr addr;
	struct hlist_node addr_hash;
	struct hlist_node name_hash;
};

extern bool is_symbol_ptr(const char *name);
extern int symbol_read_exports(FILE *file);
extern int symbol_read_symtab(int fd);
extern struct symbol *symbol_get(const char *name);

/*
 * dwarf.c
 */

struct state {
	Dwfl_Module *mod;
	Dwarf *dbg;
	struct symbol *sym;
	Dwarf_Die die;
};

typedef int (*die_callback_t)(struct state *state, Dwarf_Die *die);
typedef bool (*die_match_callback_t)(Dwarf_Die *die);
extern bool match_all(Dwarf_Die *die);

extern int process_die_container(struct state *state, Dwarf_Die *die,
				 die_callback_t func,
				 die_match_callback_t match);

extern int process_module(Dwfl_Module *mod, Dwarf *dbg, Dwarf_Die *cudie);

#endif /* __GENDWARFKSYMS_H */
