/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 Google LLC
 */

#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <linux/hashtable.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef __GENDWARFKSYMS_H
#define __GENDWARFKSYMS_H

/*
 * Options -- in gendwarfksyms.c
 */
extern bool debug;
extern bool no_cache;
extern bool no_pretty_print;

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

/* Consistent aliases (DW_TAG_<type>_type) for DWARF tags */
#define DW_TAG_formal_parameter_type DW_TAG_formal_parameter
#define DW_TAG_typedef_type DW_TAG_typedef

/*
 * symbols.c
 */
enum symbol_state { UNPROCESSED, PROCESSING, PROCESSED_ADDR, PROCESSED_NAME };

/* Exported symbol -- matching either the name or the address */
struct symbol {
	const char *name;
	uintptr_t addr;
	struct hlist_node addr_hash;
	struct hlist_node name_hash;
	enum symbol_state state;
	unsigned long crc;
};

extern int symbol_set_crc(struct symbol *sym, unsigned long crc);
extern int symbol_read_list(FILE *file);
extern struct symbol *symbol_get_unprocessed(uintptr_t addr, const char *name);
extern void symbol_print_versions(void);

/*
 * cache.c
 */
enum cached_item_type { EMPTY, STRING, LINEBREAK, DIE };

struct cached_item {
	enum cached_item_type type;
	union {
		char *str;
		int linebreak;
		uintptr_t addr;
	} data;
	struct cached_item *next;
};

enum cached_die_state { INCOMPLETE, COMPLETE };

struct cached_die {
	enum cached_die_state state;
	uintptr_t addr;
	struct cached_item *list;
	struct hlist_node hash;
};

extern int cache_get(Dwarf_Die *die, enum cached_die_state state,
		     struct cached_die **res);
extern int cache_add_string(struct cached_die *pd, const char *str);
extern int cache_add_linebreak(struct cached_die *pd, int linebreak);
extern int cache_add_die(struct cached_die *pd, Dwarf_Die *die);
extern void cache_free(void);

/*
 * types.c
 */

struct state {
	Dwfl_Module *mod;
	Dwarf *dbg;
	struct symbol *sym;
	Dwarf_Die die;
	unsigned long crc;
};

typedef int (*die_callback_t)(struct state *state, struct cached_die *cache,
			      Dwarf_Die *die);
typedef bool (*die_match_callback_t)(Dwarf_Die *die);
extern bool match_all(Dwarf_Die *die);

extern int process_die_container(struct state *state, struct cached_die *cache,
				 Dwarf_Die *die, die_callback_t func,
				 die_match_callback_t match);

extern int process_module(Dwfl_Module *mod, Dwarf *dbg, Dwarf_Die *cudie);

#endif /* __GENDWARFKSYMS_H */
