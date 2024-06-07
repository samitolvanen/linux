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
extern bool inline_debug;
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

#define __inline_debug(color, format, ...)                              \
	do {                                                            \
		if (debug && inline_debug)                              \
			fprintf(stderr,                                 \
				"\033[" #color "m<" format ">\033[39m", \
				__VA_ARGS__);                           \
	} while (0)

#define inline_debug_r(format, ...) __inline_debug(91, format, __VA_ARGS__)
#define inline_debug_g(format, ...) __inline_debug(92, format, __VA_ARGS__)
#define inline_debug_b(format, ...) __inline_debug(94, format, __VA_ARGS__)

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
#define DW_TAG_enumerator_type DW_TAG_enumerator
#define DW_TAG_formal_parameter_type DW_TAG_formal_parameter
#define DW_TAG_member_type DW_TAG_member
#define DW_TAG_template_type_parameter_type DW_TAG_template_type_parameter
#define DW_TAG_typedef_type DW_TAG_typedef
#define DW_TAG_variant_part_type DW_TAG_variant_part
#define DW_TAG_variant_type DW_TAG_variant

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
#define DIE_HASH_BITS 10

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

enum cached_die_state { INCOMPLETE, UNEXPANDED, COMPLETE };

static inline const char *cache_state_name(enum cached_die_state state)
{
	switch (state) {
	default:
	case INCOMPLETE:
		return "INCOMPLETE";
	case UNEXPANDED:
		return "UNEXPANDED";
	case COMPLETE:
		return "COMPLETE";
	}
}

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

struct state;

extern int cache_mark_expanded(struct state *state, Dwarf_Die *die);
extern bool cache_was_expanded(struct state *state, Dwarf_Die *die);
extern void cache_clear_expanded(struct state *state);

/*
 * types.c
 */
struct expansion_state {
	bool expand;
	bool in_pointer_type;
	unsigned int ptr_expansion_depth;
};

struct state {
	Dwfl_Module *mod;
	Dwarf *dbg;
	struct symbol *sym;
	Dwarf_Die die;
	unsigned long crc;

	/* Structure expansion */
	struct expansion_state expand;
	DECLARE_HASHTABLE(expansion_cache, DIE_HASH_BITS);
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
