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
extern bool inline_debug;
extern bool no_pretty_print;
extern bool stable;
extern bool symtypes;

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

static inline u32 name_hash(const char *name)
{
	return jhash(name, strlen(name), 0);
}

/*
 * symbols.c
 */
#define SYMBOL_PTR_PREFIX "__gendwarfksyms_ptr_"
#define SYMBOL_PTR_PREFIX_LEN (sizeof(SYMBOL_PTR_PREFIX) - 1)

#define SYMBOL_DECLONLY_PREFIX "__gendwarfksyms_declonly_"
#define SYMBOL_DECLONLY_PREFIX_LEN (sizeof(SYMBOL_DECLONLY_PREFIX) - 1)

enum symbol_state {
	UNPROCESSED,
	PROCESSED,
};

struct symbol_addr {
	uint32_t section;
	Elf64_Addr address;
};

static inline u32 symbol_addr_hash(const struct symbol_addr *addr)
{
	return jhash(addr, sizeof(struct symbol_addr), 0);
}

/* Exported symbol */
struct symbol {
	const char *name;
	struct symbol_addr addr;
	struct hlist_node addr_hash;
	struct hlist_node name_hash;
	enum symbol_state state;
	uintptr_t die_addr;
	unsigned long crc;
};

extern bool is_symbol_ptr(const char *name);
extern int symbol_set_crc(struct symbol *sym, unsigned long crc);
extern int symbol_set_die(struct symbol *sym, Dwarf_Die *die);
extern int symbol_read_exports(FILE *file);
extern struct symbol *symbol_get_unprocessed(const char *name);

typedef int (*symbol_callback_t)(struct symbol *, void *arg);
extern int symbol_for_each_processed(symbol_callback_t func, void *arg);

extern int symbol_read_symtab(int fd);
extern bool is_struct_declonly(const char *name);
extern void symbol_free_declonly(void);
extern void symbol_print_versions(void);

/*
 * symtypes.c
 */

extern int symtypes_dump(FILE *file);

/*
 * cache.c
 */
#define DIE_HASH_BITS 18

enum cached_die_state { INCOMPLETE, UNEXPANDED, COMPLETE, SYMBOL };
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
	case SYMBOL:
		return "SYMBOL";
	}
}

struct cached_die {
	enum cached_die_state state;
	const char *name;
	int tag;
	uintptr_t addr;
	struct cached_item *list;
	struct hlist_node hash;
};

extern int __cache_get(uintptr_t addr, enum cached_die_state state,
		       struct cached_die **res);
extern int cache_get(Dwarf_Die *die, enum cached_die_state state,
		     struct cached_die **res);
extern int cache_add_string(struct cached_die *pd, const char *str);
extern int cache_add_linebreak(struct cached_die *pd, int linebreak);
extern int cache_add_die(struct cached_die *pd, struct cached_die *child);
extern void cache_free(void);

struct expansion_cache {
	DECLARE_HASHTABLE(cache, DIE_HASH_BITS);
};

extern int __cache_mark_expanded(struct expansion_cache *ec, uintptr_t addr);
extern bool __cache_was_expanded(struct expansion_cache *ec, uintptr_t addr);
extern void cache_clear_expanded(struct expansion_cache *ec);

static inline int cache_mark_expanded(struct expansion_cache *ec,
				      Dwarf_Die *die)
{
	return __cache_mark_expanded(ec, (uintptr_t)die->addr);
}

static inline bool cache_was_expanded(struct expansion_cache *ec,
				      Dwarf_Die *die)
{
	return __cache_was_expanded(ec, (uintptr_t)die->addr);
}

/*
 * types.c
 */
#define RESERVED_PREFIX "__kabi_reserved"
#define RESERVED_PREFIX_LEN (sizeof(RESERVED_PREFIX) - 1)

struct expansion_state {
	bool expand;
	bool in_pointer_type;
	unsigned int ptr_expansion_depth;
};

enum reserved_status {
	/* >0 to stop DIE processing */
	NOT_RESERVED = 1,
	RESERVED
};

struct reserved_state {
	int members;
};

struct state {
	Dwfl_Module *mod;
	Dwarf *dbg;
	struct symbol *sym;
	Dwarf_Die die;
	unsigned long crc;

	/* Structure expansion */
	struct expansion_state expand;
	struct expansion_cache expansion_cache;

	/* Reserved members */
	struct reserved_state reserved;
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
