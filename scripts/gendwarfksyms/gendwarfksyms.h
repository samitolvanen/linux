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
extern bool dump_dies;
extern bool dump_die_map;
extern bool dump_types;
extern bool dump_versions;
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

#define __die_debug(color, format, ...)                                 \
	do {                                                            \
		if (dump_dies && dump_die_map)                          \
			fprintf(stderr,                                 \
				"\033[" #color "m<" format ">\033[39m", \
				__VA_ARGS__);                           \
	} while (0)

#define die_debug_r(format, ...) __die_debug(91, format, __VA_ARGS__)
#define die_debug_g(format, ...) __die_debug(92, format, __VA_ARGS__)
#define die_debug_b(format, ...) __die_debug(94, format, __VA_ARGS__)

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

/* See symbols.c:is_symbol_ptr */
#define SYMBOL_PTR_PREFIX "__gendwarfksyms_ptr_"
#define SYMBOL_PTR_PREFIX_LEN (sizeof(SYMBOL_PTR_PREFIX) - 1)

/* See dwarf.c:is_declaration */
#define SYMBOL_DECLONLY_PREFIX "__gendwarfksyms_declonly_"
#define SYMBOL_DECLONLY_PREFIX_LEN (sizeof(SYMBOL_DECLONLY_PREFIX) - 1)

enum symbol_state { UNPROCESSED, MAPPED, PROCESSED };

struct symbol_addr {
	uint32_t section;
	Elf64_Addr address;
};

static inline u32 name_hash(const char *name)
{
	return jhash(name, strlen(name), 0);
}

static inline u32 addr_hash(uintptr_t addr)
{
	return jhash(&addr, sizeof(addr), 0);
}

struct symbol {
	const char *name;
	struct symbol_addr addr;
	struct hlist_node addr_hash;
	struct hlist_node name_hash;
	enum symbol_state state;
	uintptr_t die_addr;
	unsigned long crc;
};

typedef int (*symbol_callback_t)(struct symbol *, void *arg);

extern bool is_symbol_ptr(const char *name);
extern int symbol_read_exports(FILE *file);
extern int symbol_read_symtab(int fd);
extern struct symbol *symbol_get_unprocessed(const char *name);
extern int symbol_set_die(struct symbol *sym, Dwarf_Die *die);
extern int symbol_set_crc(struct symbol *sym, unsigned long crc);
extern int symbol_for_each(symbol_callback_t func, void *arg);
extern void symbol_print_versions(void);

extern bool is_struct_declonly(const char *name);
extern void symbol_free_declonly(void);

/*
 * die.c
 */

enum die_state { INCOMPLETE, UNEXPANDED, COMPLETE, SYMBOL, LAST = SYMBOL };
enum die_fragment_type { EMPTY, STRING, LINEBREAK, DIE };

struct die_fragment {
	enum die_fragment_type type;
	union {
		char *str;
		int linebreak;
		uintptr_t addr;
	} data;
	struct die_fragment *next;
};

#define CASE_CONST_TO_STR(name) \
	case name:              \
		return #name;

static inline const char *die_state_name(enum die_state state)
{
	switch (state) {
	default:
	CASE_CONST_TO_STR(INCOMPLETE)
	CASE_CONST_TO_STR(UNEXPANDED)
	CASE_CONST_TO_STR(COMPLETE)
	CASE_CONST_TO_STR(SYMBOL)
	}
}

struct die {
	enum die_state state;
	bool mapped;
	char *fqn;
	int tag;
	uintptr_t addr;
	struct die_fragment *list;
	struct hlist_node hash;
};

typedef int (*die_map_callback_t)(struct die *, void *arg);

extern int __die_map_get(uintptr_t addr, enum die_state state,
			 struct die **res);
extern int die_map_get(Dwarf_Die *die, enum die_state state, struct die **res);
extern int die_map_add_string(struct die *pd, const char *str);
extern int die_map_add_linebreak(struct die *pd, int linebreak);
extern int die_map_add_die(struct die *pd, struct die *child);
extern int die_map_for_each(die_map_callback_t func, void *arg);
extern void die_map_free(void);

/*
 * cache.c
 */

#define EXPANSION_CACHE_HASH_BITS 11

/* A cache for addresses we've already seen. */
struct expansion_cache {
	DECLARE_HASHTABLE(cache, EXPANSION_CACHE_HASH_BITS);
};

extern int __cache_mark_expanded(struct expansion_cache *ec, uintptr_t addr);
extern bool __cache_was_expanded(struct expansion_cache *ec, uintptr_t addr);

static inline int cache_mark_expanded(struct expansion_cache *ec, void *addr)
{
	return __cache_mark_expanded(ec, (uintptr_t)addr);
}

static inline bool cache_was_expanded(struct expansion_cache *ec, void *addr)
{
	return __cache_was_expanded(ec, (uintptr_t)addr);
}

extern void cache_clear_expanded(struct expansion_cache *ec);

/*
 * dwarf.c
 */

/* See dwarf.c:process_reserved */
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

	/* Structure expansion */
	struct expansion_state expand;
	struct expansion_cache expansion_cache;

	/* Reserved members */
	struct reserved_state reserved;
};

typedef int (*die_callback_t)(struct state *state, struct die *cache,
			      Dwarf_Die *die);
typedef bool (*die_match_callback_t)(Dwarf_Die *die);
extern bool match_all(Dwarf_Die *die);

extern int process_die_container(struct state *state, struct die *cache,
				 Dwarf_Die *die, die_callback_t func,
				 die_match_callback_t match);

extern int process_module(Dwfl_Module *mod, Dwarf *dbg, Dwarf_Die *cudie);

/*
 * types.c
 */

extern int generate_symtypes_and_versions(FILE *file);

#endif /* __GENDWARFKSYMS_H */
