// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"
#include "crc32.h"

static struct expansion_cache expansion_cache;

/*
 * A simple linked list of shared or owned strings to avoid copying strings
 * around when not necessary.
 */
struct type_list {
	const char *str;
	void *owned;
	struct type_list *next;
};

static struct type_list *type_list_alloc(void)
{
	struct type_list *list;

	list = calloc(1, sizeof(struct type_list));
	if (!list)
		error("calloc failed");

	return list;
}

static void type_list_free(struct type_list *list)
{
	struct type_list *tmp;

	while (list) {
		if (list->owned)
			free(list->owned);

		tmp = list;
		list = list->next;
		free(tmp);
	}
}

static int type_list_append(struct type_list *list, const char *s, void *owned)
{
	if (!list || !s)
		return 0;

	while (list->next)
		list = list->next;

	if (list->str) {
		list->next = type_list_alloc();

		if (!list->next) {
			error("type_list_alloc failed");
			return -1;
		}

		list = list->next;
	}

	list->str = s;
	list->owned = owned;

	return strlen(list->str);
}

static int type_list_write(struct type_list *list, FILE *file)
{
	while (list) {
		if (list->str)
			checkp(fputs(list->str, file));
		list = list->next;
	}

	return 0;
}

/*
 * An expanded type string in symtypes format.
 */
struct type_expansion {
	char *name;
	struct type_list *expanded;
	struct type_list *last;
	size_t len;
	struct hlist_node hash;
};

static int type_expansion_init(struct type_expansion *type, bool alloc)
{
	memset(type, 0, sizeof(struct type_expansion));
	if (alloc) {
		type->expanded = type_list_alloc();
		if (!type->expanded)
			return -1;

		type->last = type->expanded;
	}
	return 0;
}

static inline void type_expansion_free(struct type_expansion *type)
{
	free(type->name);
	type_list_free(type->expanded);
	type_expansion_init(type, false);
}

static int type_expansion_append(struct type_expansion *type, const char *s,
				 void *owned)
{
	type->len += checkp(type_list_append(type->last, s, owned));

	if (type->last->next)
		type->last = type->last->next;

	return 0;
}

/*
 * type_map -- the longest expansions for each type.
 *
 * const char *name -> struct type_expansion *
 */
#define TYPE_HASH_BITS 16
static DEFINE_HASHTABLE(type_map, TYPE_HASH_BITS);

static int type_map_get(const char *name, struct type_expansion **res)
{
	struct type_expansion *e;

	hash_for_each_possible(type_map, e, hash, name_hash(name)) {
		if (!strcmp(name, e->name)) {
			*res = e;
			return 0;
		}
	}

	return -1;
}

static int type_map_add(const char *name, struct type_expansion *type)
{
	struct type_expansion *e;

	if (type_map_get(name, &e)) {
		e = malloc(sizeof(struct type_expansion));
		if (!e) {
			error("malloc failed");
			return -1;
		}

		type_expansion_init(e, false);

		e->name = strdup(name);
		if (!e->name) {
			error("strdup failed");
			return -1;
		}

		hash_add(type_map, &e->hash, name_hash(e->name));

		if (dump_types)
			debug("adding %s", e->name);
	} else {
		/* Use the longest available expansion */
		if (type->len <= e->len)
			return 0;

		type_list_free(e->expanded);

		if (dump_types)
			debug("replacing %s", e->name);
	}

	/* Take ownership of type->expanded */
	e->expanded = type->expanded;
	e->last = type->last;
	e->len = type->len;
	type->expanded = NULL;
	type->last = NULL;
	type->len = 0;

	if (dump_types) {
		fputs(e->name, stderr);
		fputs(" ", stderr);
		type_list_write(e->expanded, stderr);
		fputs("\n", stderr);
	}

	return 0;
}

static int type_map_write(FILE *file)
{
	struct type_expansion *e;
	struct hlist_node *tmp;
	int i;

	if (!file)
		return 0;

	hash_for_each_safe(type_map, i, tmp, e, hash) {
		checkp(fputs(e->name, file));
		checkp(fputs(" ", file));
		type_list_write(e->expanded, file);
		checkp(fputs("\n", file));
	}

	return 0;
}

static void type_map_free(void)
{
	struct type_expansion *e;
	struct hlist_node *tmp;
	int i;

	hash_for_each_safe(type_map, i, tmp, e, hash) {
		type_expansion_free(e);
		free(e);
	}

	hash_init(type_map);
}

/*
 * CRC for a type, with an optional fully expanded type string for
 * debugging.
 */
struct version {
	struct type_expansion type;
	unsigned long crc;
};

static int version_init(struct version *version)
{
	version->crc = 0xffffffff;
	return check(type_expansion_init(&version->type, dump_versions));
}

static void version_free(struct version *version)
{
	type_expansion_free(&version->type);
}

static int version_add(struct version *version, const char *s)
{
	version->crc = partial_crc32(s, version->crc);
	if (dump_versions)
		checkp(type_expansion_append(&version->type, s, NULL));
	return 0;
}

/*
 * Type reference format: <prefix>#<name>, where prefix:
 * 	s -> structure
 * 	u -> union
 * 	e -> enum
 * 	t -> typedef
 *
 * Names with spaces are additionally wrapped in single quotes.
 */
static inline bool is_type_prefix(const char *s)
{
	return (s[0] == 's' || s[0] == 'u' || s[0] == 'e' || s[0] == 't') &&
	       s[1] == '#';
}

static char get_type_prefix(int tag)
{
	switch (tag) {
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
		return 's';
	case DW_TAG_union_type:
		return 'u';
	case DW_TAG_enumeration_type:
		return 'e';
	case DW_TAG_typedef_type:
		return 't';
	default:
		return 0;
	}
}

static char *get_type_name(struct die *cache)
{
	const char *format;
	char prefix;
	char *name;
	size_t len;

	if (cache->state == INCOMPLETE) {
		warn("found incomplete cache entry: %p", cache);
		return NULL;
	}
	if (cache->state == SYMBOL || !cache->fqn)
		return NULL;

	prefix = get_type_prefix(cache->tag);
	if (!prefix)
		return NULL;

	/* <prefix>#<type_name>\0 */
	len = 2 + strlen(cache->fqn) + 1;

	/* Wrap names with spaces in single quotes */
	if (strstr(cache->fqn, " ")) {
		format = "%c#'%s'";
		len += 2;
	} else {
		format = "%c#%s";
	}

	name = malloc(len);
	if (!name) {
		error("malloc failed");
		return NULL;
	}

	if (snprintf(name, len, format, prefix, cache->fqn) >= len) {
		error("snprintf failed for '%s' (length %zu)", cache->fqn,
		      len);
		free(name);
		return NULL;
	}

	return name;
}

static int __calculate_version(struct version *version, struct type_list *list)
{
	struct type_expansion *e;

	/* Calculate a CRC over an expanded type string */
	while (list) {
		if (is_type_prefix(list->str)) {
			check(type_map_get(list->str, &e));

			/*
			 * It's sufficient to expand each type reference just
			 * once to detect changes.
			 */
			if (cache_was_expanded(&expansion_cache, e)) {
				check(version_add(version, list->str));
			} else {
				check(cache_mark_expanded(&expansion_cache, e));
				check(__calculate_version(version,
							  e->expanded));
			}
		} else {
			check(version_add(version, list->str));
		}

		list = list->next;
	}

	return 0;
}

static int calculate_version(struct version *version, const char *name,
			     struct type_list *list)
{
	check(version_init(version));
	check(__calculate_version(version, list));
	cache_clear_expanded(&expansion_cache);
	return 0;
}

static int __type_expand(struct die *cache, struct type_expansion *type,
			 bool recursive);

static int type_expand_child(struct die *cache, struct type_expansion *type,
			     bool recursive)
{
	struct type_expansion child;
	char *name;

	name = get_type_name(cache);
	if (!name)
		return check(__type_expand(cache, type, recursive));

	if (recursive && !__cache_was_expanded(&expansion_cache, cache->addr)) {
		check(__cache_mark_expanded(&expansion_cache, cache->addr));
		check(type_expansion_init(&child, true));
		check(__type_expand(cache, &child, true));
		check(type_map_add(name, &child));
		type_expansion_free(&child);
	}

	check(type_expansion_append(type, name, name));
	return 0;
}

static int __type_expand(struct die *cache, struct type_expansion *type,
			 bool recursive)
{
	struct die_fragment *df = cache->list;
	struct die *child;

	while (df) {
		switch (df->type) {
		case STRING:
			check(type_expansion_append(type, df->data.str, NULL));
			break;
		case DIE:
			/* Use a complete die_map expansion if available */
			if (__die_map_get(df->data.addr, COMPLETE, &child) &&
			    __die_map_get(df->data.addr, UNEXPANDED, &child)) {
				error("unknown child: %" PRIxPTR,
				      df->data.addr);
				return -1;
			}

			check(type_expand_child(child, type, recursive));
			break;
		case LINEBREAK:
			/*
			 * Keep whitespace in the symtypes format, but avoid
			 * repeated spaces.
			 */
			if (!df->next || df->next->type != LINEBREAK)
				check(type_expansion_append(type, " ", NULL));
			break;
		default:
			error("empty die_fragment in %p", cache);
			return -1;
		}

		df = df->next;
	}

	return 0;
}

static int type_expand(struct die *cache, struct type_expansion *type,
		       bool recursive)
{
	check(type_expansion_init(type, true));
	check(__type_expand(cache, type, recursive));
	cache_clear_expanded(&expansion_cache);
	return 0;
}

static int expand_type(struct die *cache, void *arg)
{
	struct type_expansion type;
	char *name;

	/*
	 * Skip unexpanded die_map entries if there's a complete
	 * expansion available for this DIE.
	 */
	if (cache->state == UNEXPANDED)
		__die_map_get(cache->addr, COMPLETE, &cache);

	if (cache->mapped)
		return 0;

	cache->mapped = true;

	name = get_type_name(cache);
	if (!name)
		return 0;

	debug("%s", name);
	check(type_expand(cache, &type, true));
	check(type_map_add(name, &type));

	type_expansion_free(&type);
	free(name);

	return 0;
}

static int expand_symbol(struct symbol *sym, void *arg)
{
	struct type_expansion type;
	struct version version;
	struct die *cache;

	/*
	 * No need to expand again unless we want a symtypes file entry
	 * for the symbol. Note that this means `sym` has the same address
	 * as another symbol that was already processed.
	 */
	if (!symtypes && sym->state == PROCESSED)
		return 0;

	if (__die_map_get(sym->die_addr, SYMBOL, &cache))
		return 0; /* We'll warn about missing CRCs later. */

	check(type_expand(cache, &type, false));

	/* If the symbol already has a version, don't calculate it again. */
	if (sym->state != PROCESSED) {
		check(calculate_version(&version, sym->name, type.expanded));
		check(symbol_set_crc(sym, version.crc));
		debug("%s = %lx", sym->name, version.crc);

		if (dump_versions) {
			fputs(sym->name, stderr);
			fputs(" ", stderr);
			type_list_write(version.type.expanded, stderr);
			fputs("\n", stderr);
		}

		version_free(&version);
	}

	/* These aren't needed in type_map unless we want a symtypes file. */
	if (symtypes)
		check(type_map_add(sym->name, &type));

	type_expansion_free(&type);

	return 0;
}

int generate_symtypes_and_versions(FILE *file)
{
	hash_init(expansion_cache.cache);

	/*
	 * die_map processing:
	 *
	 *   1. die_map contains all types referenced in exported symbol
	 *      signatures, but can contain duplicates just like the original
	 *      DWARF, and some references may not be fully expanded depending
	 *      on how far we processed the DIE tree for that specific symbol.
	 *
	 *      For each die_map entry, find the longest available expansion,
	 *      and add it to type_map.
	 */
	check(die_map_for_each(expand_type, NULL));

	/*
	 *   2. For each exported symbol, expand the die_cache type, and use
	 *      type_map expansions to calculate a symbol version from the
	 *      fully expanded type string.
	 */
	check(symbol_for_each(expand_symbol, NULL));

	/*
	 *   3. If a symtypes file is requested, write type_map contents to
	 *      the file.
	 */
	check(type_map_write(file));
	type_map_free();

	return 0;
}
