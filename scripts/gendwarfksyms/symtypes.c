// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"
#include <linux/math.h>

struct symtype_buffer {
	char *buf;
	size_t len;
	size_t allocated;
};

struct symtype_expansion {
	char *name;
	char *expanded;
	size_t len;
	struct hlist_node hash;
};

/* name -> struct symtype_expansion */
static DEFINE_HASHTABLE(types, DIE_HASH_BITS);
static struct expansion_cache expansion_cache;

static int process_types(FILE *file)
{
	struct symtype_expansion *se;
	struct hlist_node *tmp;
	int i;

	hash_for_each_safe(types, i, tmp, se, hash) {
		checkp(fprintf(file, "%s %s\n", se->name, se->expanded));
		free(se->name);
		free(se->expanded);
		free(se);
	}

	hash_init(types);
	return 0;
}

static int append(struct symtype_buffer *buf, const char *src)
{
	size_t src_len = strlen(src);
	size_t min_len = buf->len + src_len + 1;

	if (buf->allocated < min_len) {
		buf->allocated = round_up(min_len, 128);
		buf->buf = realloc(buf->buf, buf->allocated);
		if (!buf->buf) {
			error("realloc failed");
			return -1;
		}
	}

	strcpy(buf->buf + buf->len, src);
	buf->len += src_len;
	return 0;
}

static char get_symtype_prefix(int tag)
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

static char *get_symtype_name(struct cached_die *cache)
{
	size_t name_len;
	char prefix;
	char *name;

	if (cache->state == INCOMPLETE) {
		warn("found incomplete cache entry: %p", cache);
		return NULL;
	}
	if (cache->state == SYMBOL || !cache->name)
		return NULL;

	prefix = get_symtype_prefix(cache->tag);
	if (!prefix)
		return NULL;

	/* <prefix>#<type_name>\0 */
	name_len = 2 + strlen(cache->name) + 1;

	name = malloc(name_len);
	if (!name) {
		error("malloc failed");
		return NULL;
	}

	if (snprintf(name, name_len, "%c#%s", prefix, cache->name) >= name_len) {
		error("snprintf failed");
		free(name);
		return NULL;
	}

	return name;
}

static int add_symtype(const char *name, const char *expanded)
{
	struct symtype_expansion *se;
	size_t len = strlen(expanded);

	hash_for_each_possible(types, se, hash, name_hash(name)) {
		if (strcmp(name, se->name))
			continue;

		/* Use the longest available expansion */
		if (len > se->len) {
			debug("replacing %s", name);
			debug("  old: %s", se->expanded);
			debug("  new: %s", expanded);

			free(se->expanded);
			se->expanded = strdup(expanded);
			se->len = len;

			if (!se->expanded) {
				error("strdup failed");
				return -1;
			}
		}

		return 0;
	}

	se = malloc(sizeof(struct symtype_expansion));
	if (!se) {
		error("malloc failed");
		return -1;
	}

	se->name = strdup(name);
	se->expanded = strdup(expanded);
	se->len = len;

	if (!se->name || !se->expanded) {
		error("strdup failed");
		return -1;
	}

	hash_add(types, &se->hash, name_hash(name));
	return 0;
}

static int expand_symtype(struct cached_die *cache, struct symtype_buffer *buf);

static int expand_symtype_child(struct cached_die *cache, struct symtype_buffer *buf)
{
	struct symtype_buffer child = {
		.buf = NULL,
		.len = 0,
		.allocated = 0,
	};
	char *name;

	name = get_symtype_name(cache);
	if (!name)
		return check(expand_symtype(cache, buf));

	if (!__cache_was_expanded(&expansion_cache, cache->addr)) {
		check(__cache_mark_expanded(&expansion_cache, cache->addr));

		check(expand_symtype(cache, &child));
		check(add_symtype(name, child.buf));

		free(child.buf);
	}

	check(append(buf, name));
	free(name);

	return 0;
}

static int expand_symtype(struct cached_die *cache, struct symtype_buffer *buf)
{
	struct cached_item *ci = cache->list;
	struct cached_die *cd;

	while (ci) {
		switch (ci->type) {
		case STRING:
			check(append(buf, ci->data.str));
			break;
		case DIE:
			if (__cache_get(ci->data.addr, COMPLETE, &cd) &&
			    __cache_get(ci->data.addr, UNEXPANDED, &cd)) {
				error("unknown child: %" PRIxPTR,
				      ci->data.addr);
				return -1;
			}

			check(expand_symtype_child(cd, buf));
			break;
		case LINEBREAK:
			if (!ci->next || ci->next->type != LINEBREAK)
				check(append(buf, " "));
			break;
		default:
			error("empty cached_item in %p", cache);
			return -1;
		}
		ci = ci->next;
	}

	/* We should never end up with an empty expansion. */
	return buf->len ? 0 : -1;
}
static int process_exported(struct symbol *sym, void *arg)
{
	struct cached_die *cache;
	struct symtype_buffer type = {
		.buf = NULL,
		.len = 0,
		.allocated = 0,
	};

	if (__cache_get(sym->die_addr, SYMBOL, &cache)) {
		error("missing symbol type string for %s", sym->name);
		return -1;
	}

	check(expand_symtype(cache, &type));
	check(add_symtype(sym->name, type.buf));
	free(type.buf);
	cache_clear_expanded(&expansion_cache);

	return 0;
}

int symtypes_dump(FILE *file)
{
	if (!symtypes)
		return 0;

	hash_init(expansion_cache.cache);
	check(symbol_for_each_processed(process_exported, NULL));
	return check(process_types(file));
}
