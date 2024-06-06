// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include <string.h>
#include "gendwarfksyms.h"

#define DIE_HASH_BITS 10

/* die->addr -> struct cached_die */
static DEFINE_HASHTABLE(die_cache, DIE_HASH_BITS);

static unsigned int cache_hits;
static unsigned int cache_misses;

static int create_die(Dwarf_Die *die, struct cached_die **res)
{
	struct cached_die *cd;

	cd = malloc(sizeof(struct cached_die));
	if (!cd) {
		error("malloc failed");
		return -1;
	}

	cd->state = INCOMPLETE;
	cd->addr = (uintptr_t)die->addr;
	cd->list = NULL;

	hash_add(die_cache, &cd->hash, cd->addr);
	*res = cd;
	return 0;
}

int cache_get(Dwarf_Die *die, enum cached_die_state state,
	      struct cached_die **res)
{
	struct cached_die *cd;
	uintptr_t addr = (uintptr_t)die->addr;

	hash_for_each_possible(die_cache, cd, hash, addr) {
		if (cd->addr == addr && cd->state == state) {
			*res = cd;
			cache_hits++;
			return 0;
		}
	}

	cache_misses++;
	return check(create_die(die, res));
}

static void reset_die(struct cached_die *cd)
{
	struct cached_item *tmp;
	struct cached_item *ci = cd->list;

	while (ci) {
		if (ci->type == STRING)
			free(ci->data.str);

		tmp = ci->next;
		free(ci);
		ci = tmp;
	}

	cd->state = INCOMPLETE;
	cd->list = NULL;
}

void cache_free(void)
{
	struct cached_die *cd;
	struct hlist_node *tmp;
	int i;

	hash_for_each_safe(die_cache, i, tmp, cd, hash) {
		reset_die(cd);
		free(cd);
	}
	hash_init(die_cache);

	if ((cache_hits + cache_misses > 0))
		debug("cache: hits %u, misses %u (hit rate %.02f%%)",
		      cache_hits, cache_misses,
		      (100.0f * cache_hits) / (cache_hits + cache_misses));
}

static int append_item(struct cached_die *cd, struct cached_item **res)
{
	struct cached_item *prev;
	struct cached_item *ci;

	ci = malloc(sizeof(struct cached_item));
	if (!ci) {
		error("malloc failed");
		return -1;
	}

	ci->type = EMPTY;
	ci->next = NULL;

	prev = cd->list;
	while (prev && prev->next)
		prev = prev->next;

	if (prev)
		prev->next = ci;
	else
		cd->list = ci;

	*res = ci;
	return 0;
}

int cache_add_string(struct cached_die *cd, const char *str)
{
	struct cached_item *ci;

	if (!cd)
		return 0;

	check(append_item(cd, &ci));

	ci->data.str = strdup(str);
	if (!ci->data.str) {
		error("strdup failed");
		return -1;
	}

	ci->type = STRING;
	return 0;
}

int cache_add_die(struct cached_die *cd, Dwarf_Die *die)
{
	struct cached_item *ci;

	if (!cd)
		return 0;

	check(append_item(cd, &ci));
	ci->data.addr = (uintptr_t)die->addr;
	ci->type = DIE;
	return 0;
}
