// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include <string.h>
#include "gendwarfksyms.h"

#define DIE_HASH_BITS 20

/* uintptr_t die->addr -> struct die * */
static DEFINE_HASHTABLE(die_map, DIE_HASH_BITS);

static unsigned int map_hits;
static unsigned int map_misses;

static int create_die(Dwarf_Die *die, struct die **res)
{
	struct die *cd;

	cd = malloc(sizeof(struct die));
	if (!cd) {
		error("malloc failed");
		return -1;
	}

	cd->state = INCOMPLETE;
	cd->mapped = false;
	cd->fqn = NULL;
	cd->tag = -1;
	cd->addr = (uintptr_t)die->addr;
	cd->list = NULL;

	hash_add(die_map, &cd->hash, addr_hash(cd->addr));
	*res = cd;
	return 0;
}

int __die_map_get(uintptr_t addr, enum die_state state, struct die **res)
{
	struct die *cd;

	hash_for_each_possible(die_map, cd, hash, addr_hash(addr)) {
		if (cd->addr == addr && cd->state == state) {
			*res = cd;
			return 0;
		}
	}

	return -1;
}

int die_map_get(Dwarf_Die *die, enum die_state state, struct die **res)
{
	if (__die_map_get((uintptr_t)die->addr, state, res) == 0) {
		map_hits++;
		return 0;
	}

	map_misses++;
	return check(create_die(die, res));
}

static void reset_die(struct die *cd)
{
	struct die_fragment *tmp;
	struct die_fragment *df = cd->list;

	while (df) {
		if (df->type == STRING)
			free(df->data.str);

		tmp = df->next;
		free(df);
		df = tmp;
	}

	cd->state = INCOMPLETE;
	cd->mapped = false;
	if (cd->fqn)
		free(cd->fqn);
	cd->fqn = NULL;
	cd->tag = -1;
	cd->addr = 0;
	cd->list = NULL;
}

void die_map_free(void)
{
	struct hlist_node *tmp;
	unsigned int stats[LAST + 1];
	struct die *cd;
	int i;

	memset(stats, 0, sizeof(stats));

	hash_for_each_safe(die_map, i, tmp, cd, hash) {
		stats[cd->state]++;
		reset_die(cd);
		free(cd);
	}
	hash_init(die_map);

	if ((map_hits + map_misses > 0))
		debug("hits %u, misses %u (hit rate %.02f%%)", map_hits,
		      map_misses,
		      (100.0f * map_hits) / (map_hits + map_misses));

	for (i = 0; i <= LAST; i++)
		debug("%s: %u entries", die_state_name(i), stats[i]);
}

static int append_item(struct die *cd, struct die_fragment **res)
{
	struct die_fragment *prev;
	struct die_fragment *df;

	df = malloc(sizeof(struct die_fragment));
	if (!df) {
		error("malloc failed");
		return -1;
	}

	df->type = EMPTY;
	df->next = NULL;

	prev = cd->list;
	while (prev && prev->next)
		prev = prev->next;

	if (prev)
		prev->next = df;
	else
		cd->list = df;

	*res = df;
	return 0;
}

int die_map_add_string(struct die *cd, const char *str)
{
	struct die_fragment *df;

	if (!cd)
		return 0;

	check(append_item(cd, &df));

	df->data.str = strdup(str);
	if (!df->data.str) {
		error("strdup failed");
		return -1;
	}

	df->type = STRING;
	return 0;
}

int die_map_add_die(struct die *cd, struct die *child)
{
	struct die_fragment *df;

	if (!cd)
		return 0;

	check(append_item(cd, &df));
	df->data.addr = child->addr;
	df->type = DIE;
	return 0;
}
