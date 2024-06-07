// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"

struct expanded {
	uintptr_t addr;
	struct hlist_node hash;
};

int __cache_mark_expanded(struct expansion_cache *ec, uintptr_t addr)
{
	struct expanded *es;

	es = malloc(sizeof(struct expanded));
	if (!es) {
		error("malloc failed");
		return -1;
	}

	es->addr = addr;
	hash_add(ec->cache, &es->hash, addr_hash(addr));
	return 0;
}

bool __cache_was_expanded(struct expansion_cache *ec, uintptr_t addr)
{
	struct expanded *es;

	hash_for_each_possible(ec->cache, es, hash, addr_hash(addr)) {
		if (es->addr == addr)
			return true;
	}

	return false;
}

void cache_clear_expanded(struct expansion_cache *ec)
{
	struct hlist_node *tmp;
	struct expanded *es;
	int i;

	hash_for_each_safe(ec->cache, i, tmp, es, hash) {
		free(es);
	}

	hash_init(ec->cache);
}
