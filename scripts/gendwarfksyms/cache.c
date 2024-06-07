// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"

struct expanded {
	uintptr_t addr;
	struct hlist_node hash;
};

void __cache_mark_expanded(struct expansion_cache *ec, uintptr_t addr)
{
	struct expanded *es;

	es = xmalloc(sizeof(struct expanded));
	es->addr = addr;
	hash_add(ec->cache, &es->hash, addr_hash(addr));
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

	hash_for_each_safe(ec->cache, es, tmp, hash) {
		free(es);
	}

	hash_init(ec->cache);
}
