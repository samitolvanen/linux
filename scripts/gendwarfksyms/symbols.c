// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include <string.h>
#include <linux/jhash.h>
#include "gendwarfksyms.h"

/* Hash tables for looking up requested symbols by address and name */
#define SYMBOL_HASH_BITS 7
static DEFINE_HASHTABLE(symbol_addrs, SYMBOL_HASH_BITS);
static DEFINE_HASHTABLE(symbol_names, SYMBOL_HASH_BITS);

static u32 name_hash(const char *name)
{
	return jhash(name, strlen(name), 0);
}

/* symbol_for_each callback -- return true to stop, false to continue */
typedef bool (*symbol_callback_t)(struct symbol *, void *arg);

static bool __for_each_addr(uintptr_t addr, symbol_callback_t func, void *data)
{
	struct symbol *sym;
	bool found = false;

	if (addr == UINTPTR_MAX)
		return false;

	hash_for_each_possible(symbol_addrs, sym, addr_hash, addr) {
		if (sym->addr == addr) {
			if (func(sym, data))
				return true;
			found = true;
		}
	}

	return found;
}

static bool __for_each_name(const char *name, symbol_callback_t func,
			    void *data)
{
	struct symbol *sym;
	bool found = false;

	if (!name)
		return false;

	hash_for_each_possible(symbol_names, sym, name_hash, name_hash(name)) {
		if (!strcmp(sym->name, name)) {
			if (func(sym, data))
				return true;
			found = true;
		}
	}

	return found;
}

static bool for_each(uintptr_t addr, const char *name, symbol_callback_t func,
		     void *data)
{
	bool found = false;

	if (__for_each_addr(addr, func, data))
		found = true;
	if (__for_each_name(name, func, data))
		found = true;

	return found;
}

int symbol_read_list(FILE *file)
{
	struct symbol *sym;
	char *line = NULL;
	char *name = NULL;
	uint64_t addr;
	size_t size = 0;

	while (getline(&line, &size, file) > 0) {
		if (sscanf(line, "%" PRIx64 " %ms\n", &addr, &name) != 2) {
			error("malformed input line (expected 'address symbol-name'): %s",
			      line);
			return -1;
		}

		free(line);
		line = NULL;

		sym = malloc(sizeof(struct symbol));
		if (!sym) {
			error("malloc failed");
			return -1;
		}

		debug("adding { %lx, \"%s\" }", addr, name);

		sym->addr = (uintptr_t)addr;
		sym->name = name;
		name = NULL;

		hash_add(symbol_addrs, &sym->addr_hash, sym->addr);
		hash_add(symbol_names, &sym->name_hash, name_hash(sym->name));
	}

	if (line)
		free(line);

	return 0;
}

static bool return_symbol(struct symbol *sym, void *arg)
{
	struct symbol **res = (struct symbol **)arg;

	*res = sym;
	return true; /* Stop -- return the first match */
}

struct symbol *symbol_get(uintptr_t addr, const char *name)
{
	struct symbol *sym;

	if (for_each(addr, name, return_symbol, &sym))
		return sym;

	return NULL;
}
