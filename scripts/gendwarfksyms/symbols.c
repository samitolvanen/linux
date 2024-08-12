// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"

#define SYMBOL_HASH_BITS 15
static DEFINE_HASHTABLE(symbol_names, SYMBOL_HASH_BITS);

typedef int (*symbol_callback_t)(struct symbol *, void *arg);

static int for_each(const char *name, symbol_callback_t func, void *data)
{
	struct hlist_node *tmp;
	struct symbol *match;

	if (!name || !*name)
		return 0;

	hash_for_each_possible_safe(symbol_names, match, tmp, name_hash,
				    name_hash(name)) {
		if (strcmp(match->name, name))
			continue;

		if (func)
			check(func(match, data));

		return 1;
	}

	return 0;
}

static bool is_exported(const char *name)
{
	return checkp(for_each(name, NULL, NULL)) > 0;
}

int symbol_read_exports(FILE *file)
{
	struct symbol *sym;
	char *line = NULL;
	char *name = NULL;
	size_t size = 0;
	int nsym = 0;

	while (getline(&line, &size, file) > 0) {
		if (sscanf(line, "%ms\n", &name) != 1) {
			error("malformed input line: %s", line);
			return -1;
		}

		free(line);
		line = NULL;

		if (is_exported(name))
			continue; /* Ignore duplicates */

		sym = malloc(sizeof(struct symbol));
		if (!sym) {
			error("malloc failed");
			return -1;
		}

		sym->name = name;
		name = NULL;

		hash_add(symbol_names, &sym->name_hash, name_hash(sym->name));
		++nsym;

		debug("%s", sym->name);
	}

	if (line)
		free(line);

	debug("%d exported symbols", nsym);
	return 0;
}

static int get_symbol(struct symbol *sym, void *arg)
{
	struct symbol **res = arg;

	*res = sym;
	return 0;
}

struct symbol *symbol_get(const char *name)
{
	struct symbol *sym = NULL;

	for_each(name, get_symbol, &sym);
	return sym;
}
