// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"

struct declonly {
	const char *name;
	struct hlist_node hash;
};

#define SYMBOL_HASH_BITS 15
#define DECLONLY_HASH_BITS 10

/* struct symbol_addr -> struct symbol */
static DEFINE_HASHTABLE(symbol_addrs, SYMBOL_HASH_BITS);
/* name -> struct symbol */
static DEFINE_HASHTABLE(symbol_names, SYMBOL_HASH_BITS);
/* name -> struct declonly */
static DEFINE_HASHTABLE(declonly_structs, DECLONLY_HASH_BITS);

static inline u32 symbol_addr_hash(const struct symbol_addr *addr)
{
	return jhash(addr, sizeof(struct symbol_addr), 0);
}

typedef int (*symbol_callback_t)(struct symbol *, void *arg);

static int __for_each_addr(struct symbol *sym, symbol_callback_t func,
			   void *data)
{
	struct hlist_node *tmp;
	struct symbol *match = NULL;
	int processed = 0;

	hash_for_each_possible_safe(symbol_addrs, match, tmp, addr_hash,
				    symbol_addr_hash(&sym->addr)) {
		if (match == sym)
			continue; /* Already processed */

		if (match->addr.section == sym->addr.section &&
		    match->addr.address == sym->addr.address) {
			check(func(match, data));
			++processed;
		}
	}

	return processed;
}

/*
 * For symbols without debugging information (e.g. symbols defined in other
 * TUs), we also match __gendwarfksyms_ptr_<symbol_name> symbols, which the
 * kernel uses to ensure type information is present in the TU that exports
 * the symbol. A __gendwarfksyms_ptr pointer must have the same type as the
 * exported symbol, e.g.:
 *
 *   typeof(symname) *__gendwarf_ptr_symname = &symname;
 */
bool is_symbol_ptr(const char *name)
{
	return name && !strncmp(name, SYMBOL_PTR_PREFIX, SYMBOL_PTR_PREFIX_LEN);
}

static int for_each(const char *name, bool name_only, symbol_callback_t func,
		    void *data)
{
	struct hlist_node *tmp;
	struct symbol *match;

	if (!name || !*name)
		return 0;
	if (is_symbol_ptr(name))
		name += SYMBOL_PTR_PREFIX_LEN;

	hash_for_each_possible_safe(symbol_names, match, tmp, name_hash,
				    name_hash(name)) {
		if (strcmp(match->name, name))
			continue;

		/* Call func for the match, and all address matches */
		if (func)
			check(func(match, data));

		if (!name_only && match->addr.section != SHN_UNDEF)
			return checkp(__for_each_addr(match, func, data)) + 1;

		return 1;
	}

	return 0;
}

static int set_crc(struct symbol *sym, void *data)
{
	unsigned long *crc = data;

	if (sym->state == PROCESSED && sym->crc != *crc)
		warn("overriding version for symbol %s (crc %lx vs. %lx)",
		     sym->name, sym->crc, *crc);

	sym->state = PROCESSED;
	sym->crc = *crc;
	return 0;
}

int symbol_set_crc(struct symbol *sym, unsigned long crc)
{
	if (checkp(for_each(sym->name, false, set_crc, &crc)) > 0)
		return 0;
	return -1;
}

static int set_die(struct symbol *sym, void *data)
{
	sym->die_addr = (uintptr_t)((Dwarf_Die *)data)->addr;
	sym->state = MAPPED;
	return 0;
}

int symbol_set_die(struct symbol *sym, Dwarf_Die *die)
{
	return checkp(for_each(sym->name, false, set_die, die));
}

static bool is_exported(const char *name)
{
	return checkp(for_each(name, true, NULL, NULL)) > 0;
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

		sym = calloc(1, sizeof(struct symbol));
		if (!sym) {
			error("calloc failed");
			return -1;
		}

		sym->name = name;
		sym->addr.section = SHN_UNDEF;
		sym->state = UNPROCESSED;
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

static int get_unprocessed(struct symbol *sym, void *arg)
{
	struct symbol **res = arg;

	if (sym->state == UNPROCESSED)
		*res = sym;

	return 0;
}

struct symbol *symbol_get_unprocessed(const char *name)
{
	struct symbol *sym = NULL;

	for_each(name, false, get_unprocessed, &sym);
	return sym;
}

int symbol_for_each(symbol_callback_t func, void *arg)
{
	struct hlist_node *tmp;
	struct symbol *sym;
	int i;

	hash_for_each_safe(symbol_names, i, tmp, sym, name_hash) {
		check(func(sym, arg));
	}

	return 0;
}

typedef int (*elf_symbol_callback_t)(const char *name, GElf_Sym *sym,
				     Elf32_Word xndx, void *arg);

static int elf_for_each_symbol(int fd, elf_symbol_callback_t func, void *arg)
{
	size_t sym_size;
	GElf_Shdr shdr_mem;
	GElf_Shdr *shdr;
	Elf_Data *xndx_data = NULL;
	Elf_Scn *scn;
	Elf *elf;

	if (elf_version(EV_CURRENT) != EV_CURRENT) {
		error("elf_version failed: %s", elf_errmsg(-1));
		return -1;
	}

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
		error("elf_begin failed: %s", elf_errmsg(-1));
		return -1;
	}

	sym_size = gelf_getclass(elf) == ELFCLASS32 ? sizeof(Elf32_Sym) :
						      sizeof(Elf64_Sym);

	scn = elf_nextscn(elf, NULL);

	while (scn) {
		shdr = gelf_getshdr(scn, &shdr_mem);

		if (shdr && shdr->sh_type == SHT_SYMTAB_SHNDX) {
			xndx_data = elf_getdata(scn, NULL);
			break;
		}

		scn = elf_nextscn(elf, scn);
	}

	scn = elf_nextscn(elf, NULL);

	while (scn) {
		shdr = gelf_getshdr(scn, &shdr_mem);

		if (shdr && shdr->sh_type == SHT_SYMTAB) {
			Elf_Data *data = elf_getdata(scn, NULL);
			unsigned int nsyms = data->d_size / sym_size;
			unsigned int n;

			for (n = 0; n < nsyms; ++n) {
				const char *name = NULL;
				Elf32_Word xndx = 0;
				GElf_Sym sym_mem;
				GElf_Sym *sym;

				sym = gelf_getsymshndx(data, xndx_data, n,
						       &sym_mem, &xndx);

				if (sym->st_shndx != SHN_XINDEX)
					xndx = sym->st_shndx;

				name = elf_strptr(elf, shdr->sh_link,
						  sym->st_name);

				/* Skip empty symbol names */
				if (name && *name &&
				    checkp(func(name, sym, xndx, arg)) > 0)
					break;
			}
		}

		scn = elf_nextscn(elf, scn);
	}

	return check(elf_end(elf));
}

static int set_symbol_addr(struct symbol *sym, void *arg)
{
	struct symbol_addr *addr = arg;

	if (sym->addr.section == SHN_UNDEF) {
		sym->addr.section = addr->section;
		sym->addr.address = addr->address;
		hash_add(symbol_addrs, &sym->addr_hash,
			 symbol_addr_hash(&sym->addr));

		debug("%s -> { %u, %lx }", sym->name, sym->addr.section,
		      sym->addr.address);
	} else {
		warn("multiple addresses for symbol %s?", sym->name);
	}

	return 0;
}

static int process_symbol(const char *name, GElf_Sym *sym, Elf32_Word xndx,
			  void *arg)
{
	struct symbol_addr addr = { .section = xndx, .address = sym->st_value };
	struct declonly *d;

	/* Set addresses for exported symbols */
	if (GELF_ST_BIND(sym->st_info) != STB_LOCAL &&
	    addr.section != SHN_UNDEF)
		checkp(for_each(name, true, set_symbol_addr, &addr));

	if (!stable)
		return 0;

	/* Process declonly structs */
	if (strncmp(name, SYMBOL_DECLONLY_PREFIX, SYMBOL_DECLONLY_PREFIX_LEN))
		return 0;

	d = malloc(sizeof(struct declonly));
	if (!d) {
		error("malloc failed");
		return -1;
	}

	name += SYMBOL_DECLONLY_PREFIX_LEN;
	d->name = strdup(name);
	if (!d->name) {
		error("strdup failed");
		return -1;
	}

	hash_add(declonly_structs, &d->hash, name_hash(d->name));
	debug("declaration-only: %s", d->name);

	return 0;
}

int symbol_read_symtab(int fd)
{
	return elf_for_each_symbol(fd, process_symbol, NULL);
}

bool is_struct_declonly(const char *name)
{
	struct declonly *d;

	if (!stable || !name)
		return false;

	hash_for_each_possible(declonly_structs, d, hash, name_hash(name)) {
		if (!strcmp(name, d->name))
			return true;
	}

	return false;
}

void symbol_free_declonly(void)
{
	struct hlist_node *tmp;
	struct declonly *d;
	int i;

	hash_for_each_safe(declonly_structs, i, tmp, d, hash) {
		free((void *)d->name);
		free(d);
	}

	hash_init(declonly_structs);
}

void symbol_print_versions(void)
{
	struct hlist_node *tmp;
	struct symbol *sym;
	int i;

	hash_for_each_safe(symbol_names, i, tmp, sym, name_hash) {
		if (sym->state != PROCESSED)
			warn("no information for symbol %s", sym->name);

		printf("#SYMVER %s 0x%08lx\n", sym->name, sym->crc);

		free((void *)sym->name);
		free(sym);
	}

	hash_init(symbol_addrs);
	hash_init(symbol_names);
}
