// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"

#define RULE_HASH_BITS 10

struct rule {
	enum kabi_rule_type type;
	const char *target;
	const char *value;
	struct hlist_node hash;
};

/* { type, target, value } -> struct rule */
static HASHTABLE_DEFINE(rules, 1 << RULE_HASH_BITS);

static inline unsigned int rule_hash(enum kabi_rule_type type,
				     const char *target, const char *value)
{
	return hash_32(type) ^ hash_str(target) ^ hash_str(value);
}

static inline unsigned int __rule_hash(const struct rule *rule)
{
	return rule_hash(rule->type, rule->target, rule->value);
}

static inline const char *get_rule_field(const char **pos, ssize_t *left)
{
	const char *start = *pos;
	size_t len;

	if (*left <= 1)
		error("unexpected end of kABI rules");

	len = strnlen(start, *left);
	if (!len)
		error("empty kABI rule field");

	len += 1;
	*pos += len;
	*left -= len;

	return start;
}

void kabi_read_rules(int fd)
{
	GElf_Shdr shdr_mem;
	GElf_Shdr *shdr;
	Elf_Data *rule_data = NULL;
	Elf_Scn *scn;
	Elf *elf;
	size_t shstrndx;
	const char *rule_str;
	ssize_t left;
	int i;

	const struct {
		enum kabi_rule_type type;
		const char *tag;
	} rule_types[] = {
		{
			.type = KABI_RULE_TYPE_STRUCT_DECLONLY,
			.tag = KABI_RULE_TAG_STRUCT_DECLONLY,
		},
		{
			.type = KABI_RULE_TYPE_ENUMERATOR_IGNORE,
			.tag = KABI_RULE_TAG_ENUMERATOR_IGNORE,
		},
	};

	if (!stable)
		return;

	if (elf_version(EV_CURRENT) != EV_CURRENT)
		error("elf_version failed: %s", elf_errmsg(-1));

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf)
		error("elf_begin failed: %s", elf_errmsg(-1));

	if (elf_getshdrstrndx(elf, &shstrndx) < 0)
		error("elf_getshdrstrndx failed: %s", elf_errmsg(-1));

	scn = elf_nextscn(elf, NULL);

	while (scn) {
		shdr = gelf_getshdr(scn, &shdr_mem);
		if (shdr) {
			const char *sname =
				elf_strptr(elf, shstrndx, shdr->sh_name);

			if (sname && !strcmp(sname, KABI_RULE_SECTION)) {
				rule_data = elf_getdata(scn, NULL);
				break;
			}
		}

		scn = elf_nextscn(elf, scn);
	}

	if (!rule_data) {
		debug("kABI rules not found");
		return;
	}

	rule_str = rule_data->d_buf;
	left = shdr->sh_size;

	if (left < KABI_RULE_MIN_ENTRY_SIZE)
		error("kABI rule section too small: %zd bytes", left);

	if (rule_str[left - 1] != '\0')
		error("kABI rules are not null-terminated");

	while (left > KABI_RULE_MIN_ENTRY_SIZE) {
		enum kabi_rule_type type = KABI_RULE_TYPE_UNKNOWN;
		const char *field;
		struct rule *rule;

		/* version */
		field = get_rule_field(&rule_str, &left);

		if (strcmp(field, KABI_RULE_VERSION))
			error("unsupported kABI rule version: '%s'", field);

		/* type */
		field = get_rule_field(&rule_str, &left);

		for (i = 0; i < ARRAY_SIZE(rule_types); i++) {
			if (!strcmp(field, rule_types[i].tag)) {
				type = rule_types[i].type;
				break;
			}
		}

		if (type == KABI_RULE_TYPE_UNKNOWN)
			error("unsupported kABI rule type: '%s'", field);

		rule = xmalloc(sizeof(struct rule));

		rule->type = type;
		rule->target = xstrdup(get_rule_field(&rule_str, &left));
		rule->value = xstrdup(get_rule_field(&rule_str, &left));

		hash_add(rules, &rule->hash, __rule_hash(rule));

		debug("kABI rule: type: '%s', target: '%s', value: '%s'", field,
		      rule->target, rule->value);
	}

	if (left > 0)
		warn("unexpected data at the end of the kABI rules section");

	check(elf_end(elf));
}

bool kabi_is_struct_declonly(const char *fqn)
{
	struct rule *rule;

	if (!stable)
		return false;
	if (!fqn || !*fqn)
		return false;

	hash_for_each_possible(rules, rule, hash,
			       rule_hash(KABI_RULE_TYPE_STRUCT_DECLONLY, fqn,
					 KABI_RULE_EMPTY_VALUE)) {
		if (rule->type == KABI_RULE_TYPE_STRUCT_DECLONLY &&
		    !strcmp(fqn, rule->target))
			return true;
	}

	return false;
}

bool kabi_is_enumerator_ignored(const char *fqn, const char *field)
{
	struct rule *rule;

	if (!stable)
		return false;
	if (!fqn || !*fqn || !field || !*field)
		return false;

	hash_for_each_possible(rules, rule, hash,
			       rule_hash(KABI_RULE_TYPE_ENUMERATOR_IGNORE, fqn,
					 field)) {
		if (rule->type == KABI_RULE_TYPE_ENUMERATOR_IGNORE &&
		    !strcmp(fqn, rule->target) && !strcmp(field, rule->value))
			return true;
	}

	return false;
}

void kabi_free(void)
{
	struct hlist_node *tmp;
	struct rule *rule;

	hash_for_each_safe(rules, rule, tmp, hash) {
		free((void *)rule->target);
		free((void *)rule->value);
		free(rule);
	}

	hash_init(rules);
}
