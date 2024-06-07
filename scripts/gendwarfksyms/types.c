// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"
#include "crc32.h"

static bool do_linebreak;
static int indentation_level;

/* Line breaks and indentation for pretty-printing */
static int process_linebreak(struct cached_die *cache, int n)
{
	indentation_level += n;
	do_linebreak = true;
	return check(cache_add_linebreak(cache, n));
}

#define DEFINE_GET_ATTR(attr, type)                                    \
	static bool get_##attr##_attr(Dwarf_Die *die, unsigned int id, \
				      type *value)                     \
	{                                                              \
		Dwarf_Attribute da;                                    \
		return dwarf_attr(die, id, &da) &&                     \
		       !dwarf_form##attr(&da, value);                  \
	}

DEFINE_GET_ATTR(addr, Dwarf_Addr)
DEFINE_GET_ATTR(udata, Dwarf_Word)

static bool get_ref_die_attr(Dwarf_Die *die, unsigned int id, Dwarf_Die *value)
{
	Dwarf_Attribute da;

	/* dwarf_formref_die returns a pointer instead of an error value. */
	return dwarf_attr(die, id, &da) && dwarf_formref_die(&da, value);
}

static const char *get_name(Dwarf_Die *die)
{
	Dwarf_Attribute attr;

	/* rustc uses DW_AT_linkage_name for exported symbols */
	if (dwarf_attr(die, DW_AT_linkage_name, &attr) ||
	    dwarf_attr(die, DW_AT_name, &attr)) {
		return dwarf_formstring(&attr);
	}

	return NULL;
}

static bool is_unprocessed_export_symbol(struct state *state, Dwarf_Die *die)
{
	Dwarf_Die *source = die;
	Dwarf_Word addr = UINTPTR_MAX;
	Dwarf_Die origin;

	state->sym = NULL;

	/* If the DIE has an abstract origin, use it for type information. */
	if (get_ref_die_attr(die, DW_AT_abstract_origin, &origin))
		source = &origin;

	/*
	 * Only one name is emitted for aliased functions, so we must match
	 * the address too, if available.
	 */
	if (get_addr_attr(die, DW_AT_low_pc, &addr) &&
	    dwfl_module_relocate_address(state->mod, &addr) < 0) {
		error("dwfl_module_relocate_address failed");
		return NULL;
	}

	state->sym = symbol_get_unprocessed(addr, get_name(die));

	/* Look up using the origin name if there are no matches. */
	if (!state->sym && source != die)
		state->sym = symbol_get_unprocessed(addr, get_name(source));

	state->die = *source;
	return !!state->sym;
}

/*
 * Type string and CRC processing
 */
static int process(struct state *state, struct cached_die *cache, const char *s)
{
	s = s ?: "<null>";

	if (debug && !no_pretty_print && do_linebreak) {
		fputs("\n", stderr);
		for (int i = 0; i < indentation_level; i++)
			fputs("  ", stderr);
		do_linebreak = false;
	}
	if (debug)
		fputs(s, stderr);

	state->crc = partial_crc32(s, state->crc);
	return cache_add_string(cache, s);
}

#define MAX_FMT_BUFFER_SIZE 128

static int process_fmt(struct state *state, struct cached_die *cache,
		       const char *fmt, ...)
{
	char buf[MAX_FMT_BUFFER_SIZE];
	va_list args;
	int res;

	va_start(args, fmt);

	res = checkp(vsnprintf(buf, sizeof(buf), fmt, args));
	if (res >= MAX_FMT_BUFFER_SIZE - 1) {
		error("vsnprintf overflow: increase MAX_FMT_BUFFER_SIZE");
		res = -1;
	} else {
		res = check(process(state, cache, buf));
	}

	va_end(args);
	return res;
}

/* Process a fully qualified name from DWARF scopes */
static int process_fqn(struct state *state, struct cached_die *cache,
		       Dwarf_Die *die)
{
	Dwarf_Die *scopes = NULL;
	const char *name;
	int res;
	int i;

	res = checkp(dwarf_getscopes_die(die, &scopes));
	if (!res) {
		name = get_name(die);
		name = name ?: "<unnamed>";
		return check(process(state, cache, name));
	}

	for (i = res - 1; i >= 0; i--) {
		if (dwarf_tag(&scopes[i]) == DW_TAG_compile_unit)
			continue;

		name = get_name(&scopes[i]);
		name = name ?: "<unnamed>";
		check(process(state, cache, name));
		if (i > 0)
			check(process(state, cache, "::"));
	}

	free(scopes);
	return 0;
}

#define DEFINE_PROCESS_UDATA_ATTRIBUTE(attribute)                              \
	static int process_##attribute##_attr(                                 \
		struct state *state, struct cached_die *cache, Dwarf_Die *die) \
	{                                                                      \
		Dwarf_Word value;                                              \
		if (get_udata_attr(die, DW_AT_##attribute, &value))            \
			check(process_fmt(state, cache,                        \
					  " " #attribute "(%" PRIu64 ")",      \
					  value));                             \
		return 0;                                                      \
	}

DEFINE_PROCESS_UDATA_ATTRIBUTE(accessibility)
DEFINE_PROCESS_UDATA_ATTRIBUTE(alignment)
DEFINE_PROCESS_UDATA_ATTRIBUTE(byte_size)
DEFINE_PROCESS_UDATA_ATTRIBUTE(data_member_location)

/* Match functions -- die_match_callback_t */
#define DEFINE_MATCH(type)                                     \
	static bool match_##type##_type(Dwarf_Die *die)        \
	{                                                      \
		return dwarf_tag(die) == DW_TAG_##type##_type; \
	}

DEFINE_MATCH(enumerator)
DEFINE_MATCH(formal_parameter)
DEFINE_MATCH(member)
DEFINE_MATCH(subrange)
DEFINE_MATCH(variant)

bool match_all(Dwarf_Die *die)
{
	return true;
}

int process_die_container(struct state *state, struct cached_die *cache,
			  Dwarf_Die *die, die_callback_t func,
			  die_match_callback_t match)
{
	Dwarf_Die current;
	int res;

	res = checkp(dwarf_child(die, &current));
	while (!res) {
		if (match(&current))
			check(func(state, cache, &current));
		res = checkp(dwarf_siblingof(&current, &current));
	}

	return 0;
}

static int process_type(struct state *state, struct cached_die *parent,
			Dwarf_Die *die);

static int process_type_attr(struct state *state, struct cached_die *cache,
			     Dwarf_Die *die)
{
	Dwarf_Die type;

	if (get_ref_die_attr(die, DW_AT_type, &type))
		return check(process_type(state, cache, &type));

	/* Compilers can omit DW_AT_type -- print out 'void' to clarify */
	return check(process(state, cache, "base_type void"));
}

/* Comma-separated with DW_AT_type */
static int __process_list_type(struct state *state, struct cached_die *cache,
			       Dwarf_Die *die, const char *type)
{
	check(process(state, cache, type));
	check(process_type_attr(state, cache, die));
	check(process_accessibility_attr(state, cache, die));
	check(process_data_member_location_attr(state, cache, die));
	check(process(state, cache, ","));
	return check(process_linebreak(cache, 0));
}

#define DEFINE_PROCESS_LIST_TYPE(type)                                         \
	static int process_##type##_type(                                      \
		struct state *state, struct cached_die *cache, Dwarf_Die *die) \
	{                                                                      \
		return __process_list_type(state, cache, die, #type " ");      \
	}

DEFINE_PROCESS_LIST_TYPE(formal_parameter)
DEFINE_PROCESS_LIST_TYPE(member)

/* Container types with DW_AT_type */
static int __process_type(struct state *state, struct cached_die *cache,
			  Dwarf_Die *die, const char *type)
{
	check(process(state, cache, type));
	check(process_fqn(state, cache, die));
	check(process(state, cache, " {"));
	check(process_linebreak(cache, 1));
	check(process_type_attr(state, cache, die));
	check(process_linebreak(cache, -1));
	check(process(state, cache, "}"));
	check(process_byte_size_attr(state, cache, die));
	return check(process_alignment_attr(state, cache, die));
}

#define DEFINE_PROCESS_TYPE(type)                                              \
	static int process_##type##_type(                                      \
		struct state *state, struct cached_die *cache, Dwarf_Die *die) \
	{                                                                      \
		return __process_type(state, cache, die, #type "_type ");      \
	}

DEFINE_PROCESS_TYPE(atomic)
DEFINE_PROCESS_TYPE(const)
DEFINE_PROCESS_TYPE(immutable)
DEFINE_PROCESS_TYPE(packed)
DEFINE_PROCESS_TYPE(pointer)
DEFINE_PROCESS_TYPE(reference)
DEFINE_PROCESS_TYPE(restrict)
DEFINE_PROCESS_TYPE(rvalue_reference)
DEFINE_PROCESS_TYPE(shared)
DEFINE_PROCESS_TYPE(template_type_parameter)
DEFINE_PROCESS_TYPE(volatile)
DEFINE_PROCESS_TYPE(typedef)

static int process_subrange_type(struct state *state, struct cached_die *cache,
				 Dwarf_Die *die)
{
	Dwarf_Word count = 0;

	if (get_udata_attr(die, DW_AT_count, &count))
		return check(process_fmt(state, cache, "[%" PRIu64 "]", count));

	return check(process(state, cache, "[]"));
}

static int process_array_type(struct state *state, struct cached_die *cache,
			      Dwarf_Die *die)
{
	check(process(state, cache, "array_type "));
	/* Array size */
	check(process_die_container(state, cache, die, process_type,
				    match_subrange_type));
	check(process(state, cache, " {"));
	check(process_linebreak(cache, 1));
	check(process_type_attr(state, cache, die));
	check(process_linebreak(cache, -1));
	return check(process(state, cache, "}"));
}

static int __process_subroutine_type(struct state *state,
				     struct cached_die *cache, Dwarf_Die *die,
				     const char *type)
{
	check(process(state, cache, type));
	check(process(state, cache, "("));
	check(process_linebreak(cache, 1));
	/* Parameters */
	check(process_die_container(state, cache, die, process_type,
				    match_formal_parameter_type));
	check(process_linebreak(cache, -1));
	check(process(state, cache, ")"));
	process_linebreak(cache, 0);
	/* Return type */
	check(process(state, cache, "-> "));
	return check(process_type_attr(state, cache, die));
}

static int process_subroutine_type(struct state *state,
				   struct cached_die *cache, Dwarf_Die *die)
{
	return check(__process_subroutine_type(state, cache, die,
					       "subroutine_type"));
}

static int process_variant_type(struct state *state, struct cached_die *cache,
				Dwarf_Die *die)
{
	return check(process_die_container(state, cache, die, process_type,
					   match_member_type));
}

static int process_variant_part_type(struct state *state,
				     struct cached_die *cache, Dwarf_Die *die)
{
	check(process(state, cache, "variant_part {"));
	check(process_linebreak(cache, 1));
	check(process_die_container(state, cache, die, process_type,
				    match_variant_type));
	check(process_linebreak(cache, -1));
	check(process(state, cache, "},"));
	return check(process_linebreak(cache, 0));
}

static int ___process_structure_type(struct state *state,
				     struct cached_die *cache, Dwarf_Die *die)
{
	switch (dwarf_tag(die)) {
	case DW_TAG_member:
	case DW_TAG_variant_part:
		return check(process_type(state, cache, die));
	case DW_TAG_class_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_structure_type:
	case DW_TAG_template_type_parameter:
	case DW_TAG_union_type:
		check(process_type(state, cache, die));
		check(process(state, cache, ","));
		return check(process_linebreak(cache, 0));
	case DW_TAG_subprogram:
		return 0; /* Skip member functions */
	default:
		error("unexpected structure_type child: %x", dwarf_tag(die));
		return -1;
	}
}

static int __process_structure_type(struct state *state,
				    struct cached_die *cache, Dwarf_Die *die,
				    const char *type,
				    die_callback_t process_func,
				    die_match_callback_t match_func)
{
	check(process(state, cache, type));
	check(process_fqn(state, cache, die));
	check(process(state, cache, " {"));
	check(process_linebreak(cache, 1));

	if (state->expand.expand) {
		check(cache_mark_expanded(state, die));
		check(process_die_container(state, cache, die, process_func,
					    match_func));
	} else {
		check(process(state, cache, "<unexpanded>"));
	}

	check(process_linebreak(cache, -1));
	check(process(state, cache, "}"));

	if (state->expand.expand) {
		check(process_byte_size_attr(state, cache, die));
		check(process_alignment_attr(state, cache, die));
	}

	return 0;
}

#define DEFINE_PROCESS_STRUCTURE_TYPE(structure)                               \
	static int process_##structure##_type(                                 \
		struct state *state, struct cached_die *cache, Dwarf_Die *die) \
	{                                                                      \
		return check(__process_structure_type(                         \
			state, cache, die, #structure "_type ",                \
			___process_structure_type, match_all));                \
	}

DEFINE_PROCESS_STRUCTURE_TYPE(class)
DEFINE_PROCESS_STRUCTURE_TYPE(structure)
DEFINE_PROCESS_STRUCTURE_TYPE(union)

static int process_enumerator_type(struct state *state,
				   struct cached_die *cache, Dwarf_Die *die)
{
	Dwarf_Word value;

	check(process(state, cache, "enumerator "));
	check(process_fqn(state, cache, die));

	if (get_udata_attr(die, DW_AT_const_value, &value)) {
		check(process(state, cache, " = "));
		check(process_fmt(state, cache, "%" PRIu64, value));
	}

	check(process(state, cache, ","));
	return check(process_linebreak(cache, 0));
}

static int process_enumeration_type(struct state *state,
				    struct cached_die *cache, Dwarf_Die *die)
{
	return check(__process_structure_type(state, cache, die,
					      "enumeration_type ", process_type,
					      match_enumerator_type));
}

static int process_base_type(struct state *state, struct cached_die *cache,
			     Dwarf_Die *die)
{
	check(process(state, cache, "base_type "));
	check(process_fqn(state, cache, die));
	check(process_byte_size_attr(state, cache, die));
	return check(process_alignment_attr(state, cache, die));
}

static int process_cached(struct state *state, struct cached_die *cache,
			  Dwarf_Die *die)
{
	struct cached_item *ci = cache->list;
	Dwarf_Die child;

	while (ci) {
		switch (ci->type) {
		case STRING:
			check(process(state, NULL, ci->data.str));
			break;
		case LINEBREAK:
			check(process_linebreak(NULL, ci->data.linebreak));
			break;
		case DIE:
			if (!dwarf_die_addr_die(state->dbg,
						(void *)ci->data.addr,
						&child)) {
				error("dwarf_die_addr_die failed");
				return -1;
			}
			check(process_type(state, NULL, &child));
			break;
		default:
			error("empty cached_item");
			return -1;
		}
		ci = ci->next;
	}

	return 0;
}

static void state_init(struct state *state)
{
	state->expand.expand = true;
	state->expand.in_pointer_type = false;
	state->expand.ptr_expansion_depth = 0;
	state->crc = 0xffffffff;
}
static void expansion_state_restore(struct expansion_state *state,
				    struct expansion_state *saved)
{
	state->ptr_expansion_depth = saved->ptr_expansion_depth;
	state->in_pointer_type = saved->in_pointer_type;
	state->expand = saved->expand;
}

static void expansion_state_save(struct expansion_state *state,
				 struct expansion_state *saved)
{
	expansion_state_restore(saved, state);
}

static bool is_pointer_type(int tag)
{
	return tag == DW_TAG_pointer_type || tag == DW_TAG_reference_type;
}

static bool is_expanded_type(int tag)
{
	return tag == DW_TAG_class_type || tag == DW_TAG_structure_type ||
	       tag == DW_TAG_union_type || tag == DW_TAG_enumeration_type;
}

/* The maximum depth for expanding structures in pointers */
#define MAX_POINTER_EXPANSION_DEPTH 2

#define PROCESS_TYPE(type)                                       \
	case DW_TAG_##type##_type:                               \
		check(process_##type##_type(state, cache, die)); \
		break;

static int process_type(struct state *state, struct cached_die *parent,
			Dwarf_Die *die)
{
	enum cached_die_state want_state = COMPLETE;
	struct cached_die *cache = NULL;
	struct expansion_state saved;
	int tag = dwarf_tag(die);

	expansion_state_save(&state->expand, &saved);

	/*
	 * Structures and enumeration types are expanded only once per
	 * exported symbol. This is sufficient for detecting ABI changes
	 * within the structure.
	 *
	 * If the exported symbol contains a pointer to a structure,
	 * at most MAX_POINTER_EXPANSION_DEPTH levels are expanded into
	 * the referenced structure.
	 */
	state->expand.in_pointer_type = saved.in_pointer_type ||
					is_pointer_type(tag);

	if (state->expand.in_pointer_type &&
	    state->expand.ptr_expansion_depth >= MAX_POINTER_EXPANSION_DEPTH)
		state->expand.expand = false;
	else
		state->expand.expand = saved.expand &&
				       !cache_was_expanded(state, die);

	/* Keep track of pointer expansion depth */
	if (state->expand.expand && state->expand.in_pointer_type &&
	    is_expanded_type(tag))
		state->expand.ptr_expansion_depth++;

	/*
	 * If we have want_state already cached, use it instead of walking
	 * through DWARF.
	 */
	if (!no_cache) {
		if (!state->expand.expand && is_expanded_type(tag))
			want_state = UNEXPANDED;

		check(cache_get(die, want_state, &cache));

		if (cache->state == want_state) {
			if (want_state == COMPLETE && is_expanded_type(tag))
				check(cache_mark_expanded(state, die));

			check(process_cached(state, cache, die));
			check(cache_add_die(parent, die));

			expansion_state_restore(&state->expand, &saved);
			return 0;
		}
	}

	switch (tag) {
	/* Type modifiers */
	PROCESS_TYPE(atomic)
	PROCESS_TYPE(const)
	PROCESS_TYPE(immutable)
	PROCESS_TYPE(packed)
	PROCESS_TYPE(pointer)
	PROCESS_TYPE(reference)
	PROCESS_TYPE(restrict)
	PROCESS_TYPE(rvalue_reference)
	PROCESS_TYPE(shared)
	PROCESS_TYPE(volatile)
	/* Container types */
	PROCESS_TYPE(class)
	PROCESS_TYPE(structure)
	PROCESS_TYPE(union)
	PROCESS_TYPE(enumeration)
	/* Subtypes */
	PROCESS_TYPE(enumerator)
	PROCESS_TYPE(formal_parameter)
	PROCESS_TYPE(member)
	PROCESS_TYPE(subrange)
	PROCESS_TYPE(template_type_parameter)
	PROCESS_TYPE(variant)
	PROCESS_TYPE(variant_part)
	/* Other types */
	PROCESS_TYPE(array)
	PROCESS_TYPE(base)
	PROCESS_TYPE(subroutine)
	PROCESS_TYPE(typedef)
	default:
		error("unexpected type: %x", tag);
		return -1;
	}

	if (!no_cache) {
		/* Update cache state and append to the parent (if any) */
		cache->state = want_state;
		check(cache_add_die(parent, die));
	}

	expansion_state_restore(&state->expand, &saved);
	return 0;
}

/*
 * Exported symbol processing
 */
static int process_subprogram(struct state *state, Dwarf_Die *die)
{
	check(__process_subroutine_type(state, NULL, die, "subprogram"));
	return check(process(state, NULL, ";\n"));
}

static int process_variable(struct state *state, Dwarf_Die *die)
{
	check(process(state, NULL, "variable "));
	check(process_type_attr(state, NULL, die));
	return check(process(state, NULL, ";\n"));
}

static int process_exported_symbols(struct state *state,
				    struct cached_die *cache, Dwarf_Die *die)
{
	int tag = dwarf_tag(die);

	switch (tag) {
	/* Possible containers of exported symbols */
	case DW_TAG_namespace:
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
		return check(process_die_container(state, cache, die,
						   process_exported_symbols,
						   match_all));

	/* Possible exported symbols */
	case DW_TAG_subprogram:
	case DW_TAG_variable:
		if (!is_unprocessed_export_symbol(state, die))
			return 0;

		/*
		 * For each exported symbol, compute a CRC of the expanded type
		 * description.
		 */
		debug("%s (@ %lx)", state->sym->name, state->sym->addr);
		state_init(state);

		if (tag == DW_TAG_subprogram)
			check(process_subprogram(state, &state->die));
		else
			check(process_variable(state, &state->die));

		cache_clear_expanded(state);
		return check(
			symbol_set_crc(state->sym, state->crc ^ 0xffffffff));
	default:
		return 0;
	}
}

int process_module(Dwfl_Module *mod, Dwarf *dbg, Dwarf_Die *cudie)
{
	struct state state = { .mod = mod, .dbg = dbg };

	return check(process_die_container(
		&state, NULL, cudie, process_exported_symbols, match_all));
}
