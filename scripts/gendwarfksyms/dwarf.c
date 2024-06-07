// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"

static bool do_linebreak;
static int indentation_level;

/* Line breaks and indentation for pretty-printing */
static int process_linebreak(struct die *cache, int n)
{
	indentation_level += n;
	do_linebreak = true;
	return check(die_map_add_linebreak(cache, n));
}

#define DEFINE_GET_ATTR(attr, type)                                    \
	static bool get_##attr##_attr(Dwarf_Die *die, unsigned int id, \
				      type *value)                     \
	{                                                              \
		Dwarf_Attribute da;                                    \
		return dwarf_attr(die, id, &da) &&                     \
		       !dwarf_form##attr(&da, value);                  \
	}

DEFINE_GET_ATTR(flag, bool)
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

static bool is_export_symbol(struct state *state, Dwarf_Die *die)
{
	Dwarf_Die *source = die;
	Dwarf_Die origin;

	state->sym = NULL;

	/* If the DIE has an abstract origin, use it for type information. */
	if (get_ref_die_attr(die, DW_AT_abstract_origin, &origin))
		source = &origin;

	state->sym = symbol_get(get_name(die));

	/* Look up using the origin name if there are no matches. */
	if (!state->sym && source != die)
		state->sym = symbol_get(get_name(source));

	state->die = *source;
	return !!state->sym;
}

static bool is_declaration(Dwarf_Die *die)
{
	bool value;

	return get_flag_attr(die, DW_AT_declaration, &value) && value;
}

/*
 * Type string processing
 */
static int process(struct state *state, struct die *cache, const char *s)
{
	s = s ?: "<null>";

	if (debug && do_linebreak) {
		fputs("\n", stderr);
		for (int i = 0; i < indentation_level; i++)
			fputs("  ", stderr);
		do_linebreak = false;
	}
	if (debug)
		fputs(s, stderr);

	return check(die_map_add_string(cache, s));
}

#define MAX_FMT_BUFFER_SIZE 128

static int process_fmt(struct state *state, struct die *cache, const char *fmt,
		       ...)
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

#define MAX_FQN_SIZE 64

/* Get a fully qualified name from DWARF scopes */
static int get_fqn(struct state *state, Dwarf_Die *die, char **fqn)
{
	const char *list[MAX_FQN_SIZE];
	Dwarf_Die *scopes = NULL;
	int count = 0;
	int len = 0;
	int res;
	int i;

	*fqn = NULL;

	res = checkp(dwarf_getscopes_die(die, &scopes));
	if (!res) {
		list[count] = get_name(die);

		if (!list[count])
			return 0;

		len += strlen(list[count]);
		count++;

		goto done;
	}

	for (i = res - 1; i >= 0 && count < MAX_FQN_SIZE; i--) {
		if (dwarf_tag(&scopes[i]) == DW_TAG_compile_unit)
			continue;

		/*
		 * If any of the DIEs in the scope is missing a name, consider
		 * the DIE to be unnamed.
		 */
		list[count] = get_name(&scopes[i]);

		if (!list[count]) {
			free(scopes);
			return 0;
		}

		len += strlen(list[count]);
		count++;

		if (i > 0) {
			list[count++] = "::";
			len += 2;
		}
	}

	if (count == MAX_FQN_SIZE)
		warn("increase MAX_FQN_SIZE: reached the maximum");

	free(scopes);

done:
	*fqn = malloc(len + 1);
	if (!*fqn) {
		error("malloc failed");
		return -1;
	}

	**fqn = '\0';

	for (i = 0; i < count; i++)
		strcat(*fqn, list[i]);

	return 0;
}

static int process_fqn(struct state *state, struct die *cache, Dwarf_Die *die)
{
	const char *fqn;

	if (!cache->fqn)
		check(get_fqn(state, die, &cache->fqn));

	fqn = cache->fqn;
	fqn = fqn ?: "<unnamed>";
	return check(process(state, cache, fqn));
}

#define DEFINE_PROCESS_UDATA_ATTRIBUTE(attribute)                         \
	static int process_##attribute##_attr(                            \
		struct state *state, struct die *cache, Dwarf_Die *die)   \
	{                                                                 \
		Dwarf_Word value;                                         \
		if (get_udata_attr(die, DW_AT_##attribute, &value))       \
			check(process_fmt(state, cache,                   \
					  " " #attribute "(%" PRIu64 ")", \
					  value));                        \
		return 0;                                                 \
	}

DEFINE_PROCESS_UDATA_ATTRIBUTE(accessibility)
DEFINE_PROCESS_UDATA_ATTRIBUTE(alignment)
DEFINE_PROCESS_UDATA_ATTRIBUTE(bit_size)
DEFINE_PROCESS_UDATA_ATTRIBUTE(byte_size)
DEFINE_PROCESS_UDATA_ATTRIBUTE(encoding)
DEFINE_PROCESS_UDATA_ATTRIBUTE(data_bit_offset)
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

int process_die_container(struct state *state, struct die *cache,
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

static int process_type(struct state *state, struct die *parent,
			Dwarf_Die *die);

static int process_type_attr(struct state *state, struct die *cache,
			     Dwarf_Die *die)
{
	Dwarf_Die type;

	if (get_ref_die_attr(die, DW_AT_type, &type))
		return check(process_type(state, cache, &type));

	/* Compilers can omit DW_AT_type -- print out 'void' to clarify */
	return check(process(state, cache, "base_type void"));
}

/* Comma-separated with DW_AT_type */
static int __process_list_type(struct state *state, struct die *cache,
			       Dwarf_Die *die, const char *type)
{
	check(process(state, cache, type));
	check(process_type_attr(state, cache, die));
	check(process_accessibility_attr(state, cache, die));
	check(process_bit_size_attr(state, cache, die));
	check(process_data_bit_offset_attr(state, cache, die));
	check(process_data_member_location_attr(state, cache, die));
	check(process(state, cache, ","));
	return check(process_linebreak(cache, 0));
}

#define DEFINE_PROCESS_LIST_TYPE(type)                                      \
	static int process_##type##_type(struct state *state,               \
					 struct die *cache, Dwarf_Die *die) \
	{                                                                   \
		return __process_list_type(state, cache, die, #type " ");   \
	}

DEFINE_PROCESS_LIST_TYPE(formal_parameter)
DEFINE_PROCESS_LIST_TYPE(member)

/* Container types with DW_AT_type */
static int __process_type(struct state *state, struct die *cache,
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

#define DEFINE_PROCESS_TYPE(type)                                           \
	static int process_##type##_type(struct state *state,               \
					 struct die *cache, Dwarf_Die *die) \
	{                                                                   \
		return __process_type(state, cache, die, #type "_type ");   \
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

static int process_subrange_type(struct state *state, struct die *cache,
				 Dwarf_Die *die)
{
	Dwarf_Word count = 0;

	if (get_udata_attr(die, DW_AT_count, &count))
		return check(process_fmt(state, cache, "[%" PRIu64 "]", count));
	if (get_udata_attr(die, DW_AT_upper_bound, &count))
		return check(
			process_fmt(state, cache, "[%" PRIu64 "]", count + 1));

	return check(process(state, cache, "[]"));
}

static int process_array_type(struct state *state, struct die *cache,
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

static int __process_subroutine_type(struct state *state, struct die *cache,
				     Dwarf_Die *die, const char *type)
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

static int process_subroutine_type(struct state *state, struct die *cache,
				   Dwarf_Die *die)
{
	return check(__process_subroutine_type(state, cache, die,
					       "subroutine_type"));
}
static int process_variant_type(struct state *state, struct die *cache,
				Dwarf_Die *die)
{
	return check(process_die_container(state, cache, die, process_type,
					   match_member_type));
}

static int process_variant_part_type(struct state *state, struct die *cache,
				     Dwarf_Die *die)
{
	check(process(state, cache, "variant_part {"));
	check(process_linebreak(cache, 1));
	check(process_die_container(state, cache, die, process_type,
				    match_variant_type));
	check(process_linebreak(cache, -1));
	check(process(state, cache, "},"));
	return check(process_linebreak(cache, 0));
}

static int ___process_structure_type(struct state *state, struct die *cache,
				     Dwarf_Die *die)
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

static int __process_structure_type(struct state *state, struct die *cache,
				    Dwarf_Die *die, const char *type,
				    die_callback_t process_func,
				    die_match_callback_t match_func)
{
	bool is_decl = is_declaration(die);

	check(process(state, cache, type));
	check(process_fqn(state, cache, die));
	check(process(state, cache, " {"));
	check(process_linebreak(cache, 1));

	if (!is_decl && state->expand.expand) {
		check(cache_mark_expanded(&state->expansion_cache, die->addr));
		check(process_die_container(state, cache, die, process_func,
					    match_func));
	}

	check(process_linebreak(cache, -1));
	check(process(state, cache, "}"));

	if (!is_decl && state->expand.expand) {
		check(process_byte_size_attr(state, cache, die));
		check(process_alignment_attr(state, cache, die));
	}

	return 0;
}

#define DEFINE_PROCESS_STRUCTURE_TYPE(structure)                        \
	static int process_##structure##_type(                          \
		struct state *state, struct die *cache, Dwarf_Die *die) \
	{                                                               \
		return check(__process_structure_type(                  \
			state, cache, die, #structure "_type ",         \
			___process_structure_type, match_all));         \
	}

DEFINE_PROCESS_STRUCTURE_TYPE(class)
DEFINE_PROCESS_STRUCTURE_TYPE(structure)
DEFINE_PROCESS_STRUCTURE_TYPE(union)

static int process_enumerator_type(struct state *state, struct die *cache,
				   Dwarf_Die *die)
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

static int process_enumeration_type(struct state *state, struct die *cache,
				    Dwarf_Die *die)
{
	return check(__process_structure_type(state, cache, die,
					      "enumeration_type ", process_type,
					      match_enumerator_type));
}

static int process_base_type(struct state *state, struct die *cache,
			     Dwarf_Die *die)
{
	check(process(state, cache, "base_type "));
	check(process_fqn(state, cache, die));
	check(process_byte_size_attr(state, cache, die));
	check(process_encoding_attr(state, cache, die));
	return check(process_alignment_attr(state, cache, die));
}

static int process_cached(struct state *state, struct die *cache,
			  Dwarf_Die *die)
{
	struct die_fragment *df = cache->list;
	Dwarf_Die child;

	while (df) {
		switch (df->type) {
		case STRING:
			check(process(state, NULL, df->data.str));
			break;
		case LINEBREAK:
			check(process_linebreak(NULL, df->data.linebreak));
			break;
		case DIE:
			if (!dwarf_die_addr_die(state->dbg,
						(void *)df->data.addr,
						&child)) {
				error("dwarf_die_addr_die failed");
				return -1;
			}
			check(process_type(state, NULL, &child));
			break;
		default:
			error("empty die_fragment");
			return -1;
		}
		df = df->next;
	}

	return 0;
}

static void state_init(struct state *state)
{
	state->expand.expand = true;
	state->expand.in_pointer_type = false;
	state->expand.ptr_expansion_depth = 0;
	hash_init(state->expansion_cache.cache);
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

static int process_type(struct state *state, struct die *parent, Dwarf_Die *die)
{
	enum die_state want_state = COMPLETE;
	struct die *cache = NULL;
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
		state->expand.expand =
			saved.expand &&
			!cache_was_expanded(&state->expansion_cache, die->addr);

	/* Keep track of pointer expansion depth */
	if (state->expand.expand && state->expand.in_pointer_type &&
	    is_expanded_type(tag))
		state->expand.ptr_expansion_depth++;

	/*
	 * If we have want_state already cached, use it instead of walking
	 * through DWARF.
	 */
	if (!state->expand.expand && is_expanded_type(tag))
		want_state = UNEXPANDED;

	check(die_map_get(die, want_state, &cache));

	if (cache->state == want_state) {
		if (want_state == COMPLETE && is_expanded_type(tag))
			check(cache_mark_expanded(&state->expansion_cache,
						  die->addr));

		check(process_cached(state, cache, die));
		check(die_map_add_die(parent, cache));

		expansion_state_restore(&state->expand, &saved);
		return 0;
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

	/* Update cache state and append to the parent (if any) */
	cache->tag = tag;
	cache->state = want_state;
	check(die_map_add_die(parent, cache));

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

static int process_symbol_ptr(struct state *state, Dwarf_Die *die)
{
	Dwarf_Die ptr_type;
	Dwarf_Die type;

	if (!get_ref_die_attr(die, DW_AT_type, &ptr_type) ||
	    dwarf_tag(&ptr_type) != DW_TAG_pointer_type) {
		error("%s must be a pointer type!", get_name(die));
		return -1;
	}

	if (!get_ref_die_attr(&ptr_type, DW_AT_type, &type)) {
		error("%s pointer missing a type attribute?", get_name(die));
		return -1;
	}

	if (dwarf_tag(&type) == DW_TAG_subroutine_type)
		return check(process_subprogram(state, &type));
	else
		return check(process_variable(state, &ptr_type));
}

static int process_exported_symbols(struct state *state, struct die *cache,
				    Dwarf_Die *die)
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
		if (!is_export_symbol(state, die))
			return 0;

		debug("%s", state->sym->name);
		state_init(state);

		if (is_symbol_ptr(get_name(&state->die)))
			check(process_symbol_ptr(state, &state->die));
		else if (tag == DW_TAG_subprogram)
			check(process_subprogram(state, &state->die));
		else
			check(process_variable(state, &state->die));

		cache_clear_expanded(&state->expansion_cache);
		return 0;
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
