// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"

#define DEFINE_GET_ATTR(attr, type)                                    \
	static bool get_##attr##_attr(Dwarf_Die *die, unsigned int id, \
				      type *value)                     \
	{                                                              \
		Dwarf_Attribute da;                                    \
		return dwarf_attr(die, id, &da) &&                     \
		       !dwarf_form##attr(&da, value);                  \
	}

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

/*
 * Type string processing
 */
static int process(struct state *state, const char *s)
{
	s = s ?: "<null>";

	if (debug)
		fputs(s, stderr);

	return 0;
}

#define MAX_FMT_BUFFER_SIZE 128

static int process_fmt(struct state *state, const char *fmt, ...)
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
		res = check(process(state, buf));
	}

	va_end(args);
	return res;
}

/* Process a fully qualified name from DWARF scopes */
static int process_fqn(struct state *state, Dwarf_Die *die)
{
	Dwarf_Die *scopes = NULL;
	const char *name;
	int res;
	int i;

	res = checkp(dwarf_getscopes_die(die, &scopes));
	if (!res) {
		name = get_name(die);
		name = name ?: "<unnamed>";
		return check(process(state, name));
	}

	for (i = res - 1; i >= 0; i--) {
		if (dwarf_tag(&scopes[i]) == DW_TAG_compile_unit)
			continue;

		name = get_name(&scopes[i]);
		name = name ?: "<unnamed>";
		check(process(state, name));
		if (i > 0)
			check(process(state, "::"));
	}

	free(scopes);
	return 0;
}

#define DEFINE_PROCESS_UDATA_ATTRIBUTE(attribute)                         \
	static int process_##attribute##_attr(struct state *state,        \
					      Dwarf_Die *die)             \
	{                                                                 \
		Dwarf_Word value;                                         \
		if (get_udata_attr(die, DW_AT_##attribute, &value))       \
			check(process_fmt(state,                          \
					  " " #attribute "(%" PRIu64 ")", \
					  value));                        \
		return 0;                                                 \
	}

DEFINE_PROCESS_UDATA_ATTRIBUTE(alignment)
DEFINE_PROCESS_UDATA_ATTRIBUTE(byte_size)
DEFINE_PROCESS_UDATA_ATTRIBUTE(encoding)

bool match_all(Dwarf_Die *die)
{
	return true;
}

int process_die_container(struct state *state, Dwarf_Die *die,
			  die_callback_t func, die_match_callback_t match)
{
	Dwarf_Die current;
	int res;

	res = checkp(dwarf_child(die, &current));
	while (!res) {
		if (match(&current))
			check(func(state, &current));
		res = checkp(dwarf_siblingof(&current, &current));
	}

	return 0;
}

static int process_type(struct state *state, Dwarf_Die *die);

static int process_type_attr(struct state *state, Dwarf_Die *die)
{
	Dwarf_Die type;

	if (get_ref_die_attr(die, DW_AT_type, &type))
		return check(process_type(state, &type));

	/* Compilers can omit DW_AT_type -- print out 'void' to clarify */
	return check(process(state, "base_type void"));
}

static int process_base_type(struct state *state, Dwarf_Die *die)
{
	check(process(state, "base_type "));
	check(process_fqn(state, die));
	check(process_byte_size_attr(state, die));
	check(process_encoding_attr(state, die));
	return check(process_alignment_attr(state, die));
}

static int process_type(struct state *state, Dwarf_Die *die)
{
	int tag = dwarf_tag(die);

	switch (tag) {
	case DW_TAG_base_type:
		check(process_base_type(state, die));
		break;
	default:
		debug("unimplemented type: %x", tag);
		break;
	}

	return 0;
}

/*
 * Exported symbol processing
 */
static int process_subprogram(struct state *state, Dwarf_Die *die)
{
	return check(process(state, "subprogram;\n"));
}

static int process_variable(struct state *state, Dwarf_Die *die)
{
	check(process(state, "variable "));
	check(process_type_attr(state, die));
	return check(process(state, ";\n"));
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

static int process_exported_symbols(struct state *state, Dwarf_Die *die)
{
	int tag = dwarf_tag(die);

	switch (tag) {
	/* Possible containers of exported symbols */
	case DW_TAG_namespace:
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
		return check(process_die_container(
			state, die, process_exported_symbols, match_all));

	/* Possible exported symbols */
	case DW_TAG_subprogram:
	case DW_TAG_variable:
		if (!is_export_symbol(state, die))
			return 0;

		debug("%s", state->sym->name);

		if (is_symbol_ptr(get_name(&state->die)))
			check(process_symbol_ptr(state, &state->die));
		else if (tag == DW_TAG_subprogram)
			check(process_subprogram(state, &state->die));
		else
			check(process_variable(state, &state->die));

		return 0;
	default:
		return 0;
	}
}

int process_module(Dwfl_Module *mod, Dwarf *dbg, Dwarf_Die *cudie)
{
	struct state state = { .mod = mod, .dbg = dbg };

	return check(process_die_container(
		&state, cudie, process_exported_symbols, match_all));
}
