// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include "gendwarfksyms.h"

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

/*
 * Exported symbol processing
 */
static int process_subprogram(struct state *state, Dwarf_Die *die)
{
	return check(process(state, "subprogram;\n"));
}

static int process_variable(struct state *state, Dwarf_Die *die)
{
	return check(process(state, "variable;\n"));
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
