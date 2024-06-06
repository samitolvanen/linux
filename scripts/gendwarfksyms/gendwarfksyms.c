// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include "gendwarfksyms.h"

/*
 * Options
 */

/* Print type descriptions and debugging output to stderr */
bool debug;

static const struct {
	const char *arg;
	bool *flag;
} options[] = {
	{ "--debug", &debug },
};

static int usage(void)
{
	error("usage: gendwarfksyms [options] elf-object-file < symbol-list");
	return -1;
}

static int parse_options(int argc, const char **argv, const char **filename)
{
	*filename = NULL;

	for (int i = 1; i < argc; i++) {
		bool found = false;

		for (int j = 0; j < ARRAY_SIZE(options); j++) {
			if (!strcmp(argv[i], options[j].arg)) {
				*options[j].flag = true;
				found = true;
				break;
			}
		}

		if (!found) {
			if (!*filename)
				*filename = argv[i];
			else
				return -1;
		}
	}

	return *filename ? 0 : -1;
}

static int process_modules(Dwfl_Module *mod, void **userdata, const char *name,
			   Dwarf_Addr base, void *arg)
{
	Dwarf_Addr dwbias;
	Dwarf_Die cudie;
	Dwarf_CU *cu = NULL;
	Dwarf *dbg;
	int res;

	debug("%s", name);
	dbg = dwfl_module_getdwarf(mod, &dwbias);

	do {
		res = dwarf_get_units(dbg, cu, &cu, NULL, NULL, &cudie, NULL);
		if (res < 0) {
			error("dwarf_get_units failed: no debugging information?");
			return -1;
		} else if (res == 1) {
			return DWARF_CB_OK; /* No more units */
		}

		check(process_module(mod, dbg, &cudie));
	} while (cu);

	return DWARF_CB_OK;
}

static const Dwfl_Callbacks callbacks = {
	.section_address = dwfl_offline_section_address,
	.find_debuginfo = dwfl_standard_find_debuginfo,
};

int main(int argc, const char **argv)
{
	const char *filename = NULL;
	Dwfl *dwfl;
	int fd;

	if (parse_options(argc, argv, &filename) < 0)
		return usage();

	check(symbol_read_list(stdin));

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		error("open failed for '%s': %s", filename, strerror(errno));
		return -1;
	}

	dwfl = dwfl_begin(&callbacks);
	if (!dwfl) {
		error("dwfl_begin failed for '%s': %s", filename,
		      dwarf_errmsg(-1));
		return -1;
	}

	if (!dwfl_report_offline(dwfl, filename, filename, fd)) {
		error("dwfl_report_offline failed for '%s': %s", filename,
		      dwarf_errmsg(-1));
		return -1;
	}

	dwfl_report_end(dwfl, NULL, NULL);

	if (dwfl_getmodules(dwfl, &process_modules, NULL, 0)) {
		error("dwfl_getmodules failed for '%s'", filename);
		return -1;
	}

	dwfl_end(dwfl);

	return 0;
}
