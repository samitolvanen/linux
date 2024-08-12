// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 */

#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include "gendwarfksyms.h"

/*
 * Options
 */

/* Print out debugging information to stderr */
bool debug;

static const struct {
	const char *arg;
	bool *flag;
	const char **param;
} options[] = {
	{ "--debug", &debug, NULL },
};

static int usage(void)
{
	error("usage: gendwarfksyms [options] elf-object-file ... < symbol-list");
	return -1;
}

static const char *object_files[MAX_INPUT_FILES];
static unsigned int object_count;

static int parse_options(int argc, const char **argv)
{
	for (int i = 1; i < argc; i++) {
		bool flag = false;

		for (int j = 0; j < ARRAY_SIZE(options); j++) {
			if (strcmp(argv[i], options[j].arg))
				continue;

			*options[j].flag = true;

			if (options[j].param) {
				if (++i >= argc) {
					error("%s needs an argument",
					      options[j].arg);
					return -1;
				}

				*options[j].param = argv[i];
			}

			flag = true;
			break;
		}

		if (!flag)
			object_files[object_count++] = argv[i];
	}

	return object_count ? 0 : -1;
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
			break; /* No more units */
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
	unsigned int n;

	if (parse_options(argc, argv) < 0)
		return usage();

	check(symbol_read_exports(stdin));

	for (n = 0; n < object_count; n++) {
		Dwfl *dwfl;
		int fd;

		fd = open(object_files[n], O_RDONLY);
		if (fd == -1) {
			error("open failed for '%s': %s", object_files[n],
			      strerror(errno));
			return -1;
		}

		check(symbol_read_symtab(fd));

		dwfl = dwfl_begin(&callbacks);
		if (!dwfl) {
			error("dwfl_begin failed for '%s': %s", object_files[n],
			      dwarf_errmsg(-1));
			return -1;
		}

		if (!dwfl_report_offline(dwfl, object_files[n], object_files[n],
					 fd)) {
			error("dwfl_report_offline failed for '%s': %s",
			      object_files[n], dwarf_errmsg(-1));
			return -1;
		}

		dwfl_report_end(dwfl, NULL, NULL);

		if (dwfl_getmodules(dwfl, &process_modules, NULL, 0)) {
			error("dwfl_getmodules failed for '%s'",
			      object_files[n]);
			return -1;
		}

		dwfl_end(dwfl);
		close(fd);
	}

	return 0;
}
