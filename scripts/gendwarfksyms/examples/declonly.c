// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 *
 * Declaration-only data structure example. See dwarf.c:is_declaration
 * for details.
 *
 * $ gcc -g -c examples/declonly.c
 * $ echo exported | ./gendwarfksyms --dump-dies declonly.o
 * variable structure_type struct0 {
 *   member base_type int byte_size(4) encoding(5) data_member_location(0),
 * } byte_size(4)
 *
 * With --stable, struct0 is treated as a declaration:
 *
 * $ echo exported | ./gendwarfksyms --stable --dump-dies declonly.o
 * variable structure_type struct0 {
 * }
 */

#define GENDWARFKSYMS_DECLONLY(structname) \
	static void *__gendwarfksyms_declonly_##structname \
		__attribute__((__used__)) \
		__attribute__((__section__(".discard.gendwarfksyms")));

struct struct0 {
	int a;
};

struct struct0 exported;
GENDWARFKSYMS_DECLONLY(struct0);
