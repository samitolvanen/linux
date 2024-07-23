// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Google LLC
 *
 * Reserved data structure field example. See dwarf.c:process_reserved
 * for details.
 *
 * $ gcc -g -c examples/reserved.c
 *
 * With --stable, only the reserved field placeholder is used for calculating
 * symbol versions.
 *
 * $ echo exported0 | ./gendwarfksyms --stable --dump-dies reserved.o
 * variable structure_type struct0 {
 *   member base_type int byte_size(4) encoding(5) data_member_location(0),
 *   member base_type long int byte_size(8) encoding(5) data_member_location(8),
 * } byte_size(16)
 *
 * $ echo exported1 | ./gendwarfksyms --stable --dump-dies reserved.o
 * variable structure_type struct1 {
 *   member base_type int byte_size(4) encoding(5) data_member_location(0),
 *   member base_type long int byte_size(8) encoding(5) data_member_location(8),
 * } byte_size(16)
 *
 * $ echo exported2 | ./gendwarfksyms --stable --dump-dies reserved.o
 * variable structure_type struct2 {
 *   member base_type int byte_size(4) encoding(5) data_member_location(0),
 *   member base_type long int byte_size(8) encoding(5) data_member_location(8),
 * } byte_size(16)
 */

struct struct0 {
	int a;
	union {
		long __kabi_reserved_0;
		struct {
			int b;
			int c;
		};
	};
};

struct struct1 {
	int a;
	union {
		struct {
			int b;
			int c;
		};
		long __kabi_reserved_1;
	};
};

struct struct2 {
	int a;
	union {
		unsigned long b;
		struct {
			long __kabi_reserved_1;
		};
	};
};

struct struct0 exported0;
struct struct1 exported1;
struct struct2 exported2;
