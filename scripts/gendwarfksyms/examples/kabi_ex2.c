// SPDX-License-Identifier: GPL-2.0
/*
 * kabi_ex2.c
 *
 * Copyright (C) 2024 Google LLC
 *
 * Reserved and ignored data structure field examples with --stable.
 */

/*
 * The comments below each example contain the expected gendwarfksyms
 * output, which can be verified using LLVM's FileCheck tool:
 *
 * https://llvm.org/docs/CommandGuide/FileCheck.html
 *
 * $ gcc -g -c examples/kabi_ex2.c examples/kabi_ex2.o
 *
 * Verify --stable output:
 *
 * $ echo -e "ex2a\nex2b\nex2c" | \
 * 	./gendwarfksyms --stable --dump-dies \
 * 		examples/kabi_ex2.o 2>&1 >/dev/null | \
 * 	FileCheck examples/kabi_ex2.c --check-prefix=STABLE
 *
 * Verify that symbol versions match with --stable:
 *
 * $ echo -e "ex2a\nex2b\nex2c" | \
 * 	./gendwarfksyms --stable examples/kabi_ex2.o | \
 * 	sort | \
 * 	FileCheck examples/kabi_ex2.c --check-prefix=VERSION
 */

#include "kabi.h"

/*
 * Example 2: An ignored field added to an alignment hole.
 */

struct {
	int a;
	unsigned long b;
	int c;
	unsigned long d;
} ex2a;

/*
 * STABLE:      variable structure_type {
 * STABLE-NEXT:   member base_type int byte_size(4) encoding(5) a data_member_location(0) ,
 * STABLE-NEXT:   member base_type [[ULONG:long unsigned int|unsigned long]] byte_size(8) encoding(7) b data_member_location(8)
 * STABLE-NEXT:   member base_type int byte_size(4) encoding(5) c data_member_location(16) ,
 * STABLE-NEXT:   member base_type [[ULONG]] byte_size(8) encoding(7) d data_member_location(24)
 * STABLE-NEXT: } byte_size(32)
 *
 * VERSION-DAG: #SYMVER ex2a 0x[[#%.08x,EX2:]]
 */

struct {
	int a;
	KABI_IGNORE(0, unsigned int n);
	unsigned long b;
	int c;
	unsigned long d;
} ex2b;

_Static_assert(sizeof(ex2a) == sizeof(ex2b), "ex2a size doesn't match ex2b");

/*
 * STABLE:      variable structure_type {
 * STABLE-NEXT:   member base_type int byte_size(4) encoding(5) a data_member_location(0) ,
 * STABLE-NEXT:   member base_type [[ULONG]] byte_size(8) encoding(7) b data_member_location(8)
 * STABLE-NEXT:   member base_type int byte_size(4) encoding(5) c data_member_location(16) ,
 * STABLE-NEXT:   member base_type [[ULONG]] byte_size(8) encoding(7) d data_member_location(24)
 * STABLE-NEXT: } byte_size(32)
 *
 * VERSION-DAG: #SYMVER ex2b 0x[[#%.08x,EX2]]
 */

struct {
	int a;
	KABI_IGNORE(0, unsigned int n);
	unsigned long b;
	int c;
	KABI_IGNORE(1, unsigned int m);
	unsigned long d;
} ex2c;

_Static_assert(sizeof(ex2a) == sizeof(ex2c), "ex2a size doesn't match ex2c");

/*
 * STABLE:      variable structure_type {
 * STABLE-NEXT:   member base_type int byte_size(4) encoding(5) a data_member_location(0) ,
 * STABLE-NEXT:   member base_type [[ULONG]] byte_size(8) encoding(7) b data_member_location(8)
 * STABLE-NEXT:   member base_type int byte_size(4) encoding(5) c data_member_location(16) ,
 * STABLE-NEXT:   member base_type [[ULONG]] byte_size(8) encoding(7) d data_member_location(24)
 * STABLE-NEXT: } byte_size(32)
 *
 * VERSION-DAG: #SYMVER ex2c 0x[[#%.08x,EX2]]
 */
