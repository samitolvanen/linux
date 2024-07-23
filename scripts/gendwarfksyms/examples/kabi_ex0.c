// SPDX-License-Identifier: GPL-2.0
/*
 * kabi_ex0.c
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
 * $ gcc -g -c examples/kabi_ex0.c examples/kabi_ex0.o
 *
 * Verify --stable output:
 *
 * $ echo -e "ex0a\nex0b\nex0c" | \
 * 	./gendwarfksyms --stable --dump-dies \
 * 		examples/kabi_ex0.o 2>&1 >/dev/null | \
 * 	FileCheck examples/kabi_ex0.c --check-prefix=STABLE
 *
 * Verify that symbol versions match with --stable:
 *
 * $ echo -e "ex0a\nex0b\nex0c" | \
 * 	./gendwarfksyms --stable examples/kabi_ex0.o | \
 * 	sort | \
 * 	FileCheck examples/kabi_ex0.c --check-prefix=VERSION
 */

#include "kabi.h"

/*
 * Example 0: Reserved fields.
 */

struct {
	int a;
	KABI_RESERVE(0);
	KABI_RESERVE(1);
} ex0a;

/*
 * STABLE:      variable structure_type {
 * STABLE-NEXT:   member base_type int byte_size(4) encoding(5) a data_member_location(0) ,
 * STABLE-NEXT:   member base_type [[ULONG:long unsigned int|unsigned long]] byte_size(8) encoding(7) data_member_location(8) ,
 * STABLE-NEXT:   member base_type [[ULONG]] byte_size(8) encoding(7) data_member_location(16)
 * STABLE-NEXT: } byte_size(24)
 *
 * VERSION-DAG: #SYMVER ex0a 0x[[#%.08x,EX0:]]
 */

struct {
	int a;
	KABI_RESERVE(0);
	KABI_USE2(1, int b, int c);
} ex0b;

/*
 * STABLE:      variable structure_type {
 * STABLE-NEXT:   member base_type int byte_size(4) encoding(5) a data_member_location(0) ,
 * STABLE-NEXT:   member base_type [[ULONG]] byte_size(8) encoding(7) data_member_location(8) ,
 * STABLE-NEXT:   member base_type [[ULONG]] byte_size(8) encoding(7) data_member_location(16)
 *
 * STABLE-NEXT: } byte_size(24)
 *
 * VERSION-DAG: #SYMVER ex0b 0x[[#%.08x,EX0]]
 */

struct {
	int a;
	KABI_USE(0, void *p);
	KABI_USE2(1, int b, int c);
} ex0c;

/*
 * STABLE:      variable structure_type {
 * STABLE-NEXT:   member base_type int byte_size(4) encoding(5) a data_member_location(0) ,
 * STABLE-NEXT:   member base_type [[ULONG]] byte_size(8) encoding(7) data_member_location(8) ,
 * STABLE-NEXT:   member base_type [[ULONG]] byte_size(8) encoding(7) data_member_location(16)
 * STABLE-NEXT: } byte_size(24)
 *
 * VERSION-DAG: #SYMVER ex0c 0x[[#%.08x,EX0]]
 */
