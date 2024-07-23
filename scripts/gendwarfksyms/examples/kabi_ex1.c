// SPDX-License-Identifier: GPL-2.0
/*
 * kabi_ex1.c
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
 * $ gcc -g -c examples/kabi_ex1.c examples/kabi_ex1.o
 *
 * Verify --stable output:
 *
 * $ echo -e "ex1a\nex1b\nex1c" | \
 * 	./gendwarfksyms --stable --dump-dies \
 * 		examples/kabi_ex1.o 2>&1 >/dev/null | \
 * 	FileCheck examples/kabi_ex1.c --check-prefix=STABLE
 *
 * Verify that symbol versions match with --stable:
 *
 * $ echo -e "ex1a\nex1b\nex1c" | \
 * 	./gendwarfksyms --stable examples/kabi_ex1.o | \
 * 	sort | \
 * 	FileCheck examples/kabi_ex1.c --check-prefix=VERSION
 */

#include "kabi.h"

/*
 * Example 1: A reserved array.
 */

struct {
	unsigned int a;
	KABI_RESERVE_ARRAY(0, 64);
} ex1a;

/*
 * STABLE:      variable structure_type {
 * STABLE-NEXT:   member base_type unsigned int byte_size(4) encoding(7) a data_member_location(0) ,
 * STABLE-NEXT:   member array_type[64] {
 * STABLE-NEXT:     base_type unsigned char byte_size(1) encoding(8)
 * STABLE-NEXT:   } data_member_location(8)
 * STABLE-NEXT: } byte_size(72)
 *
 * VERSION-DAG: #SYMVER ex1a 0x[[#%.08x,EX1:]]
 */

struct {
	unsigned int a;
	KABI_USE_ARRAY(
		0, 64, struct {
			void *p;
			KABI_RESERVE_ARRAY(1, 56);
		});
} ex1b;

/*
 * STABLE:      variable structure_type {
 * STABLE-NEXT:   member base_type unsigned int byte_size(4) encoding(7) a data_member_location(0) ,
 * STABLE-NEXT:   member array_type[64] {
 * STABLE-NEXT:     base_type unsigned char byte_size(1) encoding(8)
 * STABLE-NEXT:   } data_member_location(8)
 * STABLE-NEXT: } byte_size(72)
 *
 * VERSION-DAG: #SYMVER ex1b 0x[[#%.08x,EX1]]
 */

struct {
	unsigned int a;
	KABI_USE_ARRAY(0, 64, void *p[8]);
} ex1c;

/*
 * STABLE:      variable structure_type {
 * STABLE-NEXT:   member base_type unsigned int byte_size(4) encoding(7) a data_member_location(0) ,
 * STABLE-NEXT:   member array_type[64] {
 * STABLE-NEXT:     base_type unsigned char byte_size(1) encoding(8)
 * STABLE-NEXT:   } data_member_location(8)
 * STABLE-NEXT: } byte_size(72)
 *
 * VERSION-DAG: #SYMVER ex1c 0x[[#%.08x,EX1]]
 */
