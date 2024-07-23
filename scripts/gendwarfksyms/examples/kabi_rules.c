// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024 Google LLC
 *
 * Examples for kABI rules with --stable.
 */

/*
 * The comments below each example contain the expected gendwarfksyms
 * output which can be verified using LLVM's FileCheck tool:
 *
 * https://llvm.org/docs/CommandGuide/FileCheck.html
 *
 * RUN: gcc -g -c examples/kabi_rules.c -o examples/kabi_rules.o
 *
 * Verify --stable output:
 *
 * RUN: echo -e "ex0\nex1" | \
 * RUN:   ./gendwarfksyms --stable --dump-dies \
 * RUN:   	examples/kabi_rules.o 2>&1 >/dev/null | \
 * RUN:   FileCheck examples/kabi_rules.c --check-prefix=STABLE
 */

#include "kabi.h"

struct s {
	int a;
};

KABI_STRUCT_DECLONLY(s);

struct s e0;

/*
 * STABLE:      variable structure_type s {
 * STABLE-NEXT: }
 */

enum e {
	A,
	B,
	C,
	D,
};

KABI_ENUMERATOR_IGNORE(e, B);
KABI_ENUMERATOR_IGNORE(e, C);

enum e e1;

/*
 * STABLE:      variable enumeration_type e {
 * STABLE-NEXT:   enumerator A = 0 ,
 * STABLE-NEXT:   enumerator D = 3
 * STABLE-NEXT: } byte_size(4)
 */
