// SPDX-License-Identifier: GPL-2.0
/*
 * This includes functions that are meant to live entirely in .rodata
 * (via objcopy tricks), to validate the non-executability of .rodata.
 */
void lkdtm_rodata_do_nothing(void);

void noinstr lkdtm_rodata_do_nothing(void)
{
	/* Does nothing. We just want an architecture agnostic "return". */
}
