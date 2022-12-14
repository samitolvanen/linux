#!/usr/bin/env perl
# SPDX-License-Identifier: GPL-2.0
#
# Generates a list of exported symbols in vmlinux.o for LLD's
# --lto-symbol-export-list, in the version script format.
#
# Copyright (C) 2019 Google LLC

use strict;
use warnings;

my $nm = $ENV{'NM'} || die "$0: ERROR: NM not set?";

sub generate_lto_export_symbol_list() {
	my @exports;

	while (my $file = shift(@ARGV)) {
		open(my $fh, "\"$nm\" --defined-only \"$file\" 2>/dev/null |")
			or die "$0: ERROR: failed to execute \"$nm\": $!";

		while (<$fh>) {
			my ($symbol) = $_ =~ /__ksymtab_(\S*)$/;

			if (!defined($symbol)) {
				next;
			}

			push(@exports, $symbol);
		}

		close($fh);
	}

	print "{\n";

	foreach my $symbol (sort(@exports)) {
		print "\t\t$symbol;\n";
	}

	print "};\n";
}

generate_lto_export_symbol_list();
