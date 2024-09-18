=======================
DWARF module versioning
=======================

1. Introduction
===============

When CONFIG_MODVERSIONS is enabled, symbol versions for modules
are typically calculated from preprocessed source code using the
**genksyms** tool.  However, this is incompatible with languages such
as Rust, where the source code has insufficient information about
the resulting ABI. With CONFIG_GENDWARFKSYMS (and CONFIG_DEBUG_INFO)
selected, **gendwarfksyms** is used instead to calculate symbol versions
from the DWARF debugging information, which contains the necessary
details about the final module ABI.

1.1. Usage
==========

gendwarfksyms accepts a list of object files on the command line, and a
list of symbol names (one per line) in standard input::

        Usage: gendwarfksyms [options] elf-object-file ... < symbol-list

        Options:
          -d, --debug          Print debugging information
              --dump-dies      Dump DWARF DIE contents
              --dump-die-map   Print debugging information about die_map changes
              --dump-types     Dump type strings
              --dump-versions  Dump expanded type strings used for symbol versions
          -s, --stable         Support kABI stability features
          -T, --symtypes file  Write a symtypes file
          -h, --help           Print this message


2. Type information availability
================================

While symbols are typically exported in the same translation unit (TU)
where they're defined, it's also perfectly fine for a TU to export
external symbols. For example, this is done when calculating symbol
versions for exports in stand-alone assembly code.

To ensure the compiler emits the necessary DWARF type information in the
TU where symbols are actually exported, gendwarfksyms adds a pointer
to exported symbols in the `EXPORT_SYMBOL()` macro using the following
macro::

        #define __GENDWARFKSYMS_EXPORT(sym)                             \
                static typeof(sym) *__gendwarfksyms_ptr_##sym __used    \
                        __section(".discard.gendwarfksyms") = &sym;


When a symbol pointer is found in DWARF, gendwarfksyms can use its
type for calculating symbol versions even if the symbol is defined
elsewhere. The name of the symbol pointer is expected to start with
`__gendwarfksyms_ptr_`, followed by the name of the exported symbol.

3. Symtypes output format
=========================

Similarly to genksyms, gendwarfksyms supports writing a symtypes file
for each processed object that contain types for exported symbols and
each referenced type that was used in calculating symbol versions. These
files can be useful when trying to determine what exactly caused symbol
versions to change between builds.

Matching the existing format, the first column of each line contains
either a type reference or a symbol name. Type references have a
one-letter prefix followed by "#" and the name of the type. Four
reference types are supported::

        e#<type> = enum
        s#<type> = struct
        t#<type> = typedef
        u#<type> = union

Type names with spaces in them are wrapped in single quotes, e.g.::

        s#'core::result::Result<u8, core::num::error::ParseIntError>'

The rest of the line contains a type string. Unlike with genksyms that
produces C-style type strings, gendwarfksyms uses the same simple parsed
DWARF format produced by **--dump-dies**, but with type references
instead of fully expanded strings.

4. Maintaining a stable kABI
============================

Distribution maintainers often need the ability to make ABI compatible
changes to kernel data structures due to LTS updates or backports. Using
the traditional `#ifndef __GENKSYMS__` to hide these changes from symbol
versioning won't work when processing object files. To support this
use case, gendwarfksyms provides kABI stability features designed to
hide changes that won't affect the ABI when calculating versions. These
features are all gated behind the **--stable** command line flag and are
not used in the mainline kernel.

Examples for using these features are provided in the
**scripts/gendwarfksyms/examples** directory, including helper macros
for source code annotation. Note that as these features are only used to
transform the inputs for symbol versioning, the user is responsible for
ensuring that their changes actually won't break the ABI.

4.1. kABI rules
===============

kABI rules allow distributions to fine-tune certain parts
of gendwarfksyms output and thus control how symbol
versions are calculated. These rules are defined in the
`.discard.gendwarfksyms.kabi_rules` section of the object file and
consist of simple null-terminated strings with the following structure::

	version\0type\0target\0value\0

This string sequence is repeated as many times as needed to express all
the rules. The fields are as follows:

- `version`: Ensures backward compatibility for future changes to the
  structure. Currently expected to be "1".
- `type`: Indicates the type of rule being applied.
- `target`: Specifies the target of the rule, typically the fully
  qualified name of the DWARF Debugging Information Entry (DIE).
- `value`: Provides rule-specific data.

The following helper macro, for example, can be used to specify rules
in the source code::

	#define __KABI_RULE(hint, target, value)                             \
		static const char __PASTE(__gendwarfksyms_rule_,             \
					  __COUNTER__)[] __used __aligned(1) \
			__section(".discard.gendwarfksyms.kabi_rules") =     \
				"1\0" #hint "\0" #target "\0" #value


Currently, only the rules discussed in this section are supported, but
the format is extensible enough to allow further rules to be added as
need arises.

4.1.1. Managing structure visibility
====================================

A structure declaration can change into a full definition when
additional includes are pulled into the translation unit. This changes
the versions of any symbol that references the structure even if the ABI
remains unchanged. As it may not be possible to drop includes without
breaking the build, the `struct_declonly` rule can be used to specify a
data structure as declaration-only, even if the debugging information
contains the full definition.

The rule fields are expected to be as follows:

- `type`: "struct_declonly"
- `target`: The fully qualified name of the target data structure
  (as shown in **--dump-dies** output).
- `value`: This field is ignored and is expected to have the value ";".

Using the `__KABI_RULE` macro, this rule can be defined as::

	#define KABI_STRUCT_DECLONLY(fqn) \
		__KABI_RULE(struct_declonly, fqn, ;)

Example usage::

	struct s {
		/* definition */
	};

	KABI_STRUCT_DECLONLY(s);

4.1.2. Adding enumerators
=========================

For enums, all enumerators and their values are included in calculating
symbol versions, which becomes a problem if we later need to add more
enumerators without changing symbol versions. The `enumerator_ignore`
rule allows us to hide named enumerators from the input.

The rule fields are expected to be as follows:

- `type`: "enumerator_ignore"
- `target`: The fully qualified name of the target enum
  (as shown in **--dump-dies** output).
- `value`: The name of the enumerator to ignore.

Using the `__KABI_RULE` macro, this rule can be defined as::

	#define KABI_ENUMERATOR_IGNORE(fqn, field) \
		__KABI_RULE(enumerator_ignore, fqn, field)

Example usage::

	enum e {
		A, B, C, D,
	};

	KABI_ENUMERATOR_IGNORE(e, B);
	KABI_ENUMERATOR_IGNORE(e, C);


4.3. Adding structure members
=============================

Perhaps the most common ABI compatible changeis adding a member to a
kernel data structure. When changes to a structure are anticipated,
distribution maintainers can pre-emptively reserve space in the
structure and take it into use later without breaking the ABI. If
changes are needed to data structures without reserved space, existing
alignment holes can potentially be used instead. While kABI rules could
be added for these type of changes, using unions is typically a more
natural method. This section describes gendwarfksyms support for using
reserved space in data structures and hiding members that don't change
the ABI when calculating symbol versions.

4.3.1. Reserving space and replacing members
============================================

To reserve space in a struct, adding a member of any type with a name
that starts with `__kabi_` will result in the name being left out of
symbol versioning::

        struct s {
                long a;
                long __kabi_reserved_0; /* reserved for future use */
        };

The space reserved by this member can be later taken into use by
wrapping it into a union, which includes the original type and the
replacement struct member::

        struct s {
                long a;
                union {
                        long __kabi_reserved_0; /* original type */
                        struct b b; /* replaced field */
                };
        };

As long as the reserved member's name in the union starts with
`__kabi_reserved_`, the original type will be used for symbol
versioning and rest of the union is ignored. The examples include
`KABI_(RESERVE|USE)*` macros that help simplify the process and also
ensure the replacement member's size won't exceed the reserved space.

4.3.2. Hiding members
=====================

Predicting which structures will require changes during the support
timeframe isn't always possible, in which case one might have to resort
to placing new members into existing alignment holes::

        struct s {
                int a;
                /* a 4-byte alignment hole */
                unsigned long b;
        };


While this won't change the size of the data structure, one needs to
be able to hide the added members from symbol versioning. Similarly
to reserved fields, this can be accomplished by wrapping the added
member to a union where one of the fields has a name starting with
`__kabi_ignored`::

        struct s {
                int a;
                union {
                        char __kabi_ignored_0;
                        int n;
                };
                unsigned long b;
        };

With **--stable**, both versions produce the same symbol version.
