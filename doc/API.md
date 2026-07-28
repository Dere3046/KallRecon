# ksymless API

call `find_kallsyms_base` once. it discovers all kallsyms structures in raw
kernel memory and populates the globals. after that use the lookup functions.

## Discovery

**`void find_kallsyms_base(void)`**

the one call that starts everything. scans kernel memory upwards from
`sprint_symbol`, finds the token_index, token_table, offsets table,
relative base, markers, names, num_syms, and optionally seqs. on success
`klnum_val` is nonzero and `ksymless_klp` is ready.

if it fails all globals stay at zero. no partial state.

## Symbol Lookup

**`unsigned long (*ksymless_klp)(const char *name)`**

function pointer to the kernel's own `kallsyms_lookup_name`. the fastest
way to resolve a name. pass a symbol name string, get back the address or
zero if not found.

ready after `find_kallsyms_base` succeeds.

**`unsigned long kallsyms_name_to_addr(const char *name)`**

our own name to address lookup. on kernels that have the seqs table
(6.1+) it uses binary search. on kernels without seqs (5.10/5.15) it
falls back to a buffered linear scan of the names table. same calling
convention as `ksymless_klp`. zero return means the name was not found.

**`unsigned long sym_addr(int idx)`**

get the address of the symbol at sorted index `idx`. the index must be in
the range `0 .. klnum_val - 1`. returns the kernel virtual address.

**`int sym_name_at(unsigned long addr, char *buf, int max)`**

address to name reverse lookup. binary searches the sorted addresses
table, decodes the compressed name and writes it into `buf`. at most
`max` bytes are written. returns the sorted index.

## Table Access

**`int expand_sym(unsigned int off, char *buf, int max)`**

decode one compressed symbol name from the names table at byte offset
`off`. writes the uncompressed name into `buf` up to `max` bytes. the
first character of the output is the symbol type prefix (T, t, B, D,
etc). returns the number of bytes consumed from the names table.

this is the building block for iterating the symbol table manually.

**`unsigned int get_sym_seq(int idx)`**

map alphabetical order index to address order index. on kernels with the
seqs table (6.1+) this decodes a 3-byte entry. on kernels without seqs
(5.10/5.15) this returns `idx` unchanged.

use this before calling `get_sym_offset` when doing binary search by name.

**`unsigned int get_sym_offset(unsigned int seq)`**

map address order index to byte offset in the names table. uses the
markers array for O(1) seeking to the correct 256-symbol block, then
walks sequentially within the block.

## Global State

all globals are populated by `find_kallsyms_base`. a zero value means the
structure was not found or discovery failed.

### count and base

`klnum_val` (unsigned int) — total number of symbols discovered

`klbase_val` (unsigned long) — kernel text base address, the value of
`kallsyms_relative_base`

### layout version

`is_v1_layout` (int) — 1 for the pre-6.4 layout where the offsets table
is placed after the relative base and before the names and
token_index. 0 for the 6.4+ layout where the offsets table is placed
after the token_index. this affects how post-processing locates
`klnum_addr`, `klnames_addr`, and `klseqs_addr`.

### table addresses

`klbase_addr` — where `klbase_val` is stored in kernel memory

`kloffs_addr` — start of the `kallsyms_offsets` array

`klindex_addr` — start of the `kallsyms_token_index` array (256 uint16)

`kltable_addr` — start of the `kallsyms_token_table` array

`klmarks_addr` — start of the `kallsyms_markers` array

`klnames_addr` — start of the `kallsyms_names` array

`klnum_addr` — where `kallsyms_num_syms` is stored

### seqs

`klseqs_addr` — start of the `kallsyms_seqs_of_names` array (3-byte
entries). zero if the kernel has no seqs table (5.10/5.15)

### anchor

`sprint_addr` — runtime address of `sprint_symbol`, used as the fixed
anchor for all discovery scans

`kernel_base` — `sprint_addr` rounded down to the nearest 2MB boundary
