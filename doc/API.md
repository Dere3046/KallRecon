# KallRecon API

call `find_kallsyms_base` once. it discovers all kallsyms structures in raw
kernel memory and populates the globals. after that use the lookup functions.

## Discovery

**`void find_kallsyms_base(void)`**

the one call that starts everything. scans kernel memory upwards from
`sprint_symbol`, finds the token_index, token_table, offsets table,
relative base, markers, names, num_syms, and optionally seqs. on success
`klnum_val` is nonzero and `kallrecon_klp` is ready.

if it fails all globals stay at zero. no partial state.

### key globals

`klnum_val` — total number of symbols discovered

`klbase_val` — kernel text base, the value of `kallsyms_relative_base`

`is_v1_layout` — 1 for pre-6.4 layout (offsets before token_index), 0 for
6.4+ layout (offsets after token_index)

`sprint_addr` — runtime address of `sprint_symbol`, the discovery anchor

## Lookup

**`unsigned long (*kallrecon_klp)(const char *name)`**

function pointer to the kernel's own `kallsyms_lookup_name`. the fastest
way to resolve a name. pass a symbol name string, get back the address or
zero if not found.

ready after `find_kallsyms_base` succeeds.

**`unsigned long kallsyms_name_to_addr(const char *name)`**

our own name to address lookup. on kernels that have the seqs table
(6.1+) it uses binary search. on kernels without seqs (5.10/5.15) it
falls back to a buffered linear scan of the names table. same calling
convention as `kallrecon_klp`. zero return means the name was not found.

**`unsigned long sym_addr(int idx)`**

get the address of the symbol at sorted index `idx`. the index must be in
the range `0 .. klnum_val - 1`. returns the kernel virtual address.

**`int sym_name_at(unsigned long addr, char *buf, int max)`**

address to name reverse lookup. binary searches the sorted addresses
table, decodes the compressed name and writes it into `buf`. at most
`max` bytes are written. returns the sorted index.

## SCT (optional)

include `lib/sct.c` and `lib/sct.h` for sys_call_table discovery via
x29 stack walk. see `lib/sct.h`.

not needed for kallsyms discovery.
