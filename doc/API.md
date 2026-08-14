# KallRecon API

call `find_kallsyms_base` once. it discovers all kallsyms structures in raw
kernel memory and populates the globals. after that use the lookup functions.

## Discovery

**`void find_kallsyms_base(void)`**

the one call that starts everything. scans kernel memory upwards from
`sprint_symbol`, finds the token_index, token_table, offsets table,
relative base, markers, names, num_syms, and optionally seqs. on success
`klnum_val` is nonzero and `kallrecon_klp` is ready.

if it fails `klnum_val` stays zero and `kallrecon_klp` is not set;
`sprint_addr`/`kernel_base`/`klbase_val` are populated regardless
(useful for failure diagnosis).

### key globals

`klnum_val` — total number of symbols discovered

`klbase_val` — kernel text base, the value of `kallsyms_relative_base`

`is_v1_layout` — 1 for pre-6.4 layout (offsets before token_index), 0 for
6.4+ layout (offsets after token_index)

`sprint_addr` — runtime address of `sprint_symbol`, the discovery anchor

low level table addresses, ready after discovery:

`klbase_addr`, `kloffs_addr`, `klindex_addr`, `klseqs_addr`, `klmarks_addr`,
`kltable_addr`, `klnames_addr`, `klnum_addr` — raw kernel addresses of each
kallsyms sub-table. `klseqs_addr` nonzero means the seqs layout
(introduced in 6.1.42; all GKI 6.1 builds have it).

## Lookup

**`unsigned long (*kallrecon_klp)(const char *name)`**

function pointer to the kernel's own `kallsyms_lookup_name`. the fastest
way to resolve a name. pass a symbol name string, get back the address or
zero if not found.

ready after `find_kallsyms_base` succeeds.

**`unsigned long kallsyms_name_to_addr(const char *name)`**

our own name to address lookup. on kernels that have the seqs table
(6.1.42+, all GKI 6.1 builds) it uses binary search. on kernels without
seqs (5.10/5.15, 6.1.0~6.1.41) it falls back to a buffered linear scan
of the names table. same calling
convention as `kallrecon_klp`. zero return means the name was not found.

when built with `KALLRECON_MODULE_LOOKUP`, a failed table lookup falls
back to an indirect call of the kernel's `module_kallsyms_lookup_name`,
same as `kallrecon_klp`. experimental, off by default, may be unstable.

**`unsigned long sym_addr(int idx)`**

get the address of the symbol at sorted index `idx`. the index must be in
the range `0 .. klnum_val - 1`. returns the kernel virtual address.

**`int sym_name_at(unsigned long addr, char *buf, int max)`**

address to name reverse lookup. binary searches the sorted addresses
table, decodes the compressed name and writes it into `buf`. at most
`max` bytes are written. returns the sorted index.

**`unsigned int get_sym_seq(int idx)`**, **`unsigned int get_sym_offset(unsigned int seq)`**

raw access to the per-symbol sequence number and its offset. only valid
on the seqs layout (`klseqs_addr` nonzero). `get_sym_offset` returns
`UINT_MAX` on a decode failure, never a valid offset.

**`int expand_sym(unsigned int off, char *buf, int max)`**

decode one compressed symbol from token_table at offset `off` into `buf`.
used for manual scanning over the names table.

## Name cleanup

kallsyms names carry LTO suffixes. the core strips them before comparing:
`foo$hash` on 5.10/5.15, `foo.llvm.hash` on 6.1+. this default runs on
every lookup path and on `sym_name_at` output.

**`void kallrecon_set_cleanup(int (*cb)(char *s))`**

attach an extra cleanup hook. the default cleanup always runs first, then
your hook runs on the same buffer if registered. pass `NULL` to detach and
go back to the pure default chain. return nonzero from the hook when the
name was truncated.

your hook must truncate the buffer in place. the query name you pass to
lookup functions must already be clean, matching the kernel
`kallsyms_lookup_name` convention.

## Raw memory access

**`int safe_read(void *dst, const void *src, size_t sz)`**

fault-safe memory read used internally by discovery. returns nonzero on
failure, zero on success. exported for callers that need to poke kernel
memory the same way.

## Slide window

`lib/slide.h` provides a chunked paging helper for scanning large kernel
ranges without pinning them.

**`struct slide_win`** — `addr` current kernel position, `chunksz` page
size (64KB default), `margin` overlap (512B), `off` offset inside chunk

**`int slide_init(struct slide_win *w, unsigned long pos,
unsigned int chunksz, unsigned int margin)`**

**`int slide_advance(struct slide_win *w, unsigned int n)`**

**`void *slide_ptr(const struct slide_win *w, const void *buf)`**,
**`unsigned long slide_addr(const struct slide_win *w)`**

## Build options

`TARGET=test` — build the test probe with `KALLRECON_DEBUG` logging

`CHECK=1` — extra sanity checks in discovery

`KALLRECON_MODULE_LOOKUP=1` — enable the experimental
`module_kallsyms_lookup_name` fallback
