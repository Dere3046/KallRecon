# KallRecon API

call `find_kallsyms_base` once. it discovers all kallsyms structures in raw
kernel memory and populates the globals. after that use the lookup functions.

## Discovery

**`void find_kallsyms_base(void)`**

the one call that starts everything. scans kernel memory upwards from
`sprint_symbol`, finds the token_index, token_table, offsets table
(self relative on v3), relative base, markers, names, num_syms, and
optionally seqs. on success `klnum_val` is nonzero and `kallrecon_klp`
is ready.

if it fails `klnum_val` stays zero and `kallrecon_klp` is not set;
`sprint_addr`/`kernel_base`/`klbase_val` are populated regardless
(useful for failure diagnosis).

### key globals

`klnum_val` — total number of symbols discovered

`klbase_val` — kernel text base, the value of `kallsyms_relative_base`

`kl_layout` — LAYOUT_V1 / LAYOUT_V2 / LAYOUT_V3. v1 is the pre-6.4 layout
(offsets before token_index), v2 the 6.4+ layout (offsets after
token_index), v3 the 7.0+ self relative layout without a relative base.
`is_v1_layout` stays as a mirror of `kl_layout == LAYOUT_V1` for existing
consumers

`sprint_addr` — runtime address of `sprint_symbol`, the discovery anchor

low level table addresses, ready after discovery:

`klbase_addr`, `kloffs_addr`, `klindex_addr`, `klseqs_addr`, `klmarks_addr`,
`kltable_addr`, `klnames_addr`, `klnum_addr` — raw kernel addresses of each
kallsyms sub-table. `klseqs_addr` nonzero means the seqs layout
(introduced in 6.1.42; all GKI 6.1 builds have it).

## Layout hint

for kernels whose `.rodata` layout deviates from the GKI build contract
(the offsets table sits outside the default scan window) discovery can
be seeded with known addresses. every hint field is a runtime address:
a value obtained offline (`vmlinux-to-elf` on the boot image) has to be
slid to the current boot by the caller, a value read at runtime (for
example `/proc/kallsyms` or a previous `kallrecon_layout_get`) can be
passed as is.

**`int kallrecon_supply(const struct kallrecon_hint *hint)`**

optional, call before `find_kallsyms_base`. a zero field means auto
discover that one, a filled field skips its search step. provided
values still go through the same checks as the scan path, a mismatch
fails discovery with `KALLRECON_HINT_INVALID` and is never trusted.

`struct kallrecon_hint` fields: `offsets`, `relative_base`,
`num_syms`, `names`, `markers`, `seqs`, `token_table`, `token_index`
(table addresses), `scan_back`, `scan_fwd` (auto scan window in bytes,
zero means the default 4MiB / 2MiB, a consumer that enlarges the window
pays the extra scan time) and `timeout_ms` (discovery cap, zero means
no cap).

`offsets` alone is enough for the common shifted table case, the rest
is derived and verified as usual.

**`void kallrecon_layout_get(struct kallrecon_layout *out)`**

filled with the runtime addresses and values of the final layout
(`layout`, `kernel_base`, the table addresses, `relative_base_val`,
`num_syms_val`) after `find_kallsyms_base`, all zero before.

**`enum kallrecon_fail kallrecon_fail_reason(void)`**

one of `KALLRECON_OK`, `KALLRECON_NO_ANCHOR`,
`KALLRECON_NO_TOKEN_INDEX`, `KALLRECON_NO_OFFSETS`,
`KALLRECON_NO_LAYOUT`, `KALLRECON_HINT_INVALID` or
`KALLRECON_TIMEOUT` after a discovery attempt.

after a failed `find_kallsyms_base` the attempt state is reset and the
call can be repeated with a changed hint: whether to retry with a
larger scan window (or with explicit addresses) is the caller's
decision, the library never enlarges the window by itself.

consumers that never call `kallrecon_supply` are not affected, the
default discovery path is unchanged.

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
the range `0 .. klnum_val - 1`; anything outside that range returns 0.

**`int sym_name_at(unsigned long addr, char *buf, int max)`**

address to name reverse lookup. binary searches the sorted addresses
table, decodes the compressed name and writes it into `buf`. at most
`max` bytes are written. returns the sorted index, or `-1` when `max` is
not positive, the table is empty or the name cannot be decoded (with a
positive `max`, `buf` is then set to an empty string).

**`unsigned int get_sym_seq(int idx)`**, **`unsigned int get_sym_offset(unsigned int seq)`**

raw access to the per-symbol sequence number and its offset. only valid
on the seqs layout (`klseqs_addr` nonzero). `get_sym_offset` returns
`UINT_MAX` on a decode failure, never a valid offset.

**`int expand_sym(unsigned int off, char *buf, int max)`**

decode one compressed symbol from token_table at offset `off` into `buf`.
used for manual scanning over the names table. returns the number of bytes
the compressed entry occupies, or `0` when `max` is not positive or on a
read/decode failure — with a positive `max`, `buf` is then set to an empty
string.

## Variant lookup

on CFI_CLANG kernels the callable target of a function pointer can be a
suffix variant of the plain name, for example the `.cfi_jt` jump table
entry. LTO builds add `.llvm.` clones on top.

**`unsigned long kallrecon_find_variant(const char *name, int prefer_cfi_jt)`**

resolve a symbol that may only exist with a suffix variant. a match is
the exact name, or a name that has `name` as prefix followed by `.` or
`$`. with `prefer_cfi_jt` a `.cfi_jt` variant wins over every other
match, otherwise the first match in address order is returned. zero
means not found. declared in `lib/variant.h`.

the names stream is read through the sliding window, a stream hole
resyncs at the next 256 symbol marker (markers are verified during
discovery). `KALLRECON_VARIANT_FAST` swaps the full expansion for an
incremental token matcher, off by default, an implementation variant
with identical results.

**`void kallrecon_set_variant_bisect(int enable)`**

only compiled with `KALLRECON_VARIANT_BISECT`, off at compile time by
default and off at runtime until this call enables it. requires the
seqs table (`klseqs_addr` nonzero), otherwise the scan path runs.
searches both seqs sort spaces in use (raw names and names stripped at
`.llvm.`), merges the candidates, validates every candidate against the
raw rules and falls back to the scan when nothing is found. explicit
opt in: verify the result on the target kernel before enabling.

## Name cleanup

kallsyms names carry LTO suffixes. the built in cleanup strips one of
them before comparing, so the query name you pass to lookup functions
can stay clean.

- `KALLRECON_CLEANUP_SEQS` (default) — the original rule: `.llvm.` when
  the seqs table is present, the last `$` otherwise. GKI verified,
  deterministic, no probe cost
- `KALLRECON_CLEANUP_LLVM` — always strip at `.llvm.`
- `KALLRECON_CLEANUP_DOLLAR` — always strip at the last `$`
- `KALLRECON_CLEANUP_AUTO` — probes the names stream once (up to 8192
  entries) for `.llvm.` or `$`, exactly one found is used, both or
  neither falls back to the `SEQS` rule. opt-in setting recommended for
  custom kernels with a different suffix style or a vendor seqs variant

**`void kallrecon_set_cleanup_mode(enum kallrecon_cleanup mode)`**

select the cleanup style, call before lookups. `SEQS` is the default.

**`void kallrecon_set_cleanup(int (*cb)(char *s))`**

attach an extra cleanup hook. the selected built in cleanup always runs
first, then your hook runs on the same buffer if registered. pass `NULL`
to detach and go back to the pure built in chain. return nonzero from
the hook when the name was truncated.

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

`KALLRECON_VARIANT_FAST=1` — incremental variant matcher, off by
default, an implementation variant with identical results

`KALLRECON_VARIANT_BISECT=1` — compile the seqs based variant bisect
together with the runtime `kallrecon_set_variant_bisect` switch, off by
default

`KALLRECON_FAST_BOOT=1` — sprint-walk fast path for the initial
`kallsyms_lookup_name` bootstrap on linear (no seqs) kernels, falls
back to the full lookup, off by default, only meant for speed
measurement. `KALLRECON_FAST_BOOT_ALL=1` drops the seqs check and
runs the walk on every kernel

`KALLRECON_NO_MARKERS=1` — always walk the full names table, never use
the markers shortcut
