# KallRecon

discovers and reconstructs the kallsyms symbol table from kernel
image memory on ARM64 GKI. locates kallsyms_lookup_name to provide
symbol resolution from within an LKM. inspired by
[ksymless](https://github.com/rota1001/ksymless) and depends only on
sprint_symbol.

on kallsyms: [xcellerator](https://xcellerator.github.io/posts/linux_rootkits_11/)

## optional SCT discovery

include `lib/sct.c` in your build to opt into sys_call_table
discovery via stack walk. the module walks x29 frames up to
do_el0_svc and decodes ADRP instructions to locate the SCT address.
not needed for kallsyms discovery. see `lib/sct.h`.

## requirements

- ARM64 device with GKI kernel
- sprint_symbol exported

## credits

Thanks to [汐の月](https://www.coolapk.com/u/1550124) for providing
the device for GKI 6.6 testing.

Thanks to [阿尔托莉雅·潘德拉贡](https://www.coolapk.com/u/41654149) for providing
the device for GKI 6.1 testing.

Thanks to [小初](https://www.coolapk.com/u/42372039) for providing
the device for GKI 6.1 testing.

Thanks to [haohao3001](https://github.com/haohao3001) for providing
the device for GKI 6.12/5.15 testing.

Thanks to [mx_wj](https://github.com/mx-wj) for providing
the device for GKI 6.1 testing.

Thanks to [pubglite55](https://github.com/pubglite55) for providing
the device for GKI 5.15 testing.

## license

GPL-2.0
