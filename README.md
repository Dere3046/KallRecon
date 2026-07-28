# ksymless_Android

discovers and reconstructs the kallsyms symbol table from kernel
image memory on ARM64 GKI. locates kallsyms_lookup_name to provide
symbol resolution from within an LKM. depends only on sprint_symbol.

kallsyms internals: [xcellerator](https://xcellerator.github.io/posts/linux_rootkits_11/)

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
