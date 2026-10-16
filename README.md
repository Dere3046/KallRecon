# KallRecon

a simple kernel symbol finder. discovers and reconstructs the kallsyms
symbol table from kernel image memory on ARM64 and x86_64 kernels.
covers GKI 5.10 through 6.18 and mainline 7.0+ (self relative layout).
GKI 5.10 through 6.18 on ARM64 is stably supported. locates
kallsyms_lookup_name to provide symbol resolution from within an LKM.

depends only on sprint_symbol. a full reconstruction takes only
0.06s on real devices, 0.004s with the raana engine. KallRecon has
worked on at least 30 devices and been tested at least 100 times.

on kallsyms: [xcellerator](https://xcellerator.github.io/posts/linux_rootkits_11/)

## requirements

- ARM64 or x86_64 kernel, GKI 5.10 to 6.18 or mainline 7.0+
- sprint_symbol exported

## docs

API reference: [doc/API.md](doc/API.md)

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

Thanks to [aaa终末地管理员](https://github.com/zmdAdministrators) for providing
the device for GKI 6.6 testing.

Thanks to [Alhkxsj](https://github.com/Alhkxsj) for providing
the device for GKI 6.6 testing and fix x86.
## license

GPL-2.0
