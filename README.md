# ksymless_Android

ARM64 implementation of [ksymless](https://github.com/rota1001/ksymless) for Android GKI kernels.
discovers kallsyms data and sys_call_table without exported kernel symbols.

kallsyms internals are described in [xcellerator's post](https://xcellerator.github.io/posts/linux_rootkits_11/).

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
the device for GKI 6.12 testing.

## license

GPL-2.0
