/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * anchor.S
 *
 * Copyright (C) 2026 dere3046
 *
 * LTO links unify the sprint_symbol type to Function (kallsyms.h) and
 * redirect every C-level &sprint_symbol to the module-local .cfi_jt.
 * an asm .quad reference stays a plain ABS64 relocation, resolved by
 * the module loader to the real kernel address.
 */

.section .rodata
.align 3
kr_sprint_addr_ref:
	.quad sprint_symbol
.previous

.text
.global kr_get_sprint_addr
kr_get_sprint_addr:
	adrp x0, kr_sprint_addr_ref
	ldr x0, [x0, :lo12:kr_sprint_addr_ref]
	ret
