---
title: Client g_iVisibleMouse xref locator (#281)
type: note
permalink: goldsrc-vibesignatures/locators/client-g-i-visible-mouse-xref-locator-281
tags:
- locator
- client
- svencoop
- gv
- issue-281
---

# Client g_iVisibleMouse xref locator (#281)

## Trigger

Issue #281 labeled the target as an engine private global, but the quoted store is in Sven Co-op's client module. The 8948 ELF symbol table names the object `g_iVisibleMouse` and its writer `TeamFortressViewport::UpdateCursorState()`.

## Source and binary boundary

`D:/HLND2T_official/cl_dll/inputw32.cpp:43` defines `g_iVisibleMouse`; `vgui_TeamFortressViewport.cpp:2329-2355` writes true and false according to cursor state. The public source's `IN_MouseEvent` body differs from Sven's shipped binaries, so the binary xrefs establish the read path. The actual producer is the `client` module (`client.dll`/`client.so`), for svencoop-8948 and svencoop-10257 on Windows and Linux.

## Locator

1. `find-IN_MouseEvent.py` and `find-IN_Accumulate.py` locate each exact public PE/ELF export, inspect the current function, and emit function artifacts.
2. `find-g_iVisibleMouse.py` revalidates both current artifacts and intersects their writable-data reads. The intersection contains two real candidates in 8948 and three in 10257. The PIC GOT-base instruction is excluded because it is not a data load/test.
3. Follow every candidate's code xrefs (through a GOT slot in 8948 ELF). One candidate has a writer that stores both 0 and 1 and calls `vgui::App::getInstance()`; the other candidates' writers do not call it. That writer is `TeamFortressViewport::UpdateCursorState()` in the named 8948 ELF. Zero or multiple qualifying candidates fail closed.
4. Emit a `gv` artifact from the selected `IN_MouseEvent` operand. The generated signature validates/runtime-resolves the result and never participates in discovery. Windows is absolute, 8948 ELF is GOT/GLOB_DAT, and 10257 ELF is GOTOFF.

| Build | IN_MouseEvent / IN_Accumulate xref VA | Writer VA | Global VA |
| --- | --- | --- | --- |
| 8948 Windows | 0x10082026 / 0x100820A0 | 0x100B3F30 | 0x105FC2F8 |
| 8948 Linux | 0x14318D / 0x1437F7 | 0x1807D8 | 0x7A2164 |
| 10257 Windows | 0x1003B0A6 / 0x1003B131 | 0x1006C550 | 0x1063A99C |
| 10257 Linux | 0xE0E5C / 0xE153B | 0x121AB4 | 0xA98AB4 |

## Verification

Owned IDA sessions matched each IDB input path, SHA-256 and x86 architecture. The four binary hashes, in table order, are `5e3bd90c24e829c43344f0fe18368a71cad3c9b3405695e2489b469cf694624c`, `8b5fbb8f3533b38ab3fd53dfc6078012bc2f9259ba4e347b5bf301f3d0ebacc4`, `f40e74b7a703d193188d628066660ff0ac4be2b09613ae4b7f8d2c671991e7d6`, and `50580344e1c59b3c77e8e4e52ed9f185fcec7da2da936873ec122f12c735a022`.

Both full Sven client analyzer runs produced 6 successful new nodes and zero failures. The 8948 GV nodes were forced again after filtering the PIC base and both succeeded. Generated artifacts were checked against the 8948 ELF symbol table and the independent xref probe. `format_repo_files.py --check`, unit tests (1214 tests, 5 skipped), repository-contract tests (14), Ruff on new scripts with the repository's hyphenated finder-name exception, and `git diff --cached --check` passed.

## Scope

Only the two Sven client configs are registered. The issue's `hw.dll`/`hw.so` module hint is not used; other game families are outside this Sven client private-global request.
