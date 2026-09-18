---
title: InitMultitexturing locator
type: note
permalink: goldsrc-vibesignatures/locators/init-multitexturing
tags:
  - locator
  - engine
  - func
---

# InitMultitexturing

## Symbol

- **Name**: `InitMultitexturing`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-InitMultitexturing.py`

## Availability

- Declared in 2 engine configs: svencoop-8948, svencoop-10257.
- Platforms: **linux-only** on both tags (`platform: linux` on the skill and the symbol). Both configs declare `module_linux: hw.so`.
- **Inlined into `GL_Init` on SvEngine Windows**: the diagnostic lives in `GL_Init`'s body, so a unique string owner still points at `GL_Init` (`func_size 0x403`, same `func_sig` that starts `push 1F00h` / `GL_VENDOR`). The linux body stays standalone (`func_size 0xf5`, distinct from `GL_Init` `0x563`).
- This is a SvEngine-only symbol. The classic hl/CoF/HL25 probe is `CheckMultiTextureExtensions` and prints a different diagnostic, so this finder is deliberately not registered there.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- None. `find-InitMultitexturing` has no `expected_input` and passes `old_yaml_map=None`.

## How it is located

`preprocess_common_skill` with a single exact string xref:

- `FULLMATCH:Multitexturing disabled\n` — the SvEngine diagnostic printed when the ARB/SGIS multitexture path is not taken. The trailing newline is part of the C string.

No byte signature participates in discovery. `_inspect_function_via_mcp` emits `func_name / func_sig / func_va / func_rva / func_size`.

The literal is present once in every validated SvEngine PE32 (`hw.dll`) and ELF32 (`hw.so`) engine binary.

## Pitfalls

- Trailing newline is load-bearing: pin `FULLMATCH` to the exact C string rather than the user-facing wording without `\n`.
- **Uniqueness is not a correctness proof.** SvEngine Windows inlines the probe into `GL_Init`, so the walk returns exactly one hit and looks healthy while pointing at the host. Before declaring the symbol for a new build, check that the hit is not `GL_Init` (vendor-query prologue `push 1F00h`, matching `GL_Init.{platform}.yaml` `func_va`).
- Partial registration is a real trap here. `ida_analyze_bin.py -allgamever -skill find-InitMultitexturing` aborts at the first hl/cof/cstrike tag that does not register it. Validate per registered gamever instead.
- Do not reuse the HL/CoF `NO Multitexture extensions found.` literal on SvEngine; it is absent from those binaries.
