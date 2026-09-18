---
title: CheckMultiTextureExtensions locator
type: note
permalink: goldsrc-vibesignatures/locators/check-multitexture-extensions
tags:
  - locator
  - engine
  - func
---

# CheckMultiTextureExtensions

## Symbol

- **Name**: `CheckMultiTextureExtensions`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CheckMultiTextureExtensions.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows + Linux, except **hl-10210 is linux-only**. Linux engine modules exist for hl-10210 and hl-8684.
- **Inlined into `GL_Init` on HL25 Windows** (`hl-10210`): the diagnostic lives in `GL_Init`'s body, so a unique string owner still points at `GL_Init` (`func_va 0x1024e680`, `func_size 0x52e`, same `func_sig` that starts `push 1F00h` / `GL_VENDOR`). That config therefore gates the skill and symbol with `platform: linux`. The linux body stays standalone (`func_size 0x1c3`, distinct from `GL_Init` `0x3cc`).
- Not applicable to svencoop-8948 / svencoop-10257 — SvEngine prints `Multitexturing disabled` from `InitMultitexturing` instead, so this finder is deliberately not registered there.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).
- On the BLOB builds (`hl-3248` / `hl-3266` / `hl-3329` / `hl-3647`) this function is the host that inlines `DT_Initialize`; those configs do not declare `DT_Initialize`. The blob body is `func_size 0x18d` and opens on an FPU compare (`51 D9 05 …`), which is the same host that was previously mis-recorded as `DT_Initialize`.

## Predecessors

- None. `find-CheckMultiTextureExtensions` has no `expected_input` and passes `old_yaml_map=None`.

## How it is located

`preprocess_common_skill` with a single exact string xref:

- `FULLMATCH:NO Multitexture extensions found.\n` — the `engine/gl_vidnt.c` diagnostic printed when neither `GL_ARB_multitexture` nor `GL_SGIS_multitexture` is advertised. The trailing newline is part of the C string.

No byte signature participates in discovery. `_inspect_function_via_mcp` emits `func_name / func_sig / func_va / func_rva / func_size`.

The literal is present once in every validated HL/CoF PE32 (`hw.dll` or `hw.decrypt.dll`) and ELF32 (`hw.so`) engine binary.

## Pitfalls

- Trailing newline is load-bearing: the user-facing wording without `\n` would still unique-match today, but `FULLMATCH` is pinned to the exact C string.
- **Uniqueness is not a correctness proof.** HL25 Windows inlines the probe into `GL_Init`, so the walk returns exactly one hit and looks healthy while pointing at the host. Before declaring the symbol for a new build, check that the hit is not `GL_Init` (vendor-query prologue `push 1F00h`, matching `GL_Init.{platform}.yaml` `func_va`).
- Partial registration is a real trap here. `ida_analyze_bin.py -allgamever -skill find-CheckMultiTextureExtensions` aborts at the first svencoop tag with `Skill 'find-CheckMultiTextureExtensions' not found`. Validate per registered gamever instead.
- Blob engines (hl-3248..hl-3647) are Windows-only and run against `hw.decrypt.dll`; scanning encrypted `hw.dll` reports a missing string.
- Do not treat a unique `GL_RGB_SCALE` (0x8573) immediate as this function's identity. That immediate belongs to `DT_Initialize` and only survives here because the BLOB builds inline it.
