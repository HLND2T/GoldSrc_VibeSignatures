---
title: SkyboxCommand locator
type: note
permalink: goldsrc-vibesignatures/locators/skyboxcommand
tags:
  - locator
  - engine
  - func
---

# SkyboxCommand

## Symbol

- **Name**: `SkyboxCommand`
- **Category**: `func`
- **Module**: engine (`hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-SkyboxCommand-svencoop.py`

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Linux-only (the finder node carries `platform: linux`).
- Inlined / absent: SvEngine-only symbol; it does not exist in the classic hl/CoF/HL25 engine family (those use the `skybox`/`R_LoadSkys` path). Windows SvEngine is not covered — the Windows branch recovers `R_LoadSkyBox_SvEngine` directly from the desert literal.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- None. `find-SkyboxCommand-svencoop` has no `expected_input`.

## How it is located

`preprocess_common_skill` with a single exact string xref:

- `FULLMATCH:No skybox name specified\n` — the usage message the SvEngine skybox console command prints when invoked without an argument. The literal has a single instance and a single function owner on the validated SvEngine Linux build.

The command otherwise forwards `Cmd_Argv(1)` to the outer skybox loader, which is what makes it a usable predecessor for `R_LoadSkyBox_SvEngine`.

No byte signature participates in discovery. `_inspect_function_via_mcp` emits `func_name / func_sig / func_va / func_rva / func_size`.

## Pitfalls

- The argument index is the contract: `Cmd_Argv(1)` must be the value forwarded to the loader. If a future SvEngine build adds an argument or a sub-command, the call site located by `find-SkyboxCommand-decompiles` changes semantics while the anchor still matches.
- This is the only anchor for the symbol — there is no structural fallback, and the finder is Linux-gated, so the Windows sibling (`find-R_LoadSkyBox_SvEngine`) must not be expected to produce `SkyboxCommand`.
- The literal goes through the shared IDB string list, so short-literal pollution applies; the `\n` is part of the needle and must be kept.
- PIC build: the located body opens with the `call __x86.get_pc_thunk.*` / GOT idiom, so the leading `func_sig` bytes are wildcarded.
