---
title: DT_LoadDetailTexture locator
type: note
permalink: goldsrc-vibesignatures/locators/dt-loaddetailtexture
tags:
  - locator
  - engine
  - func
---

# DT_LoadDetailTexture

## Symbol

- **Name**: `DT_LoadDetailTexture`
- **Category**: `func`
- **Module**: engine (`hw.so` — SvEngine Linux branch)
- **Producer**: `ida_preprocessor_scripts/find-DT_LoadDetailTexture.py`

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Linux-only (`find-DT_LoadDetailTexture` is `platform: linux`; the svencoop
  symbol list likewise marks it `platform: linux`).
- Inlined / absent: absent from the HL/CoF configs — the detail-texture path this diagnostic
  belongs to is SvEngine-only. Present as a standalone function on the validated SvEngine
  Linux branch.

## Predecessors

- None. `find-DT_LoadDetailTexture` declares no `expected_input`.
- It is itself the predecessor of `find-DT_LoadDetailTexture-decompiles`, which mines the
  nine-argument call site inside this body to recover `GL_LoadTexture2` (owned by the
  renderer-GL batch, not this one).

## How it is located

1. `preprocess_common_skill` with a single `func_xrefs` entry:
   `FULLMATCH:Detail texture map load failed: %s\n` (exact C-string equality, not a
   substring match).
2. Every function referencing that string item is collected through
   `_functions_referencing` → `_ensure_function_owner`, which backtracks a direct-call entry
   when IDA never promoted the owner to a function. Recovery is therefore part of the
   normal path, not an error branch.
3. **Exactly one** candidate must survive (`len(items) != 1` makes the finder return None and
   write nothing). No `xref_gvs`, `xref_signatures` or `xref_funcs` are declared, so the
   literal is the sole anchor.
4. The candidate's `func_name` / `func_sig` / `func_va` / `func_rva` / `func_size` are
   emitted to `DT_LoadDetailTexture.{platform}.yaml`.

## Pitfalls

- Single-owner requirement: if a future build inlines the loader into a caller the literal's
  owner changes and the finder fails closed rather than guessing.
- The string is SvEngine-specific. Do not reuse this anchor on HL/CoF builds.
- Because the owner may be un-promoted, a stale IDB missing function boundaries still
  resolves via `_ensure_function_owner`; however the emitted `func_size` then depends on the
  recovered extent, so `allow_across_function_boundary` handling in the shared emitter
  applies.
- The downstream `-decompiles` step (other batch) must pick the nine-argument
  `GL_LoadTexture2` call from the annotated reference and reject the eight-argument
  `Draw_MiptexTexture` decal specialization and the internal register-ABI upload body.
