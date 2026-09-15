---
title: Hunk_AllocName locator
type: note
permalink: goldsrc-vibesignatures/locators/hunk-allocname
tags:
  - locator
  - engine
  - func
---

# Hunk_AllocName

## Symbol

- **Name**: `Hunk_AllocName`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Hunk_AllocName.py` (Windows / string anchor) and
  `ida_preprocessor_scripts/find-Mod_LoadSpriteModel-decompiles.py` (svencoop-10257 Linux / LLM_DECOMPILE).
  Both producers emit the same artifact stem `Hunk_AllocName.{platform}.yaml`; they are gated to disjoint
  platform/`gamever` nodes so they never write the same file.

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux. `find-Hunk_AllocName` is registered for **both** platforms in every hl-*/cof-*
  config, but is explicitly `platform: windows` in svencoop-10257; `find-Mod_LoadSpriteModel-decompiles` is
  `platform: linux` in svencoop-10257 and supplies that single Linux node.
- Inlined / absent: none. Both the string-anchored path and the SvEngine Linux fallback produce a standalone
  function (svencoop-10257 `hw.so`: `func_rva 0xe27a0`, `func_size 0x149`, PIC prologue `55 57 56 53 83 EC ??`).

## Predecessors

- `find-Hunk_AllocName`: none (no `expected_input`, `old_yaml_map=None`).
- `find-Mod_LoadSpriteModel-decompiles`: `Mod_LoadSpriteModel.{platform}.yaml` (required `dependency_policy`),
  consumed via `expected_input`; the annotated reference is
  `ida_preprocessor_scripts/references/{gamever}/engine/Mod_LoadSpriteModel.{platform}.yaml` (present for
  svencoop-10257 only).

## How it is located

**Windows / general path (`find-Hunk_AllocName`)**

1. `xref_strings = ["FULLMATCH:Hunk_Alloc: bad size: %i"]` — exact-match C string. The finder docstring
   records it as an allocator guard: the hunk code aborts through this literal when the requested size is
   negative, and the literal belongs to `Hunk_AllocName` only.
2. Owner recovery maps the referencing instruction to its function; exactly one candidate must survive.
3. Signature = function prologue with operand bytes wildcarded, kept only when `_find_unique_bytes` returns
   the same VA.
4. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

**SvEngine Linux path (`find-Mod_LoadSpriteModel-decompiles`)**

1. The svencoop-10257 Linux `Hunk_AllocName` has **no single-owner string anchor**, so this node is recovered
   from the verified `Mod_LoadSpriteModel` artifact instead of from a literal.
2. `LLM_DECOMPILE` spec: `symbol_name = Hunk_AllocName`, `prompt_path = prompt/call_llm_decompile.md`,
   `reference_yaml_paths = [references/{gamever}/engine/Mod_LoadSpriteModel.{platform}.yaml]`,
   `expected_result_sections = ["found_call"]`, `dependency_policy = {"Mod_LoadSpriteModel.{platform}.yaml": "required"}`.
3. The live predecessor artifact supplies the target `func_va`; the annotated SvEngine reference pins the
   frame-allocation call site. The LLM returns `found_call` entries; the accepted entry's instruction must
   reference exactly one unique code target, and `_inspect_function_via_mcp` then generates
   `func_va`/`func_rva`/`func_size`/`func_sig` for that target.
4. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

## Pitfalls

- The svencoop-10257 Linux node has no usable literal — do not extend `find-Hunk_AllocName` to that platform;
  the config deliberately splits it (`find-Hunk_AllocName` has `platform: windows`, the decompiles finder has
  `platform: linux`). Any change that makes both runnable on the same node would double-write the artifact.
- `Hunk_AllocName` is the *named* allocator wrapper; the `"Hunk_Alloc: bad size: %i"` literal is emitted from
  this wrapper, not from a distinct `Hunk_Alloc` symbol, so one artifact covers both call spellings.
- The LLM_DECOMPILE reference is resolved as `references/{gamever}/...` with a fallback to
  `GSVIBE_REFERENCE_GAMEVER` (default `hl-10210`) when the gamever file is missing; the fallback only exists
  for symbols that ship a hl-10210 reference. `Mod_LoadSpriteModel` references exist for svencoop-10257 only,
  which matches the single node that consumes them.
- The generated `func_sig` must still resolve uniquely to the recovered VA; a merely plausible call site is
  not enough for emit.
