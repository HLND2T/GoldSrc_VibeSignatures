---
title: SV_SendServerinfo locator
type: note
permalink: goldsrc-vibesignatures/locators/sv-sendserverinfo
tags:
  - locator
  - engine
  - func
---

# SV_SendServerinfo

## Symbol

- **Name**: `SV_SendServerinfo`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-SV_SendServerinfo.py` (hl-*/cof-*)
  and `ida_preprocessor_scripts/find-SV_SendServerinfo-svencoop.py` (svencoop-10257)

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936 (generic finder), svencoop-10257 (`-svencoop` variant).
- Platforms: Windows + Linux for both producers (neither is platform-gated); Linux artifacts exist for hl-8684,
  hl-10210 and svencoop-10257.
- Inlined / absent: none observed.

## Predecessors

- None for either producer (`expected_input` empty, `old_yaml_map=old_yaml_map`).
- `SV_SendServerinfo` is itself the required `expected_input` of `find-build_number`, which reads its
  `func_va` to seed the LLM_DECOMPILE reference comparison.

## How it is located

**Generic (`find-SV_SendServerinfo`)**

1. `xref_strings = ["BUILD %d SERVER (%i CRC)"]` — substring string match (no `FULLMATCH:` prefix).
2. `XrefsTo` on the literal maps each referencing instruction to its owning function through `_ensure_function_owner`;
   the candidate set must collapse to exactly one function.
3. Prologue signature with wildcarded operands, kept only if `_find_unique_bytes` resolves to the same VA.
4. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

**SvEngine (`find-SV_SendServerinfo-svencoop`)**

1. Same algorithm, different literal: `"\n%s\nServer Engine: %s (build %d%s)\nServer Number: %i\n\n"` (the
   SvEngine server-info banner, substring match).
2. Identical candidate-uniqueness, signature and emit contract.

## Pitfalls

- The SvEngine banner carries no `FULLMATCH:` prefix and begins with `\n`; the anchor is the multi-line
  banner text itself, not the substring `BUILD %d SERVER` (which does not exist there). Using the generic
  anchor for svencoop-10257 fails; that is why the separate `-svencoop` script exists.
- This symbol is the predecessor of `build_number`. If `SV_SendServerinfo` is not emitted for a platform
  node, the `find-build_number` dependency contract (`dependency_policy: required`) makes it fail closed.
- Signature uniqueness is enforced separately from owner uniqueness; a shared server-info prologue can drop
  `func_sig` while still emitting `func_va`/`func_rva`/`func_size`.
