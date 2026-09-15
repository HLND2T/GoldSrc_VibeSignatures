---
title: g_iUser1 locator
type: note
permalink: goldsrc-vibesignatures/locators/g-iuser1
tags:
  - locator
  - client
  - gv
---

# g_iUser1

## Symbol

- **Name**: `g_iUser1`
- **Category**: `gv`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_IsThirdPerson-decompiles.py`

## Availability

- Declared in 14 configs: cof-5936, cstrike-10210, cstrike-3248, cstrike-3647, cstrike-4554, cstrike-6153, cstrike-8684, czero-10210, czero-8684, czeror-10210, czeror-8684, hl-10210, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. This is the shared spectator-mode global; it is CS-family and HL-family, not Sven-only.

## Predecessors

- `CL_IsThirdPerson.{platform}.yaml` (produced by `find-client-private-predecessors`, consumed via `expected_input`, `dependency_policy: required`).

## How it is located

1. `TARGET_GLOBAL_NAMES = ["g_iUser1", "g_iUser2"]` are recovered together by
   `preprocess_common_skill` using the generic `prompt/call_llm_decompile.md` and reference
   YAML `references/{gamever}/client/CL_IsThirdPerson.{platform}.yaml`.
2. The predecessor's recovered disassembly/pseudocode is the current-target evidence; the
   LLM maps the spectator-mode global and returns `found_gv` naming `g_iUser1`. Exactly one
   target of each name is expected.
3. Emits a GV YAML with `gv_name`/`gv_va`/`gv_rva`/`gv_sig`/`gv_sig_va`/`gv_inst_offset`/
   `gv_inst_length`/`gv_inst_disp`. No `gv_sig_allow_across_function_boundary` for this
   symbol.

## Pitfalls

- `g_iUser1` and `g_iUser2` are recovered from the same body and are siblings; do not
  collapse them into one another or accept a single global for both.
- `CL_IsThirdPerson` is an export-blob ABI root, so on Windows cstrike-3248/3647 the
  predecessor comes from the blob stack-table recovery rather than a named export.
- The reference YAML is `{gamever}`-scoped: a reference body from one family must never
  supply the address or register for another.
