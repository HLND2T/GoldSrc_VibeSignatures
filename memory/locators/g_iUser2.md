---
title: g_iUser2 locator
type: note
permalink: goldsrc-vibesignatures/locators/g-iuser2
tags:
  - locator
  - client
  - gv
---

# g_iUser2

## Symbol

- **Name**: `g_iUser2`
- **Category**: `gv`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_IsThirdPerson-decompiles.py`

## Availability

- Declared in 14 configs: cof-5936, cstrike-10210, cstrike-3248, cstrike-3647, cstrike-4554, cstrike-6153, cstrike-8684, czero-10210, czero-8684, czeror-10210, czeror-8684, hl-10210, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. Shared spectator-target global; CS-family and HL-family, not Sven-only.

## Predecessors

- `CL_IsThirdPerson.{platform}.yaml` (produced by `find-client-private-predecessors`, consumed via `expected_input`, `dependency_policy: required`).

## How it is located

1. Recovered together with `g_iUser1` — `TARGET_GLOBAL_NAMES = ["g_iUser1", "g_iUser2"]`
   produces one LLM_DECOMPILE spec per name, both against
   `references/{gamever}/client/CL_IsThirdPerson.{platform}.yaml` with the generic
   `prompt/call_llm_decompile.md`.
2. The LLM maps the spectator-target global from the predecessor body and returns
   `found_gv` naming `g_iUser2`.
3. Emits a GV YAML with `gv_name`/`gv_va`/`gv_rva`/`gv_sig`/`gv_sig_va`/`gv_inst_offset`/
   `gv_inst_length`/`gv_inst_disp`.

## Pitfalls

- `g_iUser2` holds the observed player index; a candidate-selection error that lands on
  `g_iUser1` (or vice versa) still yields a unique signature but the wrong symbol. Keep the
  two specs separate and require both.
- Windows cstrike-3248/3647 reach the predecessor only through the Metahook blob ABI
  fallback.
- Reference addresses, registers and anonymous IDA names must not be copied into the
  target result.
