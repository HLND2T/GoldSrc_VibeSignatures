---
title: g_bRenderingPortals_SCClient locator
type: note
permalink: goldsrc-vibesignatures/locators/g-brenderingportals-scclient
tags:
  - locator
  - client
  - gv
---

# g_bRenderingPortals_SCClient

## Symbol

- **Name**: `g_bRenderingPortals_SCClient`
- **Category**: `gv`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-V_CalcRefdef-decompiles.py`

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. Sven-only; the sibling Sven guards
  (`g_ViewEntityIndex_SCClient`) live in a different finder, and the CS-family extra-info
  arrays are Sven-absent.

## Predecessors

- `V_CalcRefdef.{platform}.yaml` (produced by `find-client-private-predecessors`, consumed
  via `expected_input`, `dependency_policy: required`).

## How it is located

1. `preprocess_common_skill` runs the generic LLM_DECOMPILE path with
   `prompt/call_llm_decompile.md` and reference YAML
   `references/svencoop-10257/client/V_CalcRefdef.{platform}.yaml`.
2. The predecessor's recovered disassembly is the target evidence: in the reference body the
   guard appears as `cmp g_bRenderingPortals_SCClient, 0` early in `V_CalcRefdef`, before the
   main camera path. The LLM maps the portal-pass guard and returns `found_gv`.
3. Emits a GV YAML with `gv_name`/`gv_va`/`gv_rva`/`gv_sig`/`gv_sig_va`/`gv_inst_offset`/
   `gv_inst_length`/`gv_inst_disp` and `gv_sig_allow_across_function_boundary:true`.

## Pitfalls

- This is a boolean guard with several accesses in `V_CalcRefdef`; the LLM must pick the
  guard global, not a neighbouring `ref_params` field or the `g_iWaterLevel` store.
- Sven-only scope: do not reuse the CS-family `V_CalcRefdef`-like code or any reference
  address across families. Addresses recorded in notes are evidence only.
- Depends entirely on the `V_CalcRefdef` artifact; if the export/blob ABI root fails, this
  decompiles finder fails too.
