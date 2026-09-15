---
title: CL_Set_ServerExtraInfo locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-set-serverextrainfo
tags:
  - locator
  - engine
  - func
---

# CL_Set_ServerExtraInfo

## Symbol

- **Name**: `CL_Set_ServerExtraInfo`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_Set_ServerExtraInfo.py` (thin wrapper over `_svc_callback_common.preprocess_svc_callback`)

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed for Sven. Not configured for HL/cof/CS/CZ/CZDS.

## Predecessors

- `cl_parsefuncs.{platform}.yaml` (produced by `find-cl_parsefuncs`, consumed via `expected_input`).

## How it is located

1. Loads `cl_parsefuncs.{platform}.yaml` from the new binary dir and reads its `gv_va` as the table base `TABLE_EA`. If the predecessor is missing the finder returns False.
2. Walks up to 80 entries of the x86 `svc_func_t` table at `TABLE_EA + index * 12` (opcode, `pszname`, `pfnParse`, all dwords). The walk requires the opcode sequence to start at `0` and increase by one per entry; it stops when `opcode & 0xff == 0xff` (end-of-list).
3. The entry whose NUL-terminated `pszname` equals `svc_sendextrainfo` yields `target = dword(entry + 8)`.
4. `target` must lie in an executable segment and resolve to a function whose `start_ea == target`. Older blob builds leave the indirect-only service handler unowned, so when `get_func` returns None and the bytes are code/unknown the finder calls `add_func` — the validated named table entry is itself explicit code-entry evidence. Exactly one match is required.
5. Emits a function YAML (`func_name`/`func_va`/`func_rva`/`func_size`/`func_sig`); a failed exact-entry inspection retries with `allow_across_function_boundary`.

## Pitfalls

- The table entry size and field order are x86 `svc_func_t` (12 bytes); the opcode contiguity check rejects a mis-based table.
- Do not depend on IDA function ownership for the handler: Sven blob builds can leave it indirect-only. The `add_func` fallback is deliberately restricted to code/unknown bytes in an executable segment.
- `cl_parsefuncs` is the sole anchor; no address or byte pattern is used. If the predecessor YAML is absent the finder silently returns False rather than scanning.
