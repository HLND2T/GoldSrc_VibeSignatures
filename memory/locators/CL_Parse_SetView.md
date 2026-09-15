---
title: CL_Parse_SetView locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-parse-setview
tags:
  - locator
  - engine
  - func
---

# CL_Parse_SetView

## Symbol

- **Name**: `CL_Parse_SetView`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_Parse_SetView.py` (thin wrapper over `ida_preprocessor_scripts/_svc_callback_common.py`)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: present everywhere, but on the newer engines it is a *tiny external handler* — the hl-10210 Windows body is only 0xB bytes (`call ...; mov ds:..., eax; retn`) and is emitted with `func_sig_allow_across_function_boundary: true` (non-strict fallback). The handler receives `cl.viewentity` from the server rather than computing it.

## Predecessors

- `cl_parsefuncs` (the validated `svc_func_t[]` parse table, produced by `find-cl_parsefuncs`, consumed via `expected_input`).

## How it is located

1. Load `cl_parsefuncs.{platform}.yaml` and take `TABLE_EA = gv_va`. Return `{}` for 64-bit databases.
2. Walk up to 80 entries of 12 bytes each (`svc_func_t` = `{opcode, pszname, pfnParse}`, all x86 dwords). Stop at an entry whose low byte is 0xFF (the sentinel). Require `opcode == index` for every entry (table self-validation).
3. `pszname = ida_bytes.get_strlit_contents(dword(entry+4))`; when it equals `b"svc_setview"`, `target = dword(entry+8)`.
4. Ownership recovery for older blob builds that leave indirect-only service handlers unowned: if `target` is in an executable segment but `ida_funcs.get_func(target)` is `None`, and `ida_bytes.get_full_flags(target)` is code or unknown, `ida_funcs.add_func(target)` is called. The validated named table entry is itself the explicit code-entry evidence.
5. Require exactly one surviving `target` (in an executable segment with `start_ea == target`); anything else returns `False`.
6. `_inspect_function_via_mcp` emits `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`; on strict-inspection failure it retries with `func_sig_allow_across_function_boundary: true` and records the flag. A missing `func_sig` fails the finder.

## Pitfalls

- The table walk is the *only* anchor: it validates opcode==index and the `0xFF` terminator, then matches the service name. Never assume a fixed entry index for `svc_setview` across builds.
- Older blob builds genuinely leave the handler without an IDA function owner; the explicit `add_func` recovery is required there and is safe because the pointer came from the validated named entry. Do not generalize this into creating functions from unvalidated pointers.
- The handler's `func_sig` is tiny, so `func_sig_allow_across_function_boundary: true` is expected on the newer engines and must be preserved into the downstream `cl_viewentity` resolution.
- On SvEngine Linux the parse table is PIC (`cl_parsefuncs` is a GOT-relative operand); this finder consumes the resolved `gv_va` from the `cl_parsefuncs` artifact, so the PIC contract is handled upstream and must not be re-derived here.
