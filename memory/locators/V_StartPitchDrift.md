---
title: V_StartPitchDrift locator
type: note
permalink: goldsrc-vibesignatures/locators/v-startpitchdrift
tags:
  - locator
  - client
  - func
---

# V_StartPitchDrift

## Symbol

- **Name**: `V_StartPitchDrift`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-V_StartPitchDrift.py`

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. SvEngine-only; no other config declares it.

## Predecessors

- None. `find-V_StartPitchDrift` has no `expected_input`.

## How it is located

1. `_client_registration_common.REGISTRATION_QUERY` is invoked with the label
   `centerview`. The helper collects strings whose NUL-terminated bytes end with the label
   (GCC may pool `centerview` into `force_centerview`; the registration operand still points
   at the exact NUL-terminated label, not its prefix), finds their owning functions via
   `DataRefsTo`, and scans each basic block for a `call` that consumes `(name, callback)`
   from `[esp+0]`/`[esp+4]` or from the top two pushed values.
2. Exactly one callback must be registered for `centerview`
   (`len(targets) != 1` fails). This matches `V_Init`'s
   `pfnAddCommand("centerview", V_StartPitchDrift)` from `cl_dll/view.cpp`.
3. The target is emitted as a function YAML (`func_name`/`func_va`/`func_rva`/`func_size`/
   `func_sig`). If signature generation fails at the exact entry, the finder retries with
   `allow_across_function_boundary` and records `func_sig_allow_across_function_boundary`.
4. This function then feeds `find-V_StartPitchDrift-decompiles`, which recovers
   `g_pitchdrift`.

## Pitfalls

- The registration label is the only anchor: no source address or instruction pattern is a
  locator. Do not add a byte signature or reuse an old YAML.
- GCC string pooling means a plain substring search for `centerview` can land on
  `force_centerview`; the helper defends by requiring the exact NUL-terminated label bytes.
- The finder only reads cdecl registration arguments — it does not follow the function's
  body, so the `V_StartPitchDrift` artifact is validated purely by signature uniqueness.
