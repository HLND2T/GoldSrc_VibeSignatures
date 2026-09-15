---
title: Cvar_Set locator
type: note
permalink: goldsrc-vibesignatures/locators/cvar-set
tags:
  - locator
  - engine
  - func
---

# Cvar_Set

## Symbol

- **Name**: `Cvar_Set`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Cvar_Set.py`

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux. Linux artifacts exist for hl-10210, hl-8684 and svencoop-10257.
- Inlined / absent: the standalone `Cvar_Set` body always exists. GCC additionally inlines its
  body into `Cvar_SetValue` and `Cvar_CommandWithPrivilegeCheck`, so on Linux the diagnostic
  literal has three to four owning functions; on Windows it has exactly one. On hl-8684/hl-10210
  the HL25 cvar-hook dispatch lives inside this function, just after the `Cvar_DirectSet` call.

## Predecessors

- `Cvar_DirectSet.{platform}.yaml` (produced by `find-Cvar_DirectSet`, consumed via
  `expected_input`). It is read from `new_binary_dir` as the current-EA tiebreak input, so it is a
  real run-time dependency, not documentation.

## How it is located

1. Find every exact `Cvar_Set: variable %s not found\n` string item in the live IDB.
2. Collect the owning function of every data/code xref to those items.
3. For each owner, compute `c_string_eas(start)`: the set of addresses referenced from the
   function's instructions that hold a printable-ASCII C string of length >= 2.
4. An owner survives only if the message literal occurs exactly once **and** that literal is the
   owner's *entire* C-string reference set. This is what separates the standalone `Cvar_Set` from
   the inlined copies, which also reference `"%f"`, `"%d"` or the command/privilege strings.
5. If more than one owner still survives and the `Cvar_DirectSet` artifact EA is available, keep
   only owners that `call`/`jmp` into `Cvar_DirectSet`. The branch target is resolved through up
   to four hops of tiny (<= 16 byte) thunks, matching either the artifact EA, a name containing
   `Cvar_DirectSet`, or a one-entry tail-call chain.
6. Require exactly one survivor, force-rename it to `Cvar_Set`, and emit
   `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`. A failed unique-signature
   inspection retries with `allow_across_function_boundary=True` and records the flag — small
   bodies may need it.

## Pitfalls

- The `Cvar_DirectSet` artifact is a *tiebreak*, not the primary anchor. If it is missing, the
  string-owner test alone must already be unique; otherwise the finder fails closed with
  `Cvar_Set string owner is not unique`.
- `c_string_eas` filters through `counted_c_string`, which requires decodable printable ASCII.
  When auditing a build by hand, compare referenced addresses and raw string bytes rather than
  silently dropping non-ASCII literals, or an inlined copy can look identical to `Cvar_Set`.
- Discovery does not use a byte signature or the old YAML (`old_yaml_map` is discarded).
- On Linux the function is the one that loads the inlined `cvar_vars` *before* the DirectSet call
  and the hook-list head *after* it; do not take the first absolute load in the function body as
  the cvar hook list.
- Blob engines (`hl-3248`, `hl-3266`, `hl-3329`, `hl-3647`) are analyzed from the decrypted
  `hw.decrypt.dll`; IDA may display the function as `sub_XXXXXXXX`. Match by artifact `func_va`,
  not the display name.
- Agent-produced YAML for `cvar_hooks` reuses this artifact's `func_sig`, so re-running this
  finder changes `cvar_hooks.gv_sig` too.
