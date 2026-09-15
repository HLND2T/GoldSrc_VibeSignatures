---
title: DispatchDirectUserMsg locator
type: note
permalink: goldsrc-vibesignatures/locators/dispatchdirectusermsg
tags:
  - locator
  - engine
  - func
---

# DispatchDirectUserMsg

## Symbol

- **Name**: `DispatchDirectUserMsg`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-DispatchDirectUserMsg.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. hl-10210 Windows body is 0x60 bytes.

## Predecessors

- None. `find-DispatchDirectUserMsg` has no `expected_input`; it is the root of the user-message group and the predecessor for `gClientUserMsgs`.

## How it is located

1. `FUNC_XREFS` anchors on `FULLMATCH:UserMsg: No pfn %s %d\n`.
2. That literal has **two** code xrefs — `DispatchUserMsg` and `DispatchDirectUserMsg`. The spec therefore declares `exclude_strings: ["FULLMATCH:UserMsg: Not Present on Client %d\n"]`, the diagnostic owned by `DispatchUserMsg`, and resolves the single remaining owner.
3. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size` (no `allow_across_function_boundary` flag).

## Pitfalls

- The exclusion must be `UserMsg: Not Present on Client %d\n`. Do **not** exclude on `Malformed WeaponList request, ignoring` — that string is absent on hl-3248/hl-3266/hl-3329, so excluding on it would leave the disambiguation empty and the finder would fail on the older builds.
- The two coexisting `UserMsg:` diagnostics are the whole reason this symbol needs an explicit exclusion; without it the owner set is ambiguous and the finder must fail rather than pick one.
- The name string is a *diagnostic*, so it lives in the function body — no table walk or byte signature is involved, and old artifacts are never consulted.
- The Linux build's `func_sig` here is taken from the function entry, not from the string block; on GCC builds with a `.part.N` cold clone the diagnostic can live in the clone while the entry remains the correct artifact (this finder anchors the entry, which is what the `gClientUserMsgs` predecessor needs).
