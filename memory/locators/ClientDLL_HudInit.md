---
title: ClientDLL_HudInit locator
type: note
permalink: goldsrc-vibesignatures/locators/clientdll-hudinit
tags:
  - locator
  - engine
  - func
---

# ClientDLL_HudInit

## Symbol

- **Name**: `ClientDLL_HudInit`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientDLL_HudInit.py` (thin wrapper over
  `preprocess_common_skill`)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux. Linux artifacts exist only for hl-10210 and hl-8684;
  `svencoop-10257` registers `find-ClientDLL_HudInit` with `platform: windows`, so there is
  **no** Sven Linux `ClientDLL_HudInit` artifact (and Sven Linux `HudInit` was never verified).
- Inlined / absent: never observed inlined into `CL_Init` in any covered build — every
  artifact is a standalone small function. Sizes: hl-3248 … hl-8684 Windows `0x3F` (it then
  `call`s a standalone `ClientDLL_CheckStudioInterface`), cof-5936 Windows `0x46`, svencoop-10257
  Windows `0x84`, hl-8684 Linux `0xA5`, hl-10210 Windows/Linux `0xD2` / `0x105` (on HL25 the
  whole studio-interface check from `ClientDLL_CheckStudioInterface` is inlined *into* HudInit).
  It is not an invariant: it has a single caller and is not exported, so LTO/LTCG could some day
  fold it into `CL_Init`.

## Predecessors

- None. `find-ClientDLL_HudInit` has no `expected_input`.
- It is itself a predecessor: `find-ClientDLL_HudInit-decompiles` consumes
  `ClientDLL_HudInit.{platform}.yaml` via `expected_input`.

## How it is located

1. `xref_strings: ["FULLMATCH:cl_righthand"]` — exact-string match (not substring). The literal
   is used *inside* the target function (`Cvar_FindVar("cl_righthand")` at the end of HudInit),
   so the string's owning function is the artifact.
2. `_string_candidates` unions the owning functions of every exact `cl_righthand` string item;
   `preprocess_common_skill` intersects the positive sets and requires **exactly one** surviving
   function, otherwise the finder returns False.
3. Emits `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig` (`func_sig` only when
   `_find_unique_bytes` resolves it uniquely). There is no across-boundary fallback variant for
   this finder — unlike `find-ClientDLL_Init`, whose desired-fields list has one.

## Pitfalls

- The literal is only a *byte* anchor, not an identity: a future build that inlines HudInit into
  the very large `CL_Init` would still resolve this finder to `CL_Init` and emit a `CL_Init`-sized
  body under the name `ClientDLL_HudInit`. The current single-caller/one-xref shape is what keeps
  this honest; do not treat HudInit as a stable hook entry point.
- Do not confuse this function with `ClientDLL_CheckStudioInterface`: on HL25 Windows there is no
  standalone check at all, and on HL25 Linux a cold out-of-line copy exists that the hot path
  never calls.
- Blob engines (`hl-3248`, `hl-3266`, `hl-3329`, `hl-3647`) are analyzed from the decrypted
  `hw.decrypt.dll`; IDA may render neighbours as `sub_XXXXXXXX`. Verify by artifact `func_va`,
  never by display name.
- `hw.so` string tables (`.dynstr`/`.symtab`) contain many copies of names such as
  `cl_righthand`; raw byte counts over a binary overstate the anchor. Only loaded-section string
  items are scanned, and unreferenced copies contribute no candidate.
