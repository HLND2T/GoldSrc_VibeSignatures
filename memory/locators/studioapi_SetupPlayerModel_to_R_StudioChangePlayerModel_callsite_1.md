---
title: studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_1 locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-setupplayermodel-to-r-studiochangeplayermodel-callsite-1
tags:
  - locator
  - engine
  - patch
---

# studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_1

## Symbol

- **Name**: `studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_1`
- **Category**: `patch`
- **Module**: engine (`hw.dll` only)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_CallSites.py`
  (logic in `ida_preprocessor_scripts/_func_to_func_callsites_common.py`)

## Availability

- Declared in only 7 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, cof-5936,
  svencoop-10257. **Not** declared for hl-6153, hl-8684 or hl-10210, where MSVC merges the two
  source call sites into one and only `callsite_0` exists.
- Platforms: **Windows-only** (`platform: windows`).
- Inlined / absent: on hl-6153/hl-8684/hl-10210 Windows the two source call sites are merged
  by MSVC into a single branch, so this second artifact does not exist there; on Linux the
  callee is inlined and no branch survives at all.

## Predecessors

- `studioapi_SetupPlayerModel` (owner) and `R_StudioChangePlayerModel` (callee), both consumed
  via `expected_input`.

## How it is located

Identical chain to `callsite_0`:

1. `expected_callsite_outputs` parses the declared outputs into a contiguous zero-based index
   list; because only `callsite_1` is declared on these 7 configs the list has a single
   element and the helper still requires `len(sites) == len(expected)`.
2. Owner/callee artifacts are loaded and the owner is re-verified through MCP; the callee
   must be an exact function start.
3. Every direct rel32 `call`/`jmp` in the owner body whose `XrefsFrom` targets the callee is
   collected, in owner-body instruction address order.
4. Each branch gets a forward-only unique patch signature (verbatim branch bytes + wildcarded
   operand bytes, extended up to 96 bytes / 64 instructions until exactly one match).
5. `sites[1]` is written to this artifact; `patch_va`/`patch_rva` = the branch match start,
   `patch_sig_disp = 0`, `patch_bytes` omitted.

## Pitfalls

- The index is positional, not semantic: the artifact name encodes the branch's order in the
  owner body, so a build that reorders or merges the two source call sites silently changes
  what `callsite_1` means. Never assume "newer build merges" — verify the declared count.
- Because the expected-output list is derived from configs, a config that declares
  `callsite_1` on a merged build will make the whole finder fail (it requires an exact count
  match, not a subset).
- Uniqueness is re-checked via `_find_unique_bytes`; a non-unique signature aborts the finder
  and no patch artifact is written.
