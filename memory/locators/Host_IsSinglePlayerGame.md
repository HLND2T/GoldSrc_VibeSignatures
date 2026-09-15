---
title: Host_IsSinglePlayerGame locator
type: note
permalink: goldsrc-vibesignatures/locators/host-issingleplayergame
tags:
  - locator
  - engine
  - func
---

# Host_IsSinglePlayerGame

## Symbol

- **Name**: `Host_IsSinglePlayerGame`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Host_IsSinglePlayerGame.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: present on every validated build. The callee body itself is often tiny
  (hl-8684 hw.dll is a 12-byte `== 1` trampoline), so a unique strict-window signature may
  not exist and the artifact then carries `func_sig_allow_across_function_boundary`.

## Predecessors

- `studioapi_SetupPlayerModel` (produced by `find-studioapi_SetupPlayerModel{,-svencoop}`,
  consumed via `expected_input`) — the owner function whose direct calls are scanned.

## How it is located

Source: `qboolean Host_IsSinglePlayerGame(void) { if (sv.active) return svs.maxclients == 1;
else return cl.maxclients == 1; }` (`engine/host.c`); it is consumed by
`( developer.value || !Host_IsSinglePlayerGame() )` in `engine/r_studio.c`.

1. Load the verified `studioapi_SetupPlayerModel` artifact; require its `func_va` to be a
   function start.
2. Enumerate the owner's direct `call` instructions (target from an `o_near` operand).
3. The call must be consumed as a boolean: a `test eax, eax` among the next two instructions,
   followed by a conditional jump immediately after it.
4. The callee (`callee_matches`) must be a function start with size `0 < size <= 96`, must
   produce the `== 1` boolean (a `setz`/`sete`, or the `dec`+`sbb` trick used by hl-8684
   hw.dll through a shared maxclients helper), must make no indirect calls and at most one
   direct call.
5. The callee must have at least 8 code xrefs (the source calls it from ~11 sites across
   cl_parsefn/cl_main/host/r_studio/sv_main/view).
6. Require exactly one surviving candidate; emit its `func` artifact.

## Pitfalls

- Callees that must be rejected on every build: `Q_stricmp`/`Q_strncpy`/`snprintf`/
  `Mod_ForName`-style helpers (they carry arguments or contain compare loops), `FS_FileExists`
  (SvEngine — it makes an indirect filesystem call), and `R_StudioChangePlayerModel` (it
  ignores the return value, so it fails the boolean-consumption test).
- hl-8684 hw.dll routes the `== 1` computation through a shared maxclients helper and the
  callee is only 12 bytes; without the across-boundary window the signature is ambiguous.
- DWARF cross-check on the official `hw.so` (evidence only): `0xa9500` (hl-10210),
  `0x10fe70` (hl-8684).
