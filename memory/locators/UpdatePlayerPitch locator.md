---
title: UpdatePlayerPitch locator
type: note
permalink: goldsrc-vibesignatures/locators/update-player-pitch
tags:
- locator
- client
- func
---

# UpdatePlayerPitch

## Symbol

- **Name**: `UpdatePlayerPitch`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-UpdatePlayerPitch.py`

## Availability

- Declared in 2 configs: svencoop-10257 and svencoop-8948 (both Windows + Linux).
- Sven-only closed-source client addition (view.cpp translation unit). The HLSDK official
  `cl_dll/view.cpp` in `D:\HLND2T_official` has no counterpart, and the CS/CZ/CZDS/HL/CoF
  clients never reference it.

## Function semantics

`void UpdatePlayerPitch(cl_entity_t* ent, float pitch)` clamps the pitch through exactly two
floating-point comparisons, divides it by one coefficient, then stores the result into the four
`cl_entity_t` pitch fields at `+0xB54`, `+0x2CC`, `+0x178`, `+0xB28` (byte layout identical on
8948 and 10257, Windows and Linux). On 8948 Linux the out-of-line function keeps the authoritative
local symbol `_Z17UpdatePlayerPitchP11cl_entity_sf` (size 98 = artifact `func_size 0x62`).

## Predecessors

- `GameStudioRenderer_StudioDrawPlayer.<platform>.yaml` (already covered vfunc in both configs),
  consumed via `expected_input`.

## How it is located
2. A candidate must contain exactly four memory writes whose displacement set is
   `{0xB54, 0x2CC, 0x178, 0xB28}` with a single shared base register (the first argument),
   where **every pitch-field write is itself an SSE scalar or x87 float store**
   (`movss`/`movsd`/`fst`/`fstp`, 4 or 8 bytes — integer `mov` to a pitch displacement is
   rejected), plus exactly two float comparisons (any of comiss/ucomiss/fcom/fcomp/fucom/
   fucomp/fucomi/fucomip/fcomip/fcompp) and exactly one **float** division
   (`divss`/`divsd`/`fdiv`/`fdivp`/`fdivr`; integer `div` and integer-operand `fidiv` are
   rejected). The predicate lives in `ida_preprocessor_scripts/_pitch_store_predicate.py`
   (pure Python, source-injected into the walk) and is covered by
   `tests/test_pitch_store_predicate.py` synthetic fixtures including the two
   reviewer-reproduced false positives (integer mov stores, integer div).
## Recorded evidence

| Binary | func_va | func_rva | func_size | Cross-check |
| --- | --- | --- | --- | --- |
| svencoop-10257/client/client.dll | `0x100725f0` | `0x725f0` | `0x69` | MetaHookSv call-site pattern resolves here |
| svencoop-10257/client/client.so | `0x12c1ec` | `0x12c1ec` | `0x64` | manual x87 disassembly |
| svencoop-8948/client/client.dll | `0x100b9d70` | `0xb9d70` | `0x69` | store-quad tail co-occurrence |
| svencoop-8948/client/client.so | `0x18a326` | `0x18a326` | `0x62` | symbol table `_Z17UpdatePlayerPitchP11cl_entity_sf` |

## Pitfalls
- **Width is not float semantics.** The shared decoder's `memory_writes` records operand shape
  (base/disp/size) for every store; a 4/8-byte width alone cannot prove a float store, and the
  walk's downstream `func_sig` uniqueness only proves address uniqueness, never function
  identity. The predicate therefore whitelists the float store mnemonics and float division
  mnemonics explicitly (PR #129 review).

- **"10257-exclusive" is a MetaHookSv artifact, not a fact.** The MetaHookSv byte signature
  `FF 73 40 E8 ? ? ? ? 83 C4 08 80 3D ? ? ? ? 00` requires the `cmp g_bIsRenderingPortals, 0`
  that only 10257 emits after the call site; the function itself exists on 8948 W/L too.
- **Same-TU callers are inlined.** `V_CalcNormalRefdef` also uses UpdatePlayerPitch: MSVC and
  10257-Linux GCC inline it (a second store-quad lives inside V_CalcNormalRefdef), while 8948
  Linux routes both call sites through `.plt.got`. The walk only ever sees the out-of-line body,
  which is the artifact target; the inlined copies are intentionally not produced.
- **8948 Linux symtab is the authority for Sven client symbols** (11590 symbols; 10257 ships
  only GLEW symbols plus `.gnu_debuglink`). Cross-check any new Sven client anchor there first.
- On GCC PIE builds a function can appear xref-free because callers go through PLT thunks, and a
  query aimed mid-instruction (e.g. `0x12c1ee` inside the real start `0x12c1ec`) silently returns
  no xrefs — always anchor xref queries on IDA's function start.