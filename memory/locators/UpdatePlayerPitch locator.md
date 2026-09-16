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

1. The producer loads the predecessor `func_va`, then walks its **direct callee set** through the
   shared `run_layout_walk` decoder (`ida_preprocessor_scripts/_portal_layout_ida.py`). The
   decoder's `o_near` branch routes PLT entries through `resolve_elf_plt`, so the 8948 Linux
   `.plt.got` thunk is resolved to the real target before the callee set is built.
2. A candidate must contain exactly four 4/8-byte float memory writes whose displacement set is
   `{0xB54, 0x2CC, 0x178, 0xB28}` with a single shared base register (the first argument),
   exactly two float comparisons (any of comiss/ucomiss/fcom/fcomp/fucom/fucomp/fucomi/fucomip/
   fcomip/fcompp), and exactly one float division (div/divsd/fdiv/fdivp/fdivr/fidiv). The two
   compile flavors on record are MSVC SSE2 and GCC x87; the predicate is mnemonic-based and
   platform-neutral.
3. Exactly one candidate must survive, else the finder fails closed.
   `CGameStudioRenderer` (8948: `CStudioModelRenderer`)`::StudioDrawPlayer` is the only
   cross-TU caller, so the walk is discriminating in practice (callee counts 3-5 per binary).
4. `_inspect_function_via_mcp` then emits `func_name`/`func_va`/`func_rva`/`func_size`/`func_sig`
   (with the across-boundary fallback available).

## Recorded evidence

| Binary | func_va | func_rva | func_size | Cross-check |
| --- | --- | --- | --- | --- |
| svencoop-10257/client/client.dll | `0x100725f0` | `0x725f0` | `0x69` | MetaHookSv call-site pattern resolves here |
| svencoop-10257/client/client.so | `0x12c1ec` | `0x12c1ec` | `0x64` | manual x87 disassembly |
| svencoop-8948/client/client.dll | `0x100b9d70` | `0xb9d70` | `0x69` | store-quad tail co-occurrence |
| svencoop-8948/client/client.so | `0x18a326` | `0x18a326` | `0x62` | symbol table `_Z17UpdatePlayerPitchP11cl_entity_sf` |

## Pitfalls

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