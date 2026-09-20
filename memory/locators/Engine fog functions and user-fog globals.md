---
title: Engine fog functions and user-fog globals
type: note
permalink: goldsrc-vibesignatures/locators/engine-fog-functions-and-user-fog-globals
tags:
- locator
- engine
- func
- gv
- fog
- r_triangle
- triangleapi
- pTriAPI
- svencoop
- blob
---

# Engine fog implementations and user-fog globals

## Symbols

- **Functions**: `R_RenderFog(void)` (`float *flFogColor, float flStart, float flEnd, BOOL bOn`),
  `R_FogParams(float flDensity, int iFogSkybox)`
- **Globals**: `g_bUserFogOn`, `g_bFogSkybox` (`BOOL*`), `flFinalFogColor` (`float[4]`),
  `flFogStart`, `flFogEnd`, `flFogDensity` (`float*`)
- **Category**: `func` / `gv`
- **Module**: engine (`hw.dll` / `hw.so` / `hw.decrypt.dll` for the BLOB builds)
- **Source**: `engine/r_triangle.c` (all eight live in one translation unit; `R_RenderFinalFog`
  is a seventh, separately covered symbol)
- **Owners**:
  `ida_preprocessor_scripts/find-R_RenderFog-R_FogParams-from-tri.py` (functions),
  `ida_preprocessor_scripts/find-R_RenderFog-fog-globals.py` (globals),
  shared decoder in `ida_preprocessor_scripts/_fog_tri_common.py`

## Trigger

Adding the engine user-fog symbols, or needing a stable anchor for the `triangleapi_t` table.
Root constraint: the six globals have no exported name, and the two functions are only reachable
through a published function-pointer table:

```c
triangleapi_t tri = { TRI_API_VERSION, ..., R_RenderFog, ..., R_FogParams };
void R_FogParams(float flDensity, int iFogSkybox){ flFogDensity = flDensity; g_bFogSkybox = iFogSkybox; }
void R_RenderFog(float *flFogColor, float flStart, float flEnd, BOOL bOn){
    if (bOn && gl_fog.value > 0) { g_bUserFogOn = true;
        flFinalFogColor[i] = flFogColor[i]/255.0; ...; flFogStart = flStart; flFogEnd = flEnd; }
    else g_bUserFogOn = false;
}
```

## How it is located

The anchor is the public engine table, so no byte signature, prior artifact signature or address
takes part in discovery.

1. **`tri`** — `cl_enginefunc_t cl_enginefuncs` (`engine/cdll_int.c`) publishes `&tri` as its
   `pTriAPI` field. In the initializer `&tri` is entry 82 (0-based), i.e. byte offset **`0x148`**;
   `&efx` and `&eventapi` follow at `0x14C`/`0x150`. `tri` is validated to start with
   `TRI_API_VERSION == 1` and to hold 19 further function starts.
2. **Functions** — `common/triangleapi.h` fixes the field order, so `tri + 13*4` is `Fog`
   (`R_RenderFog`) and `tri + 19*4` is `FogParams` (`R_FogParams`).
3. **Globals** — recovered from the two function bodies by the source's argument-to-global
   assignment, never from address order or a layout guess:
   - `flFinalFogColor` — the four-element colour run whose **last element is the alpha literal
     `1`** (`flFinalFogColor[3] = 1`), so its base is that write's address minus `0xC`;
   - `flFogStart` / `flFogEnd` — the writes whose value is argument 1 / argument 2;
   - `g_bUserFogOn` — the remaining write, a 0/1 constant or a stack temporary, never an
     argument slot;
   - `flFogDensity` / `g_bFogSkybox` — `R_FogParams`' argument 0 / argument 1.

Argument identity comes from the tracked caller frame: cdecl lays arguments out from
`[entry_esp+4]` upwards, so a `[esp/ebp+disp]` load resolves to argument
`(disp - frame_delta - 4) / 4` once the function's own `push`/`pop`/`sub esp`/`add esp` movement
and its `mov ebp, esp` are accounted for.

## Forms that must all be handled

| form | example | builds |
| --- | --- | --- |
| MSVC absolute stores, direct | `mov g_bUserFogOn, 1`; `fstp flt_2788DF0` | hl-3248/3266/3329/3647/4554/6153/8684/10210, cof-5936, svencoop-* |
| MSVC absolute stores, SSE with arithmetic | `movss xmm0, [eax]` → `divss` → `movss dword_111C50A0, xmm0` | hl-10210/8684/6153/4554 |
| gcc non-PIC absolute, x87 | `fld [eax]` → `fdiv ds:const` → `fstp ds:flFinalFogColor` | hl-8684/10210 linux |
| gcc PIC `gv@GOTOFF(%ebx)` | `movss ds:(flFogStart - 33A000h)[eax], xmm0` | svencoop-8948/10257 linux |
| SvEngine forwarder | slot 13 is `tri_R_RenderFog_I` (normalises `BOOL`), real body is the callee | svencoop-8948/10257 |

The SvEngine rule: a slot whose body owns **no** writable-global write is followed to the single
callee that does. The same test rejects the PIC `__x86_get_pc_thunk_*` helper.

## Evidence

- Linux ELF symbol tables confirm every address on three builds, for example hl-10210 linux:
  `tri` = `0x2c4e00` (`eventapi` = `0x2c4fc0`), `R_RenderFog` = `0x1b0540`,
  `R_FogParams` = `0x1b0060`, `flFinalFogColor` = `0x13cf7ec`, `flFogStart` = `0x13cf7d4`,
  `flFogEnd` = `0x13cf7e8`, `g_bUserFogOn` = `0x13cf7dc`, `flFogDensity` = `0x13cf7d8`,
  `g_bFogSkybox` = `0x2c4e6c`. All 24 emitted addresses on the three symbol-bearing Linux builds
  match the symtab.
- `ida_analyze_bin.py -allgamever -modules engine -skill <finder> -platform windows,linux`
  reports 15 successful / 0 failed / 0 skipped for both finders (11 gamevers, 15 platform pairs).
- Windows/BLOB builds have stripped symbols and are validated by table shape plus the fog write
  semantics (`/255.0` colour scaling, 0/1 flag, `GL_FOG_*` argument order).

## Pitfalls

- **`eventapi` looks like `tri`.** `event_api_t` also begins with `version = 1` followed by
  function pointers, so a "version + N code pointers" scan finds two adjacent candidates
  (`0x148` = `tri`, `0x150` = `eventapi`). The fixed `pTriAPI` offset plus the source order
  (`&tri, &efx, &eventapi`) is what disambiguates them; `efx` at `0x14C` is a plain data pointer.
- **Do not identify the colour array by a `k[0]` element pointer.** MSVC computes
  `flFogColor[i]/255.0` through `movss`/`divss`, so the store's value provenance is not a direct
  argument load. The `flFinalFogColor[3] = 1` alpha literal is the stable discriminator, and it
  is the *highest* address of the run.
- **`g_bUserFogOn` may be written once, not twice.** On `cof-5936` both arms store through one
  `mov g_bUserFogOn, eax` fed by a stack temporary; on classic builds the flag is written
  directly with `1`/`0`. It is identified as "the remaining write, not fed by an argument slot",
  not by counting writes.
- **Config pitfall.** `configs/svencoop-10257.yaml` attaches `platform: linux` after the
  `R_RenderScene` symbol's `category:` line; a naive insert after `category:` splits that
  attribute onto the newly added symbol and breaks the formal artifact contract for both
  platforms. Consume the whole symbol block before inserting.
