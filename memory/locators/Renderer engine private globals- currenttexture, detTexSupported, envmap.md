---
title: 'Renderer engine private globals: currenttexture, detTexSupported, envmap'
type: note
permalink: goldsrc-vibesignatures/locators/renderer-engine-private-globals-currenttexture-det-tex-supported-envmap
tags:
- locator
- renderer
- engine
- gv
- currenttexture
- dettexsupported
- envmap
- issue-141
---

# Renderer engine private globals: currenttexture, detTexSupported, envmap

Producers: `find-GL_Bind-currenttexture`, `find-DT_LoadDetailMapFile`,
`find-DT_LoadDetailMapFile-detTexSupported-decompiles`, and the `envmap` output of
`find-R_DrawViewModel-private-globals` / `find-R_RenderView-viewmodel-globals-svencoop-inlined`.

## `currenttexture` — owner `GL_Bind`

Source (`engine/gl_draw.c`): `if (currenttexture == texnum) return;` then
`currenttexture = texnum;` immediately before `qglBindTexture`. `g_currentpalette`
is the only other writable global in the body and is read later.

Rule: the **earliest writable-data global the body both reads and writes**; the
anchor is that global's first reference carrying a four-byte displacement. On PIC
builds whose store is register-indirect this is the module-base `lea`
(svencoop-10257 Linux, `lea edx, unk_2F1B78[ebx]`); on svencoop-8948 Linux the
global is GOT-indirect (`.got` slot `currenttexture_ptr` -> `.data` `currenttexture`
at `0x33F140`), which the shared `.got` pointee handling resolves.

## `detTexSupported` — owner `DT_LoadDetailMapFile`

`DT_Initialize` cannot be the predecessor on the BLOB builds
(`hl-3248/3266/3329/3647`): there it is **inlined into `CheckMultiTextureExtensions`**
(`engine/gl_vidnt.c`) and the `detTexSupported = true` store lives in a jump-target
block (e.g. hl-3248 `loc_1D35590`, store `0x20807EB`) that IDA owns as a tail
*outside* the recorded function range, so the GV contract cannot express it.
Those four tags no longer declare `DT_Initialize` at all — the registration and the
`DT_Initialize.windows.yaml` artifacts pointing at the `CheckMultiTextureExtensions`
body were removed (2026-09-18); see `memory/locators/DT_Initialize.md`.

`DT_LoadDetailMapFile` opens with `if (!detTexSupported) { return; }` and is a
standalone function on every family. It is located by
`FULLMATCH:No detail texture mapping file: %s\n`, a string byte-identical on all 15
engine binaries (BLOB included). The global is then recovered by `LLM_DECOMPILE`
(`found_gv`) against the annotated reference at
`references/hl-10210/engine/DT_LoadDetailMapFile.{platform}.yaml`.

Independent cross-check (not shipped): the first **1-byte** writable-global read in
that function is `detTexSupported`. The byte-size filter is required — the 4-byte
`mov eax, ___security_cookie` prologue load and the adjacent `g_detTexLoaded` byte
both otherwise match first.

## `envmap` — owner `R_DrawViewModel`

`R_Envmap_f` (also string-anchored) is the cleaner store site
(`envmap = true/false`) and works on GoldSrc/HL25/CoF, but on **SvEngine Linux** it
is a validating wrapper that tail-jumps into an unnamed body function, so its store
cannot be anchored in the recorded owner. The chosen owner instead reuses the
already-shipped `cl_stats` anchor in `R_DrawViewModel` (svencoop Windows: the
inlined `R_RenderView` body).

Rule: scanning backwards from the `cl_stats` site (`jle/jng` + `[reg+0xB94]`), the
first instruction that is an **integer absolute-global test** — `cmp [abs], imm/reg`
or `mov reg, [abs]` followed by `test reg,reg` / `cmp reg,0`. Float cvar tests
(`movss`/`fld` + `ucomiss`/`fucomip`) are skipped, which is what keeps the scan from
stopping on `r_drawentities.value`.

## Coverage

15/15 artifacts for each symbol across `cof-5936`, `hl-3248/3266/3329/3647`,
`hl-4554/6153/8684/10210`, `svencoop-8948/10257` (Windows, plus Linux where
declared). Validated with `ida_analyze_bin.py -allgamever -modules engine` (0
failures) and the full `tests/run_test_suite.py all` (887 tests OK).
