---
title: CVideoMode_Common_Init locator
type: note
permalink: goldsrc-vibesignatures/locators/cvideomode-common-init
tags:
  - locator
  - engine
  - func
---

# CVideoMode_Common_Init

## Symbol

- **Name**: `CVideoMode_Common_Init`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CVideoMode_Common_Init.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257. **Not** registered for hl-10210.
- Platforms: Windows + Linux (no `platform:` gate; Linux artifacts exist for hl-8684 and svencoop-10257). All GDI-era builds in this repo ship only `hw.dll`, so in practice it is Windows for cof-5936 / hl-3248..hl-6153.
- Inlined / absent: absent as a standalone entry on HL25 (hl-10210). HL25's `Init` does not call the startup graphic directly, so hl-10210 routes the startup-graphic predecessor through `CVideoMode_Common_PlayStartupSequence` instead of `Init`.

## Predecessors

- None. `find-CVideoMode_Common_Init` has no `expected_input`.

## How it is located

1. `FUNC_XREFS_SPECS` is an ordered list of two complete anchor sets, tried in order; the first that yields a single owner wins (`preprocess_common_skill` is called per spec and the loop returns `True` on the first success).
2. Spec 1: `xref_strings: ["FULLMATCH:-forceres"]` — exact C-string match on the `-forceres` command-line literal, owners = functions with an xref to it.
3. Spec 2 (fallback): `xref_strings: ["FULLMATCH:-24bpp"]` — the older `-24bpp` literal.
4. Both specs use empty `xref_gvs` / `xref_signatures` / `xref_funcs`, and there are no exclusion lists; the candidate set is exactly the literal's owners, which must collapse to one function.
5. Owner recovery runs, and the survivor is emitted as `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`. No LLM, no byte scan.

The reason the spec list exists is that the literal set differs by build family: the annotated references show hl-3248 carrying `-24bpp` while hl-8684 (Windows and Linux) carries both `-forceres` and `-24bpp`. Trying `-forceres` first keeps the newer builds on the more specific literal and lets older builds fall through.

## Pitfalls

- If a literal is missing, or has more than one owner on some build, that spec fails closed and the next spec is tried — an all-specs failure returns `False` and writes nothing, so a silent "no artifact" here usually means both literals are ambiguous or absent, not that the finder is broken.
- Do not add a `-24bpp`-only build to a spec list that omits it; the fallback ordering is the compatibility mechanism.
- The function is a predecessor of `CVideoMode_Common_DrawStartupGraphic` for the GDI family (cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554) and the GL family (hl-6153, hl-8684, svencoop-10257). If this artifact goes stale or its `func_va` moves, the DrawStartupGraphic LLM step loses its required dependency and produces nothing.
- Do not register this finder for hl-10210: HL25 has no such call path, which is why the config omits it there and uses `CVideoMode_Common_PlayStartupSequence` as the hl-10210 predecessor.
- Registry access inside `Init` is via the `off_...` `registry` vptr (`EngineD3D`, `ScreenWidth`, `ScreenHeight`), so the function body is dominated by indirect registry calls; that is expected and not evidence of a wrong owner.
