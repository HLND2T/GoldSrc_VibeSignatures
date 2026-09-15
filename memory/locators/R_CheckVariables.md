---
title: R_CheckVariables locator
type: note
permalink: goldsrc-vibesignatures/locators/r-checkvariables
tags:
  - locator
  - engine
  - func
---

# R_CheckVariables

## Symbol

- **Name**: `R_CheckVariables`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_CheckVariables.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only. The finder is not platform-gated.
- Inlined / absent: never inlined; the `gl_rmisc.c` function survives as a standalone entry in every registered build.

## Predecessors

- `GL_LoadFilterTexture` (produced by `find-GL_LoadFilterTexture`, consumed via `expected_input` / `xref_funcs`).

## How it is located

1. `xref_funcs = ["GL_LoadFilterTexture"]`: resolve the dependency artifact's `func_va` into the IDB, then build the candidate set as every function that has any xref to that address (`_functions_referencing`).
2. `R_CheckVariables` is the only engine function that calls `GL_LoadFilterTexture` (filter-cvar change detection), so the candidate set collapses to it.
3. Emits `func_name`/`func_sig`/`func_va`/`func_rva`/`func_size`. No byte signature and no float anchor participate.

## Pitfalls

- The finder docstring states that SvEngine's Linux build inlines the `GL_LoadFilterTexture` call and that the platform is excluded through config-level gating. The shipped `svencoop-10257` config nonetheless registers `find-R_CheckVariables` for both platforms and `R_CheckVariables.linux.yaml` exists, so the `xref_funcs` route evidently still resolves the symbol there. Treat the docstring as stale on this point; the config plus artifact is the ground truth.
- `R_CheckVariables` is the anchor for two downstream chains (`find-R_ForceCVars_R-AnimateLight`, `find-S_ExtraUpdate`); a wrong host here silently corrupts three symbols.
