---
title: GL_BuildLightmaps locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-buildlightmaps
tags:
  - locator
  - engine
  - func
---

# GL_BuildLightmaps

## Symbol

- **Name**: `GL_BuildLightmaps`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GL_BuildLightmaps.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config).
- Inlined / absent: present as a standalone entry on every validated branch; only the discovery anchor differs per branch.

## Predecessors

- `R_NewMap.{platform}.yaml` (produced by `find-R_NewMap`, consumed via `expected_input`) — used by the default branch only.

## How it is located

The branch is chosen from the current `(gamever, platform)` tag; unknown tags fall back to the R_NewMap chain. Addresses, byte patterns and call ordinals are never used for discovery — the signature is generated afterwards for validation.

1. `hl-10210/windows`: the UTF-16LE assertion literal `surface->polys->next == NULL` is resolved through the shared `xref_unicode_strings` STRTYPE_C_16 collector; it has exactly one owner, GL_BuildLightmaps.
2. `svencoop-10257/linux`: ASCII `FULLMATCH:AllocBlock: full`, a single-owner literal inside GL_BuildLightmaps' lightmap block allocator.
3. Every other validated branch: LLM_DECOMPILE `found_call` against the annotated reference `references/{gamever}/engine/R_NewMap.{platform}.yaml`; the covered R_NewMap body calls GL_BuildLightmaps directly, so the call (or tail `jmp`) resolves the entry.

Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

## Pitfalls

- Two branches use in-binary literals; the rest depend on the R_NewMap artifact plus its annotated reference YAML. When the analyzed gamever has no reference, `{gamever}` falls back to the canonical reference gamever (hl-10210), so the default chain still resolves for the shared hl/cof family.
- The UTF-16 branch fails closed if the literal is present but no owning function boundary is recoverable (`_unicode_string_candidates` records such hits instead of silently returning zero owners).
- `AllocBlock: full` is SvEngine-only wording — do not expect it on the hl/cof builds, and do not use it as a cross-engine anchor.
