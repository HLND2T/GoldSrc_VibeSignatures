---
title: R_StudioSetupSkin locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiosetupskin
tags:
  - locator
  - engine
  - func
---

# R_StudioSetupSkin

## Symbol

- **Name**: `R_StudioSetupSkin`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioSetupSkin.py`
  (also emits `GL_UnloadTexture`)

## Availability

- Declared in 11 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, hl-10210, cof-5936, svencoop-8948, svencoop-10257.
- Platforms: no `platform:` gating. Linux artifacts exist for hl-8684, hl-10210,
  svencoop-8948 and svencoop-10257; CoF is Windows-only.
- Inlined / absent: never inlined. On GCC Linux the `"DM_Base.bmp"` owner is the
  outlined `.part.N` body (MetaHook ReverseSearch hit). The 33/41-byte exported
  wrapper only tests `STUDIO_NF_CHROME` and tail-jumps into that body; the
  artifact VA is the body.

## Predecessors

- None. The finder has no `expected_input` and passes `old_yaml_map=None`.

## How it is located

`exact_string_owner("DM_Base.bmp")` — the studio texture name compared only
inside `engine/r_studio.c` `R_StudioSetupSkin`. The literal occurs once and its
code xrefs collapse to one function on every configured engine build. Generated
`func_sig` validates the located entry and is not a discovery anchor.

Linux ELF names: unmangled `R_StudioSetupSkin` / `R_StudioSetupSkin.part.N` on
hl-8684/10210; `_Z17R_StudioSetupSkinPvi` / `.part.10` on svencoop-8948;
svencoop-10257 `hw.so` is stripped. Artifact `func_name` stays `R_StudioSetupSkin`.

## Pitfalls

- `"Remap"` belongs to `R_IsRemapSkin`. It is inlined into this body on HL25
  Windows and SvEngine Windows and has two owners on SvEngine Windows, so it is
  not an `R_StudioSetupSkin` string anchor.
- CoF's function start is an odd VA (`push ebp` at `0x...f1`); incoming `call`
  targets match that entry.
- BLOB tags analyze `hw.decrypt.dll`.
