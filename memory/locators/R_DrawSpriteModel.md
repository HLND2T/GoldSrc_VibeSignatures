---
title: R_DrawSpriteModel locator
type: note
permalink: goldsrc-vibesignatures/locators/r-drawspritemodel
tags:
  - locator
  - engine
  - func
---

# R_DrawSpriteModel

## Symbol

- **Name**: `R_DrawSpriteModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawSpriteModel.py`
- **Source**: `engine/gl_rmain.c` — draws one sprite polygon for the entity being
  rendered: frame lookup, the `r_blend` normal-render assignment and the
  four-corner quad emission.

## Availability

- All 11 engine configs, every declared platform. Real symbol name is preserved
  in every non-stripped `.so`.

## Predecessors

- None. It is the predecessor of [[r_entorigin]] (it used to also carry
  [[r_blend]], which now comes from [[studioapi_StudioSetRenderamt]]).

## How it is located

Pattern A string xref: `FULLMATCH:R_DrawSpriteModel:  couldn't get sprite frame
for %s\n`. The literal is the `Sys_Warning` format argument inside the function
itself, so its data xref names the owning function directly. It is byte-identical
in all 15 (binary, platform) pairs, including the BLOB builds that are analyzed
through `hw.decrypt.dll`, and IDA has the function defined in every one of them,
so no `add_func` recovery is needed.

Note the two spaces after the colon and the trailing newline; both are required
by `FULLMATCH`.

## Pitfalls

- The string is a plain diagnostic, not a unique protocol label at first glance,
  but it occurs exactly once per binary and owns exactly one function, so it is
  safe as an anchor. `xref_strings` maps data xrefs to the containing function,
  which is why it works on SvEngine Windows even though the MetaHookSv
  `"R_DrawSpriteModel:  couldn"` + reverse-search heuristic needs a byte-signature
  fallback there.
- Validation evidence: hl-10210 W `0x10242cb0` / L `0x16c950` (`.symtab` size
  `0x56b`), hl-8684 L `0x1c2c70` (`.symtab` size `0x57b`), svencoop-8948 L
  `_Z17R_DrawSpriteModelP11cl_entity_s` `0x184820` (`.symtab` size `0x62d`),
  svencoop-10257 W `0x1d532c0` / L `0x137d70`.

## Relations

- relates_to [[r_blend]]
- relates_to [[r_entorigin]]
- relates_to [[R_DrawTEntitiesOnList]]
