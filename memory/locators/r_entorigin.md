---
title: r_entorigin locator
type: note
permalink: goldsrc-vibesignatures/locators/r-entorigin
tags:
  - locator
  - engine
  - gv
---

# r_entorigin

## Symbol

- **Name**: `r_entorigin`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawTEntitiesOnList-decompiles.py`
- **Source**: `engine/gl_rmain.c` — `vec3_t modelorg, r_entorigin;` — the origin of
  the entity currently being rendered, copied out while the transparent-entity
  list is walked and consumed by the sprite/glow paths.

## Availability

- Declared in 11 engine configs; produced in 9 of them (every family except
  SvEngine).
- Platforms: Windows + Linux.
- **Not covered on SvEngine.** Both `svencoop-8948` and `svencoop-10257` write
  `r_entorigin` in the entity dispatcher instead of the transparent-entity
  loader, and the dispatcher is not reachable from any existing engine artifact:
  the renderer's direct callees on `svencoop-8948/hw.dll` contain no matching
  vector copy, and on `hw.so` the copy sits in `R_DrawEntities.part.0`, whose
  neighbouring globals differ per platform (the `modelorg` adjacency that holds
  on Linux does not hold on Windows). The symbol is declared in the two svencoop
  configs but has no producer there.

## Predecessors

- `R_DrawTEntitiesOnList.{platform}.yaml`.

## How it is located

`LLM_DECOMPILE` with `expected_result_sections: ["found_gv"]` against the
annotated predecessor reference. The reference is annotated on both platforms
and all gamevers that need it, so the model is asked to find the instruction
that materialises `r_entorigin`, not to guess a role.

## Pitfalls

- The target is only added to the LLM spec when the config declares
  `r_entorigin.{platform}.yaml` as an output, because the same script serves the
  SvEngine configs where the global is not covered.
- `r_entorigin` has no fixed relation to `modelorg` or `r_origin`: cof-5936 puts
  it `+0x1e0` above `modelorg`, hl-10210 `-0x6e0` below, and on svencoop-10257 it
  is `modelorg - 0xc`. Never derive one from the other.
- Validation evidence: cof-5936 `0x2c0e4a0` (three consecutive dword stores),
  hl-10210 W `0x10dc5620`, hl-10210 L `0xf7d300` (`.symtab`),
  svencoop-10257 L `0x30f6f7c`.

## Relations

- relates_to [[R_DrawTEntitiesOnList]]
- relates_to [[modelorg]]
