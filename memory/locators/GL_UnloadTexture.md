---
title: GL_UnloadTexture locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-unloadtexture
tags:
  - locator
  - engine
  - func
---

# GL_UnloadTexture

## Symbol

- **Name**: `GL_UnloadTexture`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioSetupSkin.py`
  (same run as `R_StudioSetupSkin`)

## Availability

- Same 11 engine configs and platforms as `R_StudioSetupSkin`.
- Distinct from already-covered `GL_UnloadTextures` (plural, no-arg map reset).
- Inlined / absent: standalone on every validated build. Linux ELF:
  `GL_UnloadTexture` (hl-8684/10210), `_Z16GL_UnloadTexturePc` (svencoop-8948),
  stripped on svencoop-10257.

## Predecessors

- The `"DM_Base.bmp"` owner located in the same skill (the MetaHook
  `R_StudioSetupSkin` body). Not a separate `expected_input`.

## How it is located

1. After `R_StudioSetupSkin` is the unique `"DM_Base.bmp"` owner, find the
   unique `"%s%d"` xref in that body; the next `call` is the snprintf /
   `Q_snprintf` / `Q_snprintf_ServerExtraInfo` / `__snprintf_chk` of the remap
   texture name.
2. Recover arg0 of that snprintf as a stack name buffer (`lea [esp+…]` /
   `[ebp+…]`, including a later reload from a spilled stack slot).
3. The first later local `call` whose arg0 is that same buffer is
   `GL_UnloadTexture(name)`. `GL_LoadTexture` also takes the name but is the
   next, multi-argument call.

## Pitfalls

- Do not identify snprintf by import name: SvEngine Windows uses
  `Q_snprintf_ServerExtraInfo` or an unnamed helper; the `"%s%d"` xref is the
  stable selector.
- SvEngine Linux PIC spills the name pointer into a local and reloads it
  (`mov edx, [esp+var_…]`) before the unload call. Treating that load as
  “edx holds the address of the slot” misses the callee; follow the slot store
  back to the original `lea` of the name buffer.
- Direct `push [esp/ebp+slot]` also reads the spilled pointer, not the slot's
  address. Resolve it through the same store tracking; otherwise the unload
  call can be skipped in favor of the later `GL_LoadTexture` call. Behavioral
  fixtures in `StudioSetupSkinWalkTests` cover both stack bases, direct pushes,
  register reloads, and rejection of an unresolved snprintf destination.
- `GL_UnloadTextures` is adjacent in several images and is a different
  function (iterates `servercount`).
