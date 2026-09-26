---
title: ClientPortalSource_mode_offset locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalsource-mode-offset
tags:
  - locator
  - client
  - scalar
---

# ClientPortalSource_mode_offset

## Symbol

- **Name**: `ClientPortalSource_mode_offset`
- **Category**: `scalar` (artifact fields are exactly `scalar_name` + uint32 `scalar_value`)
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortal-offsets-decompiles.py`

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows + Linux (no `platform:` gate); emitted per platform as
  `ClientPortalSource_mode_offset.{platform}.yaml`.
- Inlined / absent: not a code symbol. The value is 64 on both platforms, but the two platforms
  reach it through *different* instruction shapes (see How it is located).

## Predecessors

- `ClientPortalManager_RenderPortals` (produced by `find-ClientPortalManager_RenderPortals`)
- `ClientPortal_CalculateClipPlane` (produced by `find-ClientPortal_CalculateClipPlane`)
- `ClientPortal_Constructor` (produced by `find-ClientPortal_Constructor`)

The clip-plane YAML supplies the `call` site; the RenderPortals YAML supplies the caller body.

## How it is located

1. The finder loads all three predecessor YAMLs, requires each `func_name` to match, and parses their
   `func_va`s (`constructor`, `clip`, `render`).
2. `_portal_layout.source_mode_offset(instructions, platform, clip_ea)` finds every
   `call <clip_ea>` in RenderPortals, rewinds from the call to the start of the enclosing
   statement block (max 60 instructions, stopping at the previous `j*` / `call` / `ret`), replays
   that straight-line block through `Trace`, and reads the stack arguments.
3. ABI slots: Windows `mode = args[0]`, `origin = args[3]`; Linux `mode = args[1]`, `origin = args[4]`.
   On Linux the argument may be a **spilled** pointer, so `_spilled_source` first recovers the
   relation: GCC keeps `Source* = list_node + link_header` in a stack local while loading `mode`
   directly through the retained list-node register. Recovery requires exactly one dominating
   `mov [esp+slot], reg` store, that store's register defined by a dominating
   `lea reg, [entry_base + disp]`, no intervening write to the base/esp or overlapping stack store,
   and `esp` untouched in between.
4. Acceptance: `mode` must be a 4-byte load whose base pointer equals the resolved `origin` pointer
   (same root object), and `offset = mode.disp - origin.disp` must be non-negative and 4-byte
   aligned. Multiple distinct candidate offsets ⇒ `ValueError` and no artifact.
5. `preprocess_common_skill` emits the scalar with an LLM_DECOMPILE spec anchored on the
   RenderPortals reference YAML (`references/{gamever}/client/ClientPortalManager_RenderPortals.{platform}.yaml`,
   dependency policy requires `ClientPortalManager_RenderPortals.{platform}.yaml`), and requires the
   LLM value to equal the walk value.
6. Result: 64 on both platforms.

## Pitfalls

- **This is not a `ClientPortal` field.** The `+64` slot of `ClientPortal` lies inside its plane
  array; the `mode` member belongs to a separate `ClientPortalSource` object. The symbol is named
  `ClientPortalSource_mode_offset` for exactly that reason — do not re-file it under `ClientPortal`.
- On Linux the observed displacement is 72, but it is **node-relative**: the retained register holds
  a list node and `Source* = node + 8` (link header). The source-relative mode offset remains 64.
  Neither the node offset nor the link-header size may be emitted as the scalar value.
- The `ClientPortal` passed to ClientPortal_CalculateClipPlane is a *different* object from the `ClientPortalSource`
  whose mode is read; the argument-slot pairing (mode vs. origin) is what keeps the two apart.
- Everything depends on locating the `call clip_ea` site inside RenderPortals. If the clip-plane
  artifact is wrong, this walk either finds no call site or pairs the wrong arguments and fails
  closed.
- A revision that had no spill recovery assumed Linux's constructor was inlined; that was incorrect
  and the current code treats the Linux constructor as standalone, recovering the spill instead.
