---
title: ClientPortal_origin_offset locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportal-origin-offset
tags:
  - locator
  - client
  - scalar
---

# ClientPortal_origin_offset

## Symbol

- **Name**: `ClientPortal_origin_offset`
- **Category**: `scalar` (artifact fields are exactly `scalar_name` + uint32 `scalar_value`)
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortal-offsets-decompiles.py`

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows + Linux (no `platform:` gate); emitted per platform as
  `ClientPortal_origin_offset.{platform}.yaml`.
- Inlined / absent: not a code symbol.

## Predecessors

- `ClientPortalManager_RenderPortals` (produced by `find-ClientPortalManager_RenderPortals`)
- `ClientPortal_CalculateClipPlane` (produced by `find-ClientPortal_CalculateClipPlane`)
- `ClientPortal_Constructor` (produced by `find-ClientPortal_Constructor`)

## How it is located

1. The finder validates `ClientPortal_Constructor.{platform}.yaml` (`func_name` match, `func_va >=
   image_base`) and runs a second `run_layout_walk` in the worker:
   `constructor_offsets(decode_function(values['constructor']), values['platform'])`.
2. `_portal_layout.constructor_offsets` traces the constructor straight-line (up to 400 instructions,
   stopping at the first `j*` / `ret` / `pop`) with a provenance model where `this` is `ecx`
   (Windows) and stack slots map to entry arguments. It collects stores whose destination is
   `("ptr","this",off)` and whose value is a load from an entry argument of matching width.
3. The target must receive its **three consecutive vec3 arguments** (Windows starting at `[esp+8]`,
   Linux at `[esp+12]`) copied contiguously and without overlap. Each argument's byte map must cover
   the whole 12-byte range and be contiguous in the destination; otherwise
   `constructor is missing a complete vec3 argument copy` / `constructor vec3 copy is noncontiguous`
   is raised.
4. `origin` is the destination offset of the **first** such argument, `angles` the second
   (argument order is confirmed by the portal factory's roles: view origin, view angles, surface
   origin). A zero displacement is handled correctly — the mapping compares byte sets, so a copy to
   `this+0` is accepted rather than discarded as "no evidence".
5. The value is emitted via `preprocess_common_skill` as a `scalar_name` with an LLM_DECOMPILE spec
   whose reference is `references/{gamever}/client/ClientPortal_Constructor.{platform}.yaml` and
   whose `dependency_policy` requires `ClientPortal_Constructor.{platform}.yaml`. LLM and walk values
   must agree.
6. Result: 0 on both platforms (object sizes W 0xD8 / L 0xD0, factory allocations 216/208 bytes).

## Pitfalls

- The destination offsets are proven from constructor copy evidence only; stored research addresses
  and the `ClientPortal` object size are cross-checks, not anchors.
- **No `ClientPortal_entity_offset` is emitted for 10257.** MetaHookSv's `+0x70` entity pointer was a
  5.25/build-8948 layout detail and must not be transferred into this layout; the 10257 constructor
  has no entity field.
- The oldest `+0` store is easy to lose: an implementation that treats "zero displacement" as
  "no evidence" reports origin as unverifiable. The current walk compares full byte maps instead.
- `origin` and `angles` are recovered by the same `constructor_offsets` call and must both come from
  the same accepted candidate; the walk is re-run here (not reused from `find-ClientPortal_Constructor`)
  because that finder only publishes the function.
