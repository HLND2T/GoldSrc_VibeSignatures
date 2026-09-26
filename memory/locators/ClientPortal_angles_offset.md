---
title: ClientPortal_angles_offset locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportal-angles-offset
tags:
  - locator
  - client
  - scalar
---

# ClientPortal_angles_offset

## Symbol

- **Name**: `ClientPortal_angles_offset`
- **Category**: `scalar` (artifact fields are exactly `scalar_name` + uint32 `scalar_value`)
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortal-offsets-decompiles.py`

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows + Linux (no `platform:` gate); emitted per platform as
  `ClientPortal_angles_offset.{platform}.yaml`.
- Inlined / absent: not a code symbol.

## Predecessors

- `ClientPortalManager_RenderPortals` (produced by `find-ClientPortalManager_RenderPortals`)
- `ClientPortal_CalculateClipPlane` (produced by `find-ClientPortal_CalculateClipPlane`)
- `ClientPortal_Constructor` (produced by `find-ClientPortal_Constructor`)

## How it is located

Same chain as `ClientPortal_origin_offset` — both values come from a single
`_portal_layout.constructor_offsets` call inside one `run_layout_walk`:

1. `ClientPortal_Constructor.{platform}.yaml` is validated and its `func_va` decoded in-worker.
2. The constructor is traced as a straight line (`Trace` with `constructor=True`; `this` = `ecx` on
   Windows; stack slots resolved as entry arguments on both platforms) for up to 400 instructions.
3. Stores to `("ptr","this",off)` sourced from a complete, contiguous 12-byte entry-argument copy are
   grouped per argument. The three consecutive vec3 arguments must all be present and their
   destination ranges must not overlap, else the walk raises
   (`constructor is missing a complete vec3 argument copy`, `…noncontiguous`, `constructor vectors
   overlap`).
4. `angles` is the destination offset of the **second** argument in that ordered triple (factory
   roles: view origin, view angles, surface origin — confirmed through the portal factory, not
   guessed from field order alone).
5. Emission: `preprocess_common_skill` scalar artifact after the walk value agrees with an
   LLM_DECOMPILE extraction rooted at
   `references/{gamever}/client/ClientPortal_Constructor.{platform}.yaml`, with
   `ClientPortal_Constructor.{platform}.yaml` as a required dependency.
6. Result: 12 on both platforms (a full `vec3` after the 12-byte origin at +0).

## Pitfalls

- `angles` is only as trustworthy as the chosen constructor. `find-ClientPortal_Constructor` selects
  it as the unique two-call-edge descendant of RenderPortals whose `this` receives three complete
  vec3 copies; a build with a second such object two edges below RenderPortals makes the walk
  ambiguous and the finder fails closed.
- The three-argument ordering is semantic (origin, angles, surface origin), not structural: swapping
  the role mapping would yield the surface origin offset here. The role mapping is asserted by the
  factory's call sites, which is why the walk starts from RenderPortals instead of pattern-matching
  the constructor directly.
- Both `origin` and `angles` are produced from the same accepted candidate; if one is rejected the
  other is not emitted alone.
- Do not derive `angles` as `origin + 12` in a consumer — that shortcut is true for 10257 but is a
  layout conclusion, not evidence.
