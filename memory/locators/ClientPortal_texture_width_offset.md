---
title: ClientPortal_texture_width_offset locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportal-texture-width-offset
tags:
  - locator
  - client
  - scalar
---

# ClientPortal_texture_width_offset

## Symbol

- **Name**: `ClientPortal_texture_width_offset`
- **Category**: `scalar` (artifact fields are exactly `scalar_name` + uint32 `scalar_value`)
- **Module**: client (`client.dll` / `client.so`)
- **Producer**:
  - `ida_preprocessor_scripts/find-ClientPortal-texture-decompiles.py` (Linux, `platform: linux`)
  - `ida_preprocessor_scripts/find-ClientPortal-offsets-decompiles.py` (Windows, registered as an
    `optional_output_windows` artifact of that finder)

The batch metadata names only the texture finder as producer; the svencoop-10257 config also lists
this artifact under `find-ClientPortal-offsets-decompiles` as `optional_output_windows`, which is
where the Windows YAML comes from.

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows (+208) and Linux (+200) — different values from different proof paths.
- Inlined / absent: on Windows the `glTexImage2D` upload lives inside
  `ClientPortalManager::RenderPortals` (the initializer is inlined); on Linux it is the outlined
  `ClientPortal_CreateTexture`.

## Predecessors

- Windows: `ClientPortalManager_RenderPortals`, `ClientPortal_CalculateClipPlane`,
  `ClientPortal_Constructor`.
- Linux: `ClientPortal_CreateTexture`.

## How it is located

**Windows** (`_client_portal_offsets._texture_candidates`, driven from
`recover_portal_offsets`): the member proven as the texture guard (`cmp [portal+disp], 0` followed by
a `lea` taking that exact member's address) is the texture-id slot; width is the field at
`texture_offset + 4`. Acceptance requires the 9-argument `glTexImage2D` push sequence to carry
`GL_TEXTURE_2D` as arg0 and width/height that are 4-byte loads off the **same portal object**, at
exactly `texture_offset + 4` and `texture_offset + 8`, *after* `glGenTextures(1, &portal[texture_offset])`
and `glBindTexture(GL_TEXTURE_2D, portal[texture_offset])` were seen in that order. Any unknown call
between allocate/bind/upload invalidates `generated`/`bound`, so a stale GL-state assumption cannot
produce a width.

**Linux** (`_portal_layout.linux_texture_offsets`): after locating `call glGenTextures` in the
outlined `ClientPortal_CreateTexture` (count == constant 1, texture pointer rooted in an entry
register proven to be `eax` by `_entry_register`), the walk scans forward for `glBindTexture` then
`glTexImage2D` and requires args[0] == `GL_TEXTURE_2D` and that width/height are 4-byte loads off the
same texture pointer at `+4` / `+8`. Other calls break the block; exactly one candidate must survive.

Both producers then emit the scalar through `preprocess_common_skill` with an LLM_DECOMPILE
`expected_value` and a required-dependency policy (`ClientPortalManager_RenderPortals.{platform}.yaml`
on Windows, `ClientPortal_CreateTexture.{platform}.yaml` on Linux).

## Pitfalls

- Width is never inferred from the id offset by arithmetic inside the finder; it is read from the
  actual `glTexImage2D` argument slot. The `texture_offset + 4` relation is the *assertion* being
  verified, not the method.
- The MSVC/GCC split (+208 vs +200) means a Windows value must never be published for Linux. This
  cross-contamination actually happened in an earlier revision and was corrected.
- The whole triple (id/width/height) is one proof: `recover_portal_offsets` and
  `linux_texture_offsets` both raise unless they get exactly one candidate, so the three texture
  scalars are emitted together or not at all.
- On Linux, a `glTexImage2D` reached without a preceding matching `glBindTexture`, or with a
  mismatched object, breaks the block rather than emitting a guessed width.
- Windows emission is `optional_output_windows`: absence of a Linux texture-width YAML would
  actually be a bug (the Linux finder is the sole producer there), whereas absence of the Windows one
  is merely a failed optional path.
