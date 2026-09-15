---
title: ClientPortal_texture_height_offset locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportal-texture-height-offset
tags:
  - locator
  - client
  - scalar
---

# ClientPortal_texture_height_offset

## Symbol

- **Name**: `ClientPortal_texture_height_offset`
- **Category**: `scalar` (artifact fields are exactly `scalar_name` + uint32 `scalar_value`)
- **Module**: client (`client.dll` / `client.so`)
- **Producer**:
  - `ida_preprocessor_scripts/find-ClientPortal-texture-decompiles.py` (Linux, `platform: linux`)
  - `ida_preprocessor_scripts/find-ClientPortal-offsets-decompiles.py` (Windows, registered as an
    `optional_output_windows` artifact of that finder)

The batch metadata lists only the texture finder; the svencoop-10257 config additionally assigns this
artifact to `find-ClientPortal-offsets-decompiles` under `optional_output_windows`, which produces the
Windows YAML.

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows (+212) and Linux (+204) — different values, different proof paths.
- Inlined / absent: on Windows the upload is inlined into `ClientPortalManager::RenderPortals`; on
  Linux it lives in the outlined `ClientPortal_CreateTexture`.

## Predecessors

- Windows: `ClientPortalManager_RenderPortals`, `ClientPortalManager_EnableClipPlane`,
  `ClientPortal_Constructor`.
- Linux: `ClientPortal_CreateTexture`.

## How it is located

**Windows** (`_client_portal_offsets.recover_portal_offsets` → `_texture_candidates`): the texture
guard's member (`cmp [portal+disp], 0` whose exact address is taken by a following `lea`) yields the
id slot; height is asserted to be `id + 8`. The proof requires the full ordered chain
`glGenTextures(1, &portal[id])` → `glBindTexture(GL_TEXTURE_2D, portal[id])` →
`glTexImage2D(GL_TEXTURE_2D, …, width = portal[id+4], height = portal[id+8])` with all three API
argument lists reconstructed from the tracked push stack, and with `generated`/`bound` state
invalidated by any intervening unknown call. Branch paths are tracked with independent register
states, so facts are never borrowed across the success and diagnostic branches.

**Linux** (`_portal_layout.linux_texture_offsets`): the walk finds `call glGenTextures`, proves the
count is the constant `1` and the target pointer comes from `eax` (via `_entry_register` over the
predecessor graph), then scans forward (max 60 instructions) for `glBindTexture` and `glTexImage2D`,
requiring `GL_TEXTURE_2D` as arg0 and height as a 4-byte load at `pointer + 8` of the same object.
Exactly one candidate must survive or `linux portal GL argument evidence is missing or ambiguous` is
raised.

Both paths hand the offset to `preprocess_common_skill`, which requires the deterministic value and
the LLM_DECOMPILE extraction to agree before writing `scalar_name` / `scalar_value`.

## Pitfalls

- Height is the last of the three texture scalars and shares their single accepted candidate; the
  finders raise instead of emitting a partial triple, so a missing height artifact means no texture
  evidence was proven at all.
- The Windows and Linux values differ (+212 vs +204) because the `ClientPortal` object sizes differ
  (W 0xD8 / L 0xD0) and the preceding fields shift the texture block; never carry one platform's value
  to the other.
- The `glTexImage2D` argument index matters: width is `args[3]` and height `args[4]` in the
  reconstructed ABI, and the finder requires both to be loads off the portal object rather than
  arbitrary values, so a swapped-argument build fails the walk.
- Windows emission is an optional output path; a Linux run is expected to produce all three texture
  scalars from `find-ClientPortal-texture-decompiles` and nothing texture-related from the offsets
  finder.
