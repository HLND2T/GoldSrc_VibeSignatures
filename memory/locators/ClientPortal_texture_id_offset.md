---
title: ClientPortal_texture_id_offset locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportal-texture-id-offset
tags:
  - locator
  - client
  - scalar
---

# ClientPortal_texture_id_offset

## Symbol

- **Name**: `ClientPortal_texture_id_offset`
- **Category**: `scalar` (artifact fields are exactly `scalar_name` + uint32 `scalar_value`)
- **Module**: client (`client.dll` / `client.so`)
- **Producer**:
  - `ida_preprocessor_scripts/find-ClientPortal-texture-decompiles.py` (Linux, `platform: linux`)
  - `ida_preprocessor_scripts/find-ClientPortal-offsets-decompiles.py` (Windows, registered as an
    `optional_output_windows` artifact of that finder in the svencoop-10257 config)

The batch metadata lists only `find-ClientPortal-texture-decompiles` as producer; the config
additionally registers the Windows artifact under `find-ClientPortal-offsets-decompiles`
(`optional_output_windows`), which is what actually writes `ClientPortal_texture_id_offset.windows.yaml`.

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows + Linux, but from **different** proof paths and with **different** values —
  Windows +204, Linux +196.
- Inlined / absent: on Windows the texture allocation is inlined into `ClientPortalManager::RenderPortals`
  (no standalone initializer), so the Windows value can only be proven from RenderPortals' body. On
  Linux the GL block is an outlined function, `ClientPortal_CreateTexture`.

## Predecessors

- Windows path: `ClientPortalManager_RenderPortals`, `ClientPortal_CalculateClipPlane`,
  `ClientPortal_Constructor` (`find-ClientPortal-offsets-decompiles` inputs).
- Linux path: `ClientPortal_CreateTexture` (`find-ClientPortal-texture-decompiles` input).

## How it is located

**Windows — `find-ClientPortal-offsets-decompiles`** (`_client_portal_offsets.recover_portal_offsets`):

1. After the vector pair is proven, the whole RenderPortals body is scanned for
   `cmp <mem>, 0` where `mem` is not `esp`/`ebp`-relative.
2. The address of that exact member must be taken by a following `lea reg, [same_base+same_disp]`
   within three instructions (nothing that branches or clobbers the base in between). This is the
   texture guard that branches into the allocation block; unrelated null checks are not roots.
3. From there `_texture_candidates` traces each branch separately with provenance rooted at
   `("address","portal", texture_offset)` and validates the GL calls **in ABI order**:
   `glGenTextures(count == 1, &portal[texture_offset])` → `glBindTexture(GL_TEXTURE_2D,
   portal[texture_offset])` → `glTexImage2D(GL_TEXTURE_2D, …, width = portal[texture_offset+4],
   height = portal[texture_offset+8])`. Any unknown call between allocate/bind/upload invalidates the
   GL-state proof; register clobbers, unsupported effects and unbounded walks abort the state
   exploration. Exactly one candidate triple must survive.
4. The offsets are then emitted through `preprocess_common_skill` (scalar + LLM_DECOMPILE agreement,
   reference `references/{gamever}/client/ClientPortalManager_RenderPortals.{platform}.yaml`).

**Linux — `find-ClientPortal-texture-decompiles`** (`_portal_layout.linux_texture_offsets`):

1. The `ClientPortal_CreateTexture.{platform}.yaml` predecessor is validated and its `func_va`
   decoded in-worker.
2. Every `call glGenTextures` is located; the straight-line block before it (max 16 instructions) is
   replayed to read the two arguments. `count` must be the constant `1` and the texture argument must
   be a pointer rooted in an entry register that `_entry_register` proves is `eax` (the outlined
   member's `this` register).
3. Forward from the call (max 60 instructions, stopping at `j*`/`ret`) the walk requires
   `glBindTexture(GL_TEXTURE_2D, portal[texture_offset])` followed by
   `glTexImage2D(GL_TEXTURE_2D, …, portal[texture_offset+4], portal[texture_offset+8])`; other calls
   except `glGenTextures`/`glEnable` break the block. Exactly one candidate triple must survive.
4. Emitted with the `ClientPortal_CreateTexture.{platform}.yaml` reference and dependency policy.

## Pitfalls

- **The Windows and Linux values differ (+204 vs +196).** The MSVC and GCC `ClientPortal` layouts are
  not interchangeable; an earlier revision copied the Windows numbers onto Linux and produced wrong
  Linux artifacts. Each platform must be produced by its own finder.
- The texture id is proven only when the *same object* is passed to `glGenTextures` and
  `glBindTexture` and the same object's `+4`/`+8` slots are pushed to `glTexImage2D`. Unrelated
  pushes that merely look like GL calls must not satisfy the walk (a regression that was caught and
  fixed during PR #119 review).
- On Linux the initializer receives the target `ClientPortal` in `EAX`; if that provenance cannot be
  proven, the walk declines rather than guessing a base.
- The Windows texture scalars are `optional_output_windows`, so a Linux run producing only the five
  cross-platform scalars is expected, not a failure.
- `ClientPortal_texture_id_offset.{platform}.yaml` never exists for a `{platform}` other than the one
  the producing finder ran on.
