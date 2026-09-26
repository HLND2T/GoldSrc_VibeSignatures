---
title: ClientPortalManager_CreateInvisiblePortalTextures locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-createinvisibleportaltextures
tags:
  - locator
  - client
  - func
---

# ClientPortalManager_CreateInvisiblePortalTextures

## Symbol

- **Name**: `ClientPortalManager_CreateInvisiblePortalTextures`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortalManager_CreateInvisiblePortalTextures.py`

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows + Linux (no `platform:` gate; the finder imports no PIC helper, because this
  literal keeps a resolvable reference on the validated Linux build).
- Inlined / absent: this is the intermediate symbol introduced by this repo; it does not exist as a
  named unit in MetaHookSv's five-function portal layout. Standalone on both builds.

## Predecessors

- None. `find-ClientPortalManager_CreateInvisiblePortalTextures` has no `expected_input`.
- It is itself the predecessor of `ClientPortalManager_ResetAll`.

## How it is located

1. Single anchor literal: `"Invalid GL_ACTIVE_TEXTURE, unable to reset. Couldn't create invisible
   texture for portals.\n"` (note the wording: *invisible texture*, distinct from the `PortalSource`
   texture diagnostic and from the RenderPortals diagnostic).
2. The finder calls the shared `preprocess_common_skill` directly with
   `xref_strings = ["FULLMATCH:<literal>"]`, no `xref_gvs` / `xref_signatures` / `xref_funcs`, and
   requires the literal to resolve to exactly one function owner. The owner is inspected through MCP
   and the artifact carries `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`.
3. On svencoop-10257 the owner is a leaf creator with exactly one caller
   (`ClientPortalManager::ResetAll`), which is what makes the `xref_funcs` chain in
   `find-ClientPortalManager_ResetAll` deterministic.

## Pitfalls

- Unlike RenderPortals / CalculateClipPlane / CreateTexture, this finder has **no** PIC fallback and
  imports no `_sven_client_pic_common` helper. That is deliberate: on the validated 10257 client.so
  this diagnostic keeps a resolvable literal reference, so the plain xref path suffices. If a future
  SvEngine rebuild makes this site GOTOFF-only, the primary path would report zero owners and the
  finder would fail closed rather than mis-locate — the fallback would have to be added explicitly.
- The literal prefix `"Invalid GL_ACTIVE_TEXTURE, unable to reset."` is shared by three portal
  functions; the full sentence is mandatory.
- W 0x1004c900 / L 0xf70ce are validation evidence from the anchor research, not consumed by the
  script.
- Because `ResetAll` is located solely through this artifact (`xref_funcs` unique-caller walk), a
  false or missing emission here fails the whole 2-finder chain, not just this symbol.
