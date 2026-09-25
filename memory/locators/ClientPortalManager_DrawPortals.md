---
title: ClientPortalManager_DrawPortals locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-drawportals
tags:
  - locator
  - client
  - func
---

# ClientPortalManager_DrawPortals

## Symbol

- **Name**: `ClientPortalManager_DrawPortals`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortalManager_DrawPortals.py`
- **Real symbol**: `ClientPortalManager::DrawPortals()` (`_ZN19ClientPortalManager11DrawPortalsEv`, proven by the
  retained `.symtab` of `bin/svencoop-8948/client/client.so`). The MetaHookSv-era local name is identical, so no
  alias is needed.

## Availability

- Declared in 2 configs: svencoop-8948 and svencoop-10257, client module only. Sven Co-op client state; `hw.*` and
  the `hl-*` / `cstrike-*` / `czero-*` / `cof-*` clients carry no `ClientPortalManager`, so those versions are "not
  applicable", not a coverage gap.
- Platforms: Windows + Linux (no `platform:` gate).
- Standalone on all four validated builds. This is the fourth member of the portal diagnostic family and the pass
  that draws the portal surfaces themselves.

## Predecessors

- None. The finder has no `expected_input`; it is the parent of `ClientPortalManager-shader-chain` and
  `find-IEngineClient-view-slots`, and the predecessor that
  `find-ClientPortalManager_DrawPortalSurface` recovers on its own.

## How it is located

1. Anchor literal (exact): `"Invalid GL_ACTIVE_TEXTURE, unable to reset. Portals will not be drawn.\n"` — the
   **plural** wording. Exactly one string instance and one owning function per build.
2. Discovery is the shared `preprocess_string_owner_skill_with_pic_fallback`: a plain xref owner on 8948 Windows,
   10257 Windows and 8948 Linux, and the GOTOFF displacement scan on 10257 Linux (GOT `0x61e000`, no IDA xref).
3. The owner is inspected through MCP and emitted with `func_name` / `func_va` / `func_rva` / `func_size` /
   `func_sig`.

## Pitfalls

- Do not reuse the three sibling portal literals. `RenderPortals` owns "Portal not drawn.",
  `CreateInvisiblePortalTextures` owns "Couldn't create invisible texture for portals.", and
  `ClientPortal_CreateTexture` owns "Couldn't create texture for PortalSource."; only the plural sentence belongs
  here.
- The immediate byte patterns the issue suggested (`E0 84 00 00` = GL_ACTIVE_TEXTURE, `C0 84 00 00` = GL_TEXTURE0)
  are not usable: `RenderPortals`, `CreateInvisiblePortalTextures`, `ClientPortal_CreateTexture` and
  `SetActiveTexture` all reference them.
- `find-ClientPortalManager_DrawPortalSurface` already consumes this same literal internally to reach its own
  target. It does not declare this symbol, so there is no double producer.
- Validation evidence (not consumed by the finder): 8948 W `0x10097670` / L `0x15c95e`,
  10257 W `0x1004f140` / L `0xfae44`.

## Relations

- relates_to [[ClientPortalManager_RenderPortals]]
- relates_to [[ClientPortalManager_DrawPortalSurface]]
