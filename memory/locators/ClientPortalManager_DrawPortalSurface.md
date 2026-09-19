---
title: ClientPortalManager_DrawPortalSurface locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-drawportalsurface
tags:
  - locator
  - client
  - func
---

# ClientPortalManager_DrawPortalSurface

## Symbol

- **Name**: `ClientPortalManager_DrawPortalSurface`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortalManager_DrawPortalSurface.py`
- **Real symbol**: `ClientPortalManager::DrawPortalSurface(ClientPortal&, msurface_t*, unsigned int)`
  (`_ZN19ClientPortalManager17DrawPortalSurfaceER12ClientPortalP10msurface_sj`, proven by the
  retained `.symtab` of `bin/svencoop-8948/client/client.so`). The MetaHookSv local field name is
  identical, so no alias is needed.

## Availability

- Declared in 2 configs: svencoop-10257 and svencoop-8948, client module only. This is Sven Co-op
  client state; `hw.dll` / `hw.so` and the `hl-*` / `cstrike-*` / `cof-*` clients have no
  `ClientPortalManager`, so those versions are "not applicable", not a coverage gap.
- Platforms: Windows + Linux (no `platform:` gate).
- Standalone on all four validated builds. MSVC inlines the whole GL block; GCC splits it into
  `DrawMonitor` / `DrawStencil` / `DrawPortalOrMirrorImageWhereStencilIsOne` / `DrawDepth` /
  `DrawOverlay`, so the function is ~0x600 bytes on Windows and ~0x95 bytes on Linux.

## Predecessors

- None declared in config. The finder has no `expected_input`; the predecessor
  `ClientPortalManager::DrawPortals` is recovered inside the finder and is not emitted as a symbol.
- The same run emits `ClientPortalManager_GetOriginalSurfaceTexture` from one walk.

## How it is located

1. Anchor literal (exact): `"Invalid GL_ACTIVE_TEXTURE, unable to reset. Portals will not be
   drawn.\n"` — the **plural** wording. This is the fourth sentence of that family; the other three
   belong to `RenderPortals` ("Portal not drawn."), `CreateInvisiblePortalTextures` ("Couldn't
   create invisible texture for portals.") and `ClientPortal_CreateTexture` ("Couldn't create
   texture for PortalSource."). Exactly one string instance and one owning function per build.
2. `_sven_client_pic_common.unique_string_owner_ea` resolves that owner: plain xrefs on Windows and
   on 8948 Linux, the GOTOFF displacement scan on 10257 Linux (no IDA xref there; GOT `0x61e000`).
   The owner is `ClientPortalManager::DrawPortals`.
3. An IDA-side walk (no byte pattern, no LLM) enumerates the predecessor's direct callees, resolving
   every ELF PLT stub to its local definition with `ida_elf.resolve_elf_plt` — on 8948 Linux **all**
   intra-module calls go through PLT, so an unresolved walk finds nothing.
4. The target is the unique callee that contains the overlay idiom of
   `if (texinfo && texinfo->texture && texinfo->texture->name[0] == '{')`:

   ```
   call  <GetOriginalSurfaceTexture>   ; direct, local
   ...                                 ; test/jcc only, <= 8 instruction window
   mov   R, [eax+24h]                  ; mtexinfo_t::texture
   ...                                 ; test/jcc only
   cmp   byte ptr [R], 7Bh             ; texture_t::name[0] == '{'
   ```

   Exactly one callee and exactly one site must remain; both payloads are validated before either
   artifact is written.

## Pitfalls

- The weaker rule "any `cmp byte ptr [reg], 7Bh` among the predecessor's callees" is **not** unique:
  on 10257 Windows `sub_1004C0F0` (the `ClientPortal::IsSurfaceVisible` analogue) compares the same
  character, but reads its texinfo from `surf->texinfo` instead of a call result. The `call` →
  `[eax+0x24]` chain is what disambiguates.
- Do not port MetaHookSv's byte pattern `6A 01 6A 01 6A 01 6A 01 FF 15 ?? ?? ?? ?? 68 E1 0D 00 00`
  (`gl_hooks.cpp:7001`). It matches **two** sites on 10257 Windows (`0x1004f7c1` inside this
  function and `0x10052a5c` in an unrelated GL pass) and matches nothing on Linux, where the
  `glColorMask` block lives in the split `DrawStencil` / `DrawDepth` helpers.
- `ClientPortal` layout differs by build: `mode` is at `+0x28` on 8948 and `+0x40` on 10257
  (visible as `cmp [reg+28h], 1` / `cmp [reg+40h], 1` in the first basic block). That affects
  consumers, not this locator.
- `mtexinfo_t::texture = +0x24`, `texture_t::name[0] = +0`, `texture_t::gl_texturenum = +0x18` are
  stable GoldSrc engine offsets; the walk depends on them, not on any Sven-private offset.
- Validation evidence (not consumed by the finder): 10257 W `0x1004f360` / L `0xf905c`,
  8948 W `0x10097890` / L `0x15acea`.

## Relations

- relates_to [[ClientPortalManager_GetOriginalSurfaceTexture]]
- relates_to [[ClientPortalManager_RenderPortals]]
