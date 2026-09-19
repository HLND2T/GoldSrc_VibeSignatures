---
title: ClientPortalManager_GetOriginalSurfaceTexture locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-getoriginalsurfacetexture
tags:
  - locator
  - client
  - func
---

# ClientPortalManager_GetOriginalSurfaceTexture

## Symbol

- **Name**: `ClientPortalManager_GetOriginalSurfaceTexture`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortalManager_DrawPortalSurface.py`
  (one finder emits this symbol and `ClientPortalManager_DrawPortalSurface` from a single walk)
- **Real symbol**: `ClientPortalManager::GetOriginalSurfaceTexture(msurface_t*)`
  (`_ZN19ClientPortalManager25GetOriginalSurfaceTextureEP10msurface_s`, proven by the retained
  `.symtab` of `bin/svencoop-8948/client/client.so`).

## Availability

- Declared in 2 configs: svencoop-10257 and svencoop-8948, client module only; Windows + Linux.
- Standalone and small on every validated build (0x48–0x92 bytes): it is the hash-map lookup that
  returns the `mtexinfo_t*` a portal replaced, i.e. the surface's *original* texinfo.

## Predecessors

- None declared in config. It is recovered as the call target inside
  `ClientPortalManager::DrawPortalSurface`; see [[ClientPortalManager_DrawPortalSurface]] for the
  full chain (string anchor → `ClientPortalManager::DrawPortals` → DrawPortalSurface → this).

## How it is located

1. The shared walk finds the unique overlay site inside `DrawPortalSurface`:
   `call <target>` → `mov R, [eax+0x24]` → `cmp byte ptr [R], 0x7Bh`.
2. This symbol is that `call`'s direct target, after `ida_elf.resolve_elf_plt` maps an ELF PLT stub
   back to its local definition (8948 Linux calls it through `._ZN19ClientPortalManager25Get…`).
   A target still inside a `.plt*` segment is rejected, so a GOT/PLT stub can never be emitted.
3. The address is then inspected through MCP and written with
   `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`.

## Pitfalls

- The function has no string of its own and no distinctive float set, so there is no direct anchor;
  it must be reached through `DrawPortalSurface`.
- Its `std::hash` implementation is **not** portable evidence: MSVC inlines FNV-1a over the 4-byte
  surface pointer (`0x811C9DC5`, `0x01000193` visible in the prologue), while libstdc++ uses the
  identity hash plus a modulo. Do not anchor on the FNV constants.
- It has a second caller besides `DrawPortalSurface` on every build (the portal texture-replacement
  path), so a "unique caller" rule would fail; the overlay-site rule is what makes it deterministic.
- Validation evidence (not consumed by the finder): 10257 W `0x1004e370` / L `0xf8f12`,
  8948 W `0x10096880` / L `0x15abec`.

## Relations

- relates_to [[ClientPortalManager_DrawPortalSurface]]
