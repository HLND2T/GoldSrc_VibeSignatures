---
title: MetaHookSv byte patterns are hints, not portable anchors
type: note
permalink: goldsrc-vibesignatures/lessons/metahooksv-byte-patterns-are-hints-not-portable-anchors
tags:
- lesson
- preprocessor
- anchor
- metahooksv
- elf
---

# MetaHookSv byte patterns are hints, not portable anchors

## Trigger

Porting a MetaHookSv `Client_FillAddress_*` / `*_FillAddress` locator into a repository finder.
The MetaHookSv side typically ships a byte pattern plus a `DisasmRanges` / `ReverseSearchFunctionBeginEx`
walk, and the issue text quotes it as "the anchor". Issue #160
(`ClientPortalManager_DrawPortalSurface` / `_GetOriginalSurfaceTexture`) is the worked example.

## Root cause / constraints

1. **MetaHookSv only needs the first match on the platform it ships for.** Its portal pattern
   `6A 01 6A 01 6A 01 6A 01 FF 15 ?? ?? ?? ?? 68 E1 0D 00 00` (glColorMask(1,1,1,1); glEnable(GL_TEXTURE_2D))
   matches **two** sites on svencoop-10257 `client.dll`; the loop simply `break`s on the first. A
   repository finder must be unique, so the same pattern fails closed or mis-locates.
2. **Windows-only inlining assumptions.** MSVC inlined the whole GL block into the target, while GCC
   split it into separate `DrawStencil` / `DrawDepth` / `DrawOverlay` functions — the pattern does not
   exist at all in `client.so`. Any "the GL call is inside function X" reasoning is per-compiler.
3. **A single semantic predicate is often not unique either.** `cmp byte ptr [reg], 7Bh`
   (`texture->name[0] == '{'`) selected two callees on Windows. The discriminator is the *dataflow*:
   the compared pointer must come from `mov R, [eax+24h]` (`mtexinfo_t::texture`) applied to the
   return value of a direct `call`.
4. **ELF PLT indirection hides intra-module call edges.** On svencoop-8948 `client.so` every
   `ClientPortalManager::*` call goes through a `.plt` stub, so a raw `CodeRefsFrom` callee walk sees
   stubs, not definitions, and the whole walk returns nothing.

## Correct approach

- Treat the MetaHookSv pattern only as a *hint about which function/idiom to look for*, then build the
  anchor from engine-stable structure: a unique diagnostic literal for the predecessor plus an
  instruction-level dataflow rule expressed in stable GoldSrc offsets
  (`mtexinfo_t::texture = 0x24`, `texture_t::name[0] = 0`, `texture_t::gl_texturenum = 0x18`).
- Always route call targets through `ida_elf.resolve_elf_plt` and reject a result that still lives in
  a `.plt*` segment.
- Do not anchor on `std::hash` constants: MSVC inlines FNV-1a (`0x811C9DC5` / `0x01000193`) for
  pointer keys while libstdc++ uses identity + modulo.

## Verification

- `bin/svencoop-8948/client/client.so` retains `.symtab`. When a Sven client symbol is in scope, list
  its mangled names first — it is authoritative ground truth for naming *and* for validating a walk
  designed on the stripped 10257 build. It proved
  `_ZN19ClientPortalManager17DrawPortalSurfaceER12ClientPortalP10msurface_sj` and
  `_ZN19ClientPortalManager25GetOriginalSurfaceTextureEP10msurface_s`.
- Run the finder on every configured `(gamever, platform)` and compare against independently probed
  addresses before declaring the anchor validated.

## Scope

GoldSrc/SvEngine finder authoring where MetaHookSv is the reference implementation. Does not change
the skill's locator ordering: a deterministic structural walk is still preferred over `LLM_DECOMPILE`,
and a byte signature remains output validation only.
