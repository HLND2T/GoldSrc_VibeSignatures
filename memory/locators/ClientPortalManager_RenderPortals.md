---
title: ClientPortalManager_RenderPortals locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-renderportals
tags:
  - locator
  - client
  - func
---

# ClientPortalManager_RenderPortals

## Symbol

- **Name**: `ClientPortalManager_RenderPortals`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortalManager_RenderPortals.py`

## Availability

- Declared in 2 configs: svencoop-10257 and svencoop-8948 (client module only; no engine coverage).
- Platforms: Windows + Linux (no `platform:` gate in the config, so both builds are attempted).
- Inlined / absent: the function exists standalone on both builds. RenderPortals inlines the
  `ClientPortal_CreateTexture` initializer on Windows only.
- Corrected 2026-09-19 (issue #160): an earlier revision of this note claimed the MetaHookSv-era
  sibling `DrawPortalSurface` was inlined into RenderPortals on 10257 and that the build had no
  `glColorMask` at all. Both statements are wrong. `ClientPortalManager::DrawPortalSurface` and
  `ClientPortalManager::GetOriginalSurfaceTexture` are standalone functions on all four validated
  Sven builds; they are **not** reachable from RenderPortals but from the sibling pass
  `ClientPortalManager::DrawPortals`. See [[ClientPortalManager_DrawPortalSurface]].

## Predecessors

- None. `find-ClientPortalManager_RenderPortals` has no `expected_input`.

## How it is located

1. The only semantic anchor is the exact diagnostic literal
   `"Invalid GL_ACTIVE_TEXTURE, unable to reset. Portal not drawn.\n"` (this wording is unique to
   RenderPortals; the invisible-texture creator and the CreateTexture initializer own *different*
   `"Invalid GL_ACTIVE_TEXTURE..."` sentences).
2. Primary path: the shared `preprocess_common_skill` runs a `FULLMATCH:<literal>` xref search and
   requires the string to have a single function owner. This succeeds on Windows (direct literal
   reference).
3. Linux fallback (`_sven_client_pic_common.preprocess_string_owner_skill_with_pic_fallback`): the
   GCC PIC build references `.rodata` through `lea reg, [gotreg+disp32]`, where the embedded dword is
   `literal - _GLOBAL_OFFSET_TABLE_` and IDA creates no xref. When the primary path yields nothing,
   `exact_string_ea` pins the unique exact-match C string item, then
   `write_unique_string_owner_artifact`:
   - collect owners from `XrefsTo(string_ea)`; accept immediately if exactly one;
   - otherwise resolve the module GOT anchor from any `call <4-byte-thunk>; add reg, imm32` prologue:
     `got_base = (next_insn_ea + imm32) & 0xFFFFFFFF`;
   - `disp = (string_ea - got_base) & 0xFFFFFFFF`, then byte-search executable segments for the
     little-endian 4-byte needle and keep only hits that are the head of a code item and inside a
     decoded `o_displ` operand (disp32) of that instruction;
   - owners = containing functions of the surviving sites; exactly one owner must remain.
4. The owner function is inspected through MCP and the artifact is written with
   `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`; if the function body had to be
   taken across a function boundary, `func_sig_allow_across_function_boundary: true` is added.
   Zero or multiple owners fail closed (no artifact).

## Pitfalls

- Do not anchor on the substring `"Invalid GL_ACTIVE_TEXTURE, unable to reset."` — three different
  portal functions share that prefix. Only the full sentence disambiguates.
- Linux has no xref for the diagnostic site (`lea edx,[ebx-171A5Ch]` on the validated 10257
  client.so, GOT at 0x61e000); without the GOTOFF displacement fallback the FULLMATCH machinery
  reports zero owners rather than a wrong one.
- Stored research addresses (W 0x1004E4F0 / L 0xfc2b4) are validation evidence only; the finder
  never consumes them.
- RenderPortals is the root of the portal family: `EnableClipPlane` (sole callee) and
  `ClientPortal_Constructor` (two call edges below, through the portal factory) are both located
  relative to this artifact, and `find-ClientPortal-offsets-decompiles` decodes this function's body
  to prove the manager vector and Windows texture offsets.
- The decoded instruction payload of this function exceeds the MCP result limit; the offsets walk
  embeds the tested Python helper inside the worker and returns only the recovered offsets.
