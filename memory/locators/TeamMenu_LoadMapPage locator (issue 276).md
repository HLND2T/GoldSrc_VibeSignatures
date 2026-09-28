---
title: TeamMenu_LoadMapPage locator (issue 276)
type: note
permalink: goldsrc-vibesignatures/locators/team-menu-load-map-page-locator-issue-276
tags:
- '[locator'
- client
- vgui
- cstrike]
---

# TeamMenu_LoadMapPage locator (issue 276)

## Trigger

Extending the CS-family client VGUI private finders (issue #276 / PR #278) or adding another CTeamMenu-family symbol.

## Root cause and constraints

- Issue #276's MetaHookSv snippet only lacks `TeamMenu_LoadMapPage`: `ClientVGUI_RichText_SetTextA/W` were already emitted by `find-client-vgui-teammenu.py` (PR #275). The MetaHook `TeamMenu_LoadMapPage_SearchContext` name is only a search-context struct; the real symbol is `CTeamMenu::LoadMapPage(char const*)`.
- MetaHookSv reaches the function by disassembling forward from the `push imm32` of `maps/%s.txt`; the finder's `string_owner_evidence + require_single_owner` already resolves the same owner directly, so no new locator mechanism is needed — the owner just was never emitted.

## Correct approach

- Emit the verified `loadmap_owner` as a fourth `func` artifact `TeamMenu_LoadMapPage.{platform}.yaml` with payload identity `CTeamMenu::LoadMapPage(char const*)`, reusing `_emit_function` (no across-boundary fallback needed on any of the 13 binaries).
- Keep a fail-closed assertion that the 0xFEFF BOM compare instruction lies inside the owner body before emitting.

## Verification

2026-09-28: 13/13 configured binaries succeeded (10 PE incl. cstrike-3248/3647 blob-decrypted builds, 3 ELF). Linux VAs match `_ZN9CTeamMenu11LoadMapPageEPKc` via `nm` (0x171200/0x1b26f0/0x1b1c10). Windows entries: cstrike-10210 & czero-10210 `0x100b2040`, 3248/3647 `0x199fe20`, 4554 `0x19aab90`, 6153 `0x19a74c0`, 8684 & czero-8684 `0x19a8920`, czeror-10210 `0x10034de0`, czeror-8684 `0x27034210`. Bodies verified to carry the FEFF branch plus both `RichText::SetText` overloads at the artifact addresses.

## Scope

`ida_preprocessor_scripts/find-client-vgui-teammenu.py`; all ten cstrike/czero/czeror client configs.
