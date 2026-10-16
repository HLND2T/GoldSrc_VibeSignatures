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
- Correction (2026-10-16, VGUI2Extension issue 15): the maps/%s.txt owner is not always CTeamMenu::LoadMapPage. Windows CS/CZ 10210 inlines it into four-argument CTeamMenu::Update; emitting the owner under the single-argument identity caused a trampoline ABI mismatch and native UtlVector assertion.
- The string/BOM evidence identifies map-page behavior, not the containing function's ABI. Windows cleanup and guarded forwarding of this/teamNames/numTeams to the &%i %s owner must agree; Linux must also match its original symbol.
- Three 10210 PE nodes require Update (ret 16); seven older PE nodes retain LoadMapPage (ret 4). All seven configured ELF nodes retain standalone LoadMapPage. Never choose the signature solely from game tag, string ownership or cleanup size.
## Correct approach
- find-client-vgui-teammenu.py proves map-file/BOM behavior, then _teammenu_identity.py classifies the current owner with machine-flow facts.
- Update requires four-argument cleanup on Windows plus a unique direct team-button call carrying this, arg3 and arg4 behind both teamNames and teamNames[0] non-null guards. The target is corroborated by its &%i %s literal. Standalone LoadMapPage must have single-argument cleanup and no team-button call. Linux identity must match the corresponding mangled name. Ambiguity fails closed.
- Emit TeamMenu_Update.windows.yaml with CTeamMenu::Update(char const*, bool, char const**, int) for the three 10210 PE nodes, replacing their incorrect old artifact. Use platform-specific config outputs and symbols; preserve true LoadMapPage records elsewhere.
- Verify with synthetic ABI/guard/argument/ambiguity regressions and the current binaries; consumer hooks must use distinct signatures.
## Verification

2026-09-28: 13/13 configured binaries succeeded (10 PE incl. cstrike-3248/3647 blob-decrypted builds, 3 ELF). Linux VAs match `_ZN9CTeamMenu11LoadMapPageEPKc` via `nm` (0x171200/0x1b26f0/0x1b1c10). Windows entries: cstrike-10210 & czero-10210 `0x100b2040`, 3248/3647 `0x199fe20`, 4554 `0x19aab90`, 6153 `0x19a74c0`, 8684 & czero-8684 `0x19a8920`, czeror-10210 `0x10034de0`, czeror-8684 `0x27034210`. Bodies verified to carry the FEFF branch plus both `RichText::SetText` overloads at the artifact addresses.

## Scope

`ida_preprocessor_scripts/find-client-vgui-teammenu.py`; all ten cstrike/czero/czeror client configs.

## Corrected verification (2026-10-16)

The historical 2026-09-28 check above proved string/BOM ownership but did not prove the Windows function identity; its three 10210 LoadMapPage names were incorrect. After the correction, all 17 current CS/CZ nodes pass. Unit suite: 1516 tests, 12 skips, no failures; repository-contract: 15 passed; format check passed. Updated canonical JSON candidates and a 21-snapshot plugin catalog validate. Plugin Release and 5 CTest targets pass. Windows czero 10210 live run installs Update only, logs valid null/0 and non-null/2 team arguments, renders Chinese map instructions, enters spectator, switches Chinese-named bots and does not hit the wassert breakpoint. Other versions are statically verified, not live-tested. Corrected catalog must be published before consumers enable the previously skipped hooks; old 10210 catalogs mislabel the ABI.
