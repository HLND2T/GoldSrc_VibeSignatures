---
title: Client private VGUI ABI and artifact identities
type: note
permalink: goldsrc-vibesignatures/locators/client-private-vgui-abi-and-artifact-identities
---

# Client private VGUI ABI and artifact identities

## Trigger

Reviewing or extending the CS-family client VGUI finders from #272 / PR #275, especially when multiple Panel::Init bodies match the same layout stores.

## Root cause and constraints

- Linux cstrike-6153 and cstrike-8684 contain both `vgui2::Panel::Init(int, int, int, int)` and `.constprop.105`. The constructor-called clone receives this in EAX and hardcodes x/y/w/h, while the ordinary cdecl entry reads this and four dimensions from the stack. Internal caller counts cannot establish ABI equivalence.
- `ClientVGUI_*` are MetaHook lookup identities, not actual C++ symbol names. Config identities and artifact filenames may retain them; payload identities must describe the actual target, including overload arguments.

## Correct approach

- Keep the Panel layout-store and interface-dispatch filters. On Linux, require dword reads of all five incoming cdecl arguments at entry-ESP offsets 4, 8, 12, 16, 20, normalized with IDA stack deltas; fail closed if no unique body remains. The locator does not use symbol names as discovery anchors.
- Emit demangled function identities: `vgui2::Panel::Init(int, int, int, int)`, `vgui2::Frame::LoadControlSettings(char const*, char const*)`, both `vgui2::RichText::SetText` overloads, and `KeyValues::LoadFromFile(IFileSystem*, char const*, char const*)`.
- KeyValues uses `vtable_class` / `vtable_name` = `KeyValues`; its vtable symbol is `??_7KeyValues@@6B@` on Windows and `_ZTV9KeyValues + 0x8` on Linux. LoadFromFile remains slot 2, byte offset 8.

## Verification

2026-09-28: owned strict/no-save IDA batch `analysis-batch-20260928T110928-44be4e49e60e45e2be4337a0d3e76574` rebuilt all 39 selected finder nodes on 13 binaries (10 PE, 3 ELF), producing 78 artifacts with Agent fallback disabled. All nodes succeeded. Independent `nm -C` checks matched all 18 Linux payloads to their ordinary function symbols or KeyValues vtable address point.

Only two addresses changed: 6153 Panel::Init `0x1770f0` -> `0x179ce0`; 8684 `0x177450` -> `0x17a040`. Every other artifact changed identity fields only; signatures, addresses, table entries and slot metadata were unchanged.

## Scope

`find-vgui2_Panel_Init.py`, `find-client-vgui-keyvalues.py`, `find-client-vgui-teammenu.py`; all ten cstrike/czero/czeror client configs. Revalidate the complete binary matrix when compiler/ABI support changes.

## Issue #277: CS background panel and Frame::Activate

### Trigger

Adding CounterStrikeViewport::Start, its m_pCSBackGround member offset, the CCSBackGroundPanel vtable/Activate override, and the shared vgui2::Frame::Activate slot across CS-family clients.

### Root cause and constraints

- The issue's hw.dll/hw.so module hint is incorrect for these targets: the objects and methods live in client.dll/client.so. The source names m_pCSBackGround in CounterStrikeViewport; target ELF symbols nest CCSBackGroundPanel under CounterStrikeViewport.
- The field offset differs by ABI: 0x72c in eight CS/CZ Windows builds, 0x730 in the three cstrike Linux builds. The Frame/override slot is 159 for cstrike-3248/3647 Windows, 160 for later Windows CS/CZ and both czeror builds, and 161 for cstrike Linux.
- czeror has the vgui2::Frame vtable but no CCSBackGroundPanel RTTI or BackgroundPanel.res, so only Frame::Activate applies there.

### Correct approach

- Find the exact Resource/UI/BackgroundPanel.res literal's unique owning constructor; require its derived-class vptr store, then follow its unique direct caller to CounterStrikeViewport::Start. Recover the member displacement from the constructed pointer's paired derived/base stores before the next call, allowing unrelated stores between them.
- Find vgui2::Frame via the exact MSVC/Itanium vtable aliases, scan its entries for the four source-ordered Panel virtual dispatches and the final surface SetMinimized dispatch. Derive the slot from that current-binary table, not from a version number.
- Verify the background-panel vtable at its constructor's terminal vptr store and require its override at the current Frame slot to call Frame::Activate after Panel::SetPos. Preserve real demangled payload identities while the config/file lookup names retain MetaHook terminology.

### Verification and scope

2026-09-28: strict/no-save owned IDA batch forced 24 selected nodes over 13 client binaries (10 Windows, 3 Linux): 24 succeeded, 0 failed, 0 skipped. All 57 new YAML artifacts were cross-checked for names, member offsets, vtable entries, and slot/address relationships. This note applies to cstrike-3248/3647/4554/6153/8684/10210, czero-8684/10210, and czeror-8684/10210 where the target exists.

## Issue #280: CZDS WorldMap and CS background offsets

### Trigger

Adding `CClientVGUI_WorldMapPanel`, two CZDS WorldMap vtables and PaintBackground overrides, `CCSBackGroundPanel_XOffset`/`YOffset`, and slot-only `ISurface_GetScreenSize` to the CS-family client artifacts.

### Root cause and constraints

- The issue's `hw.dll`/`hw.so` hint is wrong for these targets. The objects live in `client.dll`/`client.so`. The WorldMap holder is `CZEROViewPort`, not the common `CClientVGUI`; czeror has only Windows client binaries in this repository. The requested `m_pWorldMapPanel` field name is semantic because no czeror ELF/source declaration is available.
- czeror-8684's restored IDB merges the virtual-only `CWorldMap::PaintBackground` body into an earlier function. The WorldMap and MissionSelect paint bodies are identical after normal relocation wildcards, so an ordinary normalized signature does not uniquely identify either entry.
- `CCSBackGroundPanel` X/Y offsets vary by client layout: 0x130/0x134 in CS 3248/3647, 0x134/0x138 in CS 4554/6153/8684 and CZ 8684, and 0x13c/0x140 in CS/CZ 10210. `ISurface::GetScreenSize` is slot 0x80 on these Windows clients and 0x84 on Linux CS clients.

### Correct approach

- Locate the unique WorldMap resource strings and confirm constructor-owned installs of the exact `CWorldMap` and `CWorldMapMissionSelect` RTTI vtables. Follow the unique `CWorldMap` constructor call into `CZEROViewPort::Start` and the return-value store to recover the viewport member.
- Compare both derived vtables with `vgui2::Panel` and select the unique common overridden slot whose bodies call the same surface getter, dispatch screen size through two output pointers, and call `ceil` while painting map tiles. This yields PaintBackground slot 106 (0x1a8) in both czeror builds, with no slot constant in the locator.
- Decode the paint bodies directly from their vtable entries. For the 8684 merged-IDB entry, redefine only the verified method boundary in the analyzer's owned no-save worker before runtime validation. Use a current-binary relative CALL displacement only when the normal wildcarded output signature is ambiguous; it is an output validator, never a discovery anchor.
- Extend the existing background finder: its verified `Activate` override has exactly one adjacent pair of non-stack dword member stores; the first surface getter's two-output virtual call supplies `ISurface_GetScreenSize`. Emit actual class/member identities and slot-only interface artifacts.

### Verification and scope

2026-09-28: owned strict/no-save IDA analyzer succeeded on 11 CS/CZ background binaries (8 Windows, 3 Linux) and 2 czeror Windows map binaries. Independent artifact relation checks confirmed all 45 new YAML outputs, including paint vtable entries, offsets, and slot arithmetic. Unit suite: 1214 tests OK (9 skipped); repository-contract suite: 14 tests OK; format check passed. Applies to the 10 cstrike/czero/czeror client configs and only their available platforms.

## Cross-module Panel::Init locator

2026-09-29: `find-vgui2_Panel_Init.py` reuses the structural Panel layout, interface-dispatch, and Linux cdecl-argument checks in the 11 configured HL/Sven/CoF engine (`hw`) and gameui modules. Their output is `vgui2_Panel_Init`; the ten CS/CZ client configs retain the existing `ClientVGUI_Panel_Init` artifact identity. The latter is a MetaHook lookup name rather than the payload's function name.

HL/Sven/CoF client binaries do not embed this Panel implementation: their Linux symbol tables and available client binaries lack the Panel RTTI and `_proportional` layout-store evidence that is present in the engine/gameui binaries. Do not register this finder on a client module without first proving that the implementation exists there.

Verification: strict/no-save IDA analysis produced all 30 configured engine/gameui artifacts (26 newly executed, four HL-10210 pilot artifacts), with zero failures. A forced 17-node batch rebuilt the existing CS/CZ client outputs with zero failures. The analyzer validated each emitted function signature against its current binary.

## ServerBrowser Panel::Init coverage

### Trigger and constraints

The 11 HL/Sven/CoF `serverbrowser` modules contain 15 PE32/ELF32 binaries (11 Windows, 4 Linux). CS/CZ gamevers have no separate `serverbrowser` binary in the repository or available depots. Six early HL Windows DLLs (3248, 3266, 3329, 3647, 4554, 6153) were initially untracked in the `bin` submodule and must be pinned there for a fresh checkout to rebuild their artifacts.

### Root cause and correct approach

`find-vgui2_Panel_Init.py` recognized `call [vtable+slot]` after interface getters but missed Windows builds that load a slot into a register before `call reg`. Tie both forms to the same decoded vtable register. CoF spills a getter result to a stack local before loading its vtable, so accept a zero-displacement vtable load from a non-stack register rather than requiring `[eax]`. Keep the proportional/layout filters and Linux five-argument cdecl check to reject optimized clones.

IDA auto-analysis merges many adjacent functions in the identical HL-3248/3266/3329 ServerBrowser DLLs. Their true Panel::Init entry lies after a return and alignment inside a larger IDA function. For each proportional-store site, isolate the code region after that boundary and through its next return, validate the region, then restore only the selected function boundary in the owned no-save worker before signature generation. Reject ambiguous candidates and unbounded aligned regions.

### Verification and scope

2026-09-29: an exact 62-node strict/no-save batch forced all 47 previously configured engine/gameui/client Panel::Init nodes plus all 15 new serverbrowser nodes; 62 succeeded, zero failed/skipped. The new artifacts are `bin_artifacts/<tag>/serverbrowser/vgui2_Panel_Init.<platform>.yaml`. Unit suite: 1217 tests OK (5 skipped); repository-contract suite: 14 tests OK after its Sven PE32 smoke check was made inventory-independent; formatting passed. Six legacy HL DLLs were added to the `bin` submodule's local dev branch with IDA databases excluded.
