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

`find-client-vgui-panel-init.py`, `find-client-vgui-keyvalues.py`, `find-client-vgui-teammenu.py`; all ten cstrike/czero/czeror client configs. Revalidate the complete binary matrix when compiler/ABI support changes.

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
