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

## GameUI dialog constructors and QueryBox (#290)

### Trigger

Adding MetaHookSv's four private GameUI constructor lookups to the 11 HL/Sven/CoF gameui configs (15 Windows/Linux binaries). The issue's `hw.dll/hw.so` label is misleading: all four call targets live in `GameUI.dll/gameui.so`.

### Root cause and constraints

- `#GameUI_Console` and `#GameUI_Options` move into specialized `SetTitle` helpers in optimized Linux builds; their xrefs do not reliably own the requested constructor.
- `#QueryBox_Cancel` belongs to both the `char` and `wchar_t` QueryBox constructors. HL25/SvEngine Windows inline the quit-dialog creator into a larger `CTaskbar::OnCommand` body, which can call the same narrow constructor several times. A fixed call number or a requirement for one call in the whole owner is wrong.
- IDA's existing string list may omit a referenced literal. Rebuild the C-string index before exact `FULLMATCH` xrefs; raw mapped-byte scans were used to audit actual literals.
- The two QueryBox overloads share a long wildcarded instruction prefix. The unique current-binary output signature may need a validated relative `call` displacement to the corresponding `MessageBox` overload; this is not a discovery anchor.

### Correct approach

- Find `CGameConsoleDialog::CGameConsoleDialog()` through its own `ConsoleSubmit`, `CCreateMultiplayerGameDialog::CCreateMultiplayerGameDialog(vgui2::Panel*)` through `CSBotConfig`, and `COptionsDialog::COptionsDialog(vgui2::Panel*)` through `#GameUI_Keyboard`.
- Find the current containing Taskbar body through `#GameUI_QuitConfirmationTitle`. Pattern D selects direct `QueryBox_ctor` calls from the generated `hl-8684` Windows/Linux reference. Require every reported call to resolve to one callee, and require one reported call in the control-flow block containing both quit title and text xrefs. The callee must itself reference `#QueryBox_Cancel`; emit the narrow-string `vgui2::QueryBox::QueryBox(char const*, char const*, vgui2::Panel*)` identity.
- Keep the predecessor artifact named `CTaskbar_QuitConfirmationOwner` because the containing source function changes under inlining. No VA/RVA, call order, frame size, or vtable offset is used as a locator.

### Verification and scope

2026-09-29: owned IDA sessions bound each exact GameUI binary; an exact 45-node bounded batch forced the three new finder skills on all 15 configured GameUI binaries, with 45 successes, no failures or skips. All 75 function artifacts passed current-binary signature validation; the four requested VAs were also matched to independent string/call evidence. Unit suite: 1217 OK (9 skipped); repository-contract: 14 OK; formatter check passed. Old HL and CoF Linux builds, CS/CZ gamevers, `hw`, and the wchar_t QueryBox overload have no applicable requested GameUI target here.

## GameUI career-frame constructors (#291)

### Trigger

Adding MetaHookSv's three private career-frame constructor lookups (`CCareerProfileFrame_ctor`,
`CCareerMapFrame_ctor`, `CCareerBotFrame_ctor`) to the nine gameui configs whose GameUI ships these
classes (11 Windows/Linux binaries). The issue's `hw.dll/hw.so` module hint is wrong again: all three
constructors live in `GameUI.dll`/`gameui.so`.

### Root cause and constraints

- MetaHookSv anchors the Windows-only `68 ?? 68 <literal>` two-push form and then backtracks with
  `ReverseSearchFunctionBegin(..., 0x150)`. GCC emits `mov reg, offset literal` / stack spills instead,
  and the window is a heuristic, so neither is portable.
- hl-10210 and hl-8684 `gameui.so` expose only C1/C2 constructor symbols; the literal reference resolves
  to the same body that `nm -C` reports for `_ZN..C1E` and `_ZN..C2E` (identical address).
- hl-8684 `gameui.so` carries DWARF, and IDA types `0x167919..0x167dcd` as a single
  `const CCareerProfileData save` item. `ProfileSelectionBackground` is therefore rendered as
  `save.tutorData+56h` and is absent from IDA's string list even after a full rebuild, so the shared
  `xref_strings: FULLMATCH:` locator cannot see it.
- The literal is target-owned, not caller-owned: the constructor calls
  `CDottedBgLabel::CDottedBgLabel(this, "<literal>", ...)` and stores the result in the matching `m_p*`
  member (confirmed in the hl-10210 Linux decompilation).

### Correct approach

- Scan non-executable segment bytes for `literal\0` (repo precedent: `find-client-vgui-worldmap.py`
  `exact_code_ref`, the shared raw-byte lesson), collect code xrefs, and require exactly one owning
  function for each literal.
- Independently require that this owner installs its own RTTI vtable address point
  (`??_7<Class>@@6B@` on Windows, `_ZTV<n><Class> + 8` on Linux) through `mov [reg+0], imm` before the
  literal reference, and that the address point is a validated ≥4-slot executable table.
- No VA/RVA, call order, byte pattern, or backtrack window is a locator; the artifact signature still
  comes from the standard `_inspect_function_via_mcp` path (`inspect_unique_function`).

### Verification and scope

2026-09-29: an owned strict/no-save bounded batch (`-batch_selection`, 9 tags) forced all 11 configured
gameui nodes — 11 succeeded, 0 failed, 0 skipped. All 33 artifacts were cross-checked against an
independent lifecycle probe (single literal owner, vtable store before the literal, 1-3 direct callers)
and against `nm -C` constructor symbols on both Linux `gameui.so` files; every emitted `func_sig`
validated unique in its current binary. Unit suite: 1217 OK (9 skipped); repository-contract: 14 OK after
staging the new artifacts; formatter clean. Sven's GameUI contains no career-frame classes, and the
CS/CZ configs declare no gameui module (CZ loads valve's GameUI, already covered by the hl-\* artifacts),
so the finder is registered only on the nine configs above.
