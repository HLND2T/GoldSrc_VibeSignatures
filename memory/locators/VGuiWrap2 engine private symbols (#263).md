---
title: VGuiWrap2 engine private symbols (#263)
type: note
permalink: goldsrc-vibesignatures/locators/vgui-wrap2-engine-private-symbols-263
tags:
- locator
- engine
- vgui
---

# VGuiWrap2 engine private symbols (#263)

## Trigger

Issue #263 requests `VGuiWrap2_Startup`, `staticUIFuncs`, `IBaseUI` startup slots, `VGuiWrap2_ConPrintf`, `staticGameConsole`, and `IGameConsole::Printf` from engine `hw.dll`/`hw.so`.

## Root constraints

- `BaseUI001` has two code owners in every configured engine binary: a registrar and `VGuiWrap2_Startup`. On Windows `VEngineVGui001` belongs to a separate registrar function, so `exclude_strings` does not remove the BaseUI registrar. The startup role is the `BaseUI001` factory query followed by two IBaseUI calls with arguments 2 and 7.
- The arguments 2 and 7 are not vtable indices. The virtual destructor occupies one Windows MSVC slot and two Linux Itanium ABI slots. Thus `IBaseUI::Initialize`/`Start` are indices 1/2 on Windows, 2/3 on Linux; `IGameConsole::Printf` is index 6 on Windows, 7 on Linux.
- `VGuiWrap2_Startup` may inline the console-printing call, so its direct call target is not a universal locator for the standalone `VGuiWrap2_ConPrintf` entry. Linux `%s` may point into a longer literal, so `FULLMATCH:%s` is also unsuitable.
- SvEngine Windows tail-merges the actual console wrapper entry into a notification caller's IDA function. In `svencoop-8948`, IDA originally attributed the wrapper at `0x1d16fa0` to owner `0x1d403d0`; in `svencoop-10257`, `0x1d16e00` to `0x1d40760`. Those owner entries execute extra developer-notification work and are not the wrapper. Verify the tail chunk starts at the wrapper entry, has one owner and one incoming direct jump, then detach the tail and establish the real function entry in the owned worker. Validate a unique signature there. The analyzer's warm IDB is not saved.
- The GNU console wrapper and its `DPrintf` sibling can have the same wildcarded function prefix. After semantic discovery, a generated runtime signature can use the unique relative thunk-call displacement or a validated across-boundary signature; never use this as the discovery anchor.

## Correct approach

- `find-VGuiWrap2_Startup.py`: exact `BaseUI001` code owners, filtered by both startup vcalls and arguments.
- `find-VGuiWrap2_Startup-dependents.py`: the guard global that receives the factory return is `staticUIFuncs`; derive the two interface slots from verified calls.
- `find-staticGameConsole.py`: trace the `GameConsole003` factory return into one writable global, including PIC/GOT forms. It works for Sven Linux even where the existing `CBaseUI__Initialize` finder is Windows-only.
- `find-VGuiWrap2_ConPrintf.py`: use `staticGameConsole`, the Printf slot, and shared temporary-console-buffer data with `Startup`; exclude the inlined `Startup` body and siblings. `_vgui_console_common.py` recovers the actual entry when IDA assigns its tail to another function.
- `find-IGameConsole_Printf.py`: revalidate/recover the source function entry, then emit only the indirect slot.
- Linux symbols retain observed names where present: `VGuiWrap2_Startup`/`VGuiWrap2_ConPrintf` on HL builds, `_Z17VGuiWrap2_Startupv`/`_Z19VGuiWrap2_ConPrintfPKc` on `svencoop-8948`. `svencoop-10257 hw.so` is stripped, so source-role labels are used for its private functions.

## Verification and applicability
The five production finders generated 105 artifacts for all 15 configured engine/platform combinations: 11 Windows and four Linux. Old HL BLOB inputs use verified `hw.decrypt.dll` mirrors. Initial `ConPrintf` owner attribution passed schema checks but failed semantic review; after correcting both Sven Windows entries, targeted analyzer runs of `ConPrintf` and `IGameConsole::Printf` succeeded. The other 13 combinations passed production analyzer runs. The final locator was checked against all 15 current IDBs; it selected one semantically matching code region in each, and the two Sven Windows artifacts now record that region's real entry rather than its unrelated IDA tail owner. Format, unit, and repository-contract gates passed. No engine module is declared for `cstrike`/`czero`/`czeror`, so they do not receive these artifacts.