---
title: client-viewport-singleton
type: note
permalink: goldsrc-vibesignatures/client-viewport-singleton
tags:
- client
- gamedata
- viewport
---

# client-viewport-singleton

## Overview

`find-client-viewport-singleton` recovers the complete static viewport object exposed through `VClientVGUI001`. CS/CZ publish `__g_CounterStrikeViewport_singleton`; CZDS publishes `__g_CZEROViewPort_singleton`. These GLOBAL records denote the object itself, so consumers use `imageBase + gv_rva` without dereferencing it.

## Responsibilities

- Prove a unique current-binary factory and pair its interface address with complete-object construction and class RTTI.
- Recover the secondary-interface displacement from RTTI rather than assuming a four-byte subtraction.
- Produce ordinary GV access metadata and a unique signature from an instruction containing the complete-object address.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-client-viewport-singleton.py` — `preprocess_skill`, injected `locate`, bounded `recover_linear_owner`.
- `ida_preprocessor_scripts/_client_viewport_singleton.py` — `constant_factory_return`, `unique_constructed_base`.
- `ida_preprocessor_scripts/_vgui_paint_common.py` — current-binary RTTI lookup for `CounterStrikeViewport` and `CZEROViewPort`.
- `configs/cstrike-*.yaml`, `configs/czero-*.yaml`, `configs/czeror-*.yaml` — client finder, GLOBAL declarations and explicit `artifact` paths preserving the leading `__`.
- `bin_artifacts/<game>/client/__g_*_singleton.<platform>.yaml` — 17 platform records across ten game versions.
- `tests/test_client_viewport_singleton.py` — pure behavior coverage for factory arithmetic, RTTI displacement, ambiguity and complete pointer writes.

## Architecture

The unique `VClientVGUI001` literal leads to decoded `InterfaceReg` constructor arguments and its registered factory. A bounded evaluator proves the returned static interface, including CS 4554's `NEG/SBB/AND` null-preserving conversion. Primary class RTTI and matching secondary RTTI supply the interface offset. Current constructor/initializer data flow must install both vptrs using complete x86 pointer writes; caller arguments provide the complete static object when construction is out of line. Only a uniquely proved base is accepted. The final signature validates a verified complete-object operand and does not discover the object. Old YAML is not a discovery input.

## Dependencies

- Shared x86 data flow, decoded call arguments, RTTI lookup, `inspect_unique_function` and `write_located_globals`.
- Owned no-save IDA workers and the exact configured client binary/platform. Old CZDS 8684 databases may lack callable boundaries and xrefs; bounded decoded operand and return/tail-call evidence repairs worker metadata without persisting IDBs.
- Downstream `VGUI2Extension::ClientVGUI_InstallHooks` selects the CS/CZ or CZDS GLOBAL symbol.

## Notes

### Interface subobject versus complete object

- Trigger: a consumer subtracts one `IClientVGUI` from a factory-returned interface.
- Constraint: the interface is a subobject; the ABI displacement must be established for each binary. The inspected 3248/3647/4554/6153 and newer binaries use `+4`, but the locator derives this from RTTI and paired vptr stores.
- Correct approach: publish the true static object as a GLOBAL and resolve its address directly. Retain the currently unused consumer variable because the user explicitly requested future use.
- Verification: production analysis on all ten configured game versions, covering 17 Windows/Linux clients, plus tests with varied RTTI offsets and rejection of partial pointer writes. CS 3248/3647 raw BLOB files and decrypted binaries are identical in each pair.
- Scope: the configured CS/CZ/CZDS clients; absent or ambiguous evidence fails closed.

### BLOB client module identity

- Trigger: resolving the new GLOBAL on CS 3248/3647 yields `MODULE_PATH_UNAVAILABLE`.
- Root cause: `MH_NLoadBlob` previously retained only the BLOB handle; client images lack a PE file path and their loader notification has no filename. `LoadBlobFromBuffer` decrypts its input in place.
- Correct approach: downstream hashes the original input bytes before decryption, then registers the successful client's image base, original CRC-64/XZ and image size before notification/entry-point queries. Internal registration reuses ordinary identity invalidation; the public MetaHook API remains unchanged.
- Verification: downstream C++ tests link real `GameData.cpp`, check CRC-64/XZ against raw CS 3248 (`33bcc90499401812`), and exercise GLOBAL address resolution, mirrors, reload, unload and reset. Actual game startup remains unverified.

### Delivery boundaries

New viewport records pass canonical snapshot/JSON export and the downstream viewport consumer gate. Full downstream snapshot validation also reports an existing `vgui2::ISurface::GetScreenSize` contract mismatch in all ten versions: upstream publishes a slot-only virtual record while the validator requires function address/size/signature. Publishing and game startup require separate verification; local artifacts alone do not update the hosted catalog.

## Callers

- `ida_analyze_bin.py` invokes the registered preprocessor from each target client skill graph.
- Downstream `Plugins/VGUI2Extension/ClientVGUI.cpp` resolves the object through `GamedataResolvePtr(..., MH_GAMESYMBOL_KIND_GLOBAL)`.
