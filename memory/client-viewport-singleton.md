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
- Owned no-save IDA workers and the exact configured client binary/platform. Old CZDS 8684 databases may lack or merge callable boundaries and xrefs; bounded decoded operand and return/tail-call evidence recovers logical bodies without changing IDA function ownership.
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

### Merged warm-IDB callable boundaries (issue #306)

- Trigger: `VClientVGUI001 registered factory is absent or ambiguous` on CZDS 8684 Windows, despite identical input bytes passing in a saved IDB with separate functions.
- Root cause: the warm IDB merges registration, factory, initializer and constructor chunks under an unrelated entry. Shared argument recovery correctly rejects unreachable definitions; function-start checks also discard direct targets. Fixing registration and factory alone still fails constructor proof.
- Correct approach: keep shared dominance semantics. Decode bounded Windows registration/factory bodies, derive local stack depth, and recover constructor/caller bodies from decoded boundaries and incoming code references. Accept a tail jump only to the separately selected constructor body, then transfer its proven receiver into the existing vptr/RTTI proof. Reject unsupported branches, stack effects and partial pointer writes. For an embedded or absent signature owner, generate a unique signature at the verified object operand instead of splitting IDA functions.
- Evidence: the supplied `bin/czero-8684/client/ci-self-runner.client.dll.i64` identifies `czeror-8684/client/client.dll` with SHA-256 `e28ef031c1810a913227fbdf8075a367a60165d209b8071a94020a448ff76286`. Registration at `0x27036b10` recovers factory `0x27036b30`, returning interface `0x2712acdc`. Initializer `0x27036ad0` passes `0x2712acd8` in ECX through a tail jump to constructor `0x270368a0`; paired stores and secondary RTTI establish the offset of four.
- Verification: the full finder and YAML writer pass the supplied warm IDB, an additional probe hiding callable ownership and rejecting `add_func`, and all 17 configured CS/CZ/CZDS clients (including CZDS 10210 Windows/Linux). Each generated signature is unique and each object RVA agrees with its existing artifact. Tests cover bounded entry/termination, stack effects, tail receiver transfer, ambiguity and signature emission. IDB checks run in disposable fixtures with owned no-save workers.
- Scope: viewport finder and its pure proof helpers; no shared call-argument contract, configuration, or IDB repair changes.

### Preserve full module imports for trusted impact planning

- Trigger: PR validation fails in `plan` with `Changed analysis source has no mapped consumer: ida_preprocessor_scripts/_client_viewport_singleton.py`, before IDA analysis starts.
- Root cause: the trusted planner extracts `ast.ImportFrom.module` but not imported alias names. `from ida_preprocessor_scripts import _client_viewport_singleton` loses the helper edge. A lint cleanup in `27a319f` unintentionally reverted the earlier `a3b8e3a` compatibility fix.
- Correct approach: retain `import ida_preprocessor_scripts._client_viewport_singleton as _client_viewport_singleton`, with a local `noqa: PLR0402` and an explanatory comment. Do not change the trusted planner or suppress unmapped-source errors to fix this finder.
- Verification: the production source index reports zero helper consumers before the correction and all 17 configured viewport nodes afterward; run planner and viewport behavior tests as well as formatting checks. Existing reference-YAML orphan warnings are diagnostic and are not this fatal error.
- Scope: Python module imports consumed by the base-revision PR impact planner.

## Callers

- `ida_analyze_bin.py` invokes the registered preprocessor from each target client skill graph.
- Downstream `Plugins/VGUI2Extension/ClientVGUI.cpp` resolves the object through `GamedataResolvePtr(..., MH_GAMESYMBOL_KIND_GLOBAL)`.

### Stable signatures across exact and merged ownership (PR #357, 2026-10-10)

- Trigger: run 38022306420 generated a shorter CZDS 8684 Windows singleton signature than the committed output, with the same object address and same operand.
- Root cause: local IDA owns initializer 0x27036ad0 as a separate function, while the CI warm database folds it into 0x27036a50. The former used whole-function signature generation; the latter used the independently verified access signature. Identical bytes therefore followed different signature algorithms.
- Correct approach: when a proved object operand is at the decoded logical entry and has a proved body end, always generate the unique access signature there. Keep ordinary function signatures for other access forms. Do not repair/split IDA functions.
- Verification: the existing behavior test now covers missing ownership, enclosing ownership, and exact ownership with the same result. The real CZDS finder produces the CI signature on the local exact-owner IDB. Its raw PE signature has exactly one executable match, and the MOV immediate resolves the same full object 0x2712acd8. The downloaded CI logs identify this as the only logical-entry access across the 17 configured singleton nodes.
- Scope: signature serialization for logical-entry object accesses; RTTI, complete-object proof, ABI and address discovery remain unchanged. Evidence addresses are not discovery constants.
