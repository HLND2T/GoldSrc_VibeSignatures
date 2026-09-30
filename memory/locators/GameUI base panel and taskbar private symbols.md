---
title: GameUI base panel and taskbar private symbols
type: note
permalink: goldsrc-vibesignatures/locators/game-ui-base-panel-and-taskbar-private-symbols
tags:
- gameui
- anchors
- abi
- issue-311
---

# GameUI base panel and taskbar private symbols

## Trigger

Adding GameUI's CBasePanel/CTaskbar constructors, taskbar primary table and OnCommand, or exposing the single-name KeyValues constructor already located by the shared finder (#311).

## Root cause and constraints

- MetaHook's `CTaskBar` spelling is a lookup field; actual ELF methods and class RTTI use `CTaskbar`. The localization path belongs to CGameUI::Initialize, whereas `BasePanel` belongs directly to CBasePanel's constructor.
- Windows OnCommand is slot 87 (0x15c), Linux slot 88 (0x160) on this verified matrix. Those are observations, not discovery constants; destructor layout differs by ABI.
- Sven 8948 Linux routes constructor calls through local PLT/GOT. XrefsTo(entry) misses the code callers; use the existing ELF resolver instead of rejecting a constructor with a proven own-literal/this-vptr relationship.
- HL25 Windows CTaskbar has a generic normalized entry prefix: the default signature matches 37 addresses and the standard 256-byte expansion still matches two. The user explicitly permits omission of an unsuitable constructor func_sig. Keep verified entry/RVA/size and omit this field; the existing artifact/runtime contract supports it. Do not force a 521-byte expansion or introduce a new schema exception.
- HL3248/3266/3329 GameUI embeds `vgui2::KeyValues`; later targets use global `KeyValues`. Derive the namespace from current RTTI.

## Correct approach

`find-GameUI-base-taskbar.py` finds the unique exact owners of `BasePanel` and `GameMenuButton`; requires a dword store to ABI this installing the corresponding current primary RTTI table; and checks callers through `elf_code_refs_to` plus resolved call targets. It outputs CBasePanel_ctor, CTaskbar_ctor and CTaskbar_vtable.

Intersect exact owners of `OpenLoadGameDialog`, `OpenSaveGameDialog`, and `OpenOptionsDialog` to identify CTaskbar::OnCommand(char const*), then locate its unique entry in the recovered table. Emit a vfunc with the actual current slot. The required current CTaskbar_QuitConfirmationOwner input has the same body on HL10210/Sven8948/Sven10257 Windows because the helper was inlined. Reuse its signature only after independent OnCommand discovery, entry/size agreement and a unique current-image signature check; other builds use normal output inspection.

Extend `find-client-vgui-keyvalues.py` only at emission: the existing CursorEnteredMenuButton argument-flow/primary-vptr/KeyValues-RTTI walk already returns ctor. Emit optional `KeyValues_ctor` with qualified constructor identity when requested by GameUI. Existing vtable/LoadFromFile pairs in GameUI, ServerBrowser and clients remain unchanged; no second KeyValues discovery chain is needed.

## Verification

2026-09-30: owned strict/no-save selected batch `analysis-batch-20260930T192856-2181579289fe40d8b13904f1d1b2810b` forced all 15 new GameUI finder nodes and all 47 existing KeyValues nodes across 21 gamevers: 62 succeeded, zero failed/skipped, with Agent fallback unavailable. All 75 new artifacts matched the reviewed current-binary function addresses/sizes, primary tables, and slot relationships. Existing KeyValues artifacts were unchanged. Only HL10210 Windows CTaskbar_ctor lacks func_sig. Independent nm -C checks matched the four functions and taskbar table on HL8684, HL10210 and Sven8948 ELF; Sven10257 retains RTTI but lacks these private symbols.

Local warmup populated missing ServerBrowser and early CS decrypted-client IDBs through the neutral producer; no binary/IDA scratch is a tracked deliverable. The source Python and YAML gates run separately from real IDA analysis.

## Scope and source references

Module gameui: HL3248/3266/3329/3647/4554/6153/8684/10210, Sven8948/10257, CoF5936 (11 Windows, 4 Linux). Linux applies only to HL8684/10210 and Sven8948/10257. CS/CZ configs declare no separate gameui binary; do not register missing platform/module paths.

Sources: HLND2T_official/gameui/BasePanel.cpp:27; Taskbar.cpp:298,350,662; GameUI_Interface.cpp:163; public/KeyValues.cpp:35. Current target binaries and RTTI are authoritative when source revisions differ.

Related: [[Client private VGUI ABI and artifact identities]], [[idalib-mcp]].

## Delivery gates

2026-09-30 local gates: unit suite 1277 tests OK (9 platform/opt-in skips), repository-contract suite 14 tests OK, formatter and git diff --check passed. Redis utility tests passed; live Redis groups were unavailable locally. The opt-in IDA environment test was skipped; real owned binary analysis above is the IDA evidence. No shared helper/runtime behavior changed and no production-specific contract test was introduced.
