---
title: FS_Open locator
type: note
permalink: goldsrc-vibesignatures/locators/fs-open
tags:
  - locator
  - engine
  - func
---

# FS_Open

## Symbol

- **Name**: `FS_Open`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_LoadModel-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (the producer declares no `platform` gate). Linux engine modules exist only for hl-10210, hl-8684 and svencoop-10257.
- Inlined / absent: none observed. SvEngine Windows keeps it as a bare forwarding wrapper (`func_size: 0x16`); classic Windows builds carry the full body (`0x37`), Linux is PIC.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- `Mod_LoadModel.{platform}.yaml` (produced by `find-Mod_LoadModel`, consumed via `expected_input` with `dependency_policy: required`).

## How it is located

LLM_DECOMPILE, not a string anchor — FS_Open has no single-owner literal of its own.

1. `find-Mod_LoadModel` must have produced `Mod_LoadModel.{platform}.yaml`; its `func_va` is the *target* function exported from the live IDB.
2. The *reference* is `references/{gamever}/engine/Mod_LoadModel.{platform}.yaml` — the annotated disassembly + pseudocode of the owner body. `_resolve_reference_resource` falls back to the default reference gamever (`hl-10210`) when the current tag has no such file, so only svencoop-10257 needs its own copy.
3. `prompt/call_llm_decompile.md` is rendered with the reference blocks and the target block; the LLM is told that identical behaviour under different names/addresses still counts as a match, and must answer under `found_call`.
4. The entry whose `func_name` is `FS_Open` must name a *direct call* instruction inside the target Mod_LoadModel range; `detail["code_refs"]` must resolve to exactly one address. That address is taken as the FS_Open VA and `_inspect_function_via_mcp` emits `func_name / func_va / func_rva / func_size / func_sig`.
5. `expected_result_sections: ["found_call"]` — a `found_call` list is mandatory, so an empty answer fails the skill.

## Pitfalls

- Official source has exactly one `FS_Open` call in `engine/gl_model.c` (Mod_LoadModel) and one in `engine/snd_mem.c` (S_LoadSound). This finder recovers the callee (`FS_Open` itself); the *call sites* are separate patch artifacts owned by `find-Mod_LoadModel_to_FS_Open_callsites` / `find-S_LoadSound_to_FS_Open_callsites`.
- SvEngine Windows `FS_Open` is a thin dispatcher through the filesystem vtable (`mov ecx,[g_pFileSystem]; mov eax,[ecx]; call dword ptr [eax+off]; ret`) — do not reject a 22-byte extent as a decoy.
- Linux builds are PIC: the body opens with `call __x86.get_pc_thunk.*` / `add reg, offset _GLOBAL_OFFSET_TABLE_`, so the leading `func_sig` bytes are wildcarded and the callee VA is GOT-relative.
- Blob engines (hl-3248..hl-3647) run against `hw.decrypt.dll`; the callee may still be displayed as `sub_XXXXXXXX`. Everything downstream must match on the artifact `func_va`, never on the IDA display name.
- Do not attempt a byte-signature or old-YAML fast path for discovery: `FS_Open` is anonymous in most IDBs and the whole point of the decompile chain is that the reference body identifies it semantically.
