---
title: S_LoadSound locator
type: note
permalink: goldsrc-vibesignatures/locators/s-loadsound
tags:
  - locator
  - engine
  - func
---

# S_LoadSound

## Symbol

- **Name**: `S_LoadSound`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-S_LoadSound.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform` gate). Linux engine modules exist only for hl-10210, hl-8684 and svencoop-10257.
- Inlined / absent: never inlined; `S_LoadSound` is a standalone function in every build. It owns exactly one `FS_Open(namebuffer, "rb")` call site, which is what the callsite patch skill consumes.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- None. `find-S_LoadSound` has no `expected_input`.

## How it is located

`preprocess_common_skill` with a single exact string xref:

- `FULLMATCH:S_LoadSound: Couldn't load %s\n` — the `Con_DPrintf` that `engine/snd_mem.c` emits when the sound file cannot be opened. It has exactly one owning function, `S_LoadSound`, so a single spec is sufficient (no family split, unlike the model loaders).

No byte signature participates in discovery. `_inspect_function_via_mcp` emits `func_name / func_sig / func_va / func_rva / func_size`.

## Pitfalls

- The anchor involves the shared IDB string list, so a custom finder that rebuilds it with a coarser `minlen` can hide the literal (shared string-list pollution). No structural fallback exists.
- `func_va` here must be a real function *start*: `find-S_LoadSound_to_FS_Open_callsites` re-inspects it and rejects the artifact if `get_func(va).start_ea != va`.
- Blob engines (hl-3248..hl-3647) are Windows-only and run against `hw.decrypt.dll`; `S_LoadSound` there may still be named `sub_XXXXXXXX`, so consumers must use the artifact `func_va`, not the display name.
- The Linux body is PIC (`call __x86.get_pc_thunk.*` prologue), so its `func_sig` leading bytes are wildcarded — expected, not a defect.
