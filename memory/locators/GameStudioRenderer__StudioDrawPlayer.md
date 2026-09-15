---
title: GameStudioRenderer__StudioDrawPlayer locator
type: note
permalink: goldsrc-vibesignatures/locators/gamestudiorenderer-inner-studiodrawplayer
tags:
  - locator
  - client
  - vfunc
---

# GameStudioRenderer__StudioDrawPlayer

## Symbol

- **Name**: `GameStudioRenderer__StudioDrawPlayer` (double underscore: the CS/CZ inner
  player-model method, distinct from the public `GameStudioRenderer_StudioDrawPlayer` slot)
- **Category**: `vfunc`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-GameStudioRenderer-inner-player.py`

## Availability

- Declared in 8 client configs: cstrike-3248/3647/4554/6153/8684/10210, czero-8684/10210.
- Platforms: Windows for all 8 configs; Linux too only in cstrike-10210, cstrike-6153 and
  cstrike-8684 (the other five declare only `module_windows: client.dll`).
- Inlined / absent elsewhere: the CS-family prediction wrapper is the only owner of this slot.
  CZDS (`czeror-*`) has no prediction wrapper's inner `_StudioDrawPlayer`, and hl-*, cof-5936 and
  svencoop-10257 are not registered at all — no inner virtual may be manufactured for them.

## Predecessors

- `GameStudioRenderer_StudioDrawPlayer.<platform>.yaml` — the wrapper whose body is scanned.
- `GameStudioRenderer_vtable.<platform>.yaml` — resolved because the emitted index is validated
  against its `vtable_entries`.

## How it is located

1. Load the outer wrapper's `func_va` from the `GameStudioRenderer_StudioDrawPlayer` artifact and
   the entry map from `GameStudioRenderer_vtable`.
2. Run the shared `_SCAN_TEMPLATE` from
   `ida_preprocessor_scripts/_indirect_vcall_target_common.py` over the wrapper body with
   `ALLOWED = ["call", "jmp"]` and `resolve_load_then_branch=True`.
3. The scan collects each indirect branch whose operand is an `o_displ` slot offset — or a
   register previously loaded with an `o_displ` offset by a `mov`. Offsets must be 4-byte aligned
   (`offset % 4 == 0`); results are deduplicated on `(offset, index)`.
4. **Exactly one** distinct slot must remain. `vfunc_index = offset / 4` is then used to read
   the corresponding `GameStudioRenderer_vtable` entry; a missing entry fails closed.
5. That entry is inspected and written with `func_name`, `func_va/rva/size`,
   `vtable_name = GameStudioRenderer`, `vfunc_index`, `vfunc_offset = index * 4` and
   `vfunc_sig`.

## Pitfalls

- **The slot index is ABI-specific and must never be copied.** cstrike-8684 emits index 25
  (offset `0x64`) on Windows and index 26 (offset `0x68`) on Linux — a one-slot shift caused by
  the Itanium destructor pair. Both are read from the current binary's vtable artifact; neither
  is carried over from another platform or game family.
- The wrapper saves, sets up and restores local-player animation around the inner method, and GCC
  turns its early returns into tail jumps — hence `jmp` is an allowed mnemonic and
  `resolve_load_then_branch=True` recovers the `mov reg, [this+off]` + `call/jmp reg` form. The
  "exactly one distinct slot" rule is what keeps this unambiguous; a second distinct slot fails
  the finder rather than guessing.
- The resolved entry is not filtered by name or signature characteristics; identity is the vtable
  position plus the runtime signature uniqueness of the emitted `vfunc_sig`. In GCC builds the
  method is large and can be split, so the body is not used as a positive anchor.
- Existence is family-bounded: do not synthesize this artifact for CZDS, HL, CoF or SvEngine.
