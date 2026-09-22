---
title: cl_sf locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-sf-locator
tags:
- locator
- engine
- gv
---

## Symbol

- **Name**: `cl_sf`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_PolyBlend-cl_sf.py`
- **Source**: `engine/gl_rmain.c:1059` (`if (cl.sf.fadeFlags & FFADE_MODULATE)`);
  layout `common/screenfade.h:14-22`; declaration `engine/client.h:339`
  (`screenfade_t sf;` inside the global `client_state_t cl`).
- **Meaning**: `&cl.sf` — the screen-fade struct *base*, not a pointer slot.
  MetaHookSv names it `cl_sf` and treats it as `screenfade_t*`
  (`(*cl_sf).fadeFlags`, `(*cl_sf).fader`).

## Availability

- All 11 engine configs on every declared platform (11 Windows + 4 Linux).
- Real ELF symbol `cl` exists in hl-10210 / hl-8684 / svencoop-8948 `.so`
  (svencoop-10257 is stripped, same family and layout).

## Predecessors

- `R_PolyBlend.{platform}.yaml` (already covered by
  `find-R_PolyBlend-decompiles`), declared through `expected_input`.

## How it is located

Deterministic direct locator — an explicit exception to the LLM default for
globals (see the `create-preprocessor-scripts` global policy). Inside
`R_PolyBlend`, find the unique bit-1 (immediate `2`) test of a writable-data
global, in either shipped encoding:

- `test <mem>, 2` — 14/15 targets, including the SvEngine Linux PIC form
  `test byte ptr [esi+24275Ch], 2` with `esi = &cl`.
- `mov <reg>, <mem>` + `and <reg>, 2` — cof-5936 only.

then `gv_va = X - 20`, where `X = &cl.sf.fadeFlags` and `20` is the
source-declared `offsetof(screenfade_t, fadeFlags)`. The artifact is anchored on
the instruction that carries the four-byte operand: the `test` itself, or the
`mov` load for the register form (`and` has no displacement). The walk uses
`_engine_private_globals_common.scan()`, so GOT-derived bases resolve and PIC
targets emit `gv_pic_addend` instead of `gv_address_offset`.

Why not `LLM_DECOMPILE`: `found_gv` returns the tested operand's own address
(`fadeFlags`), not the struct base, so it would silently emit a wrong `gv_va`.
The same source invariant identifies the access on all 15 configured targets.

Cross-version evidence: the derived address agrees with the independently
located `cl_light_level` by exactly `0x34` and with `cl_waterlevel` by exactly
`0x24` on 15/15 (member order in `client.h:337-349`).

## Pitfalls

- `and <reg>, 2` carries no displacement; anchoring the artifact there fails
  address recovery. Anchor on the preceding load.
- SvEngine Linux reaches the member as `[esi+24275Ch]` where `esi = &cl` comes
  from a GOT slot. The raw displacement/addend is not the object; GOT-base
  resolution is required.
- Requiring only the direct encoding misses cof-5936; requiring only the
  register form misses HL/SvEngine. Both are needed, and the whole-function
  uniqueness check keeps them disjoint (zero or multiple candidates fail
  closed).
- The `20`-byte adjustment is a source constant, not an empirical guess; recheck
  it if Valve ever changes `screenfade_t`.
- Validation evidence (this exact input set): hl-10210 Windows `0x11282ea8` /
  Linux `0xc5a9c8`; cof-5936 Windows `0x2e119cc`; svencoop-8948 Linux
  `0x1830fe8`.

## Relations

- relates_to [[cl_viewentity]]
