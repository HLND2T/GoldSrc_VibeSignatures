---
title: r_visframecount locator
type: note
permalink: goldsrc-vibesignatures/locators/r-visframecount
tags:
  - locator
  - engine
  - gv
---

# r_visframecount

## Symbol

- **Name**: `r_visframecount`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_RecursiveWorldNode-globals.py`
- **Source**: `engine/gl_rmain.c` — `int r_visframecount;` — bumped when entering a
  new PVS; the world node walk rejects nodes stamped with a stale value.

## Availability

- All 11 engine configs, every declared platform. Real symbol name is preserved
  in every non-stripped `.so`.

## Predecessors

- `R_RecursiveWorldNode.{platform}.yaml`.

## How it is located

`LLM_DECOMPILE` with `expected_result_sections: ["found_gv"]` against the same
reference as [[r_framecount]]. In the walk it is the guard
(`if (node->visframe != r_visframecount) return;`).

## Pitfalls

- **It is not `r_framecount ± 4`.** The pair is adjacent on hl-10210 and
  SvEngine with `r_visframecount` either above or below, and `0x7c` apart on
  hl-10210 Linux. Each is recovered by its own LLM target.
- On svencoop-8948 the guard reaches the counter only through a `.got` slot
  (`mov eax, ds:(r_visframecount_ptr - 33A000h)[edi]`); the binary contains no
  direct absolute reference to `r_visframecount` anywhere. `_llm_global_targets`
  resolves it through `got_indirect_targets`, and `_gv_resolution_fields` then
  emits a `gv_pic_addend` that folds the GOT base into the addend
  (`0x30d72b0`), so `image_base + embedded + addend` still lands on the global.
  That is consistent with the resolver's arithmetic; the runtime resolves the
  symbol from `gv_rva` and never has to follow the slot itself.
- Validation evidence: hl-10210 L `0xf7d77c` / W `0x10dc5614`,
  svencoop-10257 L `0x30f6f74`, svencoop-8948 L `0x30d6dd4` (`.symtab`).

## Relations

- relates_to [[R_RecursiveWorldNode]]
- relates_to [[r_framecount]]
