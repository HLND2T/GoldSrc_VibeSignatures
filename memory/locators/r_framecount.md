---
title: r_framecount locator
type: note
permalink: goldsrc-vibesignatures/locators/r-framecount
tags:
  - locator
  - engine
  - gv
---

# r_framecount

## Symbol

- **Name**: `r_framecount`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_RecursiveWorldNode-globals.py`
- **Source**: `engine/gl_rmain.c` — `int r_framecount;` — the frame counter used
  for dynamic-light push checking.

## Availability

- All 11 engine configs, every declared platform. Real symbol name is preserved
  in every non-stripped `.so`.

## Predecessors

- `R_RecursiveWorldNode.{platform}.yaml`.

## How it is located

`LLM_DECOMPILE` with `expected_result_sections: ["found_gv"]` against
`references/{gamever}/engine/R_RecursiveWorldNode.{platform}.yaml`. In the world
node walk the counter stamps surviving leaves and surfaces
(`(*mark)->visframe = r_framecount`).

## Pitfalls

- On SvEngine the walk reaches the counter through a GOT slot
  (`mov -0x4dc(%edi),%eax` on svencoop-8948, `lea (slot - GOT)[edi]` on 10257),
  which `_llm_global_targets` resolves through `got_indirect_targets`. Do not
  emit the slot address as the global.
- The reference for `svencoop-10257` carries `gv_pic_addend`; the hl-10210
  reference does not.
- Validation evidence: hl-10210 L `0xf7d7f8` / W `0x10dc5610`,
  svencoop-10257 L `0x30f6f70`.

## Relations

- relates_to [[R_RecursiveWorldNode]]
- relates_to [[r_visframecount]]
