---
title: Draw_SpriteFrameGeneric_SvEngine locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-spriteframegeneric-svengine
tags:
  - locator
  - engine
  - func
---

# Draw_SpriteFrameGeneric_SvEngine

## Symbol

- **Name**: `Draw_SpriteFrameGeneric_SvEngine`
- **Category**: `func`
- **Module**: engine (`hw.dll` — SvEngine Windows branch)
- **Producer**: `ida_preprocessor_scripts/find-Draw_SpriteFrame-family-svencoop.py`

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Windows-only (`platform: windows` on both the finder registration and the
  svencoop symbol declaration).
- Inlined / absent: inlined into `SPR_Draw*` on SvEngine Linux — no standalone entry exists
  there. The `_SvEngine` suffix marks the body difference from HL/CoF
  `Draw_SpriteFrameGeneric`.

## Predecessors

- None.

## How it is located

1. `refs("SPR_DrawGeneric: Invalid frame %d\n")` — exact SvEngine diagnostic.
2. `family_union` maps each reference site to its unit: the owning IDA function, or the
   **contiguous `is_code` run** around the xref when IDA never promoted the owner (the
   SvEngine-specific recovery). References found inside promoted functions are preferred
   over orphan references.
3. Helper callees shared by all three `SPR_Draw*` families are removed by intersection; the
   renderer is the unique remaining GENERIC candidate that `call`s the shared `Draw_Frame`,
   which the same walk resolves as the target reached from one candidate of every family.
4. Non-unique → `renderer not unique`; nothing is written.

Emission: `func_va` / `func_rva` / `func_size` / `func_sig` via
`_inspect_function_via_mcp` with an `allow_across_function_boundary` retry. No byte pattern
or old YAML participates.

## Pitfalls

- The SvEngine literal (`SPR_DrawGeneric: Invalid frame %d\n`) shares no wording with the
  HL/CoF `Client.dll SPR_DrawGeneric error: invalid frame\n`; matching is exact so the two
  producers are not interchangeable.
- The contiguous-`is_code`-run recovery assumes SvEngine units are padding-separated. On old
  HL builds that assumption fails (multiple un-promoted functions in one gap), which is why
  the HL producer uses a terminator-bounded basic block instead.
- Windows-only: on SvEngine Linux the renderer is inlined into its `SPR_Draw*` owner.
- The four family artifacts are emitted from one resolved address map, so this symbol is
  either written correctly or not at all.
