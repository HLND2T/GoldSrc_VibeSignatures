---
title: gamma table globals locator
type: note
permalink: goldsrc-vibesignatures/locators/gamma-table-globals-locator
tags:
- locator
- engine
- gv
---

# texgammatable / lightgammatable / lineargammatable / screengammatable

## Symbol

Four engine globals produced together by `ida_preprocessor_scripts/find-BuildGammaTable-globals.py`.

## Predecessors

- GoldSrc/HL25/CoF: `BuildGammaTable`
- SvEngine: `V_BuildGammaTable`

## How it is located

`view.c` fills the tables in statement order: 256-byte `texgammatable`, then the 1024-int `lightgammatable` (0.075/0.875 shift), then `lineargammatable` and `screengammatable` in the dual-pow loop. Identity is first-write order, not BSS layout.

- Unique indexed byte store is `texgammatable`. Bases one apart collapse to the higher address (HL25 Linux `texgammatable[i]` vs `texgammatable-1[ebx]`).
- Indexed dword stores plus a pointer-span loop (`mov/lea reg, offset start` paired with `cmp` against `start+0x1000`) yield the three int tables.
- PIC: GOT-only scalar spills are ignored; table stores use a second index register. When GOT is a base, the address is `GOT + disp32` (do not add GOT to an already-resolved VA).
- Pointer-init `mov esi, offset table` may have `offb=0`; fall back to finding the little-endian VA in the instruction bytes (`gv_inst_disp` is then 1 for `BE imm32`).

## Pitfalls

- hl-4554/similar GoldSrc Windows fill `lightgammatable` via `mov [esi], eax` after loading the table offset, not `table[esi*4]`.
- SvEngine Linux tex stores can appear as a fake absolute equal to GOTOFF; folding is `GOT + disp32`.
