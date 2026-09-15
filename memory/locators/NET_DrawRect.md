---
title: NET_DrawRect locator
type: note
permalink: goldsrc-vibesignatures/locators/net-drawrect
tags:
  - locator
  - engine
  - func
---

# NET_DrawRect

## Symbol

- **Name**: `NET_DrawRect`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-NET_DrawRect.py`

## Availability

- Declared in exactly **1** engine config: svencoop-10257, where the producer is registered as `platform: windows`.
- Platforms: **Windows-only.** SvEngine Linux has no equivalent function shape, so the symbol is never emitted there.
- Inlined / absent: not inlined, but **merged**: MSVC `/OPT:ICF` folds `NET_DrawRect` (the netgraph filled-rectangle helper) with `D_FillRect` because the bodies are byte-identical. The emitted address therefore serves both names.

## Predecessors

- None.

## How it is located

1. Pure disassembly walk over `idautils.Functions()`; **no byte pattern is used anywhere** (`find-R124` style byte-pattern hints are explicitly not the anchor).
2. Coarse filters first: function size within `MIN_SIZE = 100 .. MAX_SIZE = 900` bytes, and **no** non-thunk internal callee (every `call` target is either not an exact function start or is a `<= 16`-byte stub).
3. Within the first `HEAD_INSNS = 24` instructions, require this ordered shape:
   - a `mov` whose source operand is a memory operand (`get_operand_type(pc, 1) == 2`) — the screen-width global loaded into `esi`;
   - then a `cmp <reg>, 0x400` (`CLAMP_IMM_A`);
   - then a `cmp <reg>, 1` (`CLAMP_IMM_B`), only counted after the `0x400` compare has been seen.
   Enforced ordering: `idx_mov < idx_a < idx_b` with all three indices inside the 24-instruction head.
4. Require exactly **one** hit across the whole database; anything else aborts.
5. Emit the standard function fields (retrying with `allow_across_function_boundary` when needed).

## Pitfalls

- The anchor is an instruction *shape*, not bytes: the head must contain the window clamp against `0x400` and `1` in order, and the body must call nothing (only vertex-array/blend GL imports).
- The merge with `D_FillRect` is real and intended — the artifact address is correct for both names, so do not "disambiguate" it by searching for a second candidate address.
- `HEAD_INSNS = 24` bounds the scan; a build that hoists the clamp past instruction 24 fails closed rather than picking a later match.
- The symbol is SvEngine-Windows-specific: neither the SvEngine Linux build nor the CoF/HL25 engine families expose this shape, so no coverage should be expected or requested there.
