---
title: CVideoMode_Common_DrawStartupGraphic locator
type: note
permalink: goldsrc-vibesignatures/locators/cvideomode-common-drawstartupgraphic
tags:
  - locator
  - engine
  - func
---

# CVideoMode_Common_DrawStartupGraphic

## Symbol

- **Name**: `CVideoMode_Common_DrawStartupGraphic`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CVideoMode_Common_DrawStartupGraphic-decompiles.py`

## Availability

- Declared in all 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate).
- Inlined / absent: always present as a standalone function, but as three behaviorally distinct variants — HL25 (hl-10210), GDI (cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, Windows-only) and GL (hl-6153, hl-8684, svencoop-10257). Size tracks the variant: GDI `0x2b9`-`0x2bd`, GL `0x648`-`0x69f`, HL25 `0xa99`-`0xaad`.

## Predecessors

- `CVideoMode_Common_Init.{platform}.yaml` (GDI and GL families) **or** `CVideoMode_Common_PlayStartupSequence.{platform}.yaml` (hl-10210 only) — selected by gamever, consumed via `expected_input` and as an LLM reference with dependency policy `required`.

## How it is located

This is an LLM_DECOMPILE finder (`found_call`) whose *reference* is branched by build family while the *target* is always the current build's predecessor:

1. The gamever tag is taken from the predecessor binary dir's parent directory name.
2. `_predecessor_reference` selects:
   - hl-10210 → predecessor `CVideoMode_Common_PlayStartupSequence`, reference family `hl-10210`;
   - cof-5936 / hl-3248 / hl-3266 / hl-3329 / hl-3647 / hl-4554 → predecessor `CVideoMode_Common_Init`, reference family `hl-3248`;
   - anything else (hl-6153, hl-8684, svencoop-10257) → predecessor `CVideoMode_Common_Init`, reference family `hl-8684`.
3. `references/{family}/engine/{predecessor}.{platform}.yaml` is loaded as the annotated example (it must contain exactly `func_name`, `func_va`, `disasm_code`, `procedure`), and the current binary's `{predecessor}.{platform}.yaml` must exist to supply the target `func_va`.
4. The current predecessor is exported over MCP (disasm + pseudocode) and the model must return a `found_call` entry naming `CVideoMode_Common_DrawStartupGraphic`.
5. Validation: the instruction must lie inside the exported target range(s) and its `code_refs` must collapse to exactly one target; that target is inspected and emitted as `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`. `func_sig_resolve_jmp_thunk` is not in the desired-field set, so no thunk unwrapping is performed.

The family split exists because the *caller* differs: hl-10210 gates on `-novid` in `PlayStartupSequence` and then calls `DrawStartupGraphic`, whereas the GDI/GL builds call it from `Init`. Each family therefore needs its own annotated example so the model can find the call instruction in a target that is disassembled without the reference's names.

## Pitfalls

- The three variants are not interchangeable: the GDI variant does DC/compatible-bitmap `BitBlt` plus image release, the GL variant does tiling/base resolution, texture upload, quad and swap, and the HL25 variant is the fullscreen-GL path. An LLM shown the wrong family's reference can latch onto a same-named-but-wrong call; that is why the family is derived from the gamever rather than from the binary content.
- Both predecessor artifacts live in the *current* binary dir; the reference YAML under `ida_preprocessor_scripts/references/` is only the annotated example and is read from a different family directory than the target's gamever.
- hl-10210's predecessor is `CVideoMode_Common_PlayStartupSequence`, **not** `CVideoMode_Common_Init` (which is not even registered for hl-10210). If the PlayStartupSequence artifact is missing, hl-10210 silently yields nothing here.
- The `-novid` call in hl-10210 is inside a 0x34-byte function, and the `-novid` literal has two raw owners, so the predecessor cannot be re-found by a plain string xref; it comes from the vtable walk in `find-CVideoMode_Common_PlayStartupSequence`.
- Linux PIC builds export the GOT-relative operands; the model is instructed to report the exact current-target instruction text, so the emitted artifact stays anchored to `insn_va` inside the predecessor rather than to a copied address.
