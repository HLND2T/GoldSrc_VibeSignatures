---
title: gTempEnts locator
type: note
permalink: goldsrc-vibesignatures/locators/gtempents
tags:
  - locator
  - engine
  - gv
---

# gTempEnts

## Symbol

- **Name**: `gTempEnts`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**:
  - `ida_preprocessor_scripts/find-CL_InitTEnts-decompiles.py` (Linux route)
  - `ida_preprocessor_scripts/find-CL_TempEntInit-decompiles.py` (Windows route)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257 (both platforms everywhere).
- Platforms: Windows + Linux, but the producer differs per platform:
  - **Windows** (cof-5936, hl-3248..hl-8684): `find-CL_TempEntInit-decompiles`, `platform: windows`, predecessor `CL_TempEntInit`.
  - **Linux** (hl-8684, svencoop-10257 gated `platform: linux`; hl-10210 ungated): `find-CL_InitTEnts-decompiles`, predecessor `CL_InitTEnts`. hl-10210 is the only config that also produces `gTempEnts.windows.yaml` through this route, because its `find-CL_InitTEnts-decompiles` entry carries no `platform:` gate while hl-8684's does.
- Inlined / absent: on HL builds the pool initialization is inlined into `CL_InitTEnts`, so there is no standalone initializer to walk — the global is recovered from the inlined `memset` destination. CoF keeps `CL_TempEntInit` out of line, which is why the Windows reference is CoF's.

## Predecessors

- `CL_InitTEnts` (produced by `find-CL_InitTEnts`) — Linux route.
- `CL_TempEntInit` (produced by `find-CL_InitTEnts-calls`) — Windows route.
- Each route declares its predecessor `required` in `dependency_policy` and returns `False` when the artifact is absent.

## How it is located

Both routes are LLM `found_gv` specs fed an annotated predecessor reference:

1. `find-CL_InitTEnts-decompiles`: `LLM_DECOMPILE` symbol `gTempEnts`, prompt `prompt/call_llm_decompile.md`, expected section `found_gv`, reference `references/{gamever}/engine/CL_InitTEnts.{platform}.yaml`.
2. `find-CL_TempEntInit-decompiles`: same section/prompt, reference `references/cof-5936/engine/CL_TempEntInit.{platform}.yaml`.
3. The LLM returns the storing/carrying instruction; shared validation resolves the operand against the *current* target and retries on mismatch.
4. Emitted fields: `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`, plus `gv_sig_allow_across_function_boundary:true` (declared in `generate_yaml_desired_fields` for both producers).

Concrete anchor shapes from current artifacts (evidence only, never selectors): hl-10210 Windows `gv_sig_va 0x101ada80`, offset `0x38d`, length 5, disp 1 (`push offset gTempEnts`); hl-10210 Linux `gv_sig_va 0x13bee0`, offset `0x470`, length 7, disp 3 (`mov [esp], imm32`).

## Pitfalls

- **Pool base vs interior member (the main trap).** The reference explicitly warns: the first `memset` argument is `gTempEnts` (the pool base), *not* the first entry's `next` member and not a pointer slot. In the CoF reference `gTempEnts = 0x01EF4810` while `dword_1EF483C = gTempEnts + 0x2C` is entry 0's `next`, written inside the link loop with a 0xBF8 (3068-byte) stride. An LLM that latches onto the `next`-member store returns an interior address 0x2C past the pool.
- Do not infer a zero `next` offset from an anonymous `dword_*` label — the member offset is 0x2C and the label does not encode it.
- Reference addresses/names are never copied across builds; match pools by initialization *behavior* (zero the whole pool, then link `next` pointers with the entry stride, then reset `gpTempEntFree`/`gpTempEntActive`).
- `gv_sig_allow_across_function_boundary:true` is set for both producers, so a rebuilt signature may span into adjacent code/padding.
