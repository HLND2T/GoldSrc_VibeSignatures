---
title: loadmodel locator
type: note
permalink: goldsrc-vibesignatures/locators/loadmodel
tags:
  - locator
  - engine
  - gv
---

# loadmodel

## Symbol

- **Name**: `loadmodel`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_LoadModel-decompiles.py`
  (emits `loadmodel` and `loadname` alongside `FS_Open` from one run)

## Availability

- Declared in 11 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257, svencoop-8948.
- Platforms: no `platform:` gating; only hl-10210, hl-8684, svencoop-8948 and svencoop-10257
  declare `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: never inlined; it is the `model_t *` slot assigned by the loading body. The
  *store encoding* differs by family/platform (below).

## Predecessors

- `Mod_LoadModel.{platform}.yaml` (produced by `find-Mod_LoadModel`), consumed via
  `expected_input`; the LLM dependency policy marks it `"required"`.
- Reference disassembly: `references/{gamever}/engine/Mod_LoadModel.{platform}.yaml`.

## How it is located

`-decompiles` (LLM) finder — no deterministic anchor of its own, and it is recovered in the
same run as `loadname`:

1. Load the required predecessor `Mod_LoadModel.{platform}.yaml`, export that function from
   the current IDB, and prompt with `prompt/call_llm_decompile.md` with
   `expected_result_sections: ["found_gv"]` against the annotated reference.
2. The model picks the `loadmodel = mod` store that immediately follows the `COM_FileBase`
   call; the shared consumer resolves the store operand and re-validates the live
   instruction/unique target before emitting the GV field set (`gv_name`, `gv_va`, `gv_rva`,
   `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`, plus
   `gv_pic_addend` where PIC).

`gv_sig` is the owning `Mod_LoadModel` function signature and `gv_sig_va` its entry, so the
runtime anchor is the verified function; `gv_inst_offset`/`gv_inst_disp` select the operand
inside it.

Observed access forms at the annotated site:

| family / platform | access | encoding |
| --- | --- | --- |
| hl-10210 hw.dll | `mov loadmodel, edi` | `89 3D imm32` (`insn_len 0x6`, `disp 0x2`) |
| hl-10210 hw.so | `mov ds:loadmodel, mod` | `89 15 imm32` (non-PIC absolute) |
| svencoop-10257 hw.dll | `mov dword ptr loadmodel, esi` | `89 35 imm32` |
| svencoop-10257 hw.so | `mov ds:(loadmodel - GOT)[ebx], esi` | PIC GOTOFF, resolved through `gv_pic_addend` |

## Pitfalls

- **Do not port MetaHookSv's locator literally.** `Engine_FillAddress_Mod_LoadModel` only
  matches `MOV [imm32], reg` with a zero base/index register, which is the MSVC absolute form.
  The ELF builds store through an absolute `ds:` operand and the PIC SvEngine build through
  `[ebx + disp]`, so the same instruction-form filter does not carry over.
- On SvEngine Linux the PIC store only resolves once the shared address-flow model ignores
  loop paths that never write the base register and x87 instructions that carry no general
  purpose register operand (see the lesson note). Both defects were live in the
  `svencoop-8948` run that produced
  `unresolved_global_address: Cannot determine EBX base for [ebx+0x2747da0]` plus a missing
  `loadmodel.linux.yaml`; a regression there fails the skill rather than emitting a wrong
  address.
- The store is a *destination* operand. A naive "first absolute data operand after `loadname`"
  scan picks the `loadname` reference itself (or the stack-argument stores around
  `COM_FileBase`); selection must stay pinned to the verified body rather than to a bare
  operand scan.
- In hl-10210 the emitted `loadmodel` and `loadname` addresses are `0x20` apart, with the
  ordering reversed between Windows (`loadname` lower) and Linux (`loadmodel` lower). Never
  derive one from the other by a fixed delta.
- Blob engines (hl-3248..hl-3647) run against `hw.decrypt.dll`; the artifact VA is resolved
  in that IDB, so downstream matching is on `gv_va`/`gv_sig`, never on an IDA display name.
