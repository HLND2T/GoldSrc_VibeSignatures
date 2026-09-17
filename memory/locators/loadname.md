---
title: loadname locator
type: note
permalink: goldsrc-vibesignatures/locators/loadname
tags:
  - locator
  - engine
  - gv
---

# loadname

## Symbol

- **Name**: `loadname`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_LoadModel-decompiles.py`
  (emits `loadname` and `loadmodel` alongside `FS_Open` from one run)

## Availability

- Declared in 11 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257, svencoop-8948.
- Platforms: no `platform:` gating; only hl-10210, hl-8684, svencoop-8948 and svencoop-10257
  declare `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: the buffer is never inlined; always present as a file-scope array. The
  *access encoding* inside the owning function differs by family/platform (below).

## Predecessors

- `Mod_LoadModel.{platform}.yaml` (produced by `find-Mod_LoadModel`), consumed via
  `expected_input`; the LLM dependency policy marks it `"required"`.
- Reference disassembly: `references/{gamever}/engine/Mod_LoadModel.{platform}.yaml`.

## How it is located

`-decompiles` (LLM) finder — no deterministic anchor of its own:

1. Load the required predecessor `Mod_LoadModel.{platform}.yaml`, export that function from
   the current IDB, and prompt with `prompt/call_llm_decompile.md` with
   `expected_result_sections: ["found_gv"]` against the annotated reference.
2. The model picks the `COM_FileBase(mod->name, loadname)` output-buffer access; the shared
   consumer resolves the operand and re-validates the live instruction/unique target before
   emitting the GV field set (`gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`,
   `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`, plus `gv_pic_addend` where PIC).

`gv_sig` is the owning `Mod_LoadModel` function signature and `gv_sig_va` its entry, so the
runtime anchor is the verified function; `gv_inst_offset`/`gv_inst_disp` select the operand
inside it.

Observed access forms at the annotated site:

| family / platform | access | encoding |
| --- | --- | --- |
| hl-10210 hw.dll | `push offset loadname` | `68 imm32` (`insn_len 0x5`, `disp 0x1`) |
| hl-10210 hw.so | `mov edx, offset loadname` | `BA imm32` (non-PIC absolute) |
| svencoop-10257 hw.dll | `push offset loadname` | `68 imm32` |
| svencoop-10257 hw.so | `lea eax, (loadname - GOT)[ebx]` | PIC GOTOFF, resolved through `gv_pic_addend` |

## Pitfalls

- **Do not port MetaHookSv's locator literally.** `Engine_FillAddress_Mod_LoadModel` accepts
  only `X86_INS_PUSH` in a `+0x50` window after the `"loading %s\n"` printf, which covers the
  MSVC `push offset` form alone. It misses the ELF `mov reg, offset` form and the SvEngine
  Linux PIC `lea reg, [ebx + disp]` form, so it is not a cross-platform anchor.
- On hl-10210 `hw.so` the format string is reached as `aFailedLoadingS+7` (the tail of
  `"Failed loading %s\n"`), so an exact search for the literal `"loading %s\n"` finds nothing
  in that binary. Semantic matching against the annotated body is what keeps this finder
  working there.
- The body references this one address from two same-shaped sites: the `COM_FileBase` output
  push and the brush-path `DT_LoadDetailMapFile(loadname)` push. The model may pick either on
  a given run, so `gv_inst_offset` can drift; both sites resolve to the same `gv_va`, so the
  artifact stays correct. Do not "stabilize" it by pinning a fixed offset.
- In hl-10210 the emitted `loadname` and `loadmodel` addresses are `0x20` apart, so the real
  array extent is 32 bytes there even though MetaHookSv declares `char (*loadname)[64]`.
  Consumers must use the recorded address, never an assumed element size.
- Blob engines (hl-3248..hl-3647) run against `hw.decrypt.dll`; the artifact VA is resolved
  in that IDB, so downstream matching is on `gv_va`/`gv_sig`, never on an IDA display name.
