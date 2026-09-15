---
title: videomode locator
type: note
permalink: goldsrc-vibesignatures/locators/videomode
tags:
  - locator
  - engine
  - gv
---

# videomode

## Symbol

- **Name**: `videomode`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-VideoMode_Create-decompiles.py`

## Availability

- Declared in all 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate; Linux artifacts exist for hl-10210, hl-8684 and svencoop-10257).
- Inlined / absent: always present as a writable-data pointer global (`IVideoMode *videomode`, `engine/sys_getmodes.cpp`). Never inlined; only its access encoding changes.

## Predecessors

- `VideoMode_Create.{platform}.yaml` (produced by `find-VideoMode_Create`, consumed via `expected_input`; dependency policy `required` in the LLM context contract). Read from the current binary dir (`bin/<gamever>/engine/`).

## How it is located

This is a real LLM_DECOMPILE finder (`found_gv`, with the annotated predecessor as reference):

1. `_prepare_llm_dependency_contract` loads `references/{gamever}/engine/VideoMode_Create.{platform}.yaml` and requires exactly the four annotated keys (`func_name`, `func_va`, `disasm_code`, `procedure`); the current binary's `VideoMode_Create.{platform}.yaml` must exist and supply `func_va`.
2. The current `VideoMode_Create` is exported over MCP as target disassembly + pseudocode and handed to the model together with the annotated reference (which marks the store instruction with `target: videomode`). The model must return a `found_gv` entry whose `gv_name` is `videomode`.
3. The entry is validated: the instruction must belong to the exported target range(s), and on **Linux** `_validate_llm_global_addresses` additionally resolves the operand's relative-store address and rejects the entry when that address cannot be fully resolved (no GOT-only / ambiguous forms).
4. On acceptance: `gv_va` = the resolved global address, `gv_rva` = `gv_va - image_base`, `gv_sig` / `gv_sig_va` = the signature and entry of the containing function (`VideoMode_Create`), `gv_inst_offset` = `insn_va - func_va`, `gv_inst_length` = instruction size, `gv_inst_disp` = first non-zero operand offset.
5. `_gv_resolution_fields` may add `gv_pic_addend` (Linux PIC operand) or `gv_address_offset` (absolute operand that is not the object base); both are emitted verbatim by `preprocess_common_skill` because dropping them silently changes the resolved address.

## Pitfalls

- Windows `videomode` has **multiple legitimate accesses**, and a probe of the shared consumer confirmed that reversing the candidate list changes the chosen anchor and can change its resolved target. The LLM must pick the store inside `VideoMode_Create` (`mov videomode, esi` / `mov ds:videomode, eax` after the `CVideoMode_OpenGL` construction), not an unrelated read.
- The access encoding is not stable: hl-10210 Windows records `gv_inst_offset 0x179`, 6-byte instruction, `disp 2` (`mov videomode, esi`); hl-8684 Linux records `offset 0x101`, 5 bytes, `disp 1` (absolute `A1`-form store). Never hardcode the offset or the displacement.
- Preserve `gv_pic_addend` when present — the embedded dword of a PIC operand is not the absolute VA (same contract as the other engine GVs).
- The chain is only as good as the predecessor: if `VideoMode_Create.{platform}.yaml` is missing or its `func_va` does not match the current database, the LLM step never runs and nothing is emitted.
- `gv_sig_va` points at `VideoMode_Create`, so this GV inherits that symbol's availability (present on all 10 configs, both platforms).
