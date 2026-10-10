---
title: cl_worldmodel locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-worldmodel
tags:
  - locator
  - engine
  - gv
---

# cl_worldmodel

## Symbol

- **Name**: `cl_worldmodel`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_NewMap-decompiles.py`
  (emits `r_worldentity`, `cl_worldmodel` and `GL_UnloadTextures` from one run)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: engine client global; always present. The *access form* differs
  (absolute operand on Windows, PIC/GOTOFF on SvEngine Linux).

## Predecessors

- `R_NewMap.{platform}.yaml` (produced by `find-R_NewMap` or, on svencoop-10257, by
  `find-CL_RegisterResources-decompiles`), consumed via `expected_input`; the LLM dependency
  policy marks it `"required"`.
- Reference disassembly: `references/{gamever}/engine/R_NewMap.{platform}.yaml`.

## How it is located

`-decompiles` (LLM) finder — no deterministic anchor of its own:

1. Load the required predecessor `R_NewMap.{platform}.yaml`, export that function from the
   current IDB, and prompt with `prompt/call_llm_decompile.md` and
   `expected_result_sections: ["found_gv"]` against the annotated reference.
2. The model picks the access that is `cl_worldmodel` inside the map-reset body; the shared
   consumer resolves it and re-validates instruction/operand evidence before emitting.
3. Emit the GV field set: `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`,
   `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp` (plus `gv_pic_addend` where PIC).

## Pitfalls

- `cl_worldmodel` has **multiple legitimate accesses** in the binary, and the same-target /
  different-anchor risk is real: selecting a different (also valid) access changes the
  emitted `gv_inst_offset`/signature anchor. Selection is therefore pinned to the verified
  R_NewMap reference rather than to a bare xref scan.
- Do not confuse the world *entity* (`r_worldentity`, cleared by the same body) with the
  world *model* pointer; both are recovered from R_NewMap in one run.
- Discovery never reuses this symbol's own pre-existing artifact (`old_yaml_map=None`); the
  consumed predecessor is the R_NewMap function artifact and it is `"required"`.
- Reference lookup falls back to the canonical gamever (`hl-10210`) when the per-gamever
  reference file is missing; reference addresses are evidence only, never selectors.
- On SvEngine Linux resolve the PIC addend (`gv_pic_addend`) instead of reading the embedded
  dword as an absolute VA.
- CoF (`cof-5936`) is Windows-only in this repo.

### Containing client-state base versus world-model field (PR #357, 2026-10-10)

- Trigger: run 38022306420 rebuilt the Sven Linux outputs as containing client-state bases (8948: 0x15ee8a0; 10257: 0x15d7d60), while committed values were only member displacements 0x600cec/0x601cec. Both are wrong world-model addresses.
- Root cause: requiring effective-address proof exposed an unsupported `neg eax` early in R_NewMap. It incorrectly invalidated the unrelated EBX PIC base, causing correct field reads to fail and LLM retries to select containing-object materialization.
- Correct approach: NEG invalidates only its explicit GPR destination; never promote a member displacement or containing object to the global field. Keep the real R_NewMap LLM semantic mapping and normal effective-address validation.
- Evidence: 8948 reads EBP from GOT slot 0x339ce0, pointee 0x15ee8a0, then reads `[ebp+0x600cec]` at 0x1c3826: true address 0x1bef58c. 10257 forms EBP as 0x15d7d60 via LEA, then reads `[ebp+0x601cec]` at 0x177916: true address 0x1bd9a4c. Both feed the cleared world entity's model member.
- Verification: NEG regression cases fail before the fix and pass afterward, including rejection when NEG writes the base itself. Both real Linux R_NewMap finders pass; independently scanning executable ELF bytes proves unique signatures and encoded operand plus generated PIC addend equals the actual field address.
- Scope: Sven Linux member-address outputs and shared x86 register-write semantics. The historical availability list above predates Sven 8948 coverage; current configs remain authoritative. Evidence addresses are not locators.
