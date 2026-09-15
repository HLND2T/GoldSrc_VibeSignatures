---
title: mod_known locator
type: note
permalink: goldsrc-vibesignatures/locators/mod-known
tags:
  - locator
  - engine
  - gv
---

# mod_known

## Symbol

- **Name**: `mod_known`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_FindName-decompiles.py`
  (emits `mod_known` and `mod_numknown` from one run)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: the file-scope known-model array; always present. The *access form*
  differs (absolute operand on Windows, PIC/GOTOFF on SvEngine Linux).

## Predecessors

- `Mod_FindName.{platform}.yaml` (produced by `find-Mod_FindName`), consumed via
  `expected_input`; the LLM dependency policy marks it `"required"`.
- Reference disassembly: `references/{gamever}/engine/Mod_FindName.{platform}.yaml`.

## How it is located

`-decompiles` (LLM) finder — no deterministic anchor of its own:

1. Load the required predecessor `Mod_FindName.{platform}.yaml`, export that function from
   the current IDB, and prompt with `prompt/call_llm_decompile.md` with
   `expected_result_sections: ["found_gv"]` against the annotated reference.
2. The model picks the global access that is `mod_known` (the model registry array traversed
   by the name lookup); the shared consumer resolves the operand and re-validates the live
   instruction/unique target before emitting the GV field set (`gv_name`, `gv_va`, `gv_rva`,
   `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`, plus
   `gv_pic_addend` where PIC).

## Pitfalls

- **Same-target / different-anchor risk**: the registry is traversed and referenced in
  multiple places, so a different (still valid) access changes the emitted anchor. Selection
  is pinned to the verified `Mod_FindName` body instead of a bare xref scan.
- `mod_known` (array) and `mod_numknown` (count) are emitted from one run and must remain
  distinct symbols; do not let one address stand in for the other.
- Discovery never reuses this symbol's own pre-existing artifact (`old_yaml_map=None`); the
  only consumed artifact is the required `Mod_FindName` predecessor.
- Reference lookup falls back to the canonical gamever (`hl-10210`) when the per-gamever
  reference file is missing; reference addresses are evidence only, never selectors.
- On SvEngine Linux resolve the PIC addend (`gv_pic_addend`) instead of reading the embedded
  dword as an absolute VA.
- CoF (`cof-5936`) is Windows-only in this repo.
