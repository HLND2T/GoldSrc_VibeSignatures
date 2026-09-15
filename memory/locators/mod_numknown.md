---
title: mod_numknown locator
type: note
permalink: goldsrc-vibesignatures/locators/mod-numknown
tags:
  - locator
  - engine
  - gv
---

# mod_numknown

## Symbol

- **Name**: `mod_numknown`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_FindName-decompiles.py`
  (emits `mod_known` and `mod_numknown` from one run)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: the known-model counter; always present. The *access form* differs
  (absolute operand on Windows, PIC/GOTOFF on SvEngine Linux).

## Predecessors

- `Mod_FindName.{platform}.yaml` (produced by `find-Mod_FindName`), consumed via
  `expected_input`; the LLM dependency policy marks it `"required"`.
- Reference disassembly: `references/{gamever}/engine/Mod_FindName.{platform}.yaml`.

## How it is located

`-decompiles` (LLM) finder — no deterministic anchor of its own:

1. Load the required predecessor `Mod_FindName.{platform}.yaml`, export that function from
   the current IDB, and prompt with `prompt/call_llm_decompile.md` with
   `expected_result_sections: ["found_gv"]` against the annotated reference.
2. The model picks the global access that is `mod_numknown` — the loop bound/count compared
   while scanning the known-model array — and the shared consumer resolves it, re-checking
   the live instruction and unique target before emitting the GV field set (`gv_name`,
   `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`,
   `gv_inst_disp`, plus `gv_pic_addend` where PIC).

## Pitfalls

- **Same-target / different-anchor risk**: the counter is compared and incremented in several
  places, so a different (still valid) access changes the emitted anchor. Selection is pinned
  to the verified `Mod_FindName` body, never a bare xref scan.
- The counter must not be confused with the array base (`mod_known`); both come from the same
  run and must stay distinct symbols.
- Discovery never reuses this symbol's own pre-existing artifact (`old_yaml_map=None`).
- Reference lookup falls back to the canonical gamever (`hl-10210`) when the per-gamever
  reference file is missing; reference addresses are evidence only, never selectors.
- On SvEngine Linux resolve the PIC addend (`gv_pic_addend`).
- CoF (`cof-5936`) is Windows-only in this repo.
