---
title: Renderer lightmap and decal private symbols
type: note
permalink: goldsrc-vibesignatures/locators/renderer-lightmap-and-decal-private-symbols
tags:
- locator
- engine
- renderer
- lightmap
- decal
---

# Renderer lightmap and decal private symbols

## Overview

Issue #156 adds engine-only locators for `R_TextureAnimation`, `R_RenderDynamicLightmaps`, `rtable`, `lightmap_textures`, `lightmap_rectchange`, `lightmaps`, `gDecalSurfs`, and `gDecalSurfCount`. The user approved the exact anchor plan, including duplicate literal storage and the HL25 Linux ELF-symbol exception, on 2026-09-19.

## Responsibilities

- Discover functions through approved strings/call references, and recover global storage through current-function LLM instruction mappings.
- Validate x86 instructions, decoded addresses and unique output signatures; old artifact signatures never discover these targets.
- Preserve retained ELF object identities after global discovery and reject disagreement between named object addresses and recovered operands.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-R_TextureAnimation.py` — exact broken-cycle diagnostic.
- `ida_preprocessor_scripts/find-R_TextureAnimation-decompiles.py` — local static random table.
- `ida_preprocessor_scripts/find-R_DrawSequentialPoly-private-decompiles.py` — five lightmap/decal globals sharing one reference context.
- `ida_preprocessor_scripts/find-R_RenderDynamicLightmaps.py` — actual call target, with HL25 Linux exact ELF STT_FUNC exception.
- `ida_preprocessor_scripts/renderer_elf_symbols.py` — bounded ELF32/I386 symbol parsing, exact function selection, object identity cross-check.
- `ida_preprocessor_scripts/references/{hl-10210,hl-8684,svencoop-10257}/engine/` — annotated predecessor references.
- `configs/<gamever>.yaml`, `bin_artifacts/<gamever>/engine/` — coverage and runtime deliverables.
- `tests/test_renderer_elf_symbols.py` — defined/duplicate/ambiguous symbols, local names, malformed tables and conflicting object addresses.
- Source evidence: `D:/HLND2T_official/engine/gl_rsurf.c` and MetaHookSv `Plugins/Renderer/gl_hooks.cpp`. The source is semantic evidence, not a byte-identical revision.

## Architecture

- `FULLMATCH:R_TextureAnimation: broken cycle` → exactly one owning function → `R_TextureAnimation`.
- `R_TextureAnimation` → zero check and 20×20 `RandomLong(0, 0x7FFF)` initialization, followed by texture-dependent table reads → whole `rtable` base.
- Existing `R_DrawSequentialPoly` artifact → `GL_Bind` indexed by surface lightmap number → `lightmap_textures`.
- Same predecessor → dirty rectangle used by `glTexSubImage2D` and reset after upload → `lightmap_rectchange`; upload pixel dataflow → whole `lightmaps` buffer.
- Same predecessor → store current surface into queue, increment index and check overflow → `gDecalSurfs` / `gDecalSurfCount`.
- Same predecessor → actual dynamic-lightmap update call → `R_RenderDynamicLightmaps`, except HL25 Linux where that behavior is inlined.

## Dependencies

- The existing `R_DrawSequentialPoly` producer and its validated predecessor chain are reused. The multi-owner `Too many decal surfaces!\n` diagnostic is corroborating behavior, not a standalone unique locator.
- `preprocess_common_skill(old_yaml_map=None)` and LLM `found_gv` / `found_call` validation. GV PIC/additional-offset metadata must survive output projection.
- Reference YAML is generated only with `generate_reference_yaml.py` after restoring relevant IDB names/prototypes; use [[idalib-mcp]] ownership and exact input identity checks.

## Notes

- Trigger: the old source resets `lightmap_rectchange` in `GL_BuildLightmaps`, but HL25 no longer does. Correct approach: recover the array from the surface renderer's upload/reset path. Verification: current Windows/Linux pseudocode and instruction operands. Scope: these renderer globals across engine families.
- Trigger: HL25 Linux has no call xrefs to the retained `R_RenderDynamicLightmaps` entry, while its behavior is inlined in `R_DrawSequentialPoly`. Correct approach: the explicitly approved exact ELF STT_FUNC name for this one branch, followed by normal function/signature validation. Never emit a fictional call or substitute `R_ReUploadLightmap`. Original investigated RVA: `0x180d70`, for SHA-256 `fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78` only; this address is evidence, not a locator.
- HL 8684 retains a real dynamic-lightmap call and has a dedicated two-platform surface-renderer reference. HL25 has a three-argument surface renderer; classic/Sven use the current two-argument ABI. Preserve compiler inlining and current layouts.
- Older Windows/BLOB/CoF images keep two copies of the broken-cycle literal. Approved uniqueness is one owning function after all xrefs are merged, not one string allocation.
- Recover whole array bases, not the end of the random-table initialization, a rectangle t/w/h member, or an interior lightmap row. If a retained ELF object exists at a different address, fail closed.
- Raw ELF local table names: `rtable.24952` (HL 8684), `rtable.26004` (HL 10210), `_ZZ18R_TextureAnimationP10msurface_sE6rtable` (Sven 8948). Sven 8948 decal names are `_ZL11gDecalSurfs` and `_ZL15gDecalSurfCount`; config/output filenames retain stable lookup names while payloads preserve these actual object identities. Sven 10257 is stripped and uses verified source-level identities.
- Target matrix: Windows for hl-3248/3266/3329/3647/4554/6153/8684/10210, svencoop-8948/10257 and cof-5936; Linux for hl-8684/10210 and svencoop-8948/10257. BLOB inputs are `hw.decrypt.dll`; no missing Linux binary is forced into coverage.

### Verified implementation pitfalls

- Trigger: HL25 Linux's first LLM-mapped rectangle operand referenced `.t`, yielding `lightmap_rectchange + 4` despite a unique valid signature. Root cause: signature uniqueness proves the instruction, not whole-object identity. Correct approach: constrain this target to the observed LEA/ADD base formation and retain the independent ELF object-address cross-check. Verification: current base LEA at `0x186c3f`, member-read rejection, and fresh cross-version analysis. Scope: indexed global arrays with member references.
- Trigger: a LEA/ADD prefix regex rejected every real instruction. Root cause: shared instruction rules use `fullmatch`, not `search`. Correct approach: match the entire disassembly including operands; do not silently relax the whole-array-base requirement. Verification: two real base-forming forms accepted and two rectangle member-read forms rejected. Scope: LLM instruction_rules.
- Trigger: the worker reported a path only on stdout. Root cause: `parse_mcp_result` consumes py_eval's last-expression result. Correct approach: return JSON as the last expression; read ELF bytes in the IDA process and return only selected symbol rows. Verification: the synthetic MCP last-expression test exercises the actual generated Python. Scope: local and remote workers without shared paths.
- Trigger: Sven 8948 Linux count stores after control-flow joins could not recover the PIC base, and retry corrections reintroduced disallowed rectangle stores. Correct approach: select the pre-enqueue MOV count load and the LEA/ADD rectangle base formation. Verification: rerun the grouped finder on every target, retaining ELF address cross-checks. Scope: decal count accesses in optimized PIC functions.
- ELF `st_value` is treated as RVA only after requiring ET_DYN and a zero minimum PT_LOAD virtual address. Unsupported ET_EXEC or nonzero link bases fail closed; tests cover both rather than applying a second image base.

### Validation
Validated on 2026-09-19:

- All four new finders completed fresh current-IDB analysis on all 15 applicable binaries. Final selected-node runs covered 62 nodes (60 new finder/platform nodes and the two existing HL 8684 reference consumers). After correcting instruction selection, the five-global finder was rerun successfully across all 15 binaries; Sven 8948 Linux's remaining dynamic-lightmap finder also succeeded. The final rerun had zero failed work items.
- All 120 target artifacts exist and carry generated signatures. Independent raw ELF checks matched 24 available target symbols (eight targets in each of HL 8684, HL 10210 and Sven 8948) to output RVAs; stripped Sven 10257 is validated through current disassembly/dataflow and signature checks instead.
- `uv run python tests/run_test_suite.py unit -b --durations 30`: 906 tests, OK (2 skipped). The seven ELF helper tests also passed after final helper edits.
- `uv run python tests/run_test_suite.py repository-contract -b --durations 30`: 14 tests, OK after adding the new artifacts to the Git index required by the tracked-inventory contract.
- `uv run python format_repo_files.py --check`, targeted `ruff check --ignore N999`, and `git diff --check`: passed. N999 is excluded for the repository's mandated `find-*.py` script names.
- Generated reference overrides were checked against exact owned IDBs. Existing HL 8684 Windows `GL_EnableMultitexture` and Linux `mtexenabled` consumers passed with the added surface-renderer references.
- No target in the available matrix remains uncovered. Missing platform binaries are not claimed as tested; BLOB artifact VAs were resolved in the decrypted-input IDBs.
## Callers

`R_DrawSequentialPoly` calls `R_RenderDynamicLightmaps` on the non-HL25-Linux branches; the HL25 Linux predecessor contains its inlined behavior. The standalone HL25 Linux entry remains in the ELF symbol table without IDA xrefs.
