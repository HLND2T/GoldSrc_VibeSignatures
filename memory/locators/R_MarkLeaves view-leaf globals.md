---
title: R_MarkLeaves view-leaf globals
type: note
permalink: goldsrc-vibesignatures/locators/r-mark-leaves-view-leaf-globals
---

# R_MarkLeaves view-leaf globals

## Overview

Issue #196 adds `r_viewleaf` and `r_oldviewleaf` as engine `gv` artifacts. Both are pointer storage objects, not leaf pointees or GOT entries. The names survive in HL 8684/10210 and Sven 8948 ELF symbols; stripped Sven 10257 has the equivalent current-binary dataflow.

## Responsibilities

- Reuse the existing `R_MarkLeaves` predecessor; do not add another function locator.
- Recover the current leaf load, old/current comparison, `r_oldviewleaf = r_viewleaf`, and `Mod_LeafPVS(r_viewleaf, cl.worldmodel)` argument together to distinguish the globals.
- Group both `found_gv` targets in one LLM request with `old_yaml_map=None`; shared x86 validation owns instruction/address resolution and unique output signatures.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-R_MarkLeaves-decompiles.py` — both globals.
- `ida_preprocessor_scripts/references/{hl-10210,svencoop-8948,svencoop-10257}/engine/R_MarkLeaves.{windows,linux}.yaml` — CLI-generated, annotated references.
- Eleven engine configs and thirty `bin_artifacts/*/engine/r_*viewleaf.*.yaml` outputs.
- `D:/HLND2T_official/engine/gl_rsurf.c:1827` — source behavior; `engine/gl_rmain.c:62` — global declarations. Source is semantic evidence, not an identical binary revision.

## Architecture

Existing render-scene/render-view discovery → current `R_MarkLeaves` artifact → grouped semantic GV mapping → checked current instruction → global artifact. The reference gamever is HL 10210; Sven references preserve its missing mirror guard and distinguish the 8948 GOT loads from 10257 PIC LEAs. No discovery address, byte signature, or adjacency assumption is hardcoded in the finder.

## Dependencies

- Existing `R_MarkLeaves.{platform}.yaml`, including the Sven Windows render-view predecessor when scene rendering is inlined.
- `preprocess_common_skill`, `found_gv`, and existing Linux PIC/GOT resolution.
- References generated using `generate_reference_yaml.py` after source-like IDB naming/prototype/local recovery through owned `IdaMcpLifecycle` sessions.

## Notes

### Coverage and evidence

Validated 15 inputs on 2026-09-22: Windows HL 3248/3266/3329/3647/4554/6153/8684/10210, CoF 5936, Sven 8948/10257; Linux HL 8684/10210 and Sven 8948/10257. Early BLOB builds use existing `hw.decrypt.dll`. The other seven versions have no configured Linux engine input. Both globals and a separate `R_MarkLeaves` body exist in all inspected inputs.

| Binary | r_viewleaf VA | r_oldviewleaf VA |
| --- | --- | --- |
| HL 3248 / 3266 Windows | 0x2c1f468 | 0x2c202e0 |
| HL 3329 Windows | 0x2bebd88 | 0x2becc00 |
| HL 3647 Windows | 0x2beac08 | 0x2beba80 |
| HL 4554 Windows | 0x2b94a08 | 0x2b95880 |
| HL 6153 Windows | 0x2bc55e8 | 0x2bc64a0 |
| HL 8684 Windows | 0x2bc8ae8 | 0x2bc99a0 |
| HL 8684 Linux | 0xf25298 | 0xf25810 |
| HL 10210 Windows | 0x10dc5568 | 0x10dc5564 |
| HL 10210 Linux | 0xf7d298 | 0xf7d7f0 |
| Sven 8948 Windows | 0x3f54014 | 0x3f54018 |
| Sven 8948 Linux | 0x30d6b84 | 0x30d6b80 |
| Sven 10257 Windows | 0x3f941e4 | 0x3f941e8 |
| Sven 10257 Linux | 0x30f6d24 | 0x30f6d20 |
| CoF 5936 Windows | 0x2c0d6e8 | 0x2c0e560 |

Addresses are evidence only; artifacts carry their own RVA/signature/operand metadata. Fifteen exact IDB identities and SHA-256 values were recorded during investigation; successful owned-session exits saved IDBs and released their ports. Production analyzer runs use strict restored/no-save lifecycles.

Validation: `uv run python ida_analyze_bin.py -allgamever -modules engine -skill find-R_MarkLeaves-decompiles -platform windows,linux -debug` succeeded with zero failed skills. An independent PE/ELF audit checked all 30 output addresses against the pre-implementation investigation, exact binary hashes, unique byte matches, instruction containment in the owner, operand resolution, and writable data storage. Formatting and `git diff --check` passed.

`tests/run_test_suite.py all -b --durations 30` ran 999 tests with six skips and one transient repository-contract error because CoF generation was still running. After all outputs existed and were Git-tracked, `repository-contract -b --durations 30` passed all 14 tests. Skips: three unavailable Redis integration groups, two opt-in CLI tests, one opt-in IDA integration test. Real finder validation above is independent of that opt-in test.

### ELF operand audit lesson

- Trigger: reading an absolute instruction operand from raw HL ELF bytes yields zero although the IDB resolves a named global.
- Constraint: `R_386_32` relocation adds the ELF symbol value at load time; disk bytes alone are not the loaded operand.
- Correct approach: apply the recorded ELF relocation before comparing the artifact resolution. Sven 8948 additionally resolves through GOT ownership; 10257 uses a PIC LEA. Preserve the existing generated `gv_pic_addend` metadata.
- Verification: reconstructed operands for all four Linux inputs resolve to the investigated global storage and signatures match uniquely.
- Scope: offline validation of ELF32 engine GV artifacts.
