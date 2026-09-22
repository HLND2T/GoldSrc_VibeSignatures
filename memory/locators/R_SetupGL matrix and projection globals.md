---
title: R_SetupGL matrix and projection globals
type: note
permalink: goldsrc-vibesignatures/locators/r-setup-gl-matrix-and-projection-globals
---

# R_SetupGL matrix and projection globals

## Overview
Issue #202 adds engine matrix objects and SvEngine's projection-mode flag through the existing `R_SetupGL` predecessor. All locations are recovered from current-binary instructions via `LLM_DECOMPILE` / `found_gv`; old artifact signatures are not discovery anchors.

## Responsibilities
- `gProjectionMatrix`: `float[16]` output of `GetFloatv(GL_PROJECTION_MATRIX = 0xBA7)`.
- `r_world_matrix`: `float[16]` output of `GetFloatv(GL_MODELVIEW_MATRIX = 0xBA6)`.
- `gWorldToScreen`: projection/modelview product and `InvertMatrix` input.
- `gScreenToWorld`: output of that inverse operation.
- `gmodinfo_vertical_fov`: address of a four-byte boolean field in `gmodinfo`, not an independent ELF symbol or an angle. SvEngine only; its liblist `vertical_fov` assignment corroborates the projection-selection read.

## Involved Files & Symbols
- `ida_preprocessor_scripts/find-R_SetupGL-matrices-decompiles.py`: grouped four-matrix producer.
- `ida_preprocessor_scripts/find-R_SetupGL-svengine-decompiles.py`: SvEngine-only field producer, separated because applicability differs.
- `ida_preprocessor_scripts/references/{hl-10210,svencoop-8948,svencoop-10257}/engine/R_SetupGL.{windows,linux}.yaml`: generated after restoring matrix boundaries/types and verified callee prototypes, then annotated in both fields.
- `configs/hl-*.yaml`, `configs/cof-5936.yaml`, `configs/svencoop-*.yaml`: production inventory and dependency on `R_SetupGL`.
- `ida_analyze_util.py`: address propagation recognizes ADC and CVTTSS2SI as destination-only clobbers.
- `tests/test_ida_skill_preprocessor.py`: preservation of unrelated address registers and rejection of full/partial writes to the base register.

## Architecture
Existing `R_SetupGL` discovery → current function export → grouped semantic mapping → current x86 instruction/operand validation → unique runtime signature and GV YAML. No new `tri`/transform predecessor chain or fixed instruction window is needed.

## Dependencies
- Public-source role: `D:/HLND2T_official/engine/gl_rmain.c` and `engine/r_part.c`; binaries remain authoritative because HL25 and SvEngine differ in FOV math and vectorization.
- Matrix ELF names corroborated in HL 8684/10210 and Sven 8948. Sven 10257 lacks these private ELF names; its dataflow matches the same roles.
- Existing owned `IdaMcpLifecycle`; current repository consumer policy is strict restored/no explicit save.

## Notes
### Address-propagation lesson
- Trigger: Sven 8948 Linux `MOV EBP,[EAX+0x358C]` in `R_SetupGL` has no direct IDA data xref, although EAX is loaded from the `gmodinfo` GOT entry.
- Root cause: `ADC EDX,...` and the envmap path's `CVTTSS2SI ESI,...` fell into the unknown-instruction case and invalidated every register, losing the still-valid EBX/GOT base.
- Correct approach: invalidate only the destination register for these known instructions; do not calculate carry-dependent or floating-point conversion results. Writes to EBX or BL still invalidate the base; unrelated EDX/ESI writes preserve it.
- Verification: synthetic instruction-inspection tests failed for both preservation cases before the fix, then passed; real Sven 8948 Linux `R_SetupGL` field preprocessing succeeded using the ordinary validator.
- Scope: current x86 address propagation. Do not replace unknown-instruction fail-closed behavior with unconditional register preservation.

### Compatibility
- Matrices: 11 Windows and 4 Linux engine inputs across configured HL, Sven and CoF versions. Old BLOB builds use existing validated `hw.decrypt.dll` inputs.
- FOV field: Sven 8948/10257, Windows/Linux only. `gmodinfo + 0x358C` is observed evidence for those inputs, never a cross-version hardcoded locator.
- Sven Linux uses PIC/GOT. Preserve generated `gv_pic_addend` and select the actual field access, not the containing object or GOT slot.
- References retain compiler-inlined projection paths and source/version differences. Windows Sven 10257 passes a byte boolean to its projection helper, while the stored configuration field remains four bytes.

## Verification
Run both registered finders against their applicable game versions, then repository formatting and test suites. Independently compare output VA/RVA with investigation evidence and check raw-binary signature uniqueness plus the complete operand/addend resolution. Production coverage remains owned by configs, not this note.

### Matrix-base selection lesson
- Trigger: HL25 Linux semantic mapping selected a SIMD store to `gWorldToScreen + 0x10`; ordinary instruction and signature validation accepted a real mapped data address, but it was an interior row.
- Root constraint: matrix-element references do not identify the complete object's base merely because they mention the matrix name.
- Correct approach: require the address-preparation instruction feeding the corresponding `GetFloatv` or `InvertMatrix` argument. Accept absolute PUSH/MOV materialization and current PIC LEA forms, including IDA register aliases. Exclude element/vector loads/stores and explicit interior expressions. The anchor remains the existing `R_SetupGL`.
- Verification: current-binary evidence contains qualifying base-argument instructions for all 60 matrix targets across the 15 inputs. Independently compare every emitted address with the pre-implementation evidence. ELF `R_386_32` operands may be zero on disk: apply the real symbol relocation before comparing the runtime result.
- Scope: aggregate globals whose interior elements also have instruction references; no fixed argument ordinal or source-layout offset is used.

### Completed validation (2026-09-22)
- Forced exact selected-node batch: 11 tags, 15 binary work items, 19 finder nodes; every work item succeeded. The batch-selection path forces execution even when output YAML already exists.
- All 64 new GV artifacts independently matched pre-implementation VA/RVA evidence, unique raw-binary signatures, and operand resolution including actual ELF relocations/PIC addends.
- `uv run python format_repo_files.py --check`: exit 0.
- `uv run python tests/run_test_suite.py all -b --durations 30`: 1070 tests, OK (9 skips for POSIX/Linux-only cases, unavailable Redis, and opt-in CLI/IDA checks). Real IDA execution is covered separately by the selected-node batch above.
- The artifact-inventory contract checks Git-tracked paths as well as on-disk files; stage task-owned generated YAML before this final gate. Merely rerunning `-allgamever -skill` can skip existing outputs, so use the exact selected-node batch for forced revalidation.
