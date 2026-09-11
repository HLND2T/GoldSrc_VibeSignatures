---
title: BulletPhysics private symbol locators
type: note
permalink: goldsrc-vibesignatures/bullet-physics-private-symbol-locators
---

# BulletPhysics private symbol locators

## Overview

Issue #106 adds source-backed x86 engine/client private-symbol discovery across HL, Sven Co-op, Cry of Fear and the Counter-Strike family. Production scope is declared in configs; generated signatures validate runtime resolution after discovery, never serve as discovery anchors.

## Responsibilities

- Recover deterministic roots from target-owned diagnostics, public API entries, exports or named callback registrations.
- Use annotated predecessor references and validated LLM instruction selections for private calls/globals without direct anchors.
- Preserve game-family and ABI boundaries; fail on ambiguity rather than copying another binary's addresses.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-client-studio-interface.py`: client Studio interface, renderer object and vtable.
- `ida_preprocessor_scripts/_client_registration_common.py`, `find-client-ScoreInfo-handler.py`: message/command cdecl argument recovery and ScoreInfo interface dispatch.
- `ida_preprocessor_scripts/_engine_public_callback_common.py`, `_svc_callback_common.py`: public callback and named svc table roots.
- `ida_preprocessor_scripts/find-R_StudioDrawPlayer-body.py`, `find-R_StudioDrawPlayerBody-decompiles.py`, `find-R_StudioMergeBones-decompiles.py`, `find-R_StudioSaveBones.py`: checked wrapper, weapon merge, cache and cache writer chain.
- `ida_preprocessor_scripts/find-CL_InitTEnts-studio-decompiles.py`, `find-R_StudioRenderModel.py`, `find-R_StudioRenderModel-decompiles.py`: shell sprite/chrome intersection and final render call.
- `ida_analyze_util.py`: x86 operand decoding, function entry validation and conservative CFG address recovery.

## Architecture

Engine strings establish R_NewMap, R_DrawTEntitiesOnList, CL_ReallocateDynamicData and model/cache owners. Studio API callbacks supply callable predecessors such as R_StudioCheckBBox; enginefuncs supplies CL_CreateVisibleEntity and VGui_ViewportPaintBackground. These public entries are anchors, not additional game-private targets.

The client HUD_GetStudioModelInterface export establishes the Studio interface and actual renderer vtable. DrawModel/DrawPlayer bodies establish semantic virtual slots; use 4-byte slots on both x86 ABIs, not one ABI's numeric index on the other.

ScoreInfo registration supplies a wrapper, which can dispatch through a different interface global from the null check. Resolve the actual call interface and constructor-assigned subobject vptr before naming the handler. The frags store at array offset zero identifies PlayerExtraInfo; actual CS/CZ stride is 0x74 and CZDS stride is 0x1c.

## Dependencies

- [[idalib-mcp]] owned lifecycles and exact binary identity checks.
- Official source under `D:/HLND2T_official`, especially `engine/r_studio.c`, `engine/r_trans.c`, `cl_dll/view.cpp`, `cl_dll/VGUI/counterstrikeviewport.cpp` and `common/ref_params.h`.
- Officially generated and annotated references under `ida_preprocessor_scripts/references`: canonical hl-10210, with source-body overrides for cof-5936, svencoop-10257, cstrike-10210 and czeror-10210.

## Notes
- CoF parsecount caveat: both sides of the frame-ring AND are memory-backed. The counter at 0x2e115a4 has parser writes; the mask at 0x1eae664 starts at 0x3f and supplies AND operations. A canonical HL reference alone allowed an LLM to choose the mask. Use the officially generated cof-5936 R_DrawTEntitiesOnList reference, which distinguishes the mutable counter load from CL_UPDATE_MASK. This is a real body difference, not a reason to copy fixed addresses into discovery.

- Trigger: LLM correctly returns a call but target text validation rejects it. Root cause: IDA can render `call target;comment` without whitespace before the semicolon; the old comment stripper required whitespace. Strip semicolons outside quoted literals consistently in target prompts and validation indexes. Preserve source annotations in references. A synthetic regression covers unspaced comments and a quoted `a;b` literal; the failing HL10210 Windows MergeBones locator then succeeds.
- Public callback forwarding must explicitly reject cycles, even if every node is an executable function entry. Synthetic two-node jump-cycle coverage verifies it never reaches signature generation.

- Boundary: allow_cheats, g_bRenderingPortals_SCClient, g_ViewEntityIndex_SCClient and g_pitchdrift are Sven-only; extra-info arrays are CS-family-only. CZDS has no CS/CZ prediction wrapper's inner _StudioDrawPlayer; do not manufacture an inner virtual there.
- ABI: Sven's existing R_RenderView reads an int argument on Windows (0x1d537b0) and Linux (0x13ba80). It is the entry called R_RenderView_SvEngine(int viewIdx) by MetaHook; no duplicate scanner is needed. Addresses are evidence only.
- size_of_frame uses the user-approved numeric scalar contract (Issue #106 comment 5636344998): only scalar_name and uint32 scalar_value. Consumers use the value directly for the matching binary identity. The original imm32-only proposal was superseded because HL-3248 pseudocode shows 17080 (0x42B8), while the machine code computes it with LEA/SHL/SUB. No signature or instruction-address fields are required.
- Trigger: exact cached_bonename xrefs find MergeBones but miss SaveBones. Root cause: optimized SaveBones references the first name's trailing byte at base+31. Correct approach: intersect cached_numbones owners with references into the first 32-byte name, exclude verified merge/top-level/setup/attachment roles, and require one candidate. Validate all engine peers and require SaveBones, MergeBones and SetupBones to remain distinct.
- Trigger: a verified exclusion disappears during owner recovery. Root cause: nearby direct-call candidates confuse backtracking. Honor exact executable function starts supplied by current validated dependency artifacts; do not infer an alternative exclusion entry. Covered by a synthetic regression.
- Trigger: Linux GV access has no IDA data xref. Root cause: a compiler reuses an address register across basic blocks. Resolve unindexed disp32 MOV/LEA only when every reachable predecessor has the same known definition; invalidate clobbers (including AH/BH aliases), reject loops/ambiguity, and preserve existing gv_pic_addend metadata. Verify relocation behavior with synthetic tests and current binaries.
- Trigger: IDA returns type/member IDs or offset-expression base refs as data candidates. Filter unmapped synthetic IDs, prefer actual encoded absolute operands when appropriate, and preserve genuine PIC/multiple-address ambiguity.
- Trigger: centerview has no full Strings entry. Root cause: suffix pooling inside force_centerview. Recover exact NUL-terminated suffix registration uses; similarly handle PIC LEA and cdecl MOV argument setup, not only PUSH forms.
- Trigger: public callbacks or StudioDrawPlayer are wrappers. Follow semantic direct forwarding or the unique external tail jump, permitting verified GCC PC thunks; never use address adjacency.
- Validation: staged artifacts must exist in Git's index before repository-contract checks because the inventory gate explicitly checks tracked files. Unit default-value tests must clear inherited GSVIBE_ANALYSIS_MAX_CONCURRENCY/MAX_MEMORY_MIB overrides. The implementation uses a forced batch selection so existing outputs cannot silently skip discovery.

### ScoreInfo candidate ambiguity (PR #108, 2026-09-11)

- Trigger: repeated isolated rebuilds change PlayerExtraInfo addresses even when the complete LLM prompt has the same SHA256. Runs `34569417228` and `34571300479` alternated between one frags store and all member accesses. Merely copying a successful rebuild into Git does not fix the producer.
- Root cause: the generic prompt requests every reference, while the finder needs only the zero-member frags store. Windows had no instruction rule. `ida_analyze_util._preprocess_llm_target` accepts the first resolvable entry, so teamnumber/deaths can become the alleged array base. Signature uniqueness proves runtime resolution, not semantic identity.
- Correct approach: `prompt/call_llm_scoreinfo.md` requests one frags store. `gamesymbol_snapshot_lib/analysis_sources.py` now resolves each declared prompt template against its node's game version, module and platform; transitive helper imports preserve shared ownership, while unrelated prompt files no longer acquire every LLM consumer. The previous whole-directory ownership expanded ScoreInfo CI to 397 nodes. The dedicated template remains in `prompt/`; no temporary prompt-file workaround remains. PR CI runs the trusted base planner, so a planner change in PR source takes effect in that trusted path only after it reaches the baseline. `_scoreinfo_dataflow.py` validates the current Windows handler's BEGIN_READ / player-byte / four-short protocol, tracks the first short and the player index through register copies and affine stride arithmetic, meets equal facts at control-flow merges, and rejects cycles, unsupported value flows and nonunique stores. It supplies a current-target instruction rule to the existing LLM retry and live instruction checks. Linux keeps its zero-member named frags rule. No reference address/register is copied and the LLM remains the symbol-mapping step.
- Validation: synthetic wrong-first/correct-first multi-candidate responses must retry; clobbers, partial registers, biased indexes, alternate paths, loops and two stores fail closed. Real isolated analysis of six Windows and two Linux nodes completed successfully (8/8). All 134 materialized artifact bytes matched the repository after correcting the additional CS/CZ 8684 Windows bases from `0x1a2f44a` to `0x1a2f420` (anchor offset `0x65` to `0x6d`). Scope: CS/CZ/CZDS ScoreInfo; stack-spilled field provenance and unknown compiler shapes are intentionally not inferred.

### ScoreInfo address-format retry failure (PR #108, 2026-09-11)

- Trigger: run `34575589896` failed during cstrike-8684 Linux ScoreInfo analysis, before artifact comparison. Two responses selected the correct frags store but wrote `000DDD8A` and `.text:000DDD8A`; the validator's matching-instruction index independently contained `0xDDD8A`. The third response exhausted output tokens, then fallback failed because this preprocessor-only node has no agent skill file.
- Root cause: the specialized prompt omitted the generic template's quoted `0x` address examples. The existing scalar parser rejects bare hex / IDA segment labels, but the correction only said instruction mismatch, leaving the model without the actual formatting repair.
- Correct approach: explicitly request quoted `0x` instruction addresses in the specialized template; distinguish unparseable instruction addresses from valid-address/text mismatches and explain the required format in retry feedback. Keep existing parsing and exact target instruction validation semantics.
- Validation: synthetic bare-hex and segment-prefixed responses reproduce missing corrective guidance before the fix and succeed after a corrected response. Full suite: 754 tests, 6 skipped. Real six Windows / two Linux ScoreInfo nodes: 8 successful, no failures; all 134 isolated YAMLs byte-identical to Git. The failed CI's 1,231 uploaded YAMLs also matched Git, but its partial analysis does not establish full CI success. Planner source changes triggered all 1,016 nodes; 93 reported failures include aborted downstream/unstarted nodes.

### Other LLM_DECOMPILE audit follow-up (not fixed by ScoreInfo)

- Sven `g_pitchdrift` follow-up is now fixed after run `34579771484` reproduced the audit finding: all 1,016 analysis nodes succeeded, then the Windows artifact changed from `laststop` (base+0x10) to the pitchvel base. Linux still consistently reproduced its incorrect `laststop` (base+0x0c) artifact. `find-V_StartPitchDrift-decompiles.py` now requires exactly one scalar-float global MOVSS store in the exported target and restricts LLM candidates to that instruction; `prompt/call_llm_pitchdrift.md` maps it to `pitchvel = v_centerspeed->value`. Loads are excluded even when they resolve to pitchvel, ensuring a stable anchor. Unsupported or ambiguous store shapes stop this preprocessor. Regenerated Windows base is `0x10645aa0` (store anchor offset `0x5a`); Linux base is `0xaa4680` (offset `0x61`, preserved PIC addend). Reference addresses are evidence only, never selectors. Regression tests reject member/load candidates in either response order and reject missing/multiple global stores. Full suite: 756 tests, 6 skipped. Two independent real Windows/Linux rebuilds succeeded (4/4 executions); all 1,371 materialized YAMLs matched the Git index after updating the two pitch-drift artifacts.
- Static different-target risks: `R_NewMap/r_worldentity` (whole-object memset vs model member), `CL_InitTEnts` and CoF `CL_TempEntInit/gTempEnts` (pool base vs interior members), CoF `R_DrawTEntitiesOnList/cl_parsecount` (counter MOV vs mask AND), and `CL_CreateVisibleEntity` (visible vs beam branch). These are candidate-selection risks, not newly observed failures.
- Same-target/different-anchor risks: `cl_worldmodel`, `cl_max_edicts`, `cl_entities`, `mod_known`, `mod_numknown`, `cached_numbones`, and Windows `videomode` have multiple legitimate accesses. A pure in-memory probe of the shared consumer confirmed list reversal changes the chosen GV anchor and can change its target.
- Non-GV risk: HL-family Linux client StudioRenderFinal's full entry and inlined hardware/software children are distinct vtable slots; accepting a mislabeled child found_vcall before a correct found_funcptr can produce the wrong function. Repeated direct calls to the same function generally produce identical function artifacts and are benign. No production structmember LLM specs were found.
- Shared-layer follow-up: resolve all candidates before selection; reject distinct semantic targets, fold equal targets and choose a stable anchor. This removes response-order dependence, but cannot fix an incomplete candidate set or a single semantically wrong result; local selectors remain necessary. Existing shared consumer behavior is unchanged by PR #108's ScoreInfo fix.

### Register-relative store addresses (PR #108)

- Trigger: investigating run `34584601153` exposed an independent Sven Linux `cl_viewentity` artifact error. The LLM correctly selected `mov ds:dword_601CE8[edx], eax`, but IDA's mapped data xref named the encoded displacement, not the effective address. The old artifact recorded `0x601ce8`; mapped-segment checks alone cannot distinguish it from a valid target.
- Root cause: the supplemental address-flow decoder only supported loads/LEA and skipped instructions with data xrefs. The GV consumer accepted the mapped displacement xref. This artifact error was not established as the CI timeout/fallback failure's trigger.
- Correct approach: for supported unindexed disp32 x86 MOV stores on Linux, resolve the base along all reachable predecessors and add the displacement modulo 32 bits, even when IDA supplies xrefs. Follow register copies, immediate arithmetic, decoded LEA operands and verified get-PC thunks; unknown/clobbered/ambiguous bases remain unresolved. MOVZX/MOVSX, XCHG and SETcc invalidate only registers they write. The resulting complete four-byte range must lie in a non-executable mapped segment. A proven target overrides displacement xrefs; failure never falls back to them. Windows indexed-absolute selection remains unchanged.
- LLM feedback: an asynchronous result validator feeds unresolved-base or invalid-effective-address details into the existing correction/retry loop. Ask for another actual instruction referencing the same global, retaining its original disassembly text. Known valid bases require no LLM correction. Exhausted retries retain the existing empty-result behavior.
- Evidence: current binary establishes EDX=`0x15d7d60`; the selected store accesses `0x15d7d60 + 0x601ce8 = 0x1bd9a48`. Regenerated `cl_viewentity.linux.yaml` records that VA/RVA and PIC addend `0x15d7d60`, preserving its signature and instruction anchor. Addresses are evidence, not selectors.
- Verification: mapped-displacement regressions failed before the fix. Tests cover relocated bases, clobbers, misleading LEA xrefs, invalid/partial/executable target ranges, CFG agreement, PIC arithmetic and LLM correction/exhaustion. Full suite: 762 tests, OK with 6 skips; formatting passed. Final isolated Sven Linux node succeeded in 25 seconds. Inspection of all five matching Sven engine store anchors corrected only cl_viewentity; the other four retained their addresses. All 1,340 available YAMLs in the isolated diagnostic artifact directory match the working tree after this correction; this is not a full CI rebuild.

## Callers

- Production configs invoke these finders through ida_analyze_bin's dependency DAG.

### Numeric scalar extraction (Issue #106)

- Trigger: a frame stride is visible as a constant in Hex-Rays, but has no single machine-code immediate. HL-3248 computes coefficients 9 → 72 → 71 → 213 → 427 → 2135 → 17080. Root constraint: compiler strength reduction changes encoding, not frame_t byte size.
- Correct approach: scalar_artifact.py owns the two-field uint32 contract, writer/normalizer and snapshot/store/JSON retain the value, and consumers do not scan or interpret expressions. Snapshot 8 / dataset 5 / analysis-output contract 3 carry the new category; index stays 4. Legacy snapshots cannot contain scalar fields and must be rebuilt through the current pipeline.
- Discovery: find-R_DrawTEntitiesOnList-decompiles.py groups cl_parsecount and size_of_frame under the same annotated predecessor. ida_scalar.recover_masked_index_stride independently traces the masked-index coefficient through register copies, IMUL, LEA, shifts and constant additions/subtractions to every StudioDrawPlayer argument. It also recognizes a slot-8 callback loaded into a register before CALL reg; INC/DEC of the independent entity index preserves its zero coefficient. The minimum-size filter is only a coarse exclusion, never the semantic locator.
- LLM contract: found_scalar contains scalar_name and scalar_value only. The finder supplies dynamically recovered expected_value; shared validation retries mismatches and rejects missing/conflicting values. Never hardcode a reference build's value. Pseudocode typed-element coefficients need byte-unit validation against actual arithmetic.
- Verification: synthetic regressions cover immediate and optimized forms, callback-register forwarding, partial/implicit register clobbers, unsupported control flow/arithmetic, conflicting or unverified paths, LLM value correction, strict uint32 validation, legacy rejection, and artifact → snapshot → SymbolStore → JSON round-trip. Real-target and final suite evidence belongs in the delivery PR.
- Scope: numeric scalar outputs and offline frame-stride verification. Other GV/function candidate-selection behavior remains unchanged.

### Sven Linux parsecount correction during scalar validation

- Trigger: the grouped size_of_frame/cl_parsecount finder rejected both real Sven Linux counter loads and accepted a PIC LEA naming the mask.
- Root cause: a Linux operand-shape rule incorrectly declared all register-relative member loads to be decoys. Current hw.so has CL_UPDATE_MASK at 0x2F1654, initialized to 63; cl.parsecount is at client base 0x15D7D60 + 0x242324 = 0x181A084. Loads 0x17E5D4 and 0x17E6DF feed the frame ring; parser store 0xFEEB5 independently confirms the mutable member. These addresses are evidence for this binary only.
- Correct approach: remove the spelling-based restriction, generate Sven Windows/Linux references through generate_reference_yaml.py, and let the existing shared CFG address resolver prove the member base and unique runtime signature. The user approved updating the existing Sven Linux artifact as part of issue #106.
- Verification: rerun all 13 engine combinations and compare all pre-existing outputs; only the corrected Sven Linux cl_parsecount output may change. The scalar verifier also decodes actual ESP operand displacements and accepts only the second call argument at [esp+4], irrespective of named stack variables or when flags were stored.
- Scope: semantic counter/mask distinction and register-relative global access; no new GV artifact contract or runtime expression evaluator.

### size_of_frame completion evidence

- Final current-binary grouped finder run: 13/13 targets succeeded across all 10 configured engine versions. The only pre-existing artifact change is the approved Sven Linux cl_parsecount correction; all other existing YAML bytes are unchanged.
- Values: configured HL-3248 through HL-8684 = 17080 (0x42B8), HL-10210 = 17176 (0x4318), CoF-5936 = 17088 (0x42C0), Sven-10257 = 34072 (0x8518). These are evidence, never cross-build fallbacks.
- Evidence: docs/size_of_frame-evidence.md contains original/analyzed SHA-256 values, two independent player-path traces per binary, root literal and predecessor signature counts, lifecycle policy, and exact verification commands.
- Gates: unit 766 tests (2 skips), repository-contract 14 tests, full Python 784 tests (6 skips), Pages 50 tests plus lint/build. All 10 real snapshots/datasets passed scalar store/JSON round trips (13 values) and the built Pages asset validator. Skips cover opt-in CLI/environment tests and unavailable Redis; real IDA analysis was executed separately.
