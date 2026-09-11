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
- Deferred: size_of_frame is an immediate scalar stride, not a GV pointer. Its proposed category/schema extension requires separate user approval (Issue #106 comment 5625307789); it is not implemented by this delivery.
- Trigger: exact cached_bonename xrefs find MergeBones but miss SaveBones. Root cause: optimized SaveBones references the first name's trailing byte at base+31. Correct approach: intersect cached_numbones owners with references into the first 32-byte name, exclude verified merge/top-level/setup/attachment roles, and require one candidate. Validate all engine peers and require SaveBones, MergeBones and SetupBones to remain distinct.
- Trigger: a verified exclusion disappears during owner recovery. Root cause: nearby direct-call candidates confuse backtracking. Honor exact executable function starts supplied by current validated dependency artifacts; do not infer an alternative exclusion entry. Covered by a synthetic regression.
- Trigger: Linux GV access has no IDA data xref. Root cause: a compiler reuses an address register across basic blocks. Resolve unindexed disp32 MOV/LEA only when every reachable predecessor has the same known definition; invalidate clobbers (including AH/BH aliases), reject loops/ambiguity, and preserve existing gv_pic_addend metadata. Verify relocation behavior with synthetic tests and current binaries.
- Trigger: IDA returns type/member IDs or offset-expression base refs as data candidates. Filter unmapped synthetic IDs, prefer actual encoded absolute operands when appropriate, and preserve genuine PIC/multiple-address ambiguity.
- Trigger: centerview has no full Strings entry. Root cause: suffix pooling inside force_centerview. Recover exact NUL-terminated suffix registration uses; similarly handle PIC LEA and cdecl MOV argument setup, not only PUSH forms.
- Trigger: public callbacks or StudioDrawPlayer are wrappers. Follow semantic direct forwarding or the unique external tail jump, permitting verified GCC PC thunks; never use address adjacency.
- Validation: staged artifacts must exist in Git's index before repository-contract checks because the inventory gate explicitly checks tracked files. Unit default-value tests must clear inherited GSVIBE_ANALYSIS_MAX_CONCURRENCY/MAX_MEMORY_MIB overrides. The implementation uses a forced batch selection so existing outputs cannot silently skip discovery.

## Callers

- Production configs invoke these finders through ida_analyze_bin's dependency DAG.
