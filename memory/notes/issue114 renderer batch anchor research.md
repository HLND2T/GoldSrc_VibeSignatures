---
title: issue114 renderer batch anchor research
type: note
permalink: goldsrc-vibesignatures/notes/issue114-renderer-batch-anchor-research
tags:
- issue114
- anchor-research
- BuildGammaTable
- CL_FxBlend
- ClientPortalManager
---

# Issue #114 anchor research (2026-09-14, pre-implementation)

Evidence gathered with owned IdaMcpLifecycle py_eval sessions; VA = IDB addresses of the exact `bin/` binaries.

## BuildGammaTable (engine func)

- Universal deterministic anchor: float constants **{1023.0, 0.075, 0.875}** (brightness-shift + pow-table divisors), unique function on every verified binary. Requires extending `_function_matches_float_filters` (ida_analyze_util py_eval template) to **x87 memory-float instructions** (fld/fmul/fdiv/fadd/fsub/fcom, width by dtype); current matcher is SSE-xmm-only and every target except hl-10210 W compiles BGT as x87.
- Verified unique hits: hl-10210 W 0x10230f90; hl-10210 L 0x169060 (symtab BuildGammaTable); hl-8684 W 0x1dc1770 (standalone; the "2.5"/"2.0" Cvar_DirectSet clamps live in caller V_CheckGamma 0x1dc1600, NOT in BGT); hl-8684 L 0x1bf660 (symtab); hl-6153 W 0x1dbf300; hl-4554 W 0x1dd8350; sven W 0x1dce3f0 (also sole owner of "2.5"/"2.0"/"gamma" strings); cof W 0x1e099b0 (sole owner of code-referenced "gamma" x2).
- hl-3248/3266/3329/3647: warm IDBs fail strict identity verification; rebuild+verify during implementation.
- **SvEngine Linux (hw.so): no sanctioned anchor.** Stripped symtab; PIC codegen hides .rodata float operands behind ebx/ebp-relative GOT offsets; "2.5"/"gamma" literals are GNU ld suffix merges inside "texgamma"/"lightgamma" (not string items; "2.5"@0x26F2F0 is undefined bytes, refs exist but no string item); every string route is >=2 LLM hops (Host_Init->V_Init->BGT). BGT there = sub_134640 (V_CheckGamma sub_134A50, V_Init sub_135F80).
- HL25/8684 Linux own full symtab (BuildGammaTable/V_CheckGamma/V_Init/CL_FxBlend/studioapi_StudioSetRenderamt named) — validation evidence only, discovery stays string/float based.

## CL_FxBlend (engine func)

- Chain: studio-interface diagnostic -> engine_studio_api table (existing `_studio_player_model_common`; handles SvEngine Linux PIC) -> fixed slot **0xAC** = studioapi_StudioSetRenderamt (52-byte body) -> its **sole direct E8** = CL_FxBlend. Emit `studioapi_StudioSetRenderamt` artifact then `CL_FxBlend` successor finder.
- Verified: hl-10210 W slot fn 0x101f3cc0 -> 0x101ad510 (IDA-named CL_FxBlend); hl-10210 L 0xc6e40 (symtab StudioSetRenderamt) -> 0x142f80 (symtab CL_FxBlend); hl-8684 W 0x1d88200 -> 0x1d267f0; hl-8684 L 0x129de0 -> 0x19abc0; sven W 0x1d92c40 -> 0x1d32a60; cof W 0x1dc3b2a -> 0x1d43296 (named); hl-6153 W, hl-4554 W OK (table code-ptr run = 46; sven = 47).
- Fallback for old builds if table <46 entries: LLM found_call from existing R_DrawTEntitiesOnList artifact (its reference YAML already annotates `call CL_FxBlend`).

## ClientPortalManager (svencoop-10257 client, W+L)

MetaHookSv's five-function layout is from an older build; 10257 differs:

| symbol | W (client.dll) | L (client.so) | anchor |
|---|---|---|---|
| RenderPortals | 0x1004E4F0 size 0xC3D (inlines DrawPortalSurface GL block; prologue matches MetaHookSv sig) | 0xfc2b4 size 0xFCB | FULLMATCH "Invalid GL_ACTIVE_TEXTURE, unable to reset. Portal not drawn.\n"; unique owner both; L ref `lea edx,[ebx-171A5Ch]` resolves via GOTOFF owner-recovery (GOT 0x61e000) |
| EnableClipPlane | 0x10050CB0 (owns "Too many clip planes", sole caller RenderPortals) | 0xfb97e | FULLMATCH "Error: Too many clip planes on portal! Maximum: 6 (Too many surfaces on brush?)\n"; L `lea edx,[ebp-171AB0h]` GOTOFF |
| ResetAll | 0x1004DCE0 (iterate mgr+140..144 destroying portals; called from 8 manager entries; matches MetaHookSv `C7 45 ?? FF FF FF FF A3 ... E8 ... 8B 0D` site in wrapper 0x1004AD40) | 0xf99a0 | 2-finder chain: "...Couldn't create invisible texture for portals.\n" -> CreateInvisiblePortalTextures (W 0x1004c900 / L 0xf70ce, unique owner) -> xref_funcs: unique caller = ResetAll (verified both platforms) |
| DrawPortalSurface | INLINED into RenderPortals (no glColorMask anywhere; GL block 0x1004EA40.. inside RenderPortals) | INLINED | not emitted |
| GetOriginalSurfaceTexture | no standalone function found | same | report not present |

Manager singleton: W dword_1063C800 (size 0x1EC), L dword_A9AAB8 (size 0x1E0); ctors W 0x1004D9B0 / L 0xF9C24; wrapper W 0x1004AD40 / L 0xFD280.

## Derived offsets (scalar contract: scalar_name + scalar_value, per platform)

- ClientPortal (size 0xD8=216, ctor W 0x10050860 authoritative): origin +0, angles +12, texture_id +204 (0xCC, glBindTexture evidence), width +208 (0xD0), height +212 (0xD4), mode +64 (0x40; passed to GetSettings/EnableClipPlane on both platforms; NOTE ctor shows an eh-vector at +0x28..+0x88 — dataflow recheck at implementation). **entity pointer: no such field in 10257 ctor/layout** (MetaHookSv +0x70 was build 8948/5.25 only) -> emit nothing, document N/A.
- Manager portal vector: **W begin +140 (0x8C) / end +144 (0x90); L begin +132 (0x84) / end +136 (0x88)** — GCC/MSVC layout differs; ctor + RenderPortals iteration evidence on both.

## Open items

- 4 stale engine IDBs (hl-3248/3266/3329/3647) block strict restore; rebuild needed before float-anchor/table-length verification.
- BuildGammaTable Sven Linux coverage decision (uncovered vs fragile 2-hop LLM) pending user confirmation.

## Implementation outcome (2026-09-14, PR round)

All shipped as finders + configs + artifacts:

- find-BuildGammaTable: `xref_floats ["1023.0","0.075","0.875"]` (sole positive source; machinery extended: x87 memory-float mnemonics + float-only positive gate in `_normalize_func_xref_specs`/`preprocess_func_xrefs_via_mcp`/template). 12 artifacts incl. old builds (3248=0x1dc8c20, 3266=0x1dc8c20, 3329=0x1dc83a0, 3647=0x1dc7510). SvEngine Linux excluded by design (platform: windows on sven registration).
- find-studioapi_StudioSetRenderamt (slot 0xAC, new SLOT_SHAPE_SKIP_GVS) + find-CL_FxBlend (sole-call walk; filters <=4-byte get_pc_thunk; GOTOFF float resolution via thunk+add anchor; validates the 363.0 pulse de-sync constant). 13 CL_FxBlend artifacts; SvEngine L CL_FxBlend=0x11fec0.
- Sven client 10257: RenderPortals W=0x1004E4F0/L=0xfc2b4, EnableClipPlane W=0x10050CB0/L=0xfb97e, CreateInvisiblePortalTextures (new intermediate) W=0x1004c900/L=0xf70ce, ResetAll via xref_funcs unique caller W=0x1004DCE0/L=0xf99a0. Linux string owners resolved by `_sven_client_pic_common` GOTOFF displacement scan (string item + GOT anchor + find_bytes of the 4-byte disp + decoded disp32 filter) because IDA creates no xref for those lea sites.
- find-ClientPortal-offsets-decompiles (deterministic walk + LLM found_scalar agreement, annotated svencoop-10257 references W+L): W vector 140/144 + texture id/w/h 204/208/212; L vector 132/136.

## Follow-up findings (not emitted this round)

- **Linux portal member layout diverges from Windows**: pseudocode shows L texture id at +196 (0xC4) vs W +204; the RenderPortals-L EnableClipPlane arg loads [portal?+0x48] vs W mode +0x40 — register provenance unresolved, verification failed closed. mode/texture offsets are windows-only scalars this round.
- origin/angles offsets: structurally invisible (origin=+0 has no displacement encoding; L ctor inlined into its factory). Needs a portal-constructor/factory artifact chain (W factory=0x1004CED0, ctor=0x10050860 writes +0/+0xC/+204/+208/+212) or an agreed pure-LLM contract change.
- ClientPortal_entity_offset: no entity pointer field in the 10257 ctor; MetaHookSv +0x70 was 5.25-only. Not emitted.
- generate_reference_yaml.py autostart cleanup previously raised `Token was created in a different Context` after writing the reference; confirmed and fixed as a lifecycle context ownership bug (see below), rather than an exception-transfer issue.
- py_eval direct delivery of the offsets walk failed with an empty payload while the same code exec'd inside a wrapper worked; the finder ships the json-embedded exec wrapper (also surfaces remote tracebacks).

## PR #119 review follow-up: operand width and offset provenance

- Trigger: synthetic behavior checks showed `fld qword [1023.0]` incorrectly matching `0.0`, and unrelated pushes satisfying the portal texture walk without any GL calls.
- Root cause: x87 pools were decoded as both f32/f64; the portal walk combined unrelated register displacements and accepted the first vector pair without proving its origin.
- Correct approach: read x87 pools at the decoded operand's actual 4/8-byte width. `_client_portal_offsets` consumes decoded byte offsets, roots the vector in the platform's `this` argument, and requires the empty-vector guard plus iterator dereference. For Windows textures, track each branch separately and require matching-object `glGenTextures` / `glBindTexture` / `glTexImage2D` arguments in ABI order; reject conflicting candidates, register clobbers, unsupported effects, and unbounded walks. Linux continues to emit only the vector pair.
- Verification: execute the production float helpers and portal dataflow on synthetic success/error fixtures, including alternate layouts, missing GL calls, swapped arguments, unrelated bases, partial/implicit register writes, and branch provenance. Real IDA reruns use a fresh `-artifactdir` so existing YAML cannot skip the finder; all 12 BuildGammaTable artifacts and all 7 portal scalars retain the committed payloads.
- MCP constraint: RenderPortals' decoded instruction payload exceeds the remote result limit. Embed the same tested Python helper alongside the IDA decoder inside the worker and return only the recovered offsets; do not transfer the full instruction list through `py_eval` results.
- Scope: shared x87 float filters and Sven 10257 portal scalar discovery; future unsupported compiler shapes fail closed instead of borrowing a known layout.

## PR #119 follow-up: reference lifecycle context ownership

- Trigger: reference YAML is written successfully, but automatic MCP shutdown raises a ContextVar token reset error. Also reproduced on Python 3.13, so this is not specific to Python 3.12.
- Root cause: separate `asyncio.to_thread` calls copy separate contexts for lifecycle entry and exit. `WorkerMcpClient` sets its token in the first context and cannot reset it in the second; reset failure precedes client transport/thread cleanup. Repeated startup cancellation could also abandon cleanup, and cleanup errors could mask the original body error.
- Correct approach: enter and exit through one dedicated `copy_context().run`, serially. Shield and drain each lifecycle operation through repeated cancellation, then propagate cancellation. Pass the original exception to exit and retain it if cleanup also fails, reporting the cleanup failure as a note where supported.
- Verification: real ContextVar test doubles cover success, body/startup/cleanup failures, combined body and cleanup failures, and repeated cancellation during startup or cleanup. All 35 reference tests pass on Python 3.12 and 3.13. A real Python 3.12 Sven client RenderPortals export writes its YAML to a temporary path, exits with status 0, and verifies every owned MCP client thread is closed.
- Scope: the synchronous lifecycle bridge in `generate_reference_yaml.py`; MCP SDK async transport ownership remains in its existing owner task. Sharing a Context is not a general replacement for same-task ownership of async transports.
