---
title: GL video private globals
type: note
permalink: goldsrc-vibesignatures/locators/gl-video-private-globals
tags:
- locator
- engine
- gv
---

# GL video private globals

## Overview

Issue #207 adds ten engine global/member locators by consuming existing GL_Init, GL_SetMode, GL_EndRendering and GL_SetModeLegacy artifacts. These are storage addresses, not runtime scalar values or code-operand-field addresses.

## Responsibilities

- GL_Init → gl_extensions, the string-pointer slot written with glGetString(GL_EXTENSIONS=0x1F03).
- GL_SetMode → s_bEnforceAspect, bDoMSAAFBO, bDoScaledFBO, s_bSupportsBlitTexturing, s_MSAAFBO and s_BackBufferFBO.
- GL_EndRendering → s_fXMouseAspectAdjustment and s_fYMouseAspectAdjustment.
- GL_SetModeLegacy → vid_d3d_value, the float value member of the legacy vid_d3d cvar.

## Involved Files & Symbols

- ida_preprocessor_scripts/find-GL_Init-decompiles.py
- ida_preprocessor_scripts/find-GL_SetMode-decompiles.py
- ida_preprocessor_scripts/find-GL_EndRendering-decompiles.py
- ida_preprocessor_scripts/find-GL_SetModeLegacy-decompiles.py
- ida_preprocessor_scripts/references/{hl-10210,svencoop-10257}/engine/GL_{Init,SetMode,EndRendering}.{windows,linux}.yaml
- ida_preprocessor_scripts/references/hl-4554/engine/GL_SetModeLegacy.windows.yaml
- configs/<gamever>.yaml and bin_artifacts/<gamever>/engine/<symbol>.<platform>.yaml
- Source evidence: D:/HLND2T_official/engine/gl_vidnt.c:178–189, 440–457, 549–558, 625–740 and 1117–1317; D:/MetaHookSv/Plugins/Renderer/gl_hooks.cpp:350–412 provides consumer clues, not portable byte anchors.

## Architecture

Existing deterministic function producers remain unchanged. Each new finder requires the current owner artifact and uses grouped LLM_DECOMPILE / found_gv with old_yaml_map=None. The shared x86 validator resolves the reported current instruction and generates the signature/operand metadata.

The six GL_SetMode targets share one request; the two GL_EndRendering targets share another. HL uses the hl-10210 canonical references; Sven 8948 uses the existing family fallback to svencoop-10257. The legacy group explicitly references hl-4554 because modern HL has no GL_SetModeLegacy body. No shared reference fallback or artifact schema change is needed.

## Dependencies

- [[GL_Init locator]], [[GL_SetMode locator]], [[GL_SetModeLegacy locator]], [[GL_EndRendering locator]].
- Existing preprocess_common_skill and Linux gv_pic_addend / relocation support.
- Reference functions reconstructed only from confirmed current-target names, prototypes and storage roles, then exported with generate_reference_yaml.py.
- HLND2T_official is a semantic source reference, not an exact revision match; SDL/WGL, Sven AA-mode selection and HL25 frame pacing remain binary-specific.

## Notes

### Coverage

- gl_extensions: all 15 engine module/platform inputs in the 11 engine configs.
- Eight FBO/aspect globals: hl-6153 Windows; hl-8684/10210 and svencoop-8948/10257 Windows/Linux, nine inputs each.
- vid_d3d_value: hl-3248/3266/3329/3647/4554 and cof-5936 Windows, six inputs. BLOB builds use the existing hw.decrypt.dll.
- Legacy GL_EndRendering bodies are short forwarding wrappers without the modern FBO/aspect path. Modern inputs lack the legacy vid_d3d cvar/D3D branch. Do not register unsupported targets.
- Nine names and object sizes were verified in raw HL 8684/10210 and Sven 8948 ELF symbol tables. Sven static names may be C++-mangled; canonical names are demangled. Sven 10257 is stripped, so equivalent current-binary dataflow supplies identity.

### Storage and semantic distinctions

- vid_d3d_value is not &vid_d3d. Across the six legacy inputs, its address is the verified cvar_t value field; the current cvar metadata has name "vid_d3d", initial string "0", and a 1.0f write in the fD3D branch. The observed offset is +12, but the finder selects the actual float access instead of hardcoding that offset. See [[scr_fov_value locator]].
- s_MSAAFBO and s_BackBufferFBO are complete 16-byte containers (four GLuint fields). Recover the base passed to GenFramebuffersEXT. Multisample renderbuffer attachments identify MSAA; a rectangle texture attachment identifies the scaled backbuffer. EndRendering resolves READ_FRAMEBUFFER from MSAA into DRAW_FRAMEBUFFER backbuffer, then reads backbuffer for presentation.
- -stretchaspect is also used by the startup-screen code for a local variable. Restrict the global mapping to the existing GL_SetMode owner.
- X/Y defaults of 1.0 are not sufficient identities. Correlate horizontal/pillarbox bounds with destination/source aspect for X, and vertical/letterbox bounds with source/destination aspect for Y.
- Sven uses SDL_GL_ExtensionSupported for blit support where HL uses string checks. Preserve PIC-derived effective storage addresses, never GOT slots or unrelocated displacement values.
- Existing Hex-Rays guesses can show an extra dereference for a simple global store. Machine instructions and recovered item types take precedence.

### Full-instruction rule validation

- Trigger: a new instruction_rules regex matches only push/mov/lea mnemonics, rejecting valid FBO argument preparation.
- Root constraint: both shared validation layers use regex fullmatch on the complete normalized instruction.
- Correct approach: use complete operand forms, following the existing R_SetupGL matrix-address rules; keep semantic restrictions in the annotated reference and rule text.
- Verification: exercise the production finder and independently compare object addresses, decoded instruction operands and unique signatures to the pre-implementation evidence. A mnemonic-only match is insufficient.
- Scope: instruction_rules in LLM-backed finders.

### Validation (2026-09-22)

- Final selected-node analyzer batch: 11 tags, 39 registered finder nodes, all 15 binary workers succeeded. The first attempt exposed the mnemonic-only fullmatch rule described above; the corrected batch completed with zero failed workers.
- Independent audit: 93/93 GV artifacts match the pre-implementation current-binary VA/RVA evidence and SHA-256. Each signature matches exactly once in mapped PE/ELF data; its offset selects an instruction inside the expected owner, the operand resolves to the expected writable storage, and ELF relocations / Sven PIC metadata are applied.
- Thirteen references were generated through the repository CLI after owned IDB reconstruction on HL 10210 Windows/Linux, Sven 10257 Windows/Linux and HL 4554 Windows. Reconstruction lifecycles saved on normal exit; analyzer consumers used restored_strict with save_on_success=False.
- `uv run python ida_analyze_bin.py -batch_selection .candidates/issue207/selection.json -batch_diagnostics .candidates/issue207/analysis-fixed -debug` — succeeded.
- `uv run python .candidates/issue207/audit_artifacts.py --require-all` — 93 checked, zero missing, zero errors.
- `uv run python tests/run_test_suite.py unit -b --durations 30` — 1054 tests, OK, five skips (three POSIX/Linux-only checks on Windows and two opt-in CLI tests).
- `uv run python tests/run_test_suite.py repository-contract -b --durations 30` — 14 tests, OK.
- `uv run python format_repo_files.py --check` and `git diff --cached --check` — passed. No tests freeze finder names, config contents or generated reference text.

## Callers

The analyzer DAG runs each group after its existing owner artifact is available. Runtime consumers resolve the global/member storage through the generated GV signature and displacement metadata.
