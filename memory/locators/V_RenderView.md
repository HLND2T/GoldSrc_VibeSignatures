---
title: V_RenderView locator
type: note
permalink: goldsrc-vibesignatures/locators/v-renderview
tags:
  - locator
  - engine
  - func
---

# V_RenderView

## Symbol

- **Name**: `V_RenderView`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-VGui_ViewportPaintBackground-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed; it is a real, separate callee of the viewport callback. hl-10210 Windows body is 0x8B9 bytes.

## Predecessors

- `VGui_ViewportPaintBackground` (produced by `find-VGui_ViewportPaintBackground`, consumed via `expected_input` and `dependency_policy: required`).

## How it is located

1. Requires the current `VGui_ViewportPaintBackground.{platform}.yaml`; returns `False` without it.
2. `LLM_DECOMPILE` spec: symbol `V_RenderView`, prompt `prompt/call_llm_decompile.md`, expected section **`found_call`**, reference `references/{gamever}/engine/VGui_ViewportPaintBackground.{platform}.yaml`.
3. Semantic intent of the reference: `V_RenderView` is the direct call made between the viewport's refdef calculation and `GL_Set2D`. The LLM returns that `call`; shared validation resolves it against the current target and retries on mismatch.
4. Emitted fields: `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig` (no `allow_across_function_boundary`).

## Pitfalls

- `found_call` supplies a *callee*; the artifact is a function, so validation must reject a call site address and the response must be the callee entry.
- The intended call sits in the middle of a long viewport callback (hl-10210: 0x199 bytes) — the reference annotation, not proximity, is what selects it.
- SvEngine has a distinct `R_RenderView`/`R_RenderView_SvEngine(int viewIdx)` entry; this finder is about the HL-family `V_RenderView` reached from `VGui_ViewportPaintBackground`, and the Sven sequence here is `VGui_ViewportPaintBackground`'s own call. Do not substitute the Sven `R_RenderView` artifact for it.
- No `allow_across_function_boundary` fallback is declared, so a non-unique signature here is a hard failure rather than a widened one.

## Engine private globals (issue #208)

- Producer: `ida_preprocessor_scripts/find-V_RenderView-decompiles.py`; one grouped `found_gv` request consumes the current `V_RenderView` artifact. `old_yaml_map=None` prevents prior signatures from becoming discovery anchors.
- Logical config IDs `cls_state` / `cls_signon` emit `gv_name: cls.state` / `cls.signon`: addresses of members of the real ELF object `cls`. Neither is a separate ELF object. The rendering gates compare state with `ca_active` and signon with `SIGNONS`.
- `r_soundOrigin` receives `r_origin`; `r_playerViewportAngles` receives `ref_params.viewangles`, both under `!onlyClientDraw`. Only element zero accesses identify the vector base. References explicitly exclude component +4/+8 accesses. Linux retained object symbols independently validate vector identity.
- Coverage verified: HL3248/3266/3329/3647/4554/6153/8684/10210, COF5936, Sven8948/10257; 11 Windows and 4 Linux nodes, 60 artifacts. BLOB analysis uses existing decrypted PE peers. Reference families are HL10210 and Sven10257, each with Windows/Linux references generated through `generate_reference_yaml.py`.

### Lesson: ELF comparison constants are not global addresses

- Trigger: a successful LLM GV run returned addresses 5 and 2 for Sven Linux rendering gates.
- Root cause: ELF maps the header at address zero, so the inspector treated small comparison immediates as mapped pointer candidates. A `cmp [reg], imm8` also has no four-byte encoded address field; reading four bytes at its immediate crossed the instruction boundary.
- Correct approach: accept address immediates for MOV/PUSH, and for ADD-to-register only when a complete imm32 has a current IDA xref to a mapped non-executable data range. Keep an explicitly empty address-operand list authoritative; never blindly fall back to all encoded operands. Decode register-relative CMP memory operands, resolve the base with CFG reaching-definition agreement, and reject unknown/clobbered bases. For a zero-displacement comparison, use the proven local address definition as the emitted runtime operand. Preserve current-binary PIC addends; never interpret a GOT slot as the requested member or copy a peer's layout.
- Verification: synthetic tests cover imm8/imm32 comparisons with mapped scalar values, operand width, copies/clobbers, separate MCP execution namespaces, and emission through the reaching definition. All 15 real binary nodes succeeded; independently checked all 60 addresses and unique signatures, including ELF REL relocation and runtime operand arithmetic.
- Scope: x86 ELF GV instruction validation in `ida_analyze_util.py`; unsupported indexed/short-displacement forms fail closed.

### Follow-up regression: preserve ADD global-base operands

- Trigger: PR #216 CI failed in `find-R_DrawSequentialPoly-private-decompiles` on five legacy HL binaries after emitting only `lightmap_textures`.
- Root cause: the new address-operand list is always present, so an empty list does not use the legacy-key fallback. Restricting its immediate classification to MOV/PUSH excluded legitimate `ADD reg, offset global` array-base materialization; the first such target aborted the multi-target finder. Missing Agent fallback was a secondary failure, not the cause.
- Correct approach: classify evidence-backed ADD imm32 operands consistently in both candidate addresses and encoded address offsets. Require a register destination, a complete four-byte immediate, and an exact IDA data xref into a non-executable mapped range. Preserve scalar/CMP/short-operand rejection and the meaning of an explicit empty list.
- Verification: regression tests execute the actual MCP inspection code with separate namespaces and run GV emission for both ADD encodings (operand offsets 1 and 2), plus scalar, missing-xref, code-address and comparison rejection. HL3248 live IDB confirms `add esi, offset unk_2C0FB60` and `add eax, offset unk_280FB40` recover the existing globals.
- Scope: shared x86 GV immediate classification. Shared-helper changes require consumer regression coverage beyond only the newly added finder; the failing CI plan selected 3179 nodes across 37 binary workers.

- Follow-up live regression: forced both `find-R_DrawSequentialPoly-private-decompiles` and `find-V_RenderView-decompiles` across all 15 engine binaries in an isolated artifact directory. All 30 nodes succeeded; all 135 GV identities/VAs/RVAs match the committed baseline. Full suite: 1078 tests, OK with 9 environment-dependent skips; format check passed.
