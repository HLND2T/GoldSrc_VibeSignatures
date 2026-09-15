---
title: cl_sprite_shell locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-sprite-shell
tags:
  - locator
  - engine
  - gv
---

# cl_sprite_shell

## Symbol

- **Name**: `cl_sprite_shell`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_InitTEnts-studio-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux. This target is present on every engine platform *independently of whether `CL_TempEntInit` is inlined* — which is why it is a separate skill from the `gTempEnts` group (that group has different platform gating and uses its own initializer on the older Windows engines).
- Inlined / absent: none observed.

## Predecessors

- `CL_InitTEnts` (produced by `find-CL_InitTEnts`, consumed via `expected_input` and `dependency_policy: required`).

## How it is located

1. Requires the current `CL_InitTEnts.{platform}.yaml` and returns `False` without it.
2. `LLM_DECOMPILE` spec: symbol `cl_sprite_shell`, prompt `prompt/call_llm_decompile.md`, expected section `found_gv`, reference `references/{gamever}/engine/CL_InitTEnts.{platform}.yaml`.
3. In that reference the shell sprite is loaded as `cl_sprite_shell = sub_...("sprites/shellchrome.spr")` — the sprite/model assignment immediately before the pool initialization. The LLM returns that instruction; shared validation resolves it against the current target and retries on mismatch.
4. Emitted fields: `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`, plus `gv_sig_allow_across_function_boundary:true`.

Concrete anchor shapes from current artifacts (evidence only): hl-10210 Windows `gv_sig_va 0x101ada80`, offset `0x392`, length 6, disp 2; hl-10210 Linux `gv_sig_va 0x13bee0`, offset `0x45d`, length 6, disp 2. The Windows and Linux anchors sit 5 bytes apart (offset 0x38d vs 0x392) from the `gTempEnts` anchor in the *same* function — the two globals are adjacent stores in the precache tail, which is exactly what makes them confusable.

## Pitfalls

- `cl_sprite_shell` and `gTempEnts` are recovered from the *same* predecessor function and their anchor instructions are a few bytes apart. If a response is off by one store it may silently name the other global. The reference annotation must keep the shellchrome assignment and the pool init distinct, and the returned instruction text must name the shellchrome store.
- The shellchrome literal is also the string anchor of `find-CL_InitTEnts`, so the reference and the predecessor share one string — that is intended, not a leak of addresses.
- Downstream consumer `find-R_StudioRenderModel` lists `cl_sprite_shell` as an input, so an interior/adjacent wrong answer here propagates into the studio render chain.
- `gv_sig_allow_across_function_boundary:true` means the signature may legitimately extend past the function tail.
