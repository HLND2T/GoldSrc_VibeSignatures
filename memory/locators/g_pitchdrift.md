---
title: g_pitchdrift locator
type: note
permalink: goldsrc-vibesignatures/locators/g-pitchdrift
tags:
  - locator
  - client
  - gv
---

# g_pitchdrift

## Symbol

- **Name**: `g_pitchdrift`
- **Category**: `gv`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-V_StartPitchDrift-decompiles.py`

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. SvEngine-only.

## Predecessors

- `V_StartPitchDrift.{platform}.yaml` (produced by `find-V_StartPitchDrift`, consumed via
  `expected_input`, `dependency_policy: required`).

## How it is located

1. `_prepare_llm_context` resolves the predecessor reference YAML
   `references/svencoop-10257/client/V_StartPitchDrift.{platform}.yaml`; exactly one target
   is required or the finder returns False.
2. `_export_llm_function` dumps the current target, and `_build_target_disasm_index` parses
   it. The finder then requires **exactly one** scalar-float global MOVSS store matching
   `_PITCHVEL_STORE_RE`:
   `movss [dword ptr] [ds:]<global_label|(<global_label> - <disp>)[regindex]], xmmN`.
   The global label deliberately excludes `xmm0`-`xmm7` so a register operand cannot be
   mistaken for a symbol. Zero or more than one matching store fails with
   `PitchDrift: expected one scalar-float global store in V_StartPitchDrift`.
3. That single instruction becomes an `instruction_rule` on the dedicated prompt
   `prompt/call_llm_pitchdrift.md`, which maps the source operation
   `g_pitchdrift.pitchvel = v_centerspeed->value` to the target. The `pitchvel` member is at
   offset zero and identifies the whole object's base.
4. Emits a GV YAML with `gv_sig_allow_across_function_boundary:true`.

## Pitfalls

- **Store-only anchor.** Loads are excluded even when they resolve to `pitchvel`, because a
  load anchor is not stable across builds. Stack transfers and the `v_centerspeed` pointer
  are also rejected. Ambiguous or unsupported store shapes stop the preprocessor.
- Windows previously produced the `laststop` base (`base+0x10`) and Linux produced
  `laststop` (`base+0x0c`); the store rule fixed both. Regenerated Windows base is
  `0x10645aa0` (store anchor offset `0x5a`); Linux base is `0xaa4680` (store offset `0x61`,
  preserved PIC addend). These addresses are evidence only.
- The LLM must reject `laststop`/`nodrift`/`driftmove` members and all loads including the
  `pitchvel` load, and must not copy reference addresses, registers or anonymous names.
- Because the prompt is dedicated, `analysis_sources.py` binds it only to this node type —
  do not widen it to every LLM consumer.
