---
title: R_StudioDrawPlayerBody locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiodrawplayerbody
tags:
  - locator
  - engine
  - func
---

# R_StudioDrawPlayerBody

## Symbol

- **Name**: `R_StudioDrawPlayerBody`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioDrawPlayer-body.py`

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: not a source-level symbol — it is the *rendering body* that some ELF
  builds outline out of `R_StudioDrawPlayer`. On builds whose entry does not tail-jump
  anywhere, the artifact degenerates to the `R_StudioDrawPlayer` entry itself (see step 3).

## Predecessors

- `R_StudioDrawPlayer.{platform}.yaml` (produced by `find-R_StudioDrawPlayer` /
  `-svencoop`, consumed via `expected_input`); its `func_va` is the walk's start.

## How it is located

1. Load `R_StudioDrawPlayer.{platform}.yaml`; abort if absent. Start `target = func_va`
   of that entry.
2. Walk the *unique external tail jump* chain. For the current `target`: it must exist,
   its `start_ea` must equal `target`, and its segment must be executable. Scan every
   instruction of the function:
   - a `call` counts as a real call unless its operand is `o_near` and the callee is a
     **PC thunk** (exactly 2 instructions: `mov reg, [esp]` then `ret`/`retn`) — get-PC
     thunks are ignored;
   - a `jmp` with a non-`o_near` operand counts as a call; otherwise its destination is
     added to the jump set when a function exists whose start equals that destination and
     differs from the current `target`.
3. Decision: if there is any real call, or the jump set has more than one element, the
   walk stops and the *current* `target` is the body (`{pointer_size: 4, target: ...}`).
   Only when the function makes no real call and has exactly one external tail jump does
   the walk continue into that destination (guarded by a `seen` set; a cycle yields `{}`).
   So an entry that already contains the checked body is returned as-is.
4. Materialize through `_inspect_function_via_mcp` at the resolved `target`. If the strict
   signature is not unique, retry with `allow_across_function_boundary=True` and emit
   `func_sig_allow_across_function_boundary: true` (ELF builds may carry GNU align padding).

## Pitfalls

- Never infer the body by address adjacency or a byte pattern; only the unique external
  tail-jump chain is accepted. Multiple jumps or any real call ends the walk at the
  current entry.
- The PC-thunk exemption matters on ELF PIC prologues (`call __x86.get_pc_thunk.bx`): a
  naive "any call disqualifies" rule would stop on the prologue and return the entry.
- An empty result from the walk (cycle) fails the finder rather than falling back to the
  entry.
- The predecessor artifact is authoritative: a stale or missing `R_StudioDrawPlayer` YAML
  stops this finder instead of re-deriving the entry.

## Evidence

- Consumed as the LLM_DECOMPILE predecessor for `R_StudioMergeBones`
  (`references/{gamever}/engine/R_StudioDrawPlayerBody.{platform}.yaml`).
