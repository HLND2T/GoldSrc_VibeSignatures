---
title: 'Renderer draw symbol anchors (issue #120)'
type: note
permalink: goldsrc-vibesignatures/notes/renderer-draw-symbol-anchors-issue-120
tags:
- renderer
- anchors
- idapython
- svencoop
- goldsrc
- issue-120
---

# Renderer draw symbol anchors (issue #120)

## Trigger
Adding finders for the Renderer engine 2D/sprite draw symbols: `Draw_SpriteFrameHoles/Additive/Generic[_SvEngine]`, `Draw_Frame`, `Draw_Pic`, `D_FillRect`, `Draw_FillRGBA`, `Draw_FillRGBABlend`, `DT_Initialize`.

## Facts
- Literal families differ by engine:
  - HL/CoF (and HL25): `Client.dll SPR_DrawHoles error:  invalid frame\n`, `...SPR_DrawAdditive...`, `...SPR_DrawGeneric error: invalid frame\n`, `Draw_TransPic: bad coordinates`, `Downloading %s`.
  - SvEngine: `SPR_DrawHoles: Invalid frame %d\n` (and Additive/Generic variants); no `Draw_TransPic`/`Downloading %s` literal.
- HL25 Windows (hl-10210/hw.dll) is the outlier: it drops the `Draw_TransPic: bad coordinates` and `Downloading %s` literals (same build has them on Linux).
- `Draw_FillRGBA` / `Draw_FillRGBABlend` have no string and `Draw_FillRGBABlend` has no engine caller; the only deterministic anchor is `cl_enginefuncs` slot 11 / 130 (`cl_enginefunc_t` field order in `engine/APIProxy.h`). Validated across hl-10210/8684/4554/6153 and cof-5936: slot 11 body has `GL_SRC_ALPHA` (0x302) and not `GL_ONE_MINUS_SRC_ALPHA` (0x303); slot 130 has both.
- SvEngine has a **different `cl_enginefuncs` layout** (slot 11 is not a function start) — do not reuse the HL indices there.
- SvEngine Linux inlines the sprite-frame renderers into `SPR_Draw*` (the `SPR_Draw*` owners call `Draw_Frame` directly), so `Draw_SpriteFrame*_SvEngine` / `Draw_Frame` are Windows-only there.

## Root constraints / pitfalls
- Half the SPR_Draw* diagnostics and (on old builds) `Draw_TransPic` live in code IDA never promoted to a function. `ida_funcs.get_func` returns None; the repo's `_ensure_function_owner` also failed for the old-HL `Draw_TransPic` case. Recovery: use the **contiguous `is_code` run** around the xref (SvEngine units are padding-separated) or, when several un-promoted functions share one gap (old HL), the terminator-bounded basic block.
- `_inspect_function_via_mcp` auto-wildcards immediates, so two functions differing only by a GL enum (Linux `Draw_FillRGBA` vs `Draw_FillRGBABlend`, identical apart from `mov edx, 1` vs `mov edx, 303h`) produce **no unique `func_sig`**. Fallback: build the signature with immediates pinned and wildcard only relocatable operands; verify uniqueness with `ida_bytes.find_bytes(sig, ..., radix=16)` (string signature form, not raw data+mask).
- `ida_bytes.find_bytes` wildcard search returns BADADDR on the terminating probe; keep the last match in a separate variable when checking uniqueness.
- `ida_analyze_bin.py -allgamever -skill X` fails if X is not registered in **every** config with the matching module; register the finder in all targeted configs or validate per gamever.
- `-force_all` cannot be combined with `-skill`; delete the artifacts to force a re-run.

## Verification
- Per-gamever runs passed for hl-3248/3266/3329/3647/4554/6153/8684/10210 and cof-5936 (engine, windows+linux) and svencoop-10257; unit 812 OK; repository-contract 14 OK; format check clean. PR #121.

## Scope
GoldSrc x86 finders for the Renderer engine draw symbols; the same recovery/signature techniques apply to any near-identical or un-promoted GoldSrc function.
