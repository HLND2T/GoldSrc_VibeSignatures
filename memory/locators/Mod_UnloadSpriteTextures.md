---
title: Mod_UnloadSpriteTextures locator
type: note
permalink: goldsrc-vibesignatures/locators/mod-unloadspritetextures
tags:
  - locator
  - engine
  - func
---

# Mod_UnloadSpriteTextures

## Symbol

- **Name**: `Mod_UnloadSpriteTextures`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_UnloadSpriteTextures.py`

## Availability

- Declared in 8 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows-only (the finder node carries `platform: windows`). Not declared in hl-10210 and not declared in svencoop-10257.
- Inlined / absent: absent as a separately anchored symbol on HL25 and SvEngine — those builds inline `ClientDLL_Shutdown` into `ClientDLL_Init`, so the whole depth-two walk has no root and the skill is not registered there.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- `ClientDLL_Shutdown.{platform}.yaml` (produced by `find-ClientDLL_Shutdown`, consumed via `expected_input`).

## How it is located

Graph walk below the predecessor, not a string anchor and **no byte signature participates in discovery**:

1. Load `ClientDLL_Shutdown.{platform}.yaml` and take its `func_va`.
2. In one `py_eval`, collect the internal direct callees of `ClientDLL_Shutdown` (`call` whose operand resolves to a function start with size > 16).
3. For each such callee `x`, collect `x`'s own internal callees `y`; keep `y` only when `callers(y) == [x]` (unique caller), `fsize(y) >= 60` (`MIN_SIZE`) and `y` has `>= 2` internal callees (`MIN_CALLEES`).
4. The surviving candidate must be **unique** — otherwise the walk returns `error: Mod_UnloadSpriteTextures candidate is not unique` and the skill fails. This encodes the engine source shape: `SPR_Shutdown` (the only `ClientDLL_Shutdown` callee looping over the loaded HUD-sprite list) calls exactly one function that both unloads by sprite-texture name and calls the shared free helper.
5. `_inspect_function_via_mcp` emits `func_name / func_va / func_rva / func_size / func_sig`; if no unique in-function signature exists, it retries with `allow_across_function_boundary=True` and records `func_sig_allow_across_function_boundary: true`.

Note the ordering: the walk finds the function, the signature is generated afterwards. Discovery never depends on the old artifact.

## Pitfalls

- The uniqueness gate is the whole safety net. `MIN_SIZE = 60` and `MIN_CALLEES = 2` are tuned to the classic `engine/cl_draw.c` + `engine/gl_model.c` pair; loosening either reintroduces ambiguity, tightening either drops builds where the loop was inlined differently.
- The depth-two shape means a compiler that inlines `SPR_Shutdown` into `ClientDLL_Shutdown`, or the callee into `SPR_Shutdown`, removes the candidate entirely — this is exactly why HL25/SvEngine are not registered.
- `callers(y) == [x]` is computed from `CodeRefsTo`, so a build where the same function is also reached through a tail-jump or via an extra thunk will report two callers and fail closed.
- On failure the walk prints no diagnostic unless `debug=True`; a "candidate is not unique" result is indistinguishable from a missing predecessor in the default logs.
