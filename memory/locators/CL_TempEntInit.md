---
title: CL_TempEntInit locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-tempentinit
tags:
  - locator
  - engine
  - func
---

# CL_TempEntInit

## Symbol

- **Name**: `CL_TempEntInit`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_InitTEnts-calls.py`

## Availability

- Declared in 8 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684. **Not** declared in hl-10210 or svencoop-10257.
- Platforms: Windows-only (`platform: windows` in hl-3248..hl-8684; cof-5936 is a Windows-only module).
- Inlined / absent: it exists as a standalone function on every config that declares it (CoF's out-of-line body is the shared Windows reference). On the canonical hl-10210 body the pool initialization is inlined into `CL_InitTEnts`, so hl-10210 deliberately does not register this skill and there is no `found_call` anchor to document.

## Predecessors

- `CL_InitTEnts` (produced by `find-CL_InitTEnts`, consumed via `expected_input` and declared in `dependency_policy` as `required`).

## How it is located

1. Requires the current `CL_InitTEnts.{platform}.yaml`; if it is missing the finder returns `False` (no fallback until then).
2. `LLM_DECOMPILE` spec: symbol `CL_TempEntInit`, prompt `prompt/call_llm_decompile.md`, expected section **`found_call`**, reference YAML `references/cof-5936/engine/CL_InitTEnts.{platform}.yaml`. The reference is the CoF out-of-line body, whose tail is `call CL_TempEntInit` with an annotation explaining that the call zeroes the complete 500-entry pool (3068 bytes each), links `next`, and resets the free/active list heads.
3. The LLM returns the `call` instruction; shared validation resolves it against the *current* target and retries on mismatch. No address is copied from the reference.
4. Emitted fields: `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`.

## Pitfalls

- The reference is a CoF artifact but the finder runs on all HL Windows engines — the reference carries *semantics* (which call is the pool initializer), never a call address.
- If a future build inlines the pool init here instead of calling out, this finder has no `found_call` to return; that build needs the `-decompiles` route (as hl-10210 already does).
- `cof-5936` registers this skill without a `platform:` gate, but the module is Windows-only, so the effective gating is Windows.
