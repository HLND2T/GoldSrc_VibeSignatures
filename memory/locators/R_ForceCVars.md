---
title: R_ForceCVars locator
type: note
permalink: goldsrc-vibesignatures/locators/r-forcecvars
tags:
  - locator
  - engine
  - func
---

# R_ForceCVars

## Symbol

- **Name**: `R_ForceCVars`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_ForceCVars_R-AnimateLight.py`

## Availability

- Declared in 6 engine configs: cof-5936, hl-10210, hl-4554, hl-6153, hl-8684, svencoop-10257. Windows, plus Linux where `hw.so` ships (hl-8684, hl-10210; svencoop-10257 gates the Linux side away with `expected_output_windows`).
- **Not declared on hl-3248, hl-3266, hl-3329, hl-3647** and **on SvEngine Linux.** In both layouts the compiler inlines `R_ForceCVars` into the setup host so it has no standalone body; a symbol the build genuinely lacks is dropped from the config rather than published, matching the `DT_Initialize` precedent. The skill still runs there for the sibling `R_AnimateLight`.

## Predecessors

- `R_CheckVariables` (produced by `find-R_CheckVariables`, consumed via `expected_input`, field `func_va`).
- `Cvar_DirectSet` (produced by `find-Cvar_DirectSet`, consumed via `expected_input`, field `func_va`) — only to reject the inlined false positive.

## How it is located

1. Load the `R_CheckVariables` and `Cvar_DirectSet` artifact `func_va` values.
2. Require exactly one caller host of `R_CheckVariables` (`R_SetupFrame`, or `R_RenderScene` with `R_SetupFrame` inlined).
3. Build the host's internal direct-call sequence in address order, skipping `<= 16`-byte thunks and indirect calls.
4. Require exactly one `R_CheckVariables` call site. `R_ForceCVars` is the internal call **immediately before** it, subject to three gates:
   - if the `R_CheckVariables` call site is the host's *first* internal call (`i == 0`), `R_ForceCVars` is reported absent;
   - if the previous call site is more than `MAX_NEIGHBOR_GAP = 96` bytes earlier, it is likewise reported absent;
   - if the previous call's direct target **is `Cvar_DirectSet`**, `R_ForceCVars` is reported inlined/absent (the alias guard — see Pitfalls).
5. Otherwise record the previous call's direct target as `R_ForceCVars` and emit it; the same host also yields `R_AnimateLight` from the following call.

## Pitfalls

- **Alias false positive (fixed).** `R_ForceCVars( cl.maxclients > 1 )` sets a set of rendering cvars in a block that ends with a final `Cvar_DirectSet` call. When MSVC inlines `R_ForceCVars` into the setup host (hl-3248/3266/3329/3647), that final `Cvar_DirectSet` call lands directly before `R_CheckVariables`, so the "preceding call" heuristic picked `Cvar_DirectSet` itself for `R_ForceCVars` — publishing the same RVA for both symbols. Consumers hooking `R_ForceCVars` would then divert the global cvar setter into a wrong-signature replacement. The `prev_t == Cvar_DirectSet` guard rejects exactly this; the identity is read from the `Cvar_DirectSet` artifact rather than guessed.
- **Absent symbol handling.** The inlined layouts are resolved by *not declaring* `R_ForceCVars` in their config and not tracking an artifact, exactly as `DT_Initialize` is handled on the same four builds. Do not add a symbol-level optional/absent marker: the PR-validation "plan" job runs the **trusted base planner** (`base.sha`), so any new config-schema field cannot take effect in the very PR that introduces it, and a declared-but-missing artifact also fails `require_complete` inventory checks.
- The 16-byte thunk filter, the 96-byte gap, and the alias guard apply identically to both neighbours' selection; a change to one silently changes the other's result.
- Both symbols share one host and one walk — if the `R_CheckVariables` host is not unique, `R_AnimateLight` is lost (and `R_ForceCVars` where it is declared).
