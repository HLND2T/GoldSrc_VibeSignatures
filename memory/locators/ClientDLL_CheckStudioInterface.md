---
title: ClientDLL_CheckStudioInterface locator
type: note
permalink: goldsrc-vibesignatures/locators/clientdll-checkstudiointerface
tags:
  - locator
  - engine
  - func
---

# ClientDLL_CheckStudioInterface

## Symbol

- **Name**: `ClientDLL_CheckStudioInterface`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: none in this repo. There is no `find-*` script for this symbol; it is the
  **owning function** referenced by the MetaHook studio-interface transaction notes. It is
  documented here because it is the anchor owner of the whole studio-interface family, not
  because a finder emits an artifact for it.

## Availability

- Not declared in any config (no finder exists).
- Engine modules only.
- Inlined / absent: this is the critical fact. The standalone function frequently does **not
  exist** at runtime:
  - hl-10210 Windows `hw.dll`: no standalone entry — the whole check is inlined into
    `ClientDLL_HudInit` at `0x10196e50` (size `0xd2`).
  - hl-10210 Linux `hw.so`: a standalone `ClientDLL_CheckStudioInterface` at `0x1593f0`
    (size `0x6E`) exists (GCC out-of-line copy, DWARF-named), but `ClientDLL_HudInit` runs its
    own inlined copy and never calls it.
  - Older Windows builds (HudInit size `0x3F`) keep a real
    `call ClientDLL_CheckStudioInterface` inside `ClientDLL_HudInit`.
  - Sven Linux was not verified in this repo.

## Predecessors

- None documented. The function owns the `ClientDLL_CheckStudioInterface` diagnostic literal,
  so a locator would root on that literal plus the `cl_funcs.pStudioInterface` slot.

## How it is located

Source (`engine/cdll_int.c`):

```c
R_ResetStudio();
cl_funcs.pStudioInterface = (HUD_STUDIO_INTERFACE_FUNC)GetProcAddress(hClientDLL, "HUD_GetStudioModelInterface");
if ( cl_funcs.pStudioInterface ) {
    if ( cl_funcs.pStudioInterface(STUDIO_INTERFACE_VERSION, &pStudioAPI, &engine_studio_api) )
        return;
    Con_DPrintf("Couldn't get client .dll studio model rendering interface.  Version mismatch?\n");
    R_ResetSvBlending();
}
```

Recommended anchor approach:

1. Anchor the exact diagnostic literal (GoldSrc `client .dll` with two spaces after the
   period vs SvEngine `client library` with one). This is the same literal the
   `studioapi_SetupPlayerModel` / accessor finders already use.
2. Collect **all** code xrefs and resolve their owning function(s). On HL25 that owner is
   `ClientDLL_HudInit`, not a symbol named `ClientDLL_CheckStudioInterface`; on Linux there
   may be two owners.
3. Require the owner(s) to collapse onto one `engine_studio_api` table / one
   `cl_funcs.pStudioInterface` slot. Do not name a function after the literal's owner alone.
4. Prefer the call-site of `cl_funcs.pStudioInterface` as the interception point: the
   `mov reg,[slot]; test reg,reg; push ...; push 1; call reg` sequence survives even when the
   function is inlined.

## Pitfalls

- **Never treat this name as a stable hook entry.** On HL25 Windows there is no entry at all,
  and on HL25 Linux the surviving standalone symbol is a cold out-of-line copy the hot path
  does not call — hooking it would wrap a body that never runs and miss the real
  `pStudioInterface` call.
- Whole-function hooking would also wrap `R_ResetStudio`, `GetProcAddress`/`dlsym` and the
  failure-path print/reset, which are outside the transaction's intent.
- Do not hook by replacing the `cl_funcs.pStudioInterface` slot: the engine assigns it from
  `GetProcAddress` before calling, so a pre-installed wrapper is overwritten (hl-10210 even
  optimizes the assignment away, but other builds do not).
- `ClientDLL_HudInit` (the usual literal owner) cannot be assumed to stay standalone either:
  it has a single caller, is not exported, and LTO/LTCG could inline it into `CL_Init`; hooking
  it would also delay hooks registered by `HUD_Init`. The call site is the only cross-version
  stable interception surface.
- `fClientLoaded` guard, joystick cvar caching and the inlining are HL25-specific deviations
  from the public source; the binary is authoritative.
