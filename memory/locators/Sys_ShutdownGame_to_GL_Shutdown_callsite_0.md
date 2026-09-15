---
title: Sys_ShutdownGame_to_GL_Shutdown_callsite_0 locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-shutdowngame-to-gl-shutdown-callsite-0
tags:
  - locator
  - engine
  - patch
---

# Sys_ShutdownGame_to_GL_Shutdown_callsite_0

## Symbol

- **Name**: `Sys_ShutdownGame_to_GL_Shutdown_callsite_0`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_ShutdownGame_to_GL_Shutdown_callsite_0.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: **Windows-gated in hl-10210 and svencoop-10257**, mirroring `GL_Shutdown`'s own gating (those tags produce no `GL_Shutdown.linux.yaml`); ungated elsewhere, so hl-8684 also produces a Linux artifact.
- Inlined / absent:
  - `svencoop-10257/linux`: the `Sys_Shutdown()` trace owner exists but the shutdown path never calls `GL_Shutdown` — the locator returns zero candidates and the skill fails closed. That is why the tag is Windows-gated.
  - The call itself is emitted three different ways (inlined, IDA tail chunk, or a separately outlined `Sys_Shutdown` body); the locator is deliberately independent of which one a build uses.

## Predecessors

- `Sys_ShutdownGame.{platform}.yaml` — the owner artifact (`find-Sys_ShutdownGame`); re-verified with `_inspect_function_via_mcp`.
- `GL_Shutdown.{platform}.yaml` — the callee identity (`find-GL_Shutdown`).

Both are declared as `expected_input`; a missing artifact fails the skill.

## How it is located

MetaHookSv redirects exactly this branch to its own `GL_Shutdown`, so the artifact is a patch whose signature starts at the call instruction.

Source is `Sys_ShutdownGame` → `TRACESHUTDOWN(Sys_Shutdown())` → `GL_Shutdown(*pmainwindow, maindc, baseRC)`. The compiler emits the last step differently per build, so the locator scans a small set rather than one body:

1. Load both predecessor artifacts and re-verify the owner's `func_va` in the live IDB; its `func_sig_allow_across_function_boundary` flag is forwarded to the inspection.
2. Build the scan set = the owner function plus every direct rel32 `call`/`jmp` target of the owner that is an exact function start (capped at 64).
3. Enumerate `idautils.FuncItems` of every scan-set function and keep direct `E8` calls whose rel32 target equals the callee EA. `FuncItems` is required because IDA attributes an outlined body as a tail chunk of the owner on some builds (hl-8684/hl-4554/hl-6153 Windows) — the chunk sits *below* the owner entry.
4. Exactly one callsite must survive; zero or more than one fails closed.
5. Signature generation: forward-only expansion from the call instruction (6..96 bytes, at most 64 instructions). The branch instruction itself is emitted verbatim (the repository's other callsite patches pin the rel32 too); later instructions wildcard relocatable operands and branch displacements. The first boundary yielding exactly one match wins.
6. The signature is re-checked with `_find_unique_bytes`; the returned EA must equal the site EA.
7. Emitted patch fields: `patch_name`, `patch_va`, `patch_rva`, `patch_sig`, `patch_sig_disp: 0`.

Observed call sites (regression evidence for the exact inputs only, never a locator):

| Tag / platform | scan owner | callsite |
| --- | --- | --- |
| hl-8684 windows | Sys_ShutdownGame (tail chunk) | `0x1dac10e` |
| hl-8684 linux | `_Z16Sys_ShutdownGamev` | `0x13a356` |
| hl-10210 windows | `sub_10220E20` | `0x10220ee6` |
| svencoop-10257 windows | `sub_1DBC990` | `0x1dbca5f` |
| cof-5936 windows | `sub_1DF42B1` (direct callee) | `0x1df42f2` |
| hl-4554 / hl-6153 windows | tail chunk | `0x1dc51fe` / `0x1da9efe` |
| hl-3248 / hl-3266 / hl-3329 / hl-3647 windows | `sub_1DBB200`-family | `0x1dbad09` / `0x1dbad09` / `0x1dba3e9` / `0x1db95c9` |

## Pitfalls

- **Do not compare the callsite address with the owner's entry address.** On hl-8684 Windows the call lives in the owner's tail chunk at `0x1dac10e`, below the owner entry `0x1dac5d0`. The shared `_func_to_func_callsites_common` helper's `patch_ea >= owner_ea` guard rejects that case, which is why this symbol has its own locator.
- The callee expansion is not optional: on cof-5936 Windows the whole call sits in `Sys_Shutdown` (`sub_1DF42B1`), a *direct callee* of `Sys_ShutdownGame`, so an owner-body-only walk finds nothing.
- The pmainwindow argument shape does **not** discriminate here. On hl-8684/hl-10210 Linux the separately emitted `Sys_Shutdown` also calls `GL_Shutdown` with the same three absolute globals and the same double dereference, so a shape filter matches both; the scan-set membership is what excludes it.
- A build that keeps `Sys_Shutdown` as a direct callee *and* keeps an inlined/duplicated call would yield two candidates; the skill fails closed rather than guessing.
