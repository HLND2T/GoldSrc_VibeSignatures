---
title: Sven Co-op engine build_number differs between Windows and Linux
type: note
permalink: goldsrc-vibesignatures/notes/svencoop-engine-build-number-differs-between-windows-and-linux
tags:
- engine
- build_number
- svencoop
- pitfall
---

# Sven Co-op engine build_number differs between Windows and Linux

## Trigger

A `svencoop-<N>` tag implies the engine reports `N`, but a Linux `hw.so` reports a
different number — or someone needs the engine's own build number and assumes the tag
value applies to both platforms. Symptom looks like "wrong binary downloaded" or
"signature targets the wrong build"; instead it is expected behaviour.

## Root cause

`build_number()` (engine `hw.dll` / `hw.so`) is **not** a stored constant. It derives the
number from the compiler-baked `__DATE__` string of its own translation unit:

```
build = (int)((year - 1901) * 365.25)   // fmul 365.25
      + days_before_month               // month table [31,28,31,30,31,30,31,31,30,31,30]
      + day - 1
      + leap_adjust                     // +1 when year%4==0 and month >= March
      - 34995;                          // 0x88b3, fixed epoch offset
```

Month is found by `strncmp` of the first 3 chars against `Jan..Nov`; December falls out of
the loop with `days_before_month = 334`. Compiled Windows and Linux engines of the same
release are built on **different days**, so they report different numbers.

The repository's tag names track the **Windows** engine value.

## Observed values (verified on the shipped binaries)

| tag | `bin/<tag>/engine/hw.dll` `__DATE__` | Windows `build_number()` | `hw.so` `__DATE__` | Linux `build_number()` |
|---|---|---|---|---|
| `svencoop-8948` (5.25) | `Apr 24 2021` | **8948** | `Jun 12 2021` | **8997** |
| `svencoop-10257` (5.26) | `Nov 23 2024` | **10257** | `Dec  5 2024` | **10269** |

Both depots of a release are packaged on the release day (5.25: depot 225842 and 225843
manifests are both `09/11/2021`), while the embedded compile dates differ — 5.25 packaged
Windows built Apr 24 and Linux built Jun 12 2021.

Note `hw.dll` also contains a `Jun 12 2021` literal used by the *engine-version banner*
(`Engine version %s (%s)`), not by `build_number`; only the `__DATE__` reachable from
`build_number`'s own GOT slot counts.

## Correct approach

- Do not assume a `svencoop-<N>` tag equals the Linux engine's build number. Resolve
  `build_number()` per platform from its own `__DATE__`.
- To confirm empirically, read the value at runtime instead of trusting the tag: the Linux
  server log header is `Log file started (file "%s") (game "%s") (version "%i/%s/%d")` — the
  first field is `build_number()`; `SCR_DrawVersion` prints `%s %i/%s (build %d%s)`; the
  `sv_version` cvar is `"%s,%i,%i"`.
- A patch that forces a specific reported build number must target each platform's own
  constant/date, not a shared value.

## Verification

`hw.so` for both tags is unstripped: `.symtab` carries `_Z12build_numberv` (`build_number()`)
and `_ZZ12build_numbervE1b` (its function-local static cache `build_number()::b`). For
`svencoop-8948` the symbols resolve to `val=0xa5350 size=0x10b` in `.text` and `val=0x342004`
in `.bss` — matching the `[ebx+0x8004]` cache load at `ebx=0x33a000`.

Two independent locators agree on the same function and value: the structural signature
used by `find-build_number` (`57 56 53 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 83 EC ?? 8B B3 ...`)
and the unique `365.25` float constant referenced as `fmul dword ptr [ebx - X]`.

The formula was validated against three tag-anchored Windows binaries
(`hl-10210`→10210, `svencoop-10257`→10257, `svencoop-8948`→8948, all exact) and on the
Linux side via `hl-10210` `hw.so` (`Oct  8 2024` → 10211, one day after its Windows peer).

## Scope

All `svencoop-*` engine nodes; any GoldSrc engine build that computes its build number from
`__DATE__` (the `hl-*` / `cstrike-*` families use the same algorithm, so the same
platform divergence applies wherever Windows and Linux were compiled on different days).

## Resolved gap: `svencoop-8948` Linux PLT support
The former Windows-only limitation was removed during the 8948 port (2026-09-16), with explicit approval to change shared analysis infrastructure.

Root cause remains relevant: `_Z12build_numberv` is a preemptible GLOBAL symbol in this build. All fifteen calls use PLT `0x9ddf0` → GOT `0x33a368` → local implementation `0xa5350`; none call the implementation directly. The `SV_SendServerinfo` call site is `0x106e30`. 10257 instead has direct calls.

The shared resolver now follows verified GOT-indirect thunks: mapped pointer bytes must equal IDA's resolved target, which must be an executable function start. `find-build_number.py` enables `func_sig_resolve_jmp_thunk`; `ida_elf.py` also supplies canonical PLT targets and reverse call edges for structural locators. Unresolved external imports are not treated as local functions.

Verification: 8948 Linux emits `func_va=0xa5350`, `func_size=0x10b`. All 15 registered platform nodes across 11 tags were rerun successfully, with all 15 prior function addresses unchanged. The platform gate has been removed from `configs/svencoop-8948.yaml`.
## Verification commands
```powershell
uv run python ida_analyze_bin.py -gamever svencoop-8948 -node engine:linux:find-build_number -oldgamever none -debug
```

Check the resulting function address against `_Z12build_numberv` in `.symtab`, then follow that function's `__DATE__` pointer and apply the formula above. The Linux reported build remains 8997, despite the tag being 8948.
# Resolve build_number per platform and confirm the reported value.
# 1. Read .symtab for _Z12build_numberv (unstripped ELF) to get its func_va/size.
# 2. Locate the __DATE__ pointer its body loads (the GOT slot referenced near the
#    365.25 fmul) and read the literal bytes at that address.
# 3. Apply the formula above to the literal; it must reproduce the tag for hw.dll.
# Note hw.dll also contains a second __DATE__ literal used by the engine-version
# banner - only the one reachable from build_number counts.

# Confirm the Linux node is absent from the DAG for svencoop-8948 (CI-safety of the platform gate).
uv run python ida_analyze_bin.py -batch_selection <sel with engine:linux:find-build_number> \
  -validate_selection_only -artifactdir bin_artifacts
# -> "Unknown selected tag/node IDs", i.e. the node cannot be selected or run in CI.
```
