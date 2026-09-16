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

## Known gap: `svencoop-8948` Linux `build_number` is not registered

`find-build-number` is declared `platform: windows` for `svencoop-8948`, so only
`bin_artifacts/svencoop-8948/engine/build_number.windows.yaml` is produced. The Linux node
cannot be produced by the current finder and was deliberately left out rather than committed
as a broken declaration.

Root cause: in this build `_Z12build_numberv` is exported as a **preemptible GLOBAL** symbol
(present in `.dynsym`), so all fifteen call sites go through the ELF PLT stub at `0x9ddf0`
(`jmp dword ptr [ebx + 0x368]` → GOT slot `0x33a368`); the module contains **zero** direct
`call` instructions targeting `0xa5350`. `svencoop-10257` differs: its `build_number` is not
preemptible, has fifteen direct call sites, and therefore resolves normally.

The LLM step answers correctly (`insn_va 0x106E30`, `call __Z12build_numberv` in
`SV_SendServerinfo`), but `_inspect_llm_instruction` resolves the instruction target to the
16-byte PLT stub, and `_inspect_function_via_mcp` cannot turn that into a unique function, so
the node fails closed and falls back to a missing Agent skill (`agent_failed`).

Enabling `func_sig_resolve_jmp_thunk` does **not** fix this: `_RESOLVE_JMP_THUNK_PY_EVAL`
(`ida_analyze_util.py`) only follows `o_near` direct jumps and breaks on the PLT stub's
indirect operand type.

This cannot be worked around with `-oldgamever`: CI's analyzer step never passes it, and
`resolve_oldgamever` only accepts a **strictly older same-family** tag (`svencoop-8948` is the
oldest), so CI would hit the same failure.

Remediation (separate change, touches shared analysis infrastructure): extend
`_RESOLVE_JMP_THUNK_PY_EVAL` to follow GOT-indirect PLT jumps, enable
`func_sig_resolve_jmp_thunk` in `find-build-number`'s `GENERATE_YAML_DESIRED_FIELDS`, then
re-validate every registered `find-build-number` node (11 tags) so no committed artifact moves.

## Verification commands

```
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
