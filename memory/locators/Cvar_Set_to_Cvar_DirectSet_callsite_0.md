---
title: Cvar_Set_to_Cvar_DirectSet_callsite_0 locator
type: note
permalink: goldsrc-vibesignatures/locators/cvar-set-to-cvar-directset-callsite-0
tags:
  - locator
  - engine
  - patch
---

# Cvar_Set_to_Cvar_DirectSet_callsite_0

## Symbol

- **Name**: `Cvar_Set_to_Cvar_DirectSet_callsite_0`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Cvar_Set_to_Cvar_DirectSet_callsites.py`

Name pattern: `Cvar_Set_to_Cvar_DirectSet_callsite_N`, `N` counted in `Cvar_Set`-body
instruction-address order starting at `0`. Every current binary that needs MetaHook
self-managed callbacks has exactly one site (`callsite_0`).

## Availability

- Declared in 8 configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  svencoop-10257.
- Platforms: Windows + Linux (the finder itself has no `platform:` gate; only svencoop-10257
  among the declaring configs builds Linux).
- Inlined / absent: **absent on hl-8684 and hl-10210**. Those builds expose the native HL25
  `cvar_hooks` list, so no callsite patch is emitted (the capability matrix marks this
  combination `native_unsupported` rather than missing).
- Encoding differs by era: older GoldSrc tail-calls (`E9`, e.g. hl-3248/hl-3266/hl-3329/hl-3647
  and svencoop-10257 Linux, whose signature is `E9 … 90`), later builds `call` (`E8`, e.g.
  hl-4554, hl-6153, cof-5936, svencoop-10257 Windows).

## Predecessors

- `Cvar_Set.{platform}.yaml` and `Cvar_DirectSet.{platform}.yaml` (produced by `find-Cvar_Set`
  and `find-Cvar_DirectSet`, consumed via `expected_input`).

## How it is located

1. `_expected_callsite_outputs` reads the finder's `expected_outputs`. Every stem must match
   `Cvar_Set_to_Cvar_DirectSet_callsite_<digit>`, indexes must be unique and form a contiguous
   `0..N-1` range. Anything else aborts the finder before any IDA work.
2. Load and re-verify the `Cvar_Set` artifact (`_inspect_function_via_mcp`, honouring its
   `func_sig_allow_across_function_boundary` flag) and load the `Cvar_DirectSet` artifact EA.
3. Walk every instruction of the `Cvar_Set` body. A site qualifies only when it is a *direct
   rel32 branch* — mnemonic `call`/`jmp`, decoded size >= 5, first byte `E8` or `E9` — and its
   xref resolves to the `Cvar_DirectSet` function start. Indirect `FF 15 [slot]` and short/near
   jcc forms are rejected.
4. For each site, generate a forward-only patch signature: the target branch is emitted
   **verbatim** (including its rel32), then following instructions are appended with their
   immediate/`near`/`far`/`mem`/`displ` operand bytes wildcarded (plus the branch-specific
   wildcarding for `E8/E9/EB`, `0F 8x` and `7x`). Expansion stops at 96 bytes / 64 instructions,
   and a candidate prefix is accepted only when its shortest form of at least 6 bytes (and at
   least the target instruction's length) matches exactly once across executable segments.
5. The wrapper re-checks uniqueness with `_find_unique_bytes` over MCP and aborts if the match
   address differs from the site.
6. Emits one YAML per site with `patch_name`, `patch_va`, `patch_rva`,
   `patch_sig`, `patch_sig_disp` (always `0x0`, because the signature always starts at the
   branch) and **no** `patch_bytes`.

## Pitfalls

- The emitted `patch_sig` embeds the branch's own relative displacement verbatim — it is a
  binary-local byte pattern, not a portable one. Never move it across builds.
- Do not add a leading instruction to the signature. `patch_sig_disp` is contractually `0x0` and
  the consumer computes the redirect from the match start; a shifted signature would silently
  redirect the wrong address.
- Do not emit `patch_bytes`: the consumer applies `MH_InlinePatchRedirectBranch` at runtime.
  Patching `Cvar_DirectSet` globally instead of the callsite is explicitly not the contract.
- Current MetaHook `GameData.cpp` normalizes only `function` and `global`; `kind: "patch"` (from
  `patch_name`) lands in `unsupportedKind` until `MH_GAMESYMBOL_KIND_PATCH = 3` is appended and
  `patch_rva` / `patch_sig` / `patch_sig_disp` are parsed. Consumers must query
  `Cvar_Set_to_Cvar_DirectSet_callsite_0 .. _N` until `SYMBOL_NOT_FOUND`, and must prefer a
  successful `cvar_hooks` query (native list) over applying these patches.
- Missing `callsite_0` on hl-8684/hl-10210 is *native capability*, not an analysis gap: those
  builds have the native hook list. Missing it anywhere else is an analysis/catalog failure, and
  the config's contiguous-index requirement means a partially produced index set (e.g. only
  `_1`) fails the whole finder.
