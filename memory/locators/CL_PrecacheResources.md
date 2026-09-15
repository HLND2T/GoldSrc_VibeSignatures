---
title: CL_PrecacheResources locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-precacheresources
tags:
  - locator
  - engine
  - func
---

# CL_PrecacheResources

## Symbol

- **Name**: `CL_PrecacheResources`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_PrecacheResources.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating is declared, but only hl-10210, hl-8684 and
  svencoop-10257 declare `module_linux: hw.so`; the other seven configs are Windows-only in
  this repo (Windows + Linux where an `hw.so` module exists).
- Inlined / absent: never absent. The *string-anchor* differs on SvEngine (see below).

## Predecessors

- None. `find-CL_PrecacheResources` has no `expected_input` and passes `old_yaml_map=None`.
- It is itself a **required predecessor** for `find-cl_resourcesonhand`
  (`CL_PrecacheResources.{platform}.yaml`).

## How it is located

Pattern A (`preprocess_func_xrefs_via_mcp`) string xref, with a SvEngine-specific anchor set
selected by the binary directory name (`Path(new_binary_dir).parent.name ==
"svencoop-10257"`):

1. Default (`FUNC_XREFS`): `xref_strings: ["#GameUI_PrecachingResources"]` — substring match,
   not `FULLMATCH`. The literal is owned by `CL_PrecacheResources`; exactly one candidate
   function must survive (`len(candidates) == 1`).
2. `svencoop-10257` (`SVENCOOP_FUNC_XREFS`): `xref_strings:
   ["FULLMATCH:begin CL_PrecacheResources()"]`. The script's comment records that the
   `#GameUI_PrecachingResources` reference is not a unique single-owner anchor there (its
   owner has multiple callers), so the unique in-function diagnostic literal is used instead.
3. Emit `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`. `func_sig` is kept only
   when the generated wildcarded signature resolves uniquely to the function start.

## Pitfalls

- Discovery never consumes an old artifact signature (`old_yaml_map=None`): a pre-existing
  same-named YAML cannot short-circuit the chain.
- The reference *instruction* form is platform-dependent — Windows emits `push imm32` for the
  literal, Linux emits `mov [esp+3Ch], imm32` — so a byte/instruction pattern is not a valid
  cross-platform anchor. Only the string xref is.
- `#GameUI_PrecachingResources` is a substring anchor: keep it `FULLMATCH`-free only because
  the full literal is unique in practice; the Sven diagnostic exists precisely because the
  substring anchor is not safe on every family.
- Downstream contract: `find-cl_resourcesonhand` re-inspects this artifact's `func_va`
  against the current IDB (`func_sig` re-validation, honoring
  `func_sig_allow_across_function_boundary` when the artifact carries it) and fails closed if
  the owner does not match.
- CoF (`cof-5936`) is Windows-only in this repo; do not expect an `hw.so` output there.
