---
title: Shared IDB string-list pollution by custom finders
type: note
permalink: goldsrc-vibesignatures/notes/shared-idb-string-list-pollution-by-custom-finders
tags:
- ida
- preprocessor
- strings
- ci
- pitfall
---

# Shared IDB string-list pollution by custom finders

## Trigger

PR validation (`Game-symbol PR validation` → analyze-self-hosted) fails on an
unrelated preprocessor with a quick `preprocessor_completed status=failed`
(≈0.2 s, no `runner_failed` diagnostic = no-match, not a crash), then dies with
`agent_failed [skill_file_missing]` because no `.claude/skills/find-X/SKILL.md`
fallback exists. Locally `-allgamever` stays green and every rebuilt artifact
byte-matches `bin_artifacts`, so the failure looks impossible.

## Root cause

`idautils.Strings().setup(...)` inside a finder's py_eval **rebuilds the
IDB-wide cached string list** and the mutated options persist in the saved IDB
for every later skill in the same worker session. A custom setup with
`minlen=6` (find-GL_Shutdown, issue #122) hid the 5-char `"bogus"` literal from
find-Mod_LoadStudioModel, whose shared-template path `_string_items()` iterates
`Strings(default_setup=False)` with **no setup of its own**. Exposure depends
purely on batch execution order: the plan's dependency topology decided that
the GL finders run before find-Mod_LoadStudioModel, which is why earlier PRs
passed on identical code and identical warm-IDB generations (check the warmup
job log's `IDB cache hit: <tag>/<platform>; generation=...` lines to rule the
cache in/out).

Other pre-existing `strings.setup(minlen=4, strtypes=[STRTYPE_C])` callers
(find-Cvar_Set, find-cl_parsefuncs, find-engine, _studio_player_model_common,
_sven_client_pic_common) are non-restoring too, but minlen=4 is a superset of
the default 5, so they cannot hide ≥5-char literals.

## Correct approach

- Custom finders must not rebuild the shared string list. Locate string
  anchors by scanning segments for the exact NUL-delimited literal and mapping
  `idautils.DataRefsTo(ea)` → function starts (pattern:
  find-GL_Shutdown `anchor_string_owners`, same idea as the GOT float fallback
  `_float_fallback_owners` in the py_eval template).
- Gate the scan by **segment permissions** (`getattr(seg, 'perm', 0) & 4`,
  readable), not section names: the `Sys_Shutdown()` literal lives in
  writable `.data` on the old Windows hw.dll family, and `.rodata`-only
  filters miss it.
- Keep FULLMATCH semantics in the raw scan: needle includes the trailing
  `\x00`; accept a hit only when it is at offset 0 or preceded by `\x00`.
- If a setup is truly unavoidable, save `ida_strlist.get_strlist_options()`
  first and `strings.setup(**saved)` in `finally` — kwargs are `strtypes`,
  `minlen`, `only_7bit`, `ignore_instructions` (option field `ignore_heads`),
  `display_only_existing_strings` (`_unicode_string_items` shows the idiom).

## Verification

- Reproduce order-dependent poisoning locally with a two-node selection:
  `{"schema_version":1,"selections":[{"tag":"hl-3248","node_ids":[
  "engine:windows:find-GL_Shutdown","engine:windows:find-Mod_LoadStudioModel"]}]}`
  run through `ida_analyze_bin.py -batch_selection ... -bindir bin`; both must
  succeed and diff clean against committed artifacts.
- Re-validate the changed anchor across **every** registered node (11
  find-GL_Shutdown nodes: 10 windows + hl-8684 linux) the same way; set
  `GSVIBE_ANALYSIS_MAX_MEMORY_MIB=16384` when the batch runs concurrent.
- CI evidence for diagnosis: `gamesymbol-analysis-*` artifacts carry per-worker
  JSON event logs; `gamesymbol-rebuilt-self-hosted-*` carries partial rebuilds
  (diff them against `bin_artifacts` — 570/570 identical proved the shared
  template change was innocent); compare completed predecessor sets between a
  passing and failing run to isolate the polluter.

## Scope

All GoldSrc preprocessor skills that reference string literals inside py_eval;
any future skill that touches `idautils.Strings`, `ida_strlist`, or other
IDB-global caches (name comments, list states) shared within a worker session.
