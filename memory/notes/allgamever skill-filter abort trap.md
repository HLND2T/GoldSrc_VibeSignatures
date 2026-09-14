---
title: allgamever skill-filter abort trap
type: note
permalink: goldsrc-vibesignatures/notes/allgamever-skill-filter-abort-trap
tags:
- goldsrc
- preprocessor
- validation
---

# allgamever skill-filter abort trap

## Trigger
Running `ida_analyze_bin.py -allgamever -skill find-X` when find-X is registered in only a subset of `configs/*.yaml` (partial registration, e.g. Sven-only or HL-only finders).

## Root cause / constraint
`-allgamever` iterates every config and errors `Skill 'find-X' not found` on the first gamever that does not register it, then aborts (exit 1). Gamever order is not alphabetical (observed: hl-3248…hl-10210, svencoop-10257, cof-5936, then cstrike/czero…), so configs after the abort point silently never run — e.g. a `find-R_LoadSkys` (not registered for Sven) `-allgamever` run aborted at svencoop-10257 and skipped cof-5936, leaving a missing artifact that only the repository-contract `bin_artifact` inventory check caught.

## Correct approach
For partially-registered skills, validate per registered gamever (`-gamever <tag> -skill find-X -oldgamever none`), or after any `-allgamever` run compare the emitted artifact set against the anchor's confirmed branch matrix; run the tail configs explicitly. Also remember new `bin_artifacts/*.yaml` must be `git add`-ed or `tests/run_test_suite.py repository-contract` fails with a tracked-inventory mismatch.

## Verification
`ls bin_artifacts/<tag>/engine/<Symbol>.<platform>.yaml` covers every confirmed branch; `func_va` values match the anchor review evidence tables.

## Scope
GoldSrc_VibeSignatures preprocessor deliveries using create-preprocessor-scripts.
