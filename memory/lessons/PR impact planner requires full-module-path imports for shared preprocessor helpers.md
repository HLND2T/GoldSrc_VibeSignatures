---
title: PR impact planner requires full-module-path imports for shared preprocessor
  helpers
type: note
permalink: goldsrc-vibesignatures/lessons/pr-planner-full-module-imports
tags:
- lesson
- ci
- preprocessor
---

# PR impact planner requires full-module-path imports

## Trigger

PR #129 failed `pr-validate` with `Changed analysis source has no mapped consumer:
ida_preprocessor_scripts/_pitch_store_predicate.py` after adding a shared helper module
imported by a finder as `from ida_preprocessor_scripts import _pitch_store_predicate`.

## Root cause

`gamesymbol_snapshot_lib/analysis_sources.py:_repo_module_path` derives dependency paths
from AST import nodes using only the module string. For `ast.ImportFrom` it never inspects
the imported names, so `from ida_preprocessor_scripts import X` resolves the package itself
to the nonexistent `ida_preprocessor_scripts.py` and the dependency edge is dropped; the new
helper file then has no owning skill node in the source index, and `pr_cli.build_plan`
rejects the changed path. The checker only runs in CI (plan/pr-validate workflow); the local
unit/repository-contract suites do not catch it.

## Correct approach

Import shared `ida_preprocessor_scripts/*` helpers by their full dotted module path so the
AST resolver maps them to the real file, e.g.
`import ida_preprocessor_scripts._pitch_store_predicate as _pitch_store_predicate` or
`from ida_preprocessor_scripts._portal_layout_ida import run_layout_walk`.

## Verification

Reproduce locally before pushing:
`python gamesymbol_pr_validation.py plan -base-ref origin/main -head-ref dev -merge-ref dev
-output <tmp>.json` — it reads committed trees only, so commit first; a clean JSON output
means the mapping is fixed. Then confirm the CI plan/pr-validate jobs pass.

## Scope

Any new shared module under `ida_preprocessor_scripts/` consumed by config-registered
finder scripts. Unrelated to runtime imports, which work either way.