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
ida_preprocessor_scripts/_pitch_store_predicate.py` after adding a shared helper imported as
`from ida_preprocessor_scripts import _pitch_store_predicate`.

The same mistake recurred in PR #256 on 2026-09-26: `_portal_render_state_ida.py` used
`from ida_preprocessor_scripts import _portal_render_state`, leaving `_portal_render_state.py`
without a mapped consumer. The failure was in the plan job, before binary analysis:
https://github.com/HLND2T/GoldSrc_VibeSignatures/actions/runs/36232392856/job/108377862405
Fix commit: `75f69f0` (full-module-path import).

This is a repeated workflow omission: the lesson already existed, but it was not consulted
when adding the helper, and successful runtime/unit tests were treated as sufficient evidence.

## Root cause

`gamesymbol_snapshot_lib/analysis_sources.py:_repo_module_path` derives dependency paths
from AST import nodes using only the module string. For `ast.ImportFrom` it never inspects
the imported names, so `from ida_preprocessor_scripts import X` resolves the package itself
to the nonexistent `ida_preprocessor_scripts.py` and the dependency edge is dropped; the new
helper file then has no owning skill node in the source index, and `pr_cli.build_plan`
rejects the changed path. CI invokes this check through the plan/pr-validate workflow;
the same planner can and should be run locally. A passing unit/repository-contract suite
does not prove source ownership for the actual committed PR diff.

## Correct approach

Before adding or extracting a shared preprocessor helper, consult this note and inspect its
import edge from a config-registered finder, including intermediate adapter modules.

Use a full dotted module path:

```python
# Do not use: the current static planner drops this dependency edge.
from ida_preprocessor_scripts import _portal_render_state

# Use when the module object is needed (e.g. inspect.getsource).
import ida_preprocessor_scripts._portal_render_state as _portal_render_state

# Named imports are also recognized when the full module path is present.
from ida_preprocessor_scripts._portal_layout_ida import run_layout_walk
```

Do not add a dummy config consumer, delete the helper, or weaken the planner to conceal this
error. Keep the correction local to the import when runtime behavior is otherwise correct.

## Verification

For any new/moved shared helper or changed import chain, run the actual PR planner before
pushing, in addition to relevant behavior tests:

```powershell
uv run python gamesymbol_pr_validation.py plan -base-ref origin/main -head-ref dev -merge-ref dev -bin-repo bin -output .tmp/pr-plan.json
```

Use the actual PR base/head refs and an available binary-object repository. The planner reads
committed trees only: commit the tested correction locally before running this command;
unstaged or staged-only edits do not affect its result. Require exit code 0 and a generated
plan, then push and check the remote plan job. Local success does not imply remote CI success.

For PR #256, the corrected committed tree generated a plan successfully; 14 portal tests,
44 PR planner tests, and formatting checks passed. The long list of `Active reference YAML
has no analysis consumer` warnings was not the fatal error; the final changed-source ownership
error identified the offending helper.

## Scope

Any new shared module under `ida_preprocessor_scripts/` consumed by config-registered
finder scripts. Unrelated to runtime imports, which work either way.