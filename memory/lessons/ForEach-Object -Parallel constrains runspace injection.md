---
title: ForEach-Object -Parallel constrains runspace injection
type: note
permalink: goldsrc-vibesignatures/lessons/for-each-object-parallel-constrains-runspace-injection
tags:
- lesson
- ci
- powershell
- workflow
---

# ForEach-Object -Parallel constrains runspace injection

## Trigger

Parallelizing the per-tag PR-validation tail (`gamesymbol-pr-validation.yml`, `analyze-self-hosted`
job) with `ForEach-Object -Parallel -ThrottleLimit` hit three constraints in a row. Two surface immediately;
one changes behavior silently.

## Constraints and correct approach

- **Scriptblocks cannot travel through `$using:`.** Passing a helper function such as
  `$using:stageFn` (from `${function:Invoke-ValidationStage}`) is rejected outright with
  `ForEach-Object -Parallel using 变量不能是脚本块`. Ship the helper as **text** and rebuild it inside
  each runspace from a single definition:

  ```powershell
  $stageHelper = @'
  function Invoke-ValidationStage([string]$Label, [scriptblock]$Action) { ... }
  '@
  . ([scriptblock]::Create($stageHelper))          # top level
  # inside the -Parallel block:
  . ([scriptblock]::Create($using:stageHelper))     # a string is allowed
  ```

  Do not reach for `${function:Name}.ToString()` as the single source: for a function declared with a
  signature the scriptblock text omits `param(...)`, so the rebuilt definition silently loses its
  parameters.
- **Preferences do not cross the runspace boundary.** `$ErrorActionPreference = 'Stop'` set at the top
  of the step arrives as `Continue` inside the parallel block (verified on pwsh 7.6.6). Set it again as
  the first statement of every `-Parallel` block, or non-terminating errors will not abort an iteration.
- **One uncaught exception aborts the whole pipeline.** Without a per-iteration `try/catch`, a
  terminating error from one iteration stops the remaining iterations, so "run every item, then report
  all failures" is impossible. Wrap each iteration, collect failures in a thread-safe
  `[System.Collections.Concurrent.ConcurrentQueue[string]]::new()` passed via `$using:`, and throw once
  after the loop. Nested scriptblocks invoked via `& $Action` still see the iteration's local variables
  (`$tag`, staging paths) through dynamic scoping, so no further plumbing is needed.

## Verification

`[System.Management.Automation.Language.Parser]::ParseFile` for syntax, then execute the extracted
`run` block with stub `uv`/`git` on `PATH` and a synthesized `plan.json`: the success path exits 0 with
no residual staging directories, a failing item leaves its siblings complete and still runs that item's
`cleanup`, and observed concurrency matches `-ThrottleLimit`. These local checks never exercise the real
self-hosted IDA run.

## Scope

Any workflow step using `ForEach-Object -Parallel` that needs helper functions, non-default
preferences, or per-item failure aggregation.
