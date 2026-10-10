---
title: cross-platform-ci-runtime
type: note
permalink: goldsrc-vibesignatures/cross-platform-ci-runtime
tags:
- ci
- linux
- self-hosted
- mcp
---

# Cross-platform CI runtime

## Overview

Issue #356 ports IDB warmup, PR analysis and Release build orchestration to Windows/Ubuntu self-hosted runners. It follows kphtools commits 25d60e6 and 8f92981 and the applicable parts of CS2 PR #1124. GoldSrc has no corresponding LLVM/PDB or C++ ABI pipeline.

## Responsibilities

- Run shared orchestration from immutable workflow tooling while retaining trusted base PR validation and existing Release authority.
- Discover compatible S3 snapshots, restore only exact consumer selections, and reclaim only owned POSIX MCP groups.

## Involved Files & Symbols

- `ci_runner.py`: checked commands, host-tool discovery, bounded PR tail stages, warm selections and Release orchestration.
- `.github/actions/ci-command/action.yml`, `.github/actions/s3-cache/action.yml`: PowerShell/Bash launchers and verified cache transport.
- `ci_s3_cache.py`: shared namespace, ordered legacy prefixes and multiline Actions outputs.
- `ida_analyze_bin.py`: owned PGID tracking and cancellation-safe cleanup; `ida_runtime_probe.py`: venv-aware installation validation.

## Architecture

Three jobs select `[self-hosted, cross-platform]`, retaining `win64`. `.ci-tools` is checked out at `github.workflow_sha`; the Python helper retains exact source/bin identities, trusted base materialization/compare/build, PR stage barriers and failure aggregation. Producer discovery tries shared, Windows, Linux, macOS; after validation a new immutable run/attempt snapshot is published and checked. Consumers receive only the exact producer key and sealed selection/lease. Target binary platform is independent of runner OS. Local staging is external to checkout and is not a cross-host shared filesystem.

## Dependencies

- Native host IDA/idalib, paired Python and idalib-mcp, Agent CLI, IDADIR, uv, archive tools, private S3 and exact bin submodule access.
- Existing `win64` secrets/variables, immutable generation and lease validation, Release publisher/verifier separation.

## Notes

### POSIX supervisor exits before workers

- Trigger: launcher has exited while a worker still owns the MCP port or database.
- Root cause: poll-based early return and descendant-tree discovery lose ownership after reparenting.
- Correct approach: spawn a new session, retain its owned PGID on the process handle, stop the group even after leader exit, send SIGTERM then bounded SIGKILL, and require port release. Preserve primary failures while reporting cleanup failures; never signal unrelated groups.
- Verification: real listener trees cover descendants, ignored SIGTERM, exited supervisors, cancellation/startup failure and repeated cleanup; unrelated processes survive.
- Scope: analyzer-owned MCP sessions. Existing Windows tree termination remains intact.

### Linux virtualenv Python links

- Trigger: a paired venv Python and idalib-mcp fail installation identity checks.
- Root cause: resolving the Python leaf link changes its directory to the common system interpreter directory.
- Correct approach: preserve the interpreter's venv directory and validate explicit POSIX shebang identity; reject different venvs even if both link to one system executable.
- Verification: reproducer on WSL Ubuntu 24.04 and regression cases for symlinks, external entrypoints and wrong shebangs.
- Scope: IDA runtime probing and CI host-tool discovery, excluding workflow dependency venvs.

## Callers

- `.github/workflows/warmup-idb.yml`
- `.github/workflows/gamesymbol-pr-validation.yml`
- `.github/workflows/release-build.yml`

Real GitHub runner, private S3 and commercial IDA evidence remain an independent acceptance gate; local tests do not authorize closing issue #356.

## Local verification (2026-10-10)

- Windows: `tests/run_test_suite.py all`, 1488 tests, 1475 passed and 13 platform/opt-in skips, zero failures/errors.
- WSL Ubuntu 24.04: the same complete suite with an independent Linux venv, 1488 tests, 1478 passed and 10 platform/opt-in skips, zero failures/errors.
- Both suites used a task-owned Redis instance on loopback port 16356; Redis integration tests executed rather than being skipped. The instance was temporary and did not change system Redis configuration.
- Regression coverage includes legacy Windows-prefix store import into Linux layout, exact generation/lease restore, bounded PR stage barriers and failure aggregation, native POSIX listener cleanup, and real Release CLI orchestration for both artifact modes using synthetic binary fixtures.
- Repository formatting, changed Python Ruff checks, actionlint (without optional ShellCheck), and git diff whitespace checks passed. No runner was deployed, no Release was published, and no issue was closed. Commercial IDA integration and notes-CLI smoke checks remain opt-in skips.

## Python 3.11 MCP scope acceptance lesson (2026-10-11)

- Trigger: real Linux PR analysis run 38055698749 attempt 6 failed in `find-GL_LoadFilterTexture` with `NameError: predicate`, followed by `skill_file_missing` during fallback.
- Root cause: MCP `py_eval` uses distinct globals/locals. Python <=3.11 comprehensions and generators use a nested scope that cannot read module-level bindings added only to locals; Python >=3.12 list/set/dict comprehension inlining can mask this. Copying globals before a loop does not cover bindings created afterwards.
- Correct approach: keep dynamic selection variables in explicit loops, and publish imported modules/helper definitions before nested scopes need them. Preserve each locator's semantic filters and fail-closed ambiguity handling. Audit confirmed related hazards in texture-mode recovery, cvar hooks, sprite accesses, texture-counter owners, resource sentinels, ELF PLT section parsing, float-candidate constraints and shared instruction inspection. The unused ordinal-vtable helper also has a scope hazard, but has no active analysis consumer; its change was reverted after the trusted planner correctly rejected it. Fix that helper separately when introducing a real consumer.
- Verification: run shipped MCP scripts with separate namespaces under Python 3.11. New `test_mcp_script_scopes.py` exercises seven active behavior paths; running the pre-fix locator versions confirms scope failures. The additional unused ordinal-vtable case was removed with its source change after planner validation. Existing instruction-flow tests now also use separate dictionaries. CI has an explicit Python 3.11 regression step with an independent venv on both hosted OSes. Tests that only compile a script or use one exec dictionary cannot establish this property.
- Scope: repository-owned raw inline MCP scripts; existing intentional single-namespace exec wrappers are unaffected. Do not change third-party MCP code or add Agent fallback files to conceal deterministic locator errors.
