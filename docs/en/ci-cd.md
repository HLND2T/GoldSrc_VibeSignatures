[Back to README](../../README.md) | [中文](../zh-CN/ci-cd.md)

# CI/CD reference

The GitHub Actions workflows run the guarded analysis and publication gates on every push and pull request.

## Continuous integration

[`.github/workflows/ci.yaml`](../../.github/workflows/ci.yaml) runs on both `ubuntu-latest` and `windows-latest`:

1. `uv sync --locked` installs the locked environment.
2. `uv run python format_repo_files.py --check` checks formatting.
3. `uv run python tests/run_test_suite.py unit -b --durations 30` runs the fast isolated suite.
4. `uv run python tests/run_test_suite.py repository-contract -b --durations 30` checks the repository contract.
5. `uv run python tests/run_test_suite.py all -b --durations 30` runs every assigned test.

A separate `redis-integration` job runs on `ubuntu-latest` with a `redis:7-alpine` service, sets `GSVIBE_REDIS_URL` and `GSVIBE_REDIS_PREFIX`, and runs `tests/run_test_suite.py redis-integration -b --durations 30`.

The `pages` job installs Node 24, runs `npm ci`, `npm test`, `npm run lint`, `npm run build`, `npm run verify:gamesymbols`, installs Chromium, and runs `npm run test:e2e` from the `pages/` directory.

## Game-symbol pull request validation

`gamesymbol-pr-validation.yml` classifies every non-closed pull request through a shared route contract. Normal branches
take the source plan/hosted/self-hosted path; every `gamesymbols/build/` branch, including malformed output-like names,
takes the output path so it can fail explicitly instead of reaching a trusted analysis runner.

Branch protection depends only on the final `pr-validate` job. Source planning runs the PR merge version of the semantic planner in the default checkout and uploads only its canonical bound `plan.json`; selected-node execution remains unchanged. The terminal job runs with `always()`, aggregates routed results with shell logic, accepts skipped jobs only when the bound plan did not select them, and fails fork analysis without granting the fork access to the protected self-hosted runner. Internal planner, hosted, and self-hosted job names are not required checks.

Hosted and self-hosted source validation rebuild the canonical gamedata manifest from the immutable symbol candidate and compare it with exact `HEAD` Git blobs. The bound plan includes base/merge gamedata subtree digests; ignored worktree files and broad staging globs are never validation inputs.

The planner also binds `cache_mode` from the `GSVIBE_IDB_CACHE_MODE` repository variable (`cold` by default). Analysis
runs on the dedicated `[self-hosted, windows, x64]` runner under the `win64` Environment and one
repository-wide IDA concurrency group. Warm mode keeps clean, probe/miss warmup, exact selection, restore, analysis, and
final clean in that one job. `cache-selection.json` binds the plan SHA, merge/bin identities, selected binaries, cache
keys, generations, and manifest hashes; its SHA-256 is rechecked and uploaded only as evidence. Cold mode never executes
a step that receives `GSVIBE_PERSISTED_WORKSPACE`.

Production warm activation requires the host and repository settings in the
[IDB cache operations runbook](idb-cache-operations.md). Unit and workflow-contract tests do not substitute for recorded
cold, first miss/publication, and subsequent hit runs on that runner.

## Release build and promotion

[`release-build.yml`](../../.github/workflows/release-build.yml) is a manual `workflow_dispatch` (`version` such as
`v20260825a` plus an optional `source_sha` and a `mode` of `new|republish`). On the self-hosted
`[self-hosted, windows, x64]` runner it: checks out the exact source and `bin` submodule, restores accepted bin, warms the
IDB cache for every game version, runs `ida_analyze_bin.py -allgamever`, builds/guards/publishes candidates and gamedata
per game version, runs `stage-build`, and opens a single `github-actions[bot]` generated-output PR
(branch `gamesymbols/build/<version>`).

- `validate-generated-output-pr.yml` verifies the output PR (bot author + same repo + `gamesymbols/build/` branch). The
  output head must be a single-parent commit whose parent equals the tracked manifest `source_sha`. The current PR base
  must be a descendant of that `source_sha`, so default-branch advancement after PR creation is not itself stale.
  Changed-path allowlist is computed from `source_sha..head` (every game version's gamesymbols/metadata/gamedata plus
  `release-manifests/<version>.json`), not from the possibly advanced PR base. Tracked output hashes still have to match.
  Trusted validation tooling continues to come from the PR base; the output workspace is the exact head.
- `promote-release-after-output-merge.yml` verifies the two-parent merge, transactionally swaps accepted bin into the
  persisted workspace, tags the single `version`, and publishes one GitHub Release with assets for every game version.
- `abandon-staged-release.yml` and `cleanup-completed-release-staging.yml` cover the lifecycle (abandon a staged build,
  sweep completed completion records).

`mode=republish` requires the `version` tag to exist and re-analyzes only the outputs affected since the last accepted
source. Publication no longer depends on `GSVIBE_RELEASE_PHASE2_ENABLED` or a GitHub App token; the gate is the
allowlisted repository + `win64` Environment + concurrency.

## Pages deployment

[`.github/workflows/deploy-pages.yml`](../../.github/workflows/deploy-pages.yml) triggers on pushes to `main` that touch `pages/**`, `gamesymbols/**`, or the workflow itself. General config edits do not redeploy historical aliases:

1. **build**: tests, lints, builds `pages/dist`, verifies current game-symbol bytes, and uploads the artifact.
2. **archive**: verifies that the `pages-snapshots` branch history is append-only (only `gamesymbols/<family-build>.<sha256>.json` additions), merges the immutable game-symbol snapshot archive, and pushes it.
3. **deploy**: deploys `pages/dist` via GitHub Pages and verifies the deployed CDN game-symbol bytes against the verification manifest.

GitHub Pages hosts only static assets; it never hosts the Process API/SSE service.

## Analyzer and CI argument reference

When driving the analyzer from CI, pass the same arguments as a local run — see [Binary acquisition and symbol analysis](analysis.md#analyze-configured-symbols). Every invocation must explicitly pass `-cache_mode cold|warm`. Batch analysis over every configured tag uses `-allgamever`; a single-tag run uses `-gamever`. CI jobs that only need to know whether binaries are already in place use `copy_depot_bin.py ... -checkonly`.
