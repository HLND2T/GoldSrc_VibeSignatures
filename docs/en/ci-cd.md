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

`gamesymbol-pr-validation.yml` classifies every non-closed pull request through a shared route contract. During the source-only rollout, generated-output branch syntax is recognized by the Python contract but remains on the source route until the output verifier is deployed atomically.

Branch protection depends only on the final `pr-validate` job. That job runs with `always()`, reads every routed job result explicitly, accepts skipped jobs only when the trusted plan did not select them, and fails fork analysis without granting the fork access to the protected self-hosted runner. Internal planner, hosted, and self-hosted job names are not required checks.

Hosted and self-hosted source validation rebuild the canonical gamedata manifest from the immutable symbol candidate and compare it with exact `HEAD` Git blobs. The bound plan includes base/merge gamedata subtree digests; ignored worktree files and broad staging globs are never validation inputs.

The planner also binds `cache_mode` from the `GSVIBE_IDB_CACHE_MODE` repository variable (`cold` by default). Analysis
runs on the dedicated `[self-hosted, Windows, X64, gsvibe-ida]` runner under the `win64` Environment and one
repository-wide IDA concurrency group. Warm mode keeps clean, probe/miss warmup, exact selection, restore, analysis, and
final clean in that one job. `cache-selection.json` binds the plan SHA, merge/bin identities, selected binaries, cache
keys, generations, and manifest hashes; its SHA-256 is rechecked and uploaded only as evidence. Cold mode never executes
a step that receives `GSVIBE_PERSISTED_WORKSPACE`.

Production warm activation requires the host and repository settings in the
[IDB cache operations runbook](idb-cache-operations.md). Unit and workflow-contract tests do not substitute for recorded
cold, first miss/publication, and subsequent hit runs on that runner.

## Release provenance shadow

[`release-shadow.yml`](../../.github/workflows/release-shadow.yml) runs only at the exact `main` commit with
`contents: read`. It builds canonical release content manifests for `hl-10210`, `hl-8684`, and `svencoop-10257`, then
rebuilds and verifies each manifest from exact Git blobs before uploading a 30-day evidence artifact. The workflow does
not check out `bin`, trust worktree globs, or write refs, repository contents, pull requests, tags, or Releases.

Shadow success proves local content identity and the `new` mode decision only. It does not activate generated-output
PRs, promotion, republish, or production release authority; those still require protected test-repository exercises and
external branch/ruleset, merge-policy, protected-tag, Environment, and GitHub App evidence.

## Pages deployment

[`.github/workflows/deploy-pages.yml`](../../.github/workflows/deploy-pages.yml) triggers on pushes to `main` that touch `pages/**`, `gamesymbols/**`, or the workflow itself. General config edits do not redeploy historical aliases:

1. **build**: tests, lints, builds `pages/dist`, verifies current game-symbol bytes, and uploads the artifact.
2. **archive**: verifies that the `pages-snapshots` branch history is append-only (only `gamesymbols/<family-build>.<sha256>.json` additions), merges the immutable game-symbol snapshot archive, and pushes it.
3. **deploy**: deploys `pages/dist` via GitHub Pages and verifies the deployed CDN game-symbol bytes against the verification manifest.

GitHub Pages hosts only static assets; it never hosts the Process API/SSE service.

## Analyzer and CI argument reference

When driving the analyzer from CI, pass the same arguments as a local run — see [Binary acquisition and symbol analysis](analysis.md#analyze-configured-symbols). Every invocation must explicitly pass `-cache_mode cold|warm`. Batch analysis over every configured tag uses `-allgamever`; a single-tag run uses `-gamever`. CI jobs that only need to know whether binaries are already in place use `copy_depot_bin.py ... -checkonly`.
