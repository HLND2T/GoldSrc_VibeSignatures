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

## Release provenance and Phase 2 workflows

[`release-shadow.yml`](../../.github/workflows/release-shadow.yml) runs only at the exact `main` commit with
`contents: read`. It builds canonical release content manifests for `hl-10210`, `hl-8684`, and `svencoop-10257`, then
rebuilds and verifies each manifest from exact Git blobs before uploading a 30-day evidence artifact. The workflow does
not check out `bin`, trust worktree globs, or write refs, repository contents, pull requests, tags, or Releases.

Shadow success proves local content identity and the `new` mode decision only. The implemented Phase 2 workflows remain
disabled by default:

- `release-build.yml` runs only for an exact `main` dispatch, on the shared `[self-hosted, windows, x64]` runner and the
  `release` Environment. A GitHub App token pushes an immutable direct-parent output branch, creates a draft PR, binds its
  remote identity into private staging, then marks it ready.
- `release-output-validation.yml` is a read-only reusable verifier. It rejects repository/author/branch identity before
  fetching the exact head object and never checks out or executes output-head code.
- `release-promotion.yml` splits a credential-free merge verifier from an Environment-protected writer. The writer
  recomputes the canonical approval digest before obtaining App-backed tag/Release authority.
- `release-operations.yml` keeps retry, resume-promotion, republish, abandon, repair-index, cleanup, and reconcile behind
  explicit identities and confirmations. See the [release operations runbook](release-operations.md).

`GSVIBE_RELEASE_PHASE2_ENABLED` must remain unset/false until protected test-repository exercises and external
branch/ruleset, merge-commit-only, up-to-date, protected-tag, Environment, and GitHub App evidence are complete.

## Pages deployment

[`.github/workflows/deploy-pages.yml`](../../.github/workflows/deploy-pages.yml) triggers on pushes to `main` that touch `pages/**`, `gamesymbols/**`, or the workflow itself. General config edits do not redeploy historical aliases:

1. **build**: tests, lints, builds `pages/dist`, verifies current game-symbol bytes, and uploads the artifact.
2. **archive**: verifies that the `pages-snapshots` branch history is append-only (only `gamesymbols/<family-build>.<sha256>.json` additions), merges the immutable game-symbol snapshot archive, and pushes it.
3. **deploy**: deploys `pages/dist` via GitHub Pages and verifies the deployed CDN game-symbol bytes against the verification manifest.

GitHub Pages hosts only static assets; it never hosts the Process API/SSE service.

## Analyzer and CI argument reference

When driving the analyzer from CI, pass the same arguments as a local run — see [Binary acquisition and symbol analysis](analysis.md#analyze-configured-symbols). Every invocation must explicitly pass `-cache_mode cold|warm`. Batch analysis over every configured tag uses `-allgamever`; a single-tag run uses `-gamever`. CI jobs that only need to know whether binaries are already in place use `copy_depot_bin.py ... -checkonly`.
