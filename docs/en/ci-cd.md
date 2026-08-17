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

## Pages deployment

[`.github/workflows/deploy-pages.yml`](../../.github/workflows/deploy-pages.yml) triggers on pushes to `main` that touch `pages/**`, `gamesymbols/**`, `configs/**`, or the workflow itself:

1. **build**: tests, lints, builds `pages/dist`, verifies current game-symbol bytes, and uploads the artifact.
2. **archive**: verifies that the `pages-snapshots` branch history is append-only (only `gamesymbols/<family-build>.<sha256>.json` additions), merges the immutable game-symbol snapshot archive, and pushes it.
3. **deploy**: deploys `pages/dist` via GitHub Pages and verifies the deployed CDN game-symbol bytes against the verification manifest.

GitHub Pages hosts only static assets; it never hosts the Process API/SSE service.

## Analyzer and CI argument reference

When driving the analyzer from CI, pass the same arguments as a local run — see [Binary acquisition and symbol analysis](analysis.md#analyze-configured-symbols). Batch analysis over every configured tag uses `-allgamever`; a single-tag run uses `-gamever`. CI jobs that only need to know whether binaries are already in place use `copy_depot_bin.py ... -checkonly`.
