[Back to README](../../README.md) | [中文](../zh-CN/ci-cd.md)

# CI/CD reference

## Continuous integration

`ci.yaml` runs formatting, unit, repository-contract, complete assigned suites, Redis integration, and Pages
test/lint/build/asset/E2E checks. Repository contract requires the complete formal `bin_artifacts` Git inventory and
forbids tracked `bin/**/*.yaml`, `gamesymbols/`, `gamedata/`, and `release-manifests/` outputs.

## Submodule downloads

Workflows sync and fetch the exact committed submodule revisions without Actions caches for `bin` or `.git/modules`.
Self-hosted runners use their preconfigured Git URL rewrites to read `https://github.com/` through
`http://HZVM:8080/` (git-cache-proxy). These settings must be visible to the runner service account, including checkout
actions; workflows do not install or change them. GitHub-hosted jobs fetch directly from GitHub because the proxy is
only reachable on the runner host's private network.

The proxy's upstream PAT is read-only and must have Contents: Read access to every private submodule it serves.
Pushes must continue to use `https://github.com/`, with the runner's `pushInsteadOf` rule keeping them off the proxy
and the job supplying its own write credentials. IDB, uv, and npm caches are independent of submodule downloads.

## Source PR validation

`gamesymbol-pr-validation.yml` has one source route. Trusted base tooling plans impact from base/head/merge Git trees,
including artifact A/M/D/R/C ownership and downstream closure. Rebuilds write only to an external temporary artifact root,
force selected nodes to execute, then compare the complete inventory and bytes with merge Git blobs. Forks that need
self-hosted analysis fail closed. `pr-validate` is the aggregate required check.

## Release workflow

The release DAG is:

```text
preflight -> warmup-idb -> build-release-bundle -> verify-release-bundle -> publish-release
```

The self-hosted read-only build force-rebuilds all analysis artifacts in a fresh root, compares them with Git truth,
derives snapshots/metadata and the browser JSON datasets, marks `json`, publishes them, then derives the single all-in-one
`gamesymbols-<version>.7z` and assembles the full release bundle, uploading one transport Artifact. The GitHub-hosted
verifier checks source ancestry, bin gitlink, artifact inventory, payload contracts, **independently re-derives the JSON
and compares it byte-for-byte with the bundle**, 7z contents, allowlist, canonical manifest, and checksums. The protected
publisher is the release workflow's only contents writer and implements immutable tag/draft/asset semantics. There is no
generated-output PR or separate promotion workflow. The Release publishes only three assets:
`gamesymbols-<version>.7z`, `release-manifest-<version>.json`, and `SHA256SUMS-<version>.txt`.

`GSVIBE_ANALYSIS_INITIAL_WORKER_RESERVATION_MIB` is also mapped into the job to tune the initial per-worker
reservation floor (default `2048` MiB); see requirements for configuration rules.

The full `-allgamever -force_all` analysis step runs the two-phase bounded coordinator. The protected `win64`
Environment maps non-secret variables into the job: `GSVIBE_ANALYSIS_MAX_CONCURRENCY` (default `1`) and
`GSVIBE_ANALYSIS_MAX_MEMORY_MIB` (unset disables the aggregate memory guard, which also blocks concurrency above
`1`). Activation is progressive: enable the memory budget first at concurrency `1` to record a real peak, then
raise concurrency to `2` only after real-runner evidence supports it; rolling back only requires setting
concurrency back to `1`. The runner-specific memory value is operational configuration and is never committed
to the repository.

## PR selected-node analysis

`gamesymbol-pr-validation.yml` exports a generic selection manifest from non-empty `plan.tags[].analysis_nodes`,
validates it, materializes each tag serially, then invokes one selected-node batch. Only IDA analysis is parallel;
compare, candidate build/guard, gamedata build/guard and mark remain serial after the global success barrier.
Exact-generation restore, trusted base validators, isolated per-tag stages and the tracked `bin_artifacts` check remain intact.
The job maps the same three `GSVIBE_ANALYSIS_*` variables as release, without changing their values or using warmup limits.
An `always()` upload retains only worker logs and summaries on success/failure, best-effort on cancellation.

For issue #81, the operator explicitly authorized using existing concurrency immediately and waived the concurrency-1/2
performance comparison on September 8, 2026. This is an activation decision, not measured performance or real-IDA evidence.
Rollback sets `GSVIBE_ANALYSIS_MAX_CONCURRENCY=1` and retains the same batch path; the budget is per invocation, not host-wide.

## Pages deployment

`deploy-pages.yml` triggers from a published Release or a manual dispatch with an explicit published tag. It downloads and
extracts `gamesymbols-*.7z`, obtaining the Release's already-derived content-addressed JSON (`index.json` +
`<tag>.<sha256>.json`); the Vite plugin relays those bytes into the build output. It preserves the non-authoritative
append-only `pages-snapshots` presentation mirror, deploys Pages, and verifies CDN bytes. Local/CI builds use a generated
minimal JSON fixture; production always sets the explicit downloaded asset directory. Only new-format Releases are
supported (dispatch for an old tag fails fast).
