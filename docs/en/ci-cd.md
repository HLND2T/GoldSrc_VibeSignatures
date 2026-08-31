[Back to README](../../README.md) | [中文](../zh-CN/ci-cd.md)

# CI/CD reference

## Continuous integration

`ci.yaml` runs formatting, unit, repository-contract, complete assigned suites, Redis integration, and Pages
test/lint/build/asset/E2E checks. Repository contract requires the complete formal `bin_artifacts` Git inventory and
forbids tracked `bin/**/*.yaml`, `gamesymbols/`, `gamedata/`, and `release-manifests/` outputs.

## Source PR validation

`gamesymbol-pr-validation.yml` has one source route. Trusted base tooling plans impact from base/head/merge Git trees,
including artifact A/M/D/R/C ownership and downstream closure. Rebuilds write only to an external temporary artifact root,
force selected nodes to execute, then compare the complete inventory and bytes with merge Git blobs. Forks that need
self-hosted analysis fail closed. `pr-validate` is the aggregate required check.

The reusable `warmup-idb` producer publishes an exact selection. Consumers verify and restore that selection, never warm
or save. The IDB key binds binary/runtime identity and intentionally does not bind `bin_artifacts` content.

## Release workflow

The release DAG is:

```text
preflight -> warmup-idb -> build-release-bundle -> verify-release-bundle -> publish-release
```

The self-hosted read-only build force-rebuilds all analysis artifacts in a fresh root, compares them with Git truth,
derives the full release bundle, and uploads one transport Artifact. The GitHub-hosted verifier checks source ancestry,
bin gitlink, artifact inventory, payload contracts, allowlist, canonical manifest, and checksums. The protected publisher
is the only contents writer and implements immutable tag/draft/asset semantics. There is no generated-output PR or
separate promotion workflow.

## Pages deployment

`deploy-pages.yml` triggers from a published Release or a manual dispatch with an explicit published tag. It downloads the
Release snapshot/metadata YAML, builds content-addressed JSON, preserves the append-only `pages-snapshots` archive, deploys
Pages, and verifies CDN bytes. Local/CI builds use a generated minimal schema fixture; production always sets the explicit
downloaded asset directory.
