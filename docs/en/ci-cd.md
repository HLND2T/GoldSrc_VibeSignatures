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

The reusable `warmup-idb` producer publishes an exact selection. It binds one IDA Python executable, then warms each
binary in a separate bare-idalib worker with bounded per-group concurrency. Consumers verify and restore that selection,
never warm or save. The IDB key binds binary/kernel/worker identity and intentionally does not bind `bin_artifacts`
content.

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

## Pages deployment

`deploy-pages.yml` triggers from a published Release or a manual dispatch with an explicit published tag. It downloads and
extracts `gamesymbols-*.7z`, obtaining the Release's already-derived content-addressed JSON (`index.json` +
`<tag>.<sha256>.json`); the Vite plugin relays those bytes into the build output. It preserves the non-authoritative
append-only `pages-snapshots` presentation mirror, deploys Pages, and verifies CDN bytes. Local/CI builds use a generated
minimal JSON fixture; production always sets the explicit downloaded asset directory. Only new-format Releases are
supported (dispatch for an old tag fails fast).
