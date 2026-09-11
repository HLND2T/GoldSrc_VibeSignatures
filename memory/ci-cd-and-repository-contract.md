---
title: ci-cd-and-repository-contract
type: architecture
permalink: goldsrc-vibesignatures/ci-cd-and-repository-contract
tags:
- ci-cd
- repository-contract
- submodule
- pr-validation
- pages
- workflows
---

# CI/CD and repository contract

## Overview

`ci.yaml` runs formatting, unit, repository-contract, complete assigned suites, Redis integration, and Pages
test/lint/build/asset/E2E checks. The repository contract requires the complete formal `bin_artifacts` Git inventory and
forbids tracked `bin/**/*.yaml`, `gamesymbols/`, `gamedata/`, and `release-manifests/` outputs. `bin_artifacts` is the
only Git YAML truth; `bin/` only provides binary/IDA state.

## Submodule downloads

Workflows sync and fetch exact committed submodule revisions without Actions caches for `bin` or `.git/modules`.
Self-hosted runners use preconfigured Git URL rewrites that read `https://github.com/` through the
`http://HZVM:8080/` git-cache-proxy. These settings must be visible to the runner service account (including checkout
actions); workflows do not install or change them. GitHub-hosted jobs fetch directly from GitHub because the proxy is
only reachable on the runner host's private network.

- The proxy upstream PAT is read-only and needs Contents: Read on every private submodule it serves.
- Pushes keep using `https://github.com/`; the runner's `pushInsteadOf` rule keeps them off the proxy, and the job
  supplies its own write credentials.
- IDB, uv, and npm caches are independent of submodule downloads.

## Source PR validation

`gamesymbol-pr-validation.yml` has one source route. Trusted base tooling plans impact from base/head/merge Git trees
(artifact A/M/D/R/C ownership and downstream closure); rebuilds write only to an external temporary artifact root, force
selected nodes to execute, then compare the complete inventory and bytes with merge Git blobs. `pr-validate` is the
aggregate required check; the gamedata consistency gate (`mark -step gamedata`) is enforced by PR validation and
`update_gamedata.py`. Forks that need self-hosted analysis fail closed. The route gate (four booleans -> four lanes) and
the planner's seed/classification sources are in [[gamesymbol PR validation routing 任务分流]]. See
[[gamesymbol PR validation candidate 基线复用]] for the materialize/compare mechanics.

The trigger set is `opened`/`synchronize`/`reopened`/`ready_for_review` and deliberately excludes `edited`: title or body
edits must not create a run, because workflow-level `cancel-in-progress: true` would cancel an in-flight validation and a
second `pr-validate` check run on the same head SHA could supersede a real failure. Retargeting a PR to another base
branch therefore does not revalidate, matching base-branch advancement, which fires no event either.

The reusable `warmup-idb` producer publishes an exact selection (see
[[Immutable warm IDB cache generations]]); consumers verify and restore that selection and never warm or save. The IDB
key binds binary/kernel/worker identity and intentionally does not bind `bin_artifacts` content.

## Release workflow and Pages deployment

Release DAG: `preflight -> warmup-idb -> build-release-bundle -> verify-release-bundle -> publish-release`. The
GitHub-hosted verifier independently re-derives the JSON datasets and compares them byte-for-byte with the bundle;
`publish-release` is the only release workflow job with `contents: write`. Manual `source_artifact_mode=tracked` skips full analysis and rebuild comparison while retaining the warm-IDB/runtime stages; the default remains `rebuild`. The trigger skill asks for the build path only when unspecified and passes the selected mode explicitly. See
[[Release bundle publication and recovery]] for the full trust/immutability contract (not repeated here).

`deploy-pages.yml` triggers from a published Release (or manual dispatch with an explicit published tag), downloads and
extracts `gamesymbols-*.7z` to obtain the already-derived content-addressed JSON (`index.json` + `<tag>.<sha256>.json`),
and the Vite plugin relays those bytes into the build output without re-deriving. It preserves the append-only
`pages-snapshots` presentation mirror and verifies current/archived/deployed CDN bytes. Local/CI builds use a generated
minimal JSON fixture; production always sets the explicit downloaded asset directory. Only new-format Releases are
supported — dispatch for an old tag fails fast. Pages never hosts the Process API (see
[[process-reporting-and-scheduler]]).

## Activation of full-analysis concurrency in the release build

The release build job maps `GSVIBE_ANALYSIS_MAX_CONCURRENCY` (default `1`) and `GSVIBE_ANALYSIS_MAX_MEMORY_MIB`
(unset disables the aggregate memory guard and blocks concurrency above `1`) from the protected `win64` Environment.
Progressive activation: enable the memory budget first at concurrency `1` to record a real peak, then raise to `2` only
after real-runner evidence; rolling back is just setting concurrency back to `1`. Runner-specific memory values are
operational configuration and are never committed to the repository. See [[full-analysis-concurrency]] for the
coordinator internals and [[self-hosted-runner-and-governance]] for the governance surface.

## Validation

Repository-contract tests and CI gates cover the formal inventory, forbidden outputs, test-group membership
([[test 文件必须登记到测试分组]]), Pages fixture/asset/E2E checks, and release verifier logic.
