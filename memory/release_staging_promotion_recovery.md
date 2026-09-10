---
title: Release bundle publication and recovery
type: note
permalink: goldsrc-vibesignatures/release-staging-promotion-recovery
---

# Release bundle publication and recovery

## Overview

`release-build.yml` builds one closed bundle from an immutable source SHA, the bound `bin` gitlink, and Git-tracked
`bin_artifacts`. The self-hosted runner is read-only; a GitHub-hosted verifier rechecks the bundle; the protected
`publish-release` job is the only `contents: write` authority inside `release-build.yml`. Git source branches no longer
version `gamesymbols/`, `gamedata/`, or release manifests, and there is no generated-output PR or separate promotion
workflow. The separate Pages workflow may write only its non-authoritative append-only presentation mirror.

## Responsibilities

- Force-rebuild every configured analysis artifact into a fresh checkout-external root and compare exact inventory and
  bytes with Git `bin_artifacts`.
- Derive snapshot/metadata pairs and browser JSON datasets (`mark -step json`), pack the single
  `gamesymbols-<version>.7z`, and write a canonical Release manifest and `SHA256SUMS` into one allowlisted bundle.
- Upload the bundle as an Actions Artifact for build-to-verifier-to-publisher transport only.
- Re-verify exact source ancestry, bin gitlink, repository artifact inventory, snapshot/metadata contracts, independently
  re-derived JSON bytes, 7z contents, bundle allowlist, manifest, and checksums on a GitHub-hosted runner.
- Create or resume only a matching draft, refuse tag/asset drift and overwrite, re-read remote asset size/hash, and publish
  only after the complete inventory matches.
- Treat published versions as immutable. Changed content requires a new version.

## Involved Files

- `.github/workflows/release-build.yml`
- `release_bundle.py`
- `release_publish.py`
- `gamesymbol_snapshot_lib/candidate.py`
- `gamedata_candidate.py`
- `release_workflow.py`
- `release_workflow_lib/accepted_bin.py`

## Architecture

`source SHA + bin gitlink + bin_artifacts -> warm selection -> read-only full rebuild -> closed bundle -> hosted verify ->
protected draft upload/remote verification -> published GitHub Release`.

The Release manifest and checksums are assets inside that publication boundary. Actions Artifacts are transport, while a
draft Release is the recoverable staging layer and a published Release is the public immutable truth.

## Binary-only accepted cache

`PERSISTED_WORKSPACE/bin/<gamever>` is a rebuildable binary/side-file cache used before release warmup. Materialization
excludes analysis YAML, IDA databases, and BinSync state and verifies copied bytes under
`accepted-bin/locks/<gamever>.lock`. It is not release truth and is never promoted as part of publication.

Legacy YAML retirement uses `cleanup-legacy-accepted-yaml`: first verify binary-only materialization, then create and
verify a canonical backup under `accepted-bin/legacy-yaml-backups/<cutover-id>/<gamever>`, and only then delete the locked
source inventory. A verified `.incoming` backup and a partial deletion are resumable with the same cutover identity.

## Recovery Notes
- Trigger signal: a matching draft exists after a failed run, an upload is incomplete, remote tag/asset identity
  differs from the verified bundle, or `releases/tags/<version>` returns 404 after a successful draft creation.
- Root constraint: REST get-by-tag and paginated `/releases` endpoints are not reliable Draft Release discovery
  mechanisms for the Actions `GITHUB_TOKEN`; they may return 404 or an empty inventory after successful creation. Discover
  IDs from the complete paginated GraphQL Release inventory, match the exact `tagName`, and read the unique match through
  `gh release view`.
- Ambiguity constraint: more than one Release with the same tag is unsafe. Report every matching Release ID and stop; never
  silently choose, delete, or publish one.
- Correct action: when exactly one matching draft exists, rerun the same version/source/build identity to resume it. When
  duplicates exist, reduce them to one matching draft through an explicit operator action before retrying. Otherwise use a
  new version.
- Verification: compare tag target, embedded build identity, complete remote asset names/sizes/hashes, and checksums. Test
  GraphQL pagination, `gh release view` normalization, and duplicate-tag rejection without asserting mutable memory text.
- Scope: one multi-game-version immutable Release per version.

## AI release notes

- `release-build.yml` adds `release-notes` after hosted bundle verification, including `publish_release=false`. It checks out exact source with full history and no `bin` submodule, uses read-only contents permission and the existing `release` Environment. Published versions skip generation, keep their body and retain asset verification/Pages dispatch recovery.
- `release_notes.py` defaults to Claude and also supports Codex. Environment variables: `RELEASE_NOTES_PROVIDER`, required `RELEASE_NOTES_MODEL`; Environment secrets: required `RELEASE_NOTES_BASE_URL` and `RELEASE_NOTES_API_KEY`, injected only into generation. Node 22 and pinned Claude Code 2.1.79/Codex 0.114.0 run with isolated home/work and an allowlisted environment. Model names are endpoint-configured, separate from binary analysis settings.
- Baseline is the latest published official Release with a resolvable ancestor tag, excluding the current version; no baseline means first release/all reachable history. Initial evidence is capped at 96 KiB and includes commits, stats, filtered diffs with `bin_artifacts`, and three style-only historical bodies. Output has matching English/Chinese sections, prioritizing game-version support and symbols/signatures.
- `release_git.py` exposes only validated log/show/diff/ls-tree on source ancestry, with no Shell/edit/network or arbitrary Git arguments. Git subprocesses have no API/GitHub credentials. Each attempt permits 32 queries, 16 KiB/30 seconds per query and 200 KiB total evidence; generation permits two 10-minute attempts. Invalid, oversized (>120 KiB), credential-containing or reserved-identity-containing output blocks publication.
- Markdown travels separately in a 7-day Actions Artifact bound to version/source SHA/run ID/attempt. Publisher checks same-run name/digest; bundle schema and asset inventory are unchanged. `release_publish.py publish --notes-file` validates unpublished notes before creating tag/Draft, appends its own identity, updates matching Draft notes on retry and checks tag/Release identity/state/body/assets before publication. Published bodies are never updated.

### AI notes failure recovery

- Trigger: notes generation fails, a matching Draft needs retry, or a published version needs Pages recovery.
- Constraint: API protocols must support streaming plus tool calls (Anthropic for Claude, Responses for Codex); base URL is a secret with no variable fallback. Both notes and publisher use release Environment protections; pre-generation approval is not review of generated text.
- Correct action: fix configuration/endpoint, rerun failed jobs within artifact retention; rerun all jobs with the same version/source after expiration. Drafts recover original build identity. Do not manually edit/publish a draft during the workflow because GitHub has no atomic compare-and-publish transaction.
- Verification: deterministic release tests cover evidence, retries, read-only queries, no mutation before valid notes, Draft recovery, remote drift and immutable published bodies. Opt-in Linux `RELEASE_CLI_SMOKE=1` tests use pinned real CLIs with a fake API/key to check evidence exchange and denied write tools. Hosted-runner/real-endpoint acceptance remains a separate `publish_release=false` run with administrator-provided Environment settings.
- Scope: AI-generated GitHub Release body only; no bundle schema/asset change, no historical published-body rewrite. See `docs/en/release-operations.md` and `docs/zh-CN/release-operations.md`.
