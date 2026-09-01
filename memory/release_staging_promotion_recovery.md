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
- Derive snapshot/metadata pairs, gamedata, archives, a canonical Release manifest, and `SHA256SUMS` into one allowlisted
  bundle.
- Upload the bundle as an Actions Artifact for build-to-verifier-to-publisher transport only.
- Re-verify exact source ancestry, bin gitlink, repository artifact inventory, candidate/gamedata contracts, bundle
  allowlist, manifest, and checksums on a GitHub-hosted runner.
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
- Root constraint: the get-by-tag endpoint is not a reliable Draft Release discovery mechanism for this workflow token.
  Discover releases from the complete paginated `/releases` inventory and match the exact `tag_name`.
- Ambiguity constraint: more than one Release with the same tag is unsafe. Report every matching Release ID and stop; never
  silently choose, delete, or publish one.
- Correct action: when exactly one matching draft exists, rerun the same version/source/build identity to resume it. When
  duplicates exist, reduce them to one matching draft through an explicit operator action before retrying. Otherwise use a
  new version.
- Verification: compare tag target, embedded build identity, complete remote asset names/sizes/hashes, and checksums. Test
  paginated Draft discovery plus duplicate-tag rejection without asserting mutable memory text.
- Scope: one multi-game-version immutable Release per version.
