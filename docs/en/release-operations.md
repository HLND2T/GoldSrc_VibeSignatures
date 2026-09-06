# Release operations

`release-build.yml` accepts an immutable `version`, optional `source_sha`, `publish_release` (default `true`), and
`cleanup_legacy_yaml` (default `false`). A production source must be reachable from the default branch.
`publish_release=false` is only a non-publishing workflow verification mode and requires the source to equal the dispatch
commit.

## Trust and permission boundary

- `preflight`, `warmup-idb`, `build-release-bundle`, and `verify-release-bundle` have read-only contents permission.
- The self-hosted build has no PAT, push, tag, or Release authority. `GSVIBE_BIN_TOKEN` is private-submodule read access.
- The GitHub-hosted verifier checks the closed bundle against exact source Git objects.
- `publish-release` runs in the protected `release` Environment and is the only `release-build.yml` job with
  `contents: write`; the Pages archive writer is a separate non-authoritative presentation mirror.
- Actions Artifact names bind version, source SHA, run ID, and attempt; their digest is checked before download.

## Immutable version state

- No tag/Release: create a tag pointing directly to source SHA, then a draft Release.
- Matching tag and draft: resume the original build identity; existing assets must match exact size/hash.
- Published Release: exact assets are an idempotent success; missing or different assets fail.
- The publisher discovers drafts by exact tag in the paginated GraphQL Release inventory, then reads the unique match with
  `gh release view`. It does not rely on REST endpoints that may return 404 or an empty draft inventory to the Actions
  `GITHUB_TOKEN`.
- Multiple Releases for one tag, tag mismatch, Release without tag, different draft identity, or overwrite request fail
  closed.
- Changed content requires a new version. `--clobber`, tag moves, and content-style republish are forbidden.

The draft is the recoverable staging layer. The publisher uploads missing assets without overwrite, re-reads remote asset
name/size/hash, and publishes only after the complete inventory matches. Preserve the run URL, source/bin SHAs, bundle
manifest, checksums, draft URL, and Release ID when diagnosing a failure. If one tag already has duplicate drafts, an
explicit operator action must reduce them to one matching draft before rerunning; the publisher never selects or deletes
one automatically.

## Binary-only accepted cache maintenance

`PERSISTED_WORKSPACE/bin/<gamever>` is a rebuildable binary/side-file cache, not release truth. Materialization ignores
analysis YAML and IDA/BinSync state. For the one-time cutover, explicitly enable `cleanup_legacy_yaml` on a reviewed
non-publishing run. The build job performs cleanup only after the release bundle passes local verification and its
transport artifact is uploaded, and before the GitHub-hosted verifier runs. The input is disabled by default and uses the
fixed cutover identity `bin-artifacts-v1` for every configured game version.

For manual recovery or a targeted rerun on the authorized runner, run one game version at a time:

```bash
uv run python release_workflow.py cleanup-legacy-accepted-yaml --repo-root <checkout> \
  --persisted-root <root> --gamever <tag> --cutover-id bin-artifacts-v1
```

The command first verifies binary-only materialization, then under the per-gamever lock creates an exact inventoried
backup in `accepted-bin/legacy-yaml-backups/<cutover-id>/<gamever>` before deleting the unchanged YAML inventory. Rerun
the same command after an interrupted rename or partial deletion; it resumes only from the canonical matching backup.

## Full-analysis concurrency runbook

The release build job reads `GSVIBE_ANALYSIS_MAX_CONCURRENCY` and `GSVIBE_ANALYSIS_MAX_MEMORY_MIB` from the
protected `win64` Environment. Safe activation order:

1. Merge with concurrency unset (`1`): production stays serial through the two-phase coordinator.
2. Set `GSVIBE_ANALYSIS_MAX_MEMORY_MIB` above the measured coordinator baseline plus one 4096 MiB worker
   reservation, and record the real peak from a concurrency-`1` run.
3. Raise concurrency to `2` and verify two verified MCP endpoints, memory below budget, and byte-identical
   artifacts through `bin_artifact_contract.py`.
4. Roll back by setting concurrency back to `1`; cache generations, selection, and release schema are
   unaffected. A hard memory-limit violation fails the run with a structured reason and is not retried at
   lower concurrency within the same run.

