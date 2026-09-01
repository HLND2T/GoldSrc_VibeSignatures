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
- Tag mismatch, Release without tag, different draft identity, or overwrite request fail closed.
- Changed content requires a new version. `--clobber`, tag moves, and content-style republish are forbidden.

The draft is the recoverable staging layer. The publisher uploads missing assets without overwrite, re-reads remote asset
name/size/hash, and publishes only after the complete inventory matches. Preserve the run URL, source/bin SHAs, bundle
manifest, checksums, and draft URL when diagnosing a failure.

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
