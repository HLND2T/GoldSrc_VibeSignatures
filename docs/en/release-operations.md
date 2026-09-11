# Release operations

`release-build.yml` accepts an immutable `version`, optional `source_sha`, `publish_release` (default `true`), and
`cleanup_legacy_yaml` (default `false`), and `source_artifact_mode` (`rebuild` by default, or `tracked`). A production source must be reachable from the default branch.
`publish_release=false` is only a non-publishing workflow verification mode and requires the source to equal the dispatch
commit. Both modes generate AI notes after bundle verification. A version already published skips AI generation and
retains its existing body while checking assets and allowing Pages dispatch recovery.

## Build-free release from tracked artifacts

`source_artifact_mode=tracked` skips full analysis and rebuilt-artifact comparison. It uses only the selected source
SHA's committed `bin_artifacts`; it proves source identity, not rebuildability. Warm-IDB preparation/restore, runtime
evidence, snapshot/JSON generation, hosted verification, notes, and protected publication remain required.

The trigger skill asks for the build path when unspecified and uses an already explicit choice. Its script accepts:

```powershell
uv run python .claude/skills/trigger-release-build/scripts/trigger_release_build.py <VERSION> --source-artifact-mode tracked
```

Use `rebuild` for normal full analysis; the script defaults to it for existing callers. Both modes share the same
workflow and version concurrency guard. The script checks immutable source/auth/version/run identity; CI performs
the artifact binding checks. Local uncommitted artifacts are never release inputs.

`release_bundle.py bind-tracked --repo-root <checkout> --source-sha <SHA> --output <binding.json>` checks HEAD,
configuration and artifact inventory, index identity, exact Git blob bytes, and canonical artifact/link contracts.
Bundle `build --source-artifact-mode tracked --tracked-binding <binding.json>` embeds canonical binding evidence.
Bundle `verify` and publisher `publish` require the matching `--source-artifact-mode tracked` and independently
recompute the binding. Missing, changed, extra, staged or linked source inputs fail closed.

New manifests use schema 3, with `source_artifact_mode` and `tracked_artifact_binding_sha256` (null for rebuild).
Schema 2 remains readable as rebuild only. Public archive payloads retain their format. Keep mode/source unchanged
when resuming a draft; switching modes must not overwrite existing assets. For runner acceptance, use
`publish_release=false` with source equal to the dispatch commit and inspect both modes' job outcomes and verified
bundles. This still requires the configured runner, warm-IDB infrastructure and notes endpoint.

## Trust and permission boundary

- `preflight`, `warmup-idb`, `build-release-bundle`, `verify-release-bundle`, and `release-notes` have read-only contents permission.
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

## AI release notes

Configure the existing `release` GitHub Environment before the first run:

| Kind | Name | Value |
| --- | --- | --- |
| Variable | `RELEASE_NOTES_PROVIDER` | `claude` (default) or `codex` |
| Variable | `RELEASE_NOTES_MODEL` | Exact model identifier supported by the endpoint; required |
| Secret | `RELEASE_NOTES_BASE_URL` | Publicly reachable HTTPS API base URL; required |
| Secret | `RELEASE_NOTES_API_KEY` | API credential; required |

There is no variable fallback for the base URL. Claude requires an Anthropic-compatible streaming endpoint with tool use;
normally use the service root, to which the CLI adds `/v1/messages`. Codex requires a Responses-compatible streaming
endpoint with function calls; include `/v1` if required by the service, as the CLI appends `/responses`.
Chat Completions-only endpoints do not work. URLs must not contain credentials, query strings or fragments, and TLS
certificates must be publicly trusted. Model selection is independent of the binary-analysis `GSVIBE_LLM_*` settings.

The notes job installs `@anthropic-ai/claude-code@latest` and `@openai/codex@latest` on every run and logs their resolved
versions for troubleshooting. It uses Node 22 with an isolated temporary
home/work directory and an allowlisted environment. API secrets are injected only into the generation step; the AI CLI
does not receive GitHub or artifact credentials. Only the local `release_git` stdio MCP tool is exposed, supporting
validated `log`, `show`, `diff` and `ls-tree` queries against source SHA and its ancestors. Shell, editing, arbitrary Git
arguments, external diff/textconv and remote transports are unavailable; Git subprocesses do not inherit API credentials.
The notes job checks out the full main-repository history without the private `bin` submodule. Both notes and publisher
use the existing `release` Environment, so configured reviewers/ref restrictions apply to both jobs, including notes in
non-publishing runs. An Environment approval before generation is not a review of the generated text.

The baseline is the most recently published non-draft, non-prerelease Release with a resolvable ancestor tag, excluding
the current version. With no baseline, all reachable history is used and the first release is identified. Evidence includes
commit messages, file statistics, filtered diffs (including `bin_artifacts` and symbol/config changes), and three historical
release bodies for style only. Initial context is bounded to 96 KiB; total evidence per attempt is 200 KiB. The AI may make
32 Git queries, each limited to 16 KiB and 30 seconds. Binary, vendor, cache and common generated bodies are excluded.
Source evidence is sent to the configured API; repository instructions and historical bodies are treated as untrusted data.

Output has matching `## English` and `## 中文` sections, prioritizing game-version support and symbol/signature changes,
then important analysis/browser/tooling changes. Empty, malformed, oversized (over 120 KiB), credential-containing or
reserved-identity-containing output fails validation. Each generation attempt has a 10-minute timeout, with two attempts
maximum. Failure blocks publication; there is no generic-notes fallback. Raw prompts, CLI output and credentials are not
logged or uploaded. Structural validation does not establish factual accuracy.

Only Markdown is uploaded in `release-notes-<version>-<source_sha>-<run_id>-<attempt>`, retained for 7 days. The publisher
checks the same-run artifact name and digest before downloading it. Notes remain outside the closed bundle and asset
manifest. `release_publish.py publish --notes-file <path>` requires valid notes before creating an unpublished version's
tag or draft, and appends the program-generated immutable identity to the body. Matching drafts may receive regenerated
notes on retry while existing assets remain immutable. Tag, Release identity/state, notes and assets are checked before
publication. Do not manually edit/publish a draft during its workflow; GitHub has no atomic compare-and-publish operation.

After fixing a provider/configuration failure, rerun failed jobs while artifacts remain available. If artifacts expire,
rerun all jobs with the same version/source; original build identity is recovered from a matching draft. Published
versions never regenerate notes or update their body. To validate a real endpoint, dispatch `publish_release=false` from
the intended source commit and inspect the notes artifact; this still runs the normal build/verification pipeline.

Deterministic validation (no API credential required):

```bash
uv run python -m unittest discover -s tests -p 'test_release*.py'
actionlint .github/workflows/release-build.yml
git diff --check
```

For Linux real-CLI/fake-API smoke tests, install the latest packages above and Node 22 on `PATH`, then run
`RELEASE_CLI_SMOKE=1 uv run python -B -m unittest discover -s tests -p test_release_cli.py -v`.
These tests use synthetic responses and a fake key to verify evidence exchange and denied write tools. They neither
publish a Release nor call a paid API, and do not replace hosted-runner/real-endpoint acceptance.

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
2. Ensure 85% of `GSVIBE_ANALYSIS_MAX_MEMORY_MIB` can accommodate the measured coordinator baseline plus one worker
   reservation (default 2048 MiB, adjustable via `GSVIBE_ANALYSIS_INITIAL_WORKER_RESERVATION_MIB`), and record the real peak from a concurrency-`1` run.
3. Raise concurrency to `2` and verify two verified MCP endpoints, memory below budget, and byte-identical
   artifacts through `bin_artifact_contract.py`.
4. Roll back by setting concurrency back to `1`; cache generations, selection, and release schema are
   unaffected. A hard memory-limit violation fails the run with a structured reason and is not retried at
   lower concurrency within the same run.

