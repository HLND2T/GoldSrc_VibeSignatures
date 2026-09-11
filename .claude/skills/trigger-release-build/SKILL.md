---
name: trigger-release-build
description: Safely dispatch a new release build or resume its matching draft from the immutable current origin/main SHA. Use only when explicitly asked to publish or resume a release version.
disable-model-invocation: true
---

# Trigger Release Build

Use the bundled script as the only remote-operation entry point. Do not construct an ad-hoc `gh workflow run`
command, accept a user-supplied SHA, move a tag, edit a Release, cancel work, or overwrite published assets.

## Procedure

1. Extract the requested release version, of the form `vYYYYMMDD[a-z]`.
2. Resolve the build path before dispatch. If the user has not specified it, ask whether to use a normal rebuild
   (`rebuild`) or build-free (`tracked`). Use an already explicit choice without asking again.
   - `rebuild` performs full analysis and compares rebuilt artifacts with Git truth.
   - `tracked` binds the selected SHA's tracked `bin_artifacts` without proving rebuildability. Warm-IDB preparation,
     runtime evidence, snapshot/JSON generation, independent verification, and publication protections still run.
3. Run from the repository root, passing the selected mode explicitly (from another directory, use the absolute script path):

   ```powershell
   uv run python .claude/skills/trigger-release-build/scripts/trigger_release_build.py <VERSION> --source-artifact-mode <rebuild-or-tracked>
   ```

4. Report the script's selected version, source artifact mode, selected release state, full `SOURCE_SHA`, commit subject,
   and Actions run URL.
5. If the script refuses the operation, surface its exact safety reason and stop. Do not bypass repository, auth,
   version, tag, duplicate-work, or `origin/main` checks.

The script allows a new version when the tag is absent and resumes only a draft whose tag points directly to the
selected `origin/main` SHA. A published version is immutable and requires a new version number for changed content.
Any requested generator/config change and its complete `bin_artifacts` must already be merged into `origin/main`.
Artifact binding is checked in CI, not by a local full analysis. Do not bypass a failed binding gate or silently switch
modes after failure. Resume with the same mode and source; existing draft assets cannot be overwritten by another mode.
The script defaults to `rebuild` for CLI compatibility, but this skill resolves the user's build-path choice explicitly.
