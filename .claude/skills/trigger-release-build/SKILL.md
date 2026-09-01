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
2. Run from any directory:

   ```powershell
   uv run python .claude/skills/trigger-release-build/scripts/trigger_release_build.py <VERSION>
   ```

3. Report the script's selected version, selected release state, full `SOURCE_SHA`, commit subject,
   and Actions run URL.
4. If the script refuses the operation, surface its exact safety reason and stop. Do not bypass repository, auth,
   version, tag, duplicate-work, or `origin/main` checks.

The script allows a new version when the tag is absent and resumes only a draft whose tag points directly to the
selected `origin/main` SHA. A published version is immutable and requires a new version number for changed content.
Any requested generator/config change must already be merged into `origin/main`.
