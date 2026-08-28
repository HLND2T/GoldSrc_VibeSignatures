---
title: Canonical gamedata bootstrap
type: architecture
permalink: goldsrc-vibesignatures/notes/canonical-gamedata-bootstrap
tags:
- gamedata
- git
- publication
- candidate
---

# Canonical gamedata bootstrap

## Overview

The release build owns reviewed/tracked `gamedata/<tag>/**` bytes; source PRs no longer commit them. The directory remains ignored by default; only a guarded candidate session may stage exact allowlisted paths.

## Empty output contract

Every snapshot tag has `gamedata/<tag>/gamedata-manifest.json`, even when no generator emits payload files. The schema-1 canonical JSON binds game version, exact snapshot SHA-256, analysis config SHA-256, generator contract SHA-256, and a payload inventory hash that excludes the manifest itself. This makes the zero-generator state trackable without placeholder files.

## Staging boundary

`gamedata_candidate.py stage` guards snapshot/config/generator/output identities, validates the published tree, creates a temporary Git index from HEAD, stages only session paths with argument-vector `git add -f -- <exact-path>`, verifies the temporary tree, then repeats the exact operations on the real index. Stale tracked paths are removed explicitly. Worktree globs and `git add -A` are not used.

## PR validation

The trusted impact plan binds base/merge gamedata subtree digests. Hosted and self-hosted jobs rebuild a guarded candidate manifest for self-consistency (build -> guard -> gamedata build -> guard -> mark gamedata) without comparing against tracked output. Changes under `gamedata/<tag>/` select only that tag and do not select IDA nodes; config, snapshot/binary identity, or generator contract changes rebuild gamedata. Publication happens only in the release build.

## Validation

Run `tests.test_gamedata`, `tests.test_gamesymbol_pr_validation`, repository-contract, and the full suite. A zero-symbol tag may remain config-only before release. When it is published, it has the same snapshot/metadata pair and a gamedata directory whose canonical manifest records an empty payload inventory.
