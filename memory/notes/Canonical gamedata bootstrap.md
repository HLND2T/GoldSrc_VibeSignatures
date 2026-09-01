---
title: Canonical gamedata bootstrap
type: architecture
permalink: goldsrc-vibesignatures/notes/canonical-gamedata-bootstrap
---

# Canonical gamedata bootstrap

## Overview

Gamedata is derived from an immutable game-symbol candidate during release build. `gamedata/<tag>/**` is no longer
Git-versioned or staged into the index; its public bytes live only inside the verified GitHub Release bundle.

## Empty output contract

Every tag has a canonical self-excluding `gamedata-manifest.json`, even when no generator emits payloads. The manifest
binds snapshot SHA-256, normalized analysis config identity, generator contract, and the exact declared payload inventory.

## Candidate and bundle boundary

`gamedata_candidate.py build -> guard -> publish` operates only on explicit staging paths. `publish` atomically copies the
verified candidate tree to caller-owned release staging and never performs Git operations. `release_bundle.py` copies the
tree into the closed bundle; the GitHub-hosted verifier rebuilds and checks the same contract before protected publication.

## PR validation

Hosted/self-hosted source validation rebuilds a temporary snapshot and gamedata candidate for self-consistency without
reading or comparing a tracked gamedata baseline. Generator/config/artifact impacts are bound by the trusted plan.

## Validation

Run gamedata candidate/contract tests, snapshot candidate tests, release bundle verification, repository contract, and
the complete suite. Test empty and declared payload inventories, generator drift, tamper, and extra bundle files.
