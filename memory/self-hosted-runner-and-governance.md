---
title: self-hosted-runner-and-governance
type: architecture
permalink: goldsrc-vibesignatures/self-hosted-runner-and-governance
tags:
- self-hosted
- runner
- environment
- governance
- secrets
- github-actions
---

# Self-hosted runner and GitHub governance

## Overview

Self-hosted `[windows, x64]` runners are the only place commercial IDA verification, official analysis, and release
builds run. This note captures the environment/secret/governance surface that CI workflows and repository code assume.
The workflow internals built on top of it live in [[Immutable warm IDB cache generations]],
[[Release bundle publication and recovery]], and [[ci-cd-and-repository-contract]].

## Configuration precedence and namespaces

The analyzer uses the GoldSrc-specific `GSVIBE_*` namespace. Precedence is explicit CLI values > environment values >
program defaults. IDB cache mode is not a CLI option and is not read from the environment: official analysis is
unconditionally warm. No manually maintained IDA-version variable is required — the kernel version is dynamically
probed. Key operational variables (details in `docs/en/requirements.md`):

- `GSVIBE_AGENT` / `GSVIBE_AGENT_MODEL` — Agent CLI and model.
- `GSVIBE_LLM_*` (`MODEL`, `APIKEY`, `BASEURL`, `TEMPERATURE`, `FAKE_AS`, `EFFORT`) — LLM-backed workflows.
- `GSVIBE_PROCESS_REPORTER` (`none|console|redis`), `GSVIBE_REDIS_URL`, `GSVIBE_REDIS_PREFIX`, `GSVIBE_RUN_ID` —
  process reporting (see [[process-reporting-and-scheduler]]).
- `GSVIBE_API_HOST/PORT/CORS_ORIGINS/ALLOW_PRIVATE_NETWORK`, `GSVIBE_SSE_BLOCK_MS/BATCH_SIZE` — read-only Process API.
- `GSVIBE_REFERENCE_GAMEVER` (default `hl-10210`) — canonical reference game version for `LLM_DECOMPILE` (see
  [[reference_yaml_generation]]).
- `GSVIBE_ANALYSIS_MAX_CONCURRENCY` (decimal `1..32`, default `1`, fail-closed), `GSVIBE_ANALYSIS_MAX_MEMORY_MIB`,
  `GSVIBE_ANALYSIS_INITIAL_WORKER_RESERVATION_MIB` (default `2048` MiB) — full-analysis admission (see
  [[full-analysis-concurrency]]). Malformed values fail closed before any worker launches; concurrency above `1`
  requires an explicit memory budget.
- `DEPOTDOWNLOADER_STEAM_USERNAME` / `DEPOTDOWNLOADER_STEAM_PASSWORD` — depot authentication when required.

## Persisted cache root governance

The cache CLI receives an explicit persisted root that CI later exposes as the `PERSISTED_WORKSPACE` secret only inside
the protected dedicated Windows runner job. Constraints:

- The root must be outside the checkout and `bin/`, must not traverse a reparse point, and must sit on storage that
  supports atomic same-filesystem rename.
- The runner account needs exclusive write access to its cache root. Byte-range locks must be mutually exclusive across
  two independent runner processes, not just threads in one process.
- A shared cache is valid only when all consumers use the same controlled storage and ACL authority. Actions Artifacts
  are evidence/selection transport and `READY.json` is a probe hint — never a cache transport or truth source.
- Warm production requires one canonical Python executable with `idapro` on the dedicated runner. CI invokes
  `idb_warm_worker.py --print-ida-version` with that executable and uses it for every bare-idalib worker. Consumer
  analysis still requires `idalib-mcp` and `IDADIR`, but neither the MCP executable nor the IDA installation path
  participates in the cache identity.
- Store the absolute persisted path as the Environment secret `PERSISTED_WORKSPACE`.

## Release runner and repository authority

- The release build runs on the same `[self-hosted, windows, x64]` runner as source analysis. Its protected `win64`
  Environment supplies only analysis/runtime secrets and the checkout-external `PERSISTED_WORKSPACE`; the build has
  read-only repository permission and no PAT, push, tag, or Release authority. PR routing must keep untrusted/fork
  analysis off this runner.
- Production release dispatch is restricted to `HLND2T/GoldSrc_VibeSignatures` and per-version concurrency. A separate
  protected `release` Environment hosts the GitHub-hosted `publish-release` job — the only release-build job granted
  `contents: write` (see [[Release bundle publication and recovery]]).
- Branch protection requires the unique Actions-owned `pr-validate` check, no direct/admin-bypass pushes to `main`,
  protected release tags, and the required approval policy for that Environment. No GitHub App token, `HLND2T_GH_TOKEN`,
  generated-output branch, or merge-time promotion is part of the release authority.
- Repository tests cannot activate or prove these external controls.

## Progressive concurrency activation

Safe activation order for the release build: merge with concurrency unset (`1`) so production stays serial; ensure 85%
of `GSVIBE_ANALYSIS_MAX_MEMORY_MIB` can accommodate the measured coordinator baseline plus one worker reservation
(default `2048` MiB) and record the real peak from a concurrency-`1` run; raise concurrency to `2` and verify two
verified MCP endpoints, memory below budget, and byte-identical artifacts (`bin_artifact_contract.py`); roll back by
setting concurrency back to `1` (cache generations, selection, and release schema are unaffected). A hard memory-limit
violation fails the run with a structured reason and is not retried at lower concurrency within the same run.
