---
title: analysis-planner-and-artifact-contract
type: architecture
permalink: goldsrc-vibesignatures/analysis-planner-and-artifact-contract
tags:
- planner
- dag
- artifact
- contract
- analysis
---

# Analysis planner and artifact contract

## Overview

`analysis_planner.py` is the single source of truth for module, symbol, artifact-path, and DAG validation. Snapshot
contracts reuse the same planner, so an output accepted by analysis cannot silently acquire different ownership at
publication time. The validated analysis DAG is the only planning source for both direct execution and the process
execution plan.

## Contract

- Outputs are module-local: artifact path is `bin_artifacts/<tag>/<module>/<symbol>.<platform>.yaml`. `bin/` is a
  separate binary + IDA-scratch root and is never an analysis-YAML truth source.
- Inputs may reference a sibling module with `../<module>/<artifact>`; the planner normalizes both producer and
  consumer to one game-root-relative owner path and creates a real cross-module edge.
- Config symbols use `name` plus the sole classifier `category`; `type` and `kind` are rejected. Categories: `func`,
  `gv`, `vfunc`, `vtable`, `patch`, `struct`, `structmember`, `scalar` (numeric scalar_name/scalar_value payload).
- Artifact payloads reject generic `name/type/kind` and use category-specific identity: `func_name`, `gv_name`,
  `patch_name`, `vtable_class`, or `struct_name`/`member_name`. Payload identity is deliberately not compared with the
  config symbol name (CS2 loader contract).
- x86 virtual-function slots are four bytes; a `structmember` also requires its parent `category: struct`.
- Fatal: unsafe paths, cycles, duplicate or case-colliding names, missing required inputs, wrong architecture, and
  binary mutation. Wrong-architecture and binary-mutation checks happen before and during work.
- `-allgamever` batch membership and order come from `configs/config.yaml` (single authority). A declared tag whose
  `configs/<tag>.yaml` is missing is fatal. Without `configs/config.yaml`, a legacy order is used for compatibility:
  `download.yaml` manifest order, then remaining `configs/*.yaml` tags lexically.
- `-gamever` or `-allgamever` is required; the analyzer no longer falls back to `GSVIBE_GAMEVER`. With `-modules` +
  `-allgamever`, tags declaring none of the requested modules are skipped.

## Analysis layers

Each DAG node runs two executable layers in order:

1. One skill-specific Preprocessor through a bound IDA MCP session (see [[idalib-mcp]]). A script receives LLM runtime
   configuration only when it explicitly declares `llm_config`, and returns `success`, `absent_ok`, `no_script`, or
   `failed`.
2. The configured Agent skill with bounded retries when fallback is required. The Agent runner validates per-CLI model
   arguments, injects the Codex developer prompt, drains stdout/stderr concurrently, and emits attempt-level structured
   diagnostics. MCP list preflight results are cached per Agent executable/server/normalized endpoint (success only).

`-skip_pp` bypasses the single Preprocessor and runs Agent skills directly. `-skip_error` lets later
module/platform/skill work continue after runtime failures, but configuration and DAG contract failures stay fatal and
any recorded runtime failure still yields a nonzero final exit status.

## Old-version handling

Raw old-YAML copying is disabled because copying address-bearing artifacts can preserve stale addresses. Automatic
old-version discovery (`-oldgamever`) is restricted to an older build in the same game family and is disabled by
`major_update: true`. The analyzer passes a new-output-to-old-YAML map to the Preprocessor so a skill-specific script
can relocate signatures through MCP and rebuild addresses.

## Current exclusions and deferrals

Plan preview remains removed (the internal builder serves real execution only). Generic Source2 vcall finding, Source2
RTTI/dispatch semantics, remote API hosting, C++ layout analysis, automatic version bumping, broad production signature
coverage, and target-specific generators remain excluded. Commercial IDA verification still requires a configured local
or self-hosted runner. Production finder coverage is declared in the game-version configs rather than maintained as a
separate documentation inventory. Shared primary/ordinal vtable helpers are explicit and fail closed; Source2-only
dispatch protocols are excluded.

## Validation

Planner/snapshot-contract reuse, cross-module edges, identity/category rules, batch membership, and old-version policy
are covered by `tests.test_analysis_planner` and the repository-contract suite. See [[full-analysis-concurrency]] for
batch scheduling, [[preprocess_func_xrefs_via_mcp]] for deterministic finder mechanics, and
[[gamesymbol PR validation candidate 基线复用]] for how PR validation reuses these artifacts.
