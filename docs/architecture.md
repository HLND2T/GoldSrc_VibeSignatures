# Architecture

## Data flow

```text
download.yaml + configs/<tag>.yaml
  -> depots/<basepath>
  -> bin/<tag>/<module>/<binary>
  -> validated analysis DAG
  -> bin/<tag>/<module>/<symbol>.<platform>.yaml
  -> immutable candidate
  -> gamesymbols/<tag>.yaml
  -> SymbolStore -> strict gamedata generator
```

`analysis_planner.py` is the single source for module, symbol, artifact-path, and DAG validation. Snapshot contracts
reuse it, so an output accepted by analysis cannot silently acquire different ownership at publication time.

## Analysis layers

For each DAG node, `ida_analyze_bin.py` currently attempts three executable layers in order:

1. Run an optional deterministic script from `ida_preprocessor_scripts/<skill>.py`.
2. Run an optional LLM script from `ida_llm_preprocessor_scripts/<skill>.py` with explicit runtime LLM configuration.
3. Run the configured Agent skill with bounded retries.

The history stage name remains reserved, but raw old-YAML reuse is disabled because copying address-bearing artifacts
can preserve stale addresses. Automatic old-version discovery is restricted to an older build in the same game family
and is disabled by `major_update: true`. The selected old directory is context only until an MCP-bound implementation
can relocate signatures and rebuild addresses.

The binary is validated as 32-bit I386 before work and its SHA-256 is checked after every skill and again after the
whole job. `ida_mcp_session.py` can bind calls to one exact active database by normalized binary identity, but the
analyzer does not yet own the IDA MCP startup, validation, recovery, or shutdown lifecycle. Consequently `-ida_args`
and `-rename` remain deferred.

`-skip_pp` bypasses history plus both preprocessor layers and runs Agent Skills directly. `-skip_error` allows later
module/platform/skill work to continue after runtime failures, while configuration and DAG contract failures remain
fatal and any recorded runtime failure still produces a nonzero final exit status.

## Snapshot boundary

The writer emits schema 5 with config digest v2, analysis-output contract version, UTC publication time, canonical
file payloads, and SHA-256/MD5/CRC32/CRC64/size metadata for every configured binary. The reader accepts schemas 1–5.
Restore and verification reject links, path escapes, undeclared YAML, missing required YAML, non-canonical bytes, and
contract drift.

The candidate manifest records the canonical candidate hash and filesystem identity. Publication is an atomic replace
and requires the guarded `gamedata` step. Candidate sessions do not contain a C++ test step.

## Current exclusions and deferrals

The framework has console and in-memory progress reporters only. CS2 process/Redis Reporter integration is deferred;
the CLI does not expose its backend, Redis, or run-ID settings. Plan preview was deliberately removed, while the
internal execution-plan builder remains the source of the real DAG. Generic Source2 vcall finding is excluded.

The repository currently does not include a service API, UI, remote release promotion, C++ layout analysis, automatic
version bumping, or target-specific production signatures/generators.
