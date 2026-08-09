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
Outputs are module-local. Inputs may reference a sibling module with `../<module>/<artifact>`; the planner normalizes
both producer and consumer to one game-root-relative owner path and creates a real cross-module edge.

Config symbols use `name + category` and reject `type/kind`. Artifact payloads use category-specific identities
(`func_name`, `gv_name`, `patch_name`, `vtable_class`, or `struct_name/member_name`) and reject generic
`name/type/kind`. Payload identity is deliberately not compared with config symbol identity.

## Analysis layers

For each DAG node, `ida_analyze_bin.py` currently attempts two executable layers in order:

1. Run and process-cache `ida_preprocessor_scripts/<skill>.py` through a bound IDA MCP session. A script receives LLM
   runtime configuration only when it explicitly declares `llm_config`, and returns `success`, `absent_ok`, `no_script`,
   or `failed`.
2. Run the configured Agent skill with bounded retries when fallback is required.

The Agent runner validates per-CLI model arguments, keeps Claude/OpenCode retry sessions stable, injects the Codex
developer prompt, drains stdout/stderr concurrently, and emits attempt-level structured diagnostics through the local
reporter. MCP list preflight results are cached per Agent executable and server.

Raw old-YAML copying is disabled because copying address-bearing artifacts can preserve stale addresses. Automatic
old-version discovery is restricted to an older build in the same game family and is disabled by `major_update: true`.
The analyzer passes a new-output-to-old-YAML map to the Preprocessor so a skill-specific script can relocate signatures
through MCP and rebuild addresses. The shared GoldSrc x86 helper preserves the CS2 Finder API for function/vfunc,
global, patch, struct-member, primary/ordinal vtable, inherited slot, xref filtering, and validated LLM fallback.

The binary is validated as 32-bit I386 before work and its SHA-256 is checked after every skill and again after the
whole job. For each module/platform binary with pending work, the analyzer owns one `idalib-mcp` lifecycle: it checks
the IDB lock and port, starts the supervisor, waits for the MCP contract, binds the exact active database, validates
survey identity, allows one health recovery, and performs targeted owned-worker shutdown plus port release. Every
Preprocessor call binds that binary/database and receives a strictly parsed image base. Preprocessor and Agent outputs
pass the same YAML, symbol-schema, and current-IDB address validator. `-ida_args` is supported while `-rename` remains
deferred.

`-skip_pp` bypasses the single Preprocessor and runs Agent Skills directly. `-skip_error` allows later
module/platform/skill work to continue after runtime failures, while configuration and DAG contract failures remain
fatal and any recorded runtime failure still produces a nonzero final exit status.

## Snapshot boundary

The writer emits schema 5 with config digest v2, analysis-output contract version 2, UTC publication time, canonical
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
version bumping, broad production signature coverage, or target-specific generators. The first production finder is
`svencoop-10257/engine/R_RenderView`.
