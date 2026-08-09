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

For each DAG node, `ida_analyze_bin.py` attempts four layers in order:

1. Reuse an old artifact only when every signature has one match in the new binary.
2. Run an optional deterministic script from `ida_preprocessor_scripts/<skill>.py`.
3. Run an optional LLM script from `ida_llm_preprocessor_scripts/<skill>.py`.
4. Run the configured Agent skill with bounded retries.

The binary is validated as 32-bit I386 before work and its SHA-256 is checked after every skill and again after the
whole job. IDA MCP routing binds calls to one exact active database by normalized binary identity.

## Snapshot boundary

The writer emits schema 5 with config digest v2, analysis-output contract version, UTC publication time, canonical
file payloads, and SHA-256/MD5/CRC32/CRC64/size metadata for every configured binary. The reader accepts schemas 1–5.
Restore and verification reject links, path escapes, undeclared YAML, missing required YAML, non-canonical bytes, and
contract drift.

The candidate manifest records the canonical candidate hash and filesystem identity. Publication is an atomic replace
and requires the guarded `gamedata` step. Candidate sessions do not contain a C++ test step.

## Deliberate exclusions

The framework has console and in-memory progress reporters only. It does not include a service API, UI, remote release
promotion, C++ layout analysis, automatic version bumping, or target-specific production signatures/generators.
