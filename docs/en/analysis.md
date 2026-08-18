[Back to README](../../README.md) | [中文](../zh-CN/analysis.md)

# Binary acquisition and symbol analysis

## Download the game depots

Download the configured depot version, then copy the target binaries into the workspace:

```bash
uv run python download_depot.py -tag cstrike-10210 -depotdir depots
uv run python download_depot.py -all -depotdir depots

uv run python copy_depot_bin.py -gamever cstrike-10210 -platform all-platform
uv run python copy_depot_bin.py -gamever cstrike-10210 -platform windows -checkonly
```

- `download_depot.py -tag <tag>` downloads a single release tag; `-all` downloads every tag declared in the download config. `-os` selects `windows`, `linux`, `macos`, or `all` (default). `download.yaml` only controls downloading; it is separate from `configs/config.yaml`, which controls batch analysis.
- `copy_depot_bin.py -platform` accepts `windows`, `linux`, or `all-platform`. `-checkonly` only checks that all expected target binaries already exist under `bin/<gamever>/...`: it returns `0` when ready, `1` when any target is missing, and `2` for configuration or argument errors.

Use `/init-gamebin` to bootstrap the `depots/` and `bin/` trees for every tag in `download.yaml`.

### Blob game binaries

Some old GoldSrc builds ship non-PE Metahook "blob" binaries. Use the `/decrypt-blob-gamebin` slash command (or `decrypt_blob.py`) to convert every non-PE blob under `bin/` into a regular PE32 DLL before analysis. Valid PE/ELF binaries, IDA databases, and YAML artifacts are skipped.

## Analyze configured symbols

The Analyzer finds and generates signatures for symbols declared in `configs/<GAMEVER>.yaml`.

Command synopsis:

```bash
uv run python ida_analyze_bin.py -gamever cstrike-10210 -configyaml configs/cstrike-10210.yaml -platform windows,linux
uv run python ida_analyze_bin.py -gamever hl-10210 -modules engine -skill find-R_RenderView -platform windows,linux -debug
```

`-gamever` or `-allgamever` is required — the analyzer no longer falls back to `GSVIBE_GAMEVER`. Supported arguments:

- `-configyaml` selects an explicit analysis config (defaults to `configs/<GAMEVER>.yaml`).
- Comma-separated `-platform` (`windows`, `linux`) and `-modules`.
- `-skill=<exact-name>` only runs an exact skill name within the active `-modules` filter.
- `-agent` and `-agent_model` select the Agent CLI and model.
- The matching `-llm_model`, `-llm_apikey`, `-llm_baseurl`, `-llm_temperature`, `-llm_effort`, and `-llm_fake_as` arguments configure LLM-backed workflows.
- `-maxretry` bounds Agent retries; per-skill `max_retries` overrides it.
- `-oldgamever` selects the latest older build from the same game family and passes an old-YAML map to the Preprocessor. A `major_update: true` download entry disables automatic old-version selection. Raw old-YAML copying remains disabled.
- `-ida_args` appends IDA startup arguments. `-rename` and Source2-only finder semantics remain excluded.
- `-skip_pp` bypasses the single Preprocessor and runs the Agent directly. `-skip_error` continues after runtime failures but the final exit status remains nonzero.
- `-process_reporter=console` emits typed `ProcessEvent` JSONL; `redis` is best-effort and writes the `gsvibe:analysis:v1` Redis protocol. `-redis_url` and `-redis_prefix` configure the Redis backend; `-run_id` sets the run identity.
- `-debug` enables debug output.

### Batch analysis with `-allgamever`

`ida_analyze_bin.py -allgamever` batches every game-version tag declared in `configs/config.yaml`. That index is the single authority for batch membership and order; a tag only runs when explicitly listed, and a declared tag whose `configs/<tag>.yaml` is missing is a fatal configuration error rather than a silent skip. Without `configs/config.yaml` the legacy order is used for compatibility: the `download.yaml` manifest declaration order, then remaining `configs/*.yaml` tags in lexical order.

When `-modules` is used with `-allgamever`, tags that declare none of the requested modules are skipped; a single `-gamever` run still reports a missing requested module as an error.

## Analysis contract

Analysis order is one skill-specific Preprocessor followed by Agent fallback. The Preprocessor runs through a bound IDA MCP session, may explicitly opt into `llm_config`, and returns `success`, `absent_ok`, `no_script`, or `failed`.

Required and optional artifacts plus explicit prerequisites form one DAG. Outputs stay module-local; inputs may use a safe sibling reference such as `../engine/X.{platform}.yaml`, normalized within the game-version root and connected as a real cross-module DAG edge. Unsafe paths, cycles, duplicate or case-colliding names, missing required inputs, wrong architectures, and binary mutation are fatal.

### Artifact paths and identity

The artifact path is `bin/<tag>/<module>/<symbol>.<platform>.yaml`. Config symbols use `name` plus the sole classifier `category`; `type` and `kind` are rejected. Artifacts reject generic `name/type/kind` and use `func_name`, `gv_name`, `patch_name`, `vtable_class`, or `struct_name/member_name` according to category. Payload identity is not required to equal the config symbol name, matching the CS2 loader contract.

Supported categories are `func`, `gv`, `vfunc`, `vtable`, `patch`, `struct`, and `structmember`. Shared primary/ordinal vtable helpers are explicit and fail closed; Source2-only dispatch protocols are excluded. x86 virtual-function slots are four bytes.

### Old-version handling

Raw old-YAML copying is disabled because copying address-bearing artifacts can preserve stale addresses. Automatic old-version discovery is restricted to an older build in the same game family and is disabled by `major_update: true`. The analyzer passes a new-output-to-old-YAML map to the Preprocessor so a skill-specific script can relocate signatures through MCP and rebuild addresses.

## Production finders

Half-Life and Sven Co-op register the production finder `engine/R_RenderView`, anchored by `"R_RenderView: NULL worldmodel"` in `hw.dll` and `hw.so`. Additional finders registered across the engine modules include `find-SV_SendServerinfo`, `find-build_number`, `find-Sys_Error`, `find-ClientDLL_Init`, `find-DispatchDirectUserMsg`, `find-DispatchDirectUserMsg-decompiles`, `find-Cvar_DirectSet`, and `find-FreeBlob`. The Windows-only `find-NLoadBlob*` chain is not registered for Sven Co-op. See [Creating symbol-analysis skills](creating-skills.md).
