# GoldSrc VibeSignatures

[中文文档](README_CN.md) | [GUI](https://hlnd2t.github.io/GoldSrc_VibeSignatures/)

GoldSrc VibeSignatures is a reproducible Python 3.10+ framework for producing and publishing x86 game-symbol snapshots and versioned downstream gamedata. It validates Windows PE32/I386 and Linux ELF32/I386 inputs, executes a dependency-checked analysis DAG, records an immutable candidate, and exposes a strict local contract to downstream gamedata generators.

Production configuration covers Half-Life build 10210, Counter-Strike build 10210, Sven Co-op build 10257, and Cry of Fear build 5936. A module may target Windows, Linux, or both; each supported platform must declare a matching `module_<platform>` and `path_<platform>` pair.

## Quick start

Install the [requirements](docs/en/requirements.md), then prepare and analyze one game version:

```bash
uv sync --locked
uv run python download_depot.py -tag cstrike-10210 -depotdir depots
uv run python copy_depot_bin.py -gamever cstrike-10210 -platform all-platform
uv run python ida_analyze_bin.py -gamever cstrike-10210 -configyaml configs/cstrike-10210.yaml -platform windows,linux
```

These commands populate `bin/<GAMEVER>/` and run the configured deterministic, LLM-assisted, and Agent-assisted analysis. Continue with the immutable candidate, gamedata, and publication flow before publishing tracked outputs.

## Workflow

1. [Download the game depots and copy target binaries](docs/en/analysis.md#download-the-game-depots).
2. [Analyze symbols declared by `configs/<GAMEVER>.yaml`](docs/en/analysis.md#analyze-configured-symbols).
3. [Build one immutable symbol and gamedata candidate](docs/en/snapshot-and-gamedata.md#immutable-candidate-transaction).
4. [Publish the guarded candidate and gamedata](docs/en/snapshot-and-gamedata.md#immutable-candidate-transaction).

Canonical tracked outputs are `gamesymbols/<GAMEVER>.yaml` and `gamedata/<GAMEVER>/`. Per-symbol analysis YAML remains private mutable state under `bin/<GAMEVER>/`.

## Documentation

- [Requirements and environment setup](docs/en/requirements.md)
- [Development checks: formatting and tests](docs/en/development.md)
- [Binary acquisition and symbol analysis](docs/en/analysis.md)
- [Process reporting, scheduling, and dashboard](docs/en/process-monitoring.md)
- [Reference YAML for `LLM_DECOMPILE`](docs/en/reference-yaml.md)
- [Snapshots, gamedata, and publication](docs/en/snapshot-and-gamedata.md)
- [Creating symbol-analysis skills](docs/en/creating-skills.md)
- [CI/CD reference](docs/en/ci-cd.md)
- [Architecture](docs/en/architecture.md)
- [Gamedata generator contract](docs/en/generator-contract.md)

## Scope

This repository includes the Redis-backed process reporter, single-concurrency scheduler, read-only Process API/SSE, and the React dashboard with a static Symbol Explorer. Commercial IDA execution still requires the configured local/self-hosted environment; broad symbol coverage, automatic version bumping, remote API hosting, C++ layout extraction, and target-specific gamedata generators remain outside this repository's default hosted CI scope.

Licensed under the [MIT License](LICENSE.md).
