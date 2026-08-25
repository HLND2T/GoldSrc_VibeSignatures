# GoldSrc VibeSignatures

[中文文档](README_CN.md) | [GUI](https://hlnd2t.github.io/GoldSrc_VibeSignatures/)

GoldSrc VibeSignatures is a reproducible Python 3.10+ framework for producing and publishing x86 game-symbol snapshots and versioned downstream gamedata. It validates Windows PE32/I386 and Linux ELF32/I386 inputs, executes a dependency-checked analysis DAG, records an immutable candidate, and exposes a strict local contract to downstream gamedata generators.

Production configuration covers Half-Life build 10210, Counter-Strike build 10210, Sven Co-op build 10257, and Cry of Fear build 5936. A module may target Windows, Linux, or both; each supported platform must declare a matching `module_<platform>` and `path_<platform>` pair.

## Quick start

Install the [requirements](docs/en/requirements.md), then:

```bash
uv run ida_analyze_bin.py -allgamever -cache_mode cold -debug
```

to run the analysis workflow to generate YAML artifacts for GoldSrc symbols.

## Documentation

- [Requirements and environment setup](docs/en/requirements.md)
- [Development checks: formatting and tests](docs/en/development.md)
- [Binary acquisition and symbol analysis](docs/en/analysis.md)
- [Process reporting, scheduling, and dashboard](docs/en/process-monitoring.md)
- [Reference YAML for `LLM_DECOMPILE`](docs/en/reference-yaml.md)
- [Snapshots, gamedata, and publication](docs/en/snapshot-and-gamedata.md)
- [Protected release operations](docs/en/release-operations.md)
- [Creating symbol-analysis skills](docs/en/creating-skills.md)
- [CI/CD reference](docs/en/ci-cd.md)
- [Architecture](docs/en/architecture.md)
- [Gamedata generator contract](docs/en/generator-contract.md)

## License

Licensed under the [MIT License](LICENSE.md).
