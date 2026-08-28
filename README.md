# GoldSrc VibeSignatures

[中文文档](README_CN.md) | [GUI](https://hlnd2t.github.io/GoldSrc_VibeSignatures/)

GoldSrc VibeSignatures is a reproducible game binary analysis framework for GoldSrc games.

Configuration covers Half-Life build 10210, Counter-Strike build 10210, Sven Co-op build 10257, and Cry of Fear build 5936.

## Quick start

Install the [requirements](docs/en/requirements.md), then:

```bash
uv run ida_analyze_bin.py -allgamever -debug
```

to run the analysis workflow to generate YAML artifacts for GoldSrc symbols. The Analyzer always requires exact warm
IDB generations to have been restored first; it never rebuilds databases or saves consumer-side changes.

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
