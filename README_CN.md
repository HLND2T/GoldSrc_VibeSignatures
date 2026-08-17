# GoldSrc VibeSignatures

[English README](README.md) | [GUI](https://hlnd2t.github.io/GoldSrc_VibeSignatures/)

GoldSrc VibeSignatures 是一个面向 32 位 GoldSrc 游戏的、可复现的符号分析框架。它严格验证 Windows PE32/I386 与 Linux ELF32/I386 输入，按依赖 DAG 执行分析，记录不可变 candidate，并通过受控的 gamedata generator 生成按版本保存的 downstream gamedata。

正式配置覆盖 Half-Life build 10210、Counter-Strike build 10210、Sven Co-op build 10257 与 Cry of Fear build 5936。每个模块可只支持 Windows、只支持 Linux 或同时支持两者；每个已支持平台都必须成对声明 `module_<platform>` 与 `path_<platform>`。

## 快速开始

先安装[依赖](docs/zh-CN/requirements.md)，再准备并分析一个游戏版本：

```bash
uv sync --locked
uv run python download_depot.py -tag cstrike-10210 -depotdir depots
uv run python copy_depot_bin.py -gamever cstrike-10210 -platform all-platform
uv run python ida_analyze_bin.py -gamever cstrike-10210 -configyaml configs/cstrike-10210.yaml -platform windows,linux
```

这些命令会填充 `bin/<GAMEVER>/`，并运行已配置的确定性、LLM-assisted 与 Agent-assisted 分析。发布 tracked output 前，还需继续执行 immutable candidate、gamedata 与发布流程。

## 工作流

1. [下载游戏 depots 并复制目标二进制](docs/zh-CN/analysis.md#下载游戏-depots)。
2. [分析 `configs/<GAMEVER>.yaml` 声明的符号](docs/zh-CN/analysis.md#分析配置的符号)。
3. [构建同一个 immutable symbol 与 gamedata candidate](docs/zh-CN/snapshot-and-gamedata.md#不可变-candidate-事务)。
4. [发布通过 guard 的 candidate 与 gamedata](docs/zh-CN/snapshot-and-gamedata.md#不可变-candidate-事务)。

canonical tracked output 是 `gamesymbols/<GAMEVER>.yaml` 与 `gamedata/<GAMEVER>/`。单个 symbol 的分析 YAML 仍作为私有可变状态保存在 `bin/<GAMEVER>/`。

## 文档

- [依赖与环境配置](docs/zh-CN/requirements.md)
- [开发检查：格式化与测试](docs/zh-CN/development.md)
- [二进制获取与符号分析](docs/zh-CN/analysis.md)
- [进度上报、调度与看板](docs/zh-CN/process-monitoring.md)
- [`LLM_DECOMPILE` reference YAML](docs/zh-CN/reference-yaml.md)
- [Snapshot、gamedata 与发布](docs/zh-CN/snapshot-and-gamedata.md)
- [创建符号分析 skill](docs/zh-CN/creating-skills.md)
- [CI/CD 参考](docs/zh-CN/ci-cd.md)
- [架构](docs/zh-CN/architecture.md)
- [Gamedata generator 合约](docs/zh-CN/generator-contract.md)

## 范围

本仓库包含 Redis-backed 进程上报、单并发 scheduler、只读 Process API/SSE 与带静态 Symbol Explorer 的 React dashboard。商业 IDA 执行仍需要已配置的本地或 self-hosted 环境；广泛的符号覆盖、自动版本 bump、远程 API hosting、C++ layout 提取与目标专属 gamedata generator 仍在本仓库默认 hosted CI 范围之外。

项目采用 [MIT License](LICENSE.md)。
