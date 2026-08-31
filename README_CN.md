# GoldSrc VibeSignatures

[English README](README.md) | [GUI](https://hlnd2t.github.io/GoldSrc_VibeSignatures/)

GoldSrc VibeSignatures 是一个面向 32 位 GoldSrc 游戏的、可复现的符号分析框架。

正式配置覆盖 Half-Life build 10210、Counter-Strike build 10210、Sven Co-op build 10257 与 Cry of Fear build 5936。

## 快速开始

先安装[依赖](docs/zh-CN/requirements.md)，然后运行:

```bash
uv run ida_analyze_bin.py -allgamever -debug
```

该命令会执行分析流程。单 symbol YAML 只在 `bin_artifacts/<gamever>/<module>/` 下读写；`bin/` 只保存二进制与
可重建的 IDA 状态。Analyzer 始终要求预先恢复 exact warm IDB generation；它不会在 consumer 中重建数据库，
也不会保存 consumer 侧修改。

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

## License

项目采用 [MIT License](LICENSE.md)。
