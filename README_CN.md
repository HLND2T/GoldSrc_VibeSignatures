# GoldSrc VibeSignatures

[English README](README.md) | [GUI](https://hlnd2t.github.io/GoldSrc_VibeSignatures/)

GoldSrc VibeSignatures 是一个面向 32 位 GoldSrc 游戏的、可复现的符号分析框架。它严格验证 Windows PE32/I386 与 Linux ELF32/I386 输入，按依赖 DAG 执行分析，记录不可变 candidate，并通过受控的 gamedata generator 生成按版本保存的 downstream gamedata。

正式配置覆盖 Half-Life build 10210、Counter-Strike build 10210、Sven Co-op build 10257 与 Cry of Fear build 5936。每个模块可只支持 Windows、只支持 Linux 或同时支持两者；每个已支持平台都必须成对声明 `module_<platform>` 与 `path_<platform>`。

## 快速开始

先安装[依赖](docs/zh-CN/requirements.md)，然后运行:

```bash
uv run ida_analyze_bin.py -allgamever -cache_mode cold -debug
```

该命令会执行分析流程并生成包含了GoldSrc游戏的符号信息的YAML产物。

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
