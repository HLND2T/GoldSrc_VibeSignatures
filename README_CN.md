# GoldSrc VibeSignatures

GoldSrc VibeSignatures 是面向 32 位 GoldSrc 游戏的可复现符号分析框架。它严格验证 Windows PE32/I386 与
Linux ELF32/I386，按依赖 DAG 执行分析，将平面 YAML 工件封装为 schema 5 快照，再通过不可变 candidate
事务交给受控的 gamedata generator。

首期正式配置覆盖 `cstrike-10120` 与 `svencoop-10257` 的 `engine`、`client`、`gameui`、`server` 四模块，
但 `skills` 和 `symbols` 均为空；仓库不会虚构生产签名。

## 快速开始

```console
uv sync --locked
uv run python download_depot.py -tag cstrike-10120 -depotdir depots
uv run python copy_depot_bin.py -gamever cstrike-10120 -platform all-platform
uv run python ida_analyze_bin.py -gamever cstrike-10120
```

完整候选构建、gamedata 门禁与发布命令见 [README.md](README.md)。架构和安全边界见
[docs/architecture_CN.md](docs/architecture_CN.md)，generator API 见
[docs/generator-contract_CN.md](docs/generator-contract_CN.md)。

## 分析与发布约束

- 分析顺序固定为：旧版本唯一签名复用 → deterministic preprocessor → LLM preprocessor → Agent skill。
- 工件固定为 `bin/<tag>/<module>/<symbol>.<platform>.yaml`；跨目录路径、重复名称、大小写冲突、环路和缺失必需输入均拒绝。
- 支持 `func`、`gv`、`vfunc`、`vtable`、`patch`、`struct`、`structmember`。
- x86 `gv` 使用 `operand` 或排序后的 `data_xref`，可执行 0–2 次 32 位解引用。
- 不提供隐式 RTTI 或通用 vtable finder；x86 vfunc slot 固定为 4 字节。
- game-symbol 发布前必须通过受 guard 保护的 `gamedata` 步骤；零 generator 时允许空 inventory。

## 本地门禁

```console
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
```

只有在 `RUN_IDA_INTEGRATION=1` 且 `idalib` 环境已激活时才运行真实 IDA 集成测试；跳过不代表真实 IDA 分析通过。

项目采用 [MIT License](LICENSE.md)。
