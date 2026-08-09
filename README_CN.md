# GoldSrc VibeSignatures

GoldSrc VibeSignatures 是面向 32 位 GoldSrc 游戏的可复现符号分析框架。它严格验证 Windows PE32/I386 与
Linux ELF32/I386，按依赖 DAG 执行分析，将平面 YAML 工件封装为 schema 5 快照，再通过不可变 candidate
事务交给受控的 gamedata generator。

正式配置覆盖 `cstrike-10120` 与 `svencoop-10257` 的 `engine`、`client`、`gameui`、`server` 四模块。
Sven Co-op 已加入首个 production finder：通过 `"R_RenderView: NULL worldmodel"` 在 `hw.dll` / `hw.so`
定位普通函数 `engine/R_RenderView`。

## 快速开始

```console
uv sync --locked
uv run python download_depot.py -tag cstrike-10120 -depotdir depots
uv run python copy_depot_bin.py -gamever cstrike-10120 -platform all-platform
uv run python ida_analyze_bin.py -gamever cstrike-10120 -configyaml configs/cstrike-10120.yaml -platform windows,linux
uv run python ida_analyze_bin.py -gamever svencoop-10257 -modules engine -skill find-R_RenderView -platform windows,linux -debug
```

完整候选构建、gamedata 门禁与发布命令见 [README.md](README.md)。架构和安全边界见
[docs/architecture_CN.md](docs/architecture_CN.md)，generator API 见
[docs/generator-contract_CN.md](docs/generator-contract_CN.md)。

## 分析与发布约束

- 当前分析顺序为单一 skill-specific Preprocessor → Agent fallback。Preprocessor 在绑定的 IDA MCP session 中运行，
  可显式声明 `llm_config` 以使用 LLM，并返回 `success`、`absent_ok`、`no_script` 或 `failed`。旧 YAML 不会被
  直接复制；`-oldgamever` 只选择同一 game family 的最近旧版本并把 old-YAML map 交给 Preprocessor。
  `download.yaml` 中的 `major_update: true` 会禁用自动旧版本选择。
- 工件输出固定为 `bin/<tag>/<module>/<symbol>.<platform>.yaml`；输入可使用受限的
  `../engine/X.{platform}.yaml` sibling 引用，并规范化为真实跨模块 DAG 边。逃逸 game-version root、重复名称、
  大小写冲突、环路和缺失必需输入均拒绝。
- Config symbol 只使用 `name + category`，严格拒绝 `type/kind`；artifact 按 category 使用 `func_name`、
  `gv_name`、`patch_name`、`vtable_class` 或 `struct_name/member_name`，不要求与 config `name` 相等。
- 支持 `func`、`gv`、`vfunc`、`vtable`、`patch`、`struct`、`structmember`。
- x86 `gv` 使用 `operand` 或排序后的 `data_xref`，可执行 0–2 次 32 位解引用。
- primary/ordinal vtable helper 必须显式使用并 fail closed；不移植 Source2 专用 dispatcher；x86 vfunc slot 固定为 4 字节。
- game-symbol 发布前必须通过受 guard 保护的 `gamedata` 步骤；零 generator 时允许空 inventory。

## Analyzer CLI 与环境变量

`ida_analyze_bin.py` 采用 CS2 风格 CLI，并使用 GoldSrc 专属的 `GSVIBE_*` 环境变量。优先级为显式 CLI、环境
变量、程序默认值；`.env.example` 是可复制的本地模板。支持：

- `GSVIBE_GAMEVER`；
- `GSVIBE_AGENT`、`GSVIBE_AGENT_MODEL`；
- `GSVIBE_LLM_MODEL`、`GSVIBE_LLM_APIKEY`、`GSVIBE_LLM_BASEURL`、`GSVIBE_LLM_TEMPERATURE`、
  `GSVIBE_LLM_FAKE_AS`、`GSVIBE_LLM_EFFORT`。

CLI 支持 `-configyaml`、逗号分隔的 `-platform` / `-modules`、`-skill`、`-agent`、`-agent_model`、全部
`-llm_*` 参数、`-maxretry`、`-oldgamever`、`-ida_args`、`-debug`、`-skip_error`、`-skip_pp` 和本地
`-console-events`。skill 显式 `max_retries` 优先于全局 `-maxretry`；`-skip_pp` 会跳过单一 Preprocessor 并直接
运行 Agent；`-skip_error` 只控制继续执行，只要存在失败最终仍返回非零。

Claude 与 OpenCode 会直接加载仓库内的 skill-runner policy。使用 Codex 前需把
`.codex/skill_runner.config.toml` 复制到 `$CODEX_HOME/skill_runner.config.toml`；runner 会通过
`--profile skill_runner` 选择该配置。Agent retry 会保持对应 CLI session、实时 drain 两条输出 pipe，并通过
progress reporter 上报结构化 attempt failure。

旧 `-config`、Analyzer 的 `all-platform` 和 `-plan-only` 已无 alias 删除。GoldSrc 排除 generic
`-vcall_finder`。存在待执行工作时，每个 binary 会在 `127.0.0.1:13337` 启动一次 owned `idalib-mcp`
生命周期，`-ida_args` 用于追加 IDA 启动参数。`-rename` 与 CS2 风格 process/Redis Reporter 的参数及环境变量
仍延期，现有本地 `-console-events` 保留。

## 本地门禁

```console
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
```

只有在 `RUN_IDA_INTEGRATION=1` 且 `idalib` 环境已激活时才运行真实 IDA 集成测试；跳过不代表真实 IDA 分析通过。

项目采用 [MIT License](LICENSE.md)。
