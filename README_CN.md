# GoldSrc VibeSignatures

GoldSrc VibeSignatures 是面向 32 位 GoldSrc 游戏的可复现符号分析框架。它严格验证 Windows PE32/I386 与
Linux ELF32/I386，按依赖 DAG 执行分析，将平面 YAML 工件封装为 schema 5 快照，再通过不可变 candidate
事务交给受控的 gamedata generator。

正式配置覆盖 `hl-10120`、`cstrike-10120` 与 `svencoop-10257`；Half-Life 和 Sven Co-op 包含
`engine`、`client`、`gameui`、`server` 四模块，Counter-Strike 包含 `client`、`server`。
Half-Life 与 Sven Co-op 均已注册 `R_RenderView` production finder：通过
`"R_RenderView: NULL worldmodel"` 在 `hw.dll` / `hw.so` 定位普通函数 `engine/R_RenderView`。

## 快速开始

```console
uv sync --locked
uv run python download_depot.py -tag cstrike-10120 -depotdir depots
uv run python download_depot.py -all -depotdir depots
uv run python copy_depot_bin.py -gamever cstrike-10120 -platform all-platform
uv run python ida_analyze_bin.py -gamever cstrike-10120 -configyaml configs/cstrike-10120.yaml -platform windows,linux
uv run python ida_analyze_bin.py -gamever hl-10120 -modules engine -skill find-R_RenderView -platform windows,linux -debug
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
- `GSVIBE_PROCESS_REPORTER`（`none`、`console` 或 `redis`）、`GSVIBE_REDIS_URL`、
  `GSVIBE_REDIS_PREFIX`、`GSVIBE_RUN_ID`。
- `GSVIBE_API_HOST`、`GSVIBE_API_PORT`、`GSVIBE_API_CORS_ORIGINS`、
  `GSVIBE_API_ALLOW_PRIVATE_NETWORK`、`GSVIBE_SSE_BLOCK_MS`、`GSVIBE_SSE_BATCH_SIZE`。

CLI 支持 `-configyaml`、逗号分隔的 `-platform` / `-modules`、`-skill`、`-agent`、`-agent_model`、全部
`-llm_*` 参数、`-maxretry`、`-oldgamever`、`-ida_args`、`-debug`、`-skip_error`、`-skip_pp`、
`-process_reporter`、`-redis_url`、`-redis_prefix` 和 `-run_id`。skill 显式 `max_retries` 优先于全局
`-maxretry`；`-skip_pp` 会跳过单一 Preprocessor 并直接运行 Agent；`-skip_error` 只控制继续执行，只要存在失败
最终仍返回非零。`-process_reporter=console` 输出新的 typed `ProcessEvent` JSONL，`redis` backend 以
best-effort 方式写入 `gsvibe:analysis:v1` 协议。

Claude 与 OpenCode 会直接加载仓库内的 skill-runner policy。使用 Codex 前需把
`.codex/skill_runner.config.toml` 复制到 `$CODEX_HOME/skill_runner.config.toml`；runner 会通过
`--profile skill_runner` 选择该配置。Agent retry 会保持对应 CLI session、实时 drain 两条输出 pipe，并通过
progress reporter 上报结构化 attempt failure。

旧 `-config`、Analyzer 的 `all-platform` 和 `-plan-only` 已无 alias 删除。GoldSrc 排除 generic
`-vcall_finder`。存在待执行工作时，每个 binary 会在 `127.0.0.1:13337` 启动一次 owned `idalib-mcp`
生命周期，`-ida_args` 用于追加 IDA 启动参数。`-rename` 和 Source2 专用 finder 语义保持排除。旧
`ProgressEvent`、emit-only reporter、`-console-events` 与旧输出格式均不保留。

## 进程服务与 Dashboard

Analyzer 会把 versioned stage/job/task execution graph 上报到 Redis。`process_scheduler_cli.py submit` 只接受
`run_id`、`gamever`、`platforms`、`modules`、`skill_filter`、`agent`、`created_at` 这组最小 RunRequest；
`process_scheduler_cli.py run` 使用受控 argv/env 和可续期的 Redis 全局 lease，以 FIFO 单并发执行 Analyzer，并处理
heartbeat、pending `XAUTOCLAIM`、stale run 与未写终态的子进程退出；恢复终态会原子 abort 未完成 task 并重算 summary。

`process_api.py` 是只读 FastAPI 服务，在 `/api/v1` 下提供 run list/detail、snapshot、graph、task、event page
与 SSE，另有 `/healthz`、`/readyz`。SSE 支持 `Last-Event-ID`，游标早于 Redis 保留窗口时要求客户端重新加载
snapshot；默认 live 游标会先固定为具体 Stream ID，连接存续期间 trim 越过游标也会返回 reset。API 默认只绑定
loopback 且不内置认证；跨主机暴露时必须置于可信边界之后并配置精确 CORS origin。

`pages/` 中的 React dashboard 同时提供运行监控和静态 Symbol Explorer。GitHub Pages 只部署静态
`pages/dist`，不会托管 API/SSE；浏览器仍连接运行它的计算机上的 Process API。`pages-snapshots` 分支只允许
追加 `<family-build>.<sha256>.json`，构建、归档和部署后都会复核精确 bytes、size 与 SHA-256。

## 本地门禁

```console
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
uv run python tests/run_test_suite.py redis-integration -b --durations 30
```

前端门禁：

```powershell
cd pages
npm ci
npm test
npm run lint
npm run build
npm run verify:gamesymbols
npm run test:e2e
```

只有在 `RUN_IDA_INTEGRATION=1` 且 `idalib` 环境已激活时才运行真实 IDA 集成测试；跳过不代表真实 IDA 分析通过。

项目采用 [MIT License](LICENSE.md)。
