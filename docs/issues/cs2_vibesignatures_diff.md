# GoldSrc 与 CS2 `ida_analyze_bin` infrastructure 差异

- 状态：Open
- 对比基线：`D:\CS2_VibeSignatures`
- 最后核对：2026-08-09
- 范围：`ida_analyze_bin` 入口、IDA/MCP 生命周期、preprocessor、Agent、配置与工件契约、进度上报、调度、测试和 CI

## 结论

当前 GoldSrc 实现已经具备严格的 x86 二进制校验、分析 DAG、四阶段回退、snapshot/candidate 和发布边界，
但整体仍属于“经过验证的分析框架骨架”，尚未达到 CS2 仓库中可实际执行、可恢复、可调度和可在
self-hosted IDA 环境持续运行的 infrastructure 水平。

最关键的缺口不是单一启动脚本，而是一组相互依赖的运行时契约：

1. production config、preprocessor 和 Agent skill 目前没有真实分析内容；
2. 主流程没有启动、绑定、验证、恢复和关闭 `idalib-mcp`；
3. GoldSrc preprocessor 接口与 CS2 的 MCP-bound 接口不兼容；
4. 旧版本工件复用会直接复制旧地址，存在生成陈旧 `VA/RVA` 的风险；
5. CLI 与环境变量已按本节决策对齐；配置 schema、artifact path、execution plan 和 reporter event 仍不兼容；
6. Redis reporter/scheduler、进度 API、dashboard 和 self-hosted IDA CI 尚不存在；
7. 部分缺口被当前文档和 repository-contract tests 明确禁止，不是偶然遗漏。

## 当前已有基础

以下能力已经存在，后续对齐时应复用，而不是从 CS2 整体重写：

- `binary_format.py` 在分析前严格验证 Windows PE32/I386 和 Linux ELF32/I386；
- `analysis_planner.py` 校验 tag、module/skill 名、artifact、重复 producer、大小写冲突、缺失输入和环路；
- `ida_analyze_bin.py` 在每个 skill 后和整个 run 结束时重新核对二进制 SHA-256，防止分析期间修改输入；
- 分析顺序固定为 history、deterministic、LLM、Agent；
- `ida_mcp_session.py` 已具备 database-bound session 和 binary identity 选择基础，但尚未接入主流程；
- snapshot schema 5、immutable candidate、gamedata guard 和原子发布已经建立；
- GoldSrc 的 flat artifact 和 x86 symbol 约束比 CS2 更严格，其中部分约束应作为目标特性保留。

关键出处：

- `ida_analyze_bin.py:29-30,240-305`
- `analysis_planner.py:14-16,87-98,268-341`
- `ida_mcp_session.py:72-133,152-204`
- `gamesymbol_snapshot_lib/operations.py:76-121`
- `gamesymbol_snapshot_lib/candidate.py`

## 优先级总览

| 优先级 | 缺口 | 直接影响 |
| --- | --- | --- |
| P0 | production config、preprocessor、Agent skill 为空 | Analyzer 无真实 DAG 节点，无法生成 production symbol YAML |
| P0 | 缺少 `idalib-mcp` 生命周期 | deterministic/LLM preprocessor 和 Agent 无可靠 IDA backend |
| P0 | history 直接复制旧 YAML | 新版本地址变化后可能保留陈旧 `VA/RVA` |
| P0 | config schema 仍不兼容 | CS2 config 不能直接复用 |
| P1 | MCP binary identity、IDB lock、健康检查和恢复未接线 | 可能连错 IDB、与交互式 IDA 冲突或在 MCP 断线后中止 |
| P1 | runtime input/output validation 不完整 | 建图成功后仍可能在执行期消费缺失或失效工件 |
| P1 | Agent runner 诊断和 session 管理较弱 | 失败原因不可追踪，retry 可能恢复错误的全局 session |
| P1 | execution plan 和 reporter contract 不兼容 | 无法接入 CS2 风格运行状态、任务图和可观测性消费者 |
| P2 | Redis scheduler/reporter、API、SSE、dashboard 缺失 | 无持久队列、恢复、heartbeat 和远程只读监控 |
| P2 | 缺少 Windows self-hosted IDA workflow | CI 无法证明真实 IDA 分析链可工作 |

## 1. Production 分析内容缺失

两份正式配置中的所有 module 都使用：

```yaml
skills: []
symbols: []
```

因此 `ida_analyze_bin.py` 当前只会解析配置、验证并哈希选中的二进制，然后完成空 DAG。仓库同时没有：

- `ida_preprocessor_scripts/`；
- `ida_llm_preprocessor_scripts/`；
- `.claude/skills/<skill>/SKILL.md`；
- `.claude/agents/sig-finder.md`；
- 可供 Codex、Claude 或 OpenCode 使用的 skill-runner settings。

`agent_runner.run_skill()` 强制要求 `.claude/skills/<skill>/SKILL.md` 存在，因而一旦 production config
加入无法由前置阶段生成的 skill，Agent fallback 会直接失败。

当前空配置还被 repository contract 明确锁定：

- `configs/cstrike-10120.yaml:1-21`
- `configs/svencoop-10257.yaml:1-21`
- `tests/test_repository_contract.py:29-36`
- `agent_runner.py:67-84`

### 对齐目标

- 至少为一个 GoldSrc module/platform 建立可真实运行的最小 production skill；
- skill name、config entry、preprocessor filename 和 `SKILL.md` 必须形成一一对应关系；
- deterministic preprocessor 优先，LLM 和 Agent 只作为有界 fallback；
- 修改 `test_production_configs_are_valid_empty_scaffolds`，不再把空配置当作长期 contract。

## 2. CLI 与环境变量契约

### GoldSrc 对齐状态（2026-08-09）

本轮已完成通用 CLI/环境变量契约对齐，并作出以下明确边界：

- 使用 `GSVIBE_*` namespace，不接受 `OPENAI_*` 或 `CS2VIBE_*` alias；
- 不保留旧 `-config` 或 Analyzer `all-platform` alias；
- `-plan-only` 和 preview 分支已删除，内部 DAG builder 只服务真实执行；
- generic `-vcall_finder` 排除；
- `-rename` 与 `-ida_args` 随 owned IDA MCP lifecycle 延期；
- CS2 process/Redis Reporter 本次延期，现有 `-console-events` 保留；
- old-version 自动选择限制在同 game family，`major_update: true` 可禁用；旧 YAML 直接复制先行禁用；
- 有效输入按 CS2 语义对齐，非法输入使用更严格的 fail-fast 校验。

### 参数差异

| 能力 | CS2 | GoldSrc |
| --- | --- | --- |
| Config 参数 | `-configyaml` | 已对齐，无 `-config` alias |
| Platform | `-platform=windows,linux` | 已对齐；拒绝 Analyzer `all-platform` |
| Game version fallback | `CS2VIBE_GAMEVER` | `GSVIBE_GAMEVER` |
| Agent 默认值 | `claude` | 已对齐；支持 `GSVIBE_AGENT` |
| Agent model | `-agent_model` / `CS2VIBE_AGENT_MODEL` | `-agent_model` / `GSVIBE_AGENT_MODEL` |
| LLM 参数 | `-llm_*` / `CS2VIBE_LLM_*` | `-llm_*` / `GSVIBE_LLM_*`；不再读取 `OPENAI_*` |
| IDA 参数 | `-ida_args` | 随 IDA MCP lifecycle 延期 |
| Retry | `-maxretry` 和 per-skill override | 已对齐；per-skill 显式值优先 |
| 控制行为 | `-skip_error`、`-skip_pp`、`-rename`、`-debug` | 已对齐 `skip_error` / `skip_pp` / `debug`；`rename` 延期 |
| Reporter | `-process_reporter`、Redis 参数、`-run_id` | 只有 `-console-events` |
| Old version | 自动寻找；`major_update` 可禁用 | 已对齐为同 game family 自动选择；原样复制旧 YAML 已禁用 |
| Plan preview | 无独立参数 | 已删除 `-plan-only` |

出处：

- GoldSrc：`ida_analyze_bin.py:443-688`
- CS2：`D:\CS2_VibeSignatures\ida_analyze_bin.py:1362-1538`
- GoldSrc LLM 环境：`ida_llm_decompile.py:15-75`

### 行为状态

- 不存在的 `-modules`、空或不存在的 `-skill`、重复/空 platform/module 值现在明确报错；
- unsupported Agent 在 CLI preflight 阶段明确报错；
- 默认输出配置回显和 success/fail/skip summary；
- `-skip_error` 只允许继续执行，最终只要存在失败仍返回非零状态；
- `-skip_pp` 会跳过 history、deterministic 和 LLM，直接进入 Agent；
- CS2 scheduler 的 `-configyaml` 与逗号 platform 可以复用，但 Reporter 环境变量仍不能直接传给 GoldSrc。

### 已落实规则

- 统一外部语义，不保留旧 GoldSrc CLI alias；
- 环境变量固定使用 `GSVIBE_*`，字段语义与 CS2 对齐；
- Plan preview 删除，真实执行继续使用统一 plan builder；
- 所有可预期配置、参数、Agent 和 preprocessor 错误应统一转为明确诊断和非零退出。

## 3. Config schema 与 DAG 契约差异

### Symbol schema

CS2 config 使用：

```yaml
- name: Example
  category: func
  alias:
    - Example::Alias
```

GoldSrc parser 要求：

```yaml
- name: Example
  type: func
```

GoldSrc 只读取 `type` 或 `kind`，不接受 CS2 的 `category`。同时两边对 `symbols` 的用途不同：

- CS2 使用 symbol category/alias 为 input validation、LLM 和 downstream gamedata 提供 metadata；
- GoldSrc 会根据 `symbols` 推导额外 required artifact，即使这些路径未由某个 skill output 声明；
- GoldSrc skill 自身还有 `aliases` 字段，但这不等价于 CS2 的 symbol alias map。

出处：

- GoldSrc：`analysis_planner.py:162-184,349-388`
- CS2 config 示例：`D:\CS2_VibeSignatures\configs\14174.yaml:51-73`
- CS2 alias/category map：`D:\CS2_VibeSignatures\ida_analyze_bin.py:289-318`

### Artifact path

GoldSrc 只允许 module 目录中的单层 `.yaml` 文件名，并明确拒绝 `../other/a.yaml`、`other/a.yaml`、绝对路径
和反斜杠路径。

CS2 允许 `../engine/Foo.{platform}.yaml` 形式的跨模块输入，只要解析后仍处于同一个 game-version root。
当前 CS2 production config 大量依赖该行为。

出处：

- GoldSrc：`analysis_planner.py:87-98`
- GoldSrc contract test：`tests/test_analysis_planner.py:81-94`
- CS2 resolver：`D:\CS2_VibeSignatures\ida_analyze_bin.py:2289-2304`
- CS2 config 示例：`D:\CS2_VibeSignatures\configs\14174.yaml:4099`

### DAG 和 plan schema

GoldSrc execution plan：

```text
ExecutionPlan(tag, nodes, edges)
PlanNode(module, platform, skill, inputs, outputs, prerequisites, ...)
```

CS2 execution plan：

```text
ExecutionPlan(schema_version, stages, jobs, nodes, edges, warnings)
stage -> module/platform job -> skill/vcall/post-process task
```

CS2 还建立 cross-stage artifact edge、stable task ID、layer 和 auxiliary nodes。GoldSrc 的 producer lookup 只在同一
module/platform 范围内发生。

出处：

- GoldSrc：`analysis_planner.py:23-59,268-341`
- CS2：`D:\CS2_VibeSignatures\process_reporter.py:69-151`
- CS2 plan builder：`D:\CS2_VibeSignatures\ida_analyze_bin.py:2217-2264`

### 对齐决策

需要明确选择以下之一：

1. 兼容 CS2 的跨模块 artifact contract，同时继续禁止逃逸 game-version root；
2. 保留 GoldSrc flat module contract，并接受 config、scheduler plan 和相关工具无法直接兼容。

如果目标是“尽可能贴近 CS2”，推荐第一种，但该改动属于 shared config/artifact contract 变更，必须同步修改
planner、snapshot contract、candidate、tests 和文档。

## 4. `idalib-mcp` 生命周期缺失

CS2 对每个 module/platform binary 执行以下流程：

```text
preflight skip
  -> 检查 <binary>.id0 lock
  -> 检查 127.0.0.1:13337 是否占用
  -> 启动 idalib-mcp --unsafe --host ... --port ... [ida_args] <binary>
  -> 等待 MCP ready
  -> 绑定唯一 active database session
  -> survey_binary 并核对 path/hash/platform
  -> 执行 skills/vcall/post-process
  -> MCP 故障时进行一次受限恢复
  -> 定向 qexit owned worker
  -> 停止本次启动的 supervisor 并等待端口释放
```

GoldSrc 当前只有 MCP client/session helper，`ida_analyze_bin.py` 没有：

- `start_idalib_mcp()`；
- port availability/readiness 检查；
- `.id0` lock 检查；
- opened binary survey 和 identity validation；
- supervisor/worker health check；
- bounded MCP restart；
- owned worker shutdown；
- port release wait；
- IDA startup timeout 和 shutdown timeout contract。

出处：

- GoldSrc 未接线 session：`ida_mcp_session.py:152-204`
- GoldSrc pipeline：`ida_analyze_bin.py:152-237`
- CS2 startup：`D:\CS2_VibeSignatures\ida_analyze_bin.py:2797-2850`
- CS2 binary processing：`D:\CS2_VibeSignatures\ida_analyze_bin.py:3105-3175`
- CS2 shutdown：`D:\CS2_VibeSignatures\ida_analyze_bin.py:1081-1180,3942-3951`

### `ida_mcp_session.py` 自身的版本差异

GoldSrc session 实现也少于 CS2：

- 没有 `McpDatabaseBinding.should_auto_quit`；
- tool error 不包含 MCP 返回的具体错误正文；
- database selection error 不输出完整 candidate summary；
- 没有 supervisor health helper；
- 没有对 nested `ExceptionGroup` 中 MCP contract error 的解包。

这些不是主阻塞；应先把现有 session 接入主流程，再补齐诊断和生命周期所有权语义。

## 5. Preprocessor 契约不兼容

GoldSrc 当前调用：

```python
preprocess_skill(skill_name, context=context) -> bool
preprocess_skill_with_llm(skill_name, context=context) -> bool
```

`context` 包含 tag、module、platform、binary path、输入输出路径和 skill aliases，但不包含 active MCP session、
image base、old YAML map、LLM runtime config 或 symbol alias map。

CS2 当前调用：

```python
await preprocess_single_skill_via_mcp(
    host,
    port,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    expected_inputs,
    optional_inputs,
    expected_binary,
    llm_config,
    symbol_aliases,
)
```

返回值为：

- `success`；
- `absent_ok`；
- `no_script`；
- `failed`。

该 status contract 决定是否成功、跳过、进入 Agent fallback 或报错。GoldSrc 的布尔值无法表达
“目标在该版本中合法不存在”和“没有 preprocessor script”的区别。

出处：

- GoldSrc：`ida_skill_preprocessor.py:16-48`
- GoldSrc context：`ida_analyze_bin.py:170-182`
- CS2：`D:\CS2_VibeSignatures\ida_skill_preprocessor.py:24-47,90-207`

### 额外语义差异

- GoldSrc 把 deterministic 和 LLM 分成两个目录及两个固定 stage；
- CS2 将 LLM-assisted 逻辑作为同一个 skill-specific preprocessor 的可选能力；
- GoldSrc 对只有 optional outputs 的 skill，Agent 成功退出即可被视为成功，即使没有生成 optional output；
- CS2 对 optional-only preprocessor 的合法无输出使用 skipped/`optional_output_absent` 表达；
- GoldSrc preprocessor runtime exception 的统一诊断范围不完整。

对齐时可以保留 GoldSrc 显式四阶段模型，但对外 status、MCP session 和 LLM config contract 应兼容 CS2 语义。

## 6. History reuse 会复制陈旧地址

当前缓解状态：旧 YAML 直接复制路径已禁用。Analyzer 仍解析/自动选择同 game family 的 `oldgamever` 并把旧目录
提供给分析上下文，但在后续 MCP-bound history migration 完成前不会用旧工件生成新 YAML。

此前的 GoldSrc `reuse_unique_history_artifact()`：

1. 读取旧 YAML；
2. 提取所有 `*_sig`；
3. 在新 binary bytes 中验证每个 signature 恰好命中一次；
4. 原样把旧 YAML 写到新版本目录。

该流程没有使用匹配位置重建：

- `func_va` / `func_rva`；
- `gv_va` / `gv_rva`；
- `patch_va` / `patch_rva`；
- vtable/vfunc 地址；
- function size、instruction displacement 或其他派生字段。

因此旧 signature 仍唯一时，GoldSrc 可能生成 signature 正确但地址属于旧版本的 YAML。

CS2 的 history reuse 是 category-aware preprocessor：它通过 MCP `find_bytes` 在新 IDB 中定位匹配，获取新的
function/global/patch metadata，并重建输出 YAML。例如 function reuse 会重新写入 `func_va`、`func_rva`、
`func_size`，必要时重新生成 `func_sig`。

出处：

- GoldSrc 当前缓解：`ida_analyze_bin.py:156-190,236-238`
- GoldSrc 移除前基线：`cabdc95:ida_analyze_bin.py:117-141,183-191`
- CS2 function reuse：`D:\CS2_VibeSignatures\ida_analyze_util.py:2839-2969,3238-3274`
- CS2 global reuse：`D:\CS2_VibeSignatures\ida_analyze_util.py:4717`
- CS2 patch reuse：`D:\CS2_VibeSignatures\ida_analyze_util.py:4883-4979`

### 对齐目标

- history stage 只复用可证明稳定的 signature/metadata，不复制旧绝对地址；
- 每种 symbol category 通过 MCP 重新定位并重算派生字段；
- 无法重建时进入 deterministic/LLM/Agent fallback；
- old-version 自动选择必须限制在相同 GoldSrc game family；
- `download.yaml` 应支持类似 `major_update` 的显式禁用策略；
- 为地址变化但 signature 不变的场景增加回归测试。

## 7. Runtime 输入、输出和失败语义不足

### Required input

GoldSrc 在 plan 构建时检查 required input 是否存在或有 producer，但执行 node 前不会再次检查文件状态。
它只把路径放入 preprocessor context。

CS2 每个 skill 执行前会：

- 重新解析 required/optional input；
- 拒绝同时声明为 required 和 optional 的同一路径；
- 明确报告缺失 required input；
- 记录缺失 optional input；
- 对 `func` / `vfunc` artifact 检查 YAML、`func_va`、segment 和 function-start identity；
- 对跨模块输入采用不同的地址验证边界。

出处：

- GoldSrc：`ida_analyze_bin.py:170-182`
- CS2：`D:\CS2_VibeSignatures\ida_analyze_bin.py:3295-3420`
- CS2 input artifact validation：`D:\CS2_VibeSignatures\ida_analyze_bin.py:451-536`

### Output

GoldSrc 在分析阶段主要以 required output 文件是否存在判定成功，内容 schema 和 canonicalization 延迟到
candidate build。CS2 同样依赖文件存在作为主要完成信号，但其 preprocessor、input validation 和 reporter
提供更细的失败原因。

### Skip/cache

两边都主要以 output 是否存在作为幂等 skip，并且都没有独立 `--force`。因此“缺少 `--force`”不是当前
GoldSrc 相对 CS2 的差异。共同风险是旧 artifact 可能因 binary/config/skill 变化而失效。

GoldSrc 额外提供 binary mutation SHA-256 guard，应保留。后续若加入 cache key，应至少考虑：

- binary identity；
- config digest；
- analysis-output contract version；
- skill/preprocessor implementation version。

### Fail-fast 与异常边界

GoldSrc 默认 fail-fast，但缺少 CS2 的：

- `-skip_error` opt-in continuation；
- success/fail/skip 计数；
- task abort reason；
- pending task finalization；
- reporter finalize/flush/close；
- unexpected exception 对 run 状态的兜底写入。

## 8. Agent runner 能力差异

GoldSrc 已支持 Claude、Codex 和 OpenCode 命令构造、MCP preflight、有界 retry 和 required output existence check，
但相对 CS2 仍缺少：

- `-agent_model` 和各 Agent 的 model 参数验证；
- Claude 独立 UUID session 和稳定 `--resume`；
- OpenCode session ID 提取和定向恢复；
- Codex `sig-finder.md` developer instructions 注入；
- Claude/OpenCode skill-runner settings；
- subprocess stdout/stderr 实时 drain，避免 pipe 缓冲阻塞；
- debug 时实时转发输出；
- timeout 后显式 kill/wait；
- `<skill_error>...</skill_error>` contract；
- cybersecurity block 检测；
- return code、timeout、missing output、missing Agent、missing skill 等结构化 reason；
- MCP preflight 成功/失败缓存；
- retry attempt 级 reporter event。

GoldSrc 当前捕获了 Agent stdout/stderr，但失败时不会把内容写入错误或事件，诊断能力明显不足。

出处：

- GoldSrc：`agent_runner.py:14-100`
- CS2：`D:\CS2_VibeSignatures\agent_runner.py:15-29,110-205,219-365,434-629`

## 9. Reporter 与 execution plan contract 不兼容

GoldSrc event：

```text
event, timestamp, tag, module, platform, skill, detail
```

仅有：

- `InMemoryReporter`；
- JSONL stdout `ConsoleReporter`；
- `NullReporter`。

CS2 event：

```text
run_id, event_type, task_id, status, phase, reason,
message, error, payload, occurred_at
```

同时定义：

- Run status state machine；
- Task status state machine；
- process phase 和 stable reason enum；
- immutable versioned execution graph；
- stage/job/task stable IDs；
- `initialize_run`、`heartbeat`、`finalize_run`、`flush`、`close`；
- best-effort wrapper，确保可观测性故障不改变 Analyzer 结果。

出处：

- GoldSrc：`process_reporter.py:11-46`
- CS2：`D:\CS2_VibeSignatures\process_reporter.py:11-182,193-247`

GoldSrc `ConsoleReporter` 可以作为本地调试 adapter 保留，但如果要接入 CS2 风格 scheduler/API，底层 domain
model 和 plan schema 需要先完成兼容。

## 10. Scheduler、恢复和监控缺失

CS2 Redis scheduler 使用结构化 `RunRequest`，而不是可执行 shell 字符串。核心 contract 为：

```text
run_id
gamever
platforms
modules
skill_filter
agent
created_at
```

它提供：

- Redis Stream Consumer Group；
- FIFO 单并发 IDA worker；
- `xautoclaim` 回收 pending entry；
- heartbeat 存活检查和防重复启动；
- terminal run 防重复执行；
- 受控 argv 构造；
- Analyzer reporter/run ID 环境注入；
- scheduler restart 后的 stale/aborted 处理；
- Analyzer 未写 final status 时根据 exit code 补齐结果。

出处：

- `D:\CS2_VibeSignatures\process_scheduler_redis.py:22-100,110-220,223-307`
- `D:\CS2_VibeSignatures\process_scheduler_cli.py:25-103`

GoldSrc 当前没有 Redis 依赖、scheduler、reporter backend、heartbeat 或持久状态。并且
`tests/test_repository_contract.py:40-47` 明确禁止 `process_reporter_redis` 出现在 runtime 代码中。

### API 和 dashboard

CS2 还提供：

- `process_api.py`；
- run list、snapshot、task、event 和 SSE API；
- snapshot + `Last-Event-ID` 恢复协议；
- health/readiness；
- CORS 和 private-network 安全配置；
- `pages/` React dashboard。

GoldSrc `docs/architecture_CN.md:40-43` 和 `README.md:71-74` 明确将 service、scheduler 和 UI 排除在范围外。
若要最大程度贴近 CS2，需要先修改这一架构决策，而不是只添加实现文件。

## 11. 测试与 CI 缺口

GoldSrc 当前真实 IDA integration test 只在 `RUN_IDA_INTEGRATION=1` 时验证 `idaapi` 和 `idalib` 是否可 import：

```python
self.assertIsNotNone(importlib.util.find_spec("idaapi"))
self.assertIsNotNone(importlib.util.find_spec("idalib"))
```

它没有验证：

- `idalib-mcp` 能否启动；
- MCP tools/list contract；
- database routing；
- opened binary identity；
- preprocessor 能否通过真实 MCP 生成 YAML；
- Agent 是否能连接所需 MCP server；
- MCP recovery 和 owned shutdown；
- Redis reporter/scheduler；
- Analyzer CLI end-to-end exit behavior。

出处：`tests/test_ida_integration.py:8-12`。

GoldSrc CI 只在 hosted Ubuntu/Windows runner 上执行 formatting、unit、repository-contract 和 all suite，
不安装商业 IDA，也不运行真实 Analyzer。

CS2 self-hosted workflow 额外执行：

- exact source checkout；
- persisted depot/bin workspace；
- immutable analysis config SHA-256；
- 多层 test suite；
- cached binary `-checkonly`；
- 缺失 binary 下载；
- 真实 `ida_analyze_bin.py`；
- immutable symbol/gamedata candidate；
- C++ ABI 验证；
- guarded publication 和 staging cleanup。

出处：

- GoldSrc：`.github/workflows/ci.yaml:1-25`
- CS2：`D:\CS2_VibeSignatures\.github\workflows\build-on-self-runner.yml:108-286`

对 GoldSrc 的第一阶段 CI 对齐不需要移植 CS2 的 C++/HL2SDK 流程，但至少需要一个受控的 Windows
self-hosted IDA smoke/analyze workflow，并明确区分“IDA 环境可 import”和“真实分析成功”。

## 当前仓库策略阻塞

以下差异被当前仓库主动定义为 contract：

1. production config 必须保持空 `skills` / `symbols`；
2. runtime 代码禁止包含 `process_reporter_redis`；
3. README/architecture 明确排除 scheduler、service、UI、C++ layout 和 production symbols；
4. flat artifact 必须留在当前 module 目录，禁止跨模块 artifact path。

相关出处：

- `tests/test_repository_contract.py:29-47`
- `tests/test_analysis_planner.py:81-94`
- `README.md:71-74`
- `docs/architecture_CN.md:40-43`

因此，最大程度对齐 CS2 不是普通局部实现，而是一次明确的 contract 和范围调整。实现前需要同步更新：

- repository-contract tests；
- architecture 和 README；
- config schema/version；
- analysis-output contract version；
- snapshot/candidate contract；
- CLI 和 automation documentation。

## 不应机械移植的 CS2 专属能力

以下能力与 Source2/CS2 目标强绑定，不属于 `ida_analyze_bin` 通用 infrastructure 的必需部分：

- 通用 `vcall_finder` 和 Source2 object aggregation；
- Source2 rename/comment post-process；
- HL2SDK_CS2 headers 和 C++ ABI layout 测试；
- CS2-specific gamedata generators；
- CS2 automatic version bump 和 release promotion；
- 64 位 virtual-function slot、RTTI 和 Source2 特定 symbol 查找策略。

GoldSrc 应保留：

- x86 vfunc slot 固定 4 字节；
- PE32/ELF32 格式门禁；
- 不提供隐式通用 RTTI/vtable finder；
- GoldSrc game tag 和 depot 布局；
- binary mutation 检测；
- 当前 immutable candidate/gamedata guard。

目标应是对齐“外部 contract、生命周期、恢复、可观测性和自动化”，而不是复制 Source2-specific 分析语义。

## 推荐实施顺序

### Phase 1：统一外部 contract

- 兼容 CS2 语义的 CLI 和 `GSVIBE_*` 环境变量（已完成）；
- 明确 `category` 与 `type/kind` 的兼容策略；
- module/skill validation 已修复，`plan-only` 已删除；
- 决定是否支持 game-root 内跨模块 artifact；
- 定义 versioned execution plan 和 event schema（Reporter 本次延期）；
- 更新 repository-contract tests 和架构文档。

验收标准：同一组 module/platform/skill filter 在直接执行和未来 scheduler 中生成相同 execution graph；不再提供
独立 preview 入口。

### Phase 2：接入 IDA runtime

- 实现 `idalib-mcp` start/readiness/lock/identity/shutdown；
- 将 `ida_mcp_session` 接入 analyzer；
- 增加 bounded health recovery；
- 保留 binary mutation guard；
- 建立真实 IDA smoke test。

验收标准：可以对一个已知 GoldSrc PE32/ELF32 binary 启动 MCP、验证打开目标、执行 `py_eval`，并只关闭本次拥有的 worker。

### Phase 3：统一 preprocessor 和 history

- 定义 MCP-bound status contract；
- 传递 old YAML map、expected/optional inputs、LLM config 和 symbol aliases；
- 将 history reuse 改为 category-aware 地址重建；
- 增加 runtime input validation；
- 建立第一个 production preprocessor 和 skill。

验收标准：旧 signature 地址发生变化时，新 YAML 中的 `VA/RVA` 来自新 IDB；无法证明唯一性时进入后续 fallback。

### Phase 4：补齐 Agent 和失败模型

- port CS2 Agent session/model/output/error handling；
- 添加 success/fail/skip summary；
- 添加 fail-fast 与 `skip_error`；
- 确保所有 terminal task 和 run 都被 finalize；
- 为 Agent、preprocessor、MCP 和 missing artifact 定义稳定 reason。

验收标准：每种失败路径都有明确非零退出、结构化 reason 和足够诊断信息，retry 不会恢复无关 session。

### Phase 5：调度、监控和 CI

- Redis reporter 和 best-effort adapter；
- 单并发 Redis scheduler、heartbeat 和 pending recovery；
- 可选只读 API/SSE/dashboard；
- Windows self-hosted IDA analyze workflow；
- candidate guard 和现有发布流程集成。

验收标准：scheduler 重启后不会重复启动仍有 heartbeat 的 Analyzer；stale pending run 可以被确定性回收或终止。

## 完成定义

当以下条件全部满足时，可认为 GoldSrc 的 `ida_analyze_bin` infrastructure 已基本贴近 CS2：

- 至少一个 production config 含真实 skill/symbol 并能生成 YAML；
- Analyzer 自己拥有完整的 `idalib-mcp` 生命周期；
- opened IDB 与预期 binary identity 始终被验证；
- preprocessor、history 和 Agent fallback 使用稳定、可测试的统一 contract；
- history reuse 不复制旧地址；
- CLI/config/plan/event contract 可供 scheduler 和 CI 稳定调用；
- 失败状态、退出码、retry 和 skip 行为有测试覆盖；
- Redis scheduler/reporter 或明确等价实现支持持久恢复；
- Windows self-hosted workflow 至少验证一次真实 GoldSrc IDA 分析；
- x86、flat output、candidate 和 GoldSrc-specific 安全边界未被 Source2 假设破坏。
