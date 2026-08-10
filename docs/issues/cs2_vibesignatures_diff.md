# GoldSrc 与 CS2 `ida_analyze_bin` infrastructure 差异

- 状态：Open
- 对比基线：`D:\CS2_VibeSignatures`
- 最后核对：2026-08-10
- 范围：`ida_analyze_bin` 入口、IDA/MCP 生命周期、preprocessor、Agent、配置与工件契约、进度上报、调度、测试和 CI

## 结论

当前 GoldSrc 实现已经具备严格的 x86 二进制校验、跨模块分析 DAG、单一 Preprocessor → Agent
回退、category-aware history relocation、snapshot/candidate 和发布边界，并已加入首个双平台
production finder `find-R_RenderView`。尚未对齐的主体已收敛到 Reporter/scheduler、self-hosted IDA CI
以及更大规模的 production symbol coverage。

最关键的缺口不是单一启动脚本，而是一组相互依赖的运行时契约：

1. 首个 production config/preprocessor/skill 已建立，但覆盖面仍很小；
2. Preprocessor 的 MCP-bound status/input/helper contract 与真实 Windows/Linux IDA smoke 均已完成；
3. history reuse 已按 category 在新 IDB 中重建地址和派生字段，不再复制旧地址；
4. config `name + category`、category-specific artifact identity、安全 sibling input 和跨模块 DAG 已对齐；
5. Redis reporter/scheduler、进度 API、dashboard 和 self-hosted IDA CI 尚不存在。

## 当前已有基础

以下能力已经存在，后续对齐时应复用，而不是从 CS2 整体重写：

- `binary_format.py` 在分析前严格验证 Windows PE32/I386 和 Linux ELF32/I386；
- `analysis_planner.py` 校验 tag、module/skill 名、artifact、重复 producer、大小写冲突、缺失输入和环路；
- `ida_analyze_bin.py` 在每个 skill 后和整个 run 结束时重新核对二进制 SHA-256，防止分析期间修改输入；
- 分析顺序固定为单一 skill-specific Preprocessor、Agent fallback；
- `ida_mcp_session.py` 已接入主流程；Analyzer 按 binary 拥有 startup、binding、identity、recovery 和 shutdown；
- snapshot schema 5、immutable candidate、gamedata guard 和原子发布已经建立；
- GoldSrc 保留 module-local output、PE32/ELF32 和 4-byte vfunc slot 约束；input 已支持受限 sibling-module path。

关键出处：

- `ida_analyze_bin.py:29-30,240-305`
- `analysis_planner.py:14-16,87-98,268-341`
- `ida_mcp_session.py:72-133,152-204`
- `gamesymbol_snapshot_lib/operations.py:76-121`
- `gamesymbol_snapshot_lib/candidate.py`

## 优先级总览

| 优先级 | 缺口 | 直接影响 |
| --- | --- | --- |
| 已完成 | 首个 production config/preprocessor/skill | `svencoop-10257/engine/R_RenderView` 已形成真实 DAG 节点 |
| 已完成 | config/artifact/helper schema 对齐 | `category`、专用 identity、跨模块 input 和 Finder API 已对齐 |
| P1 | execution plan 和 reporter contract 不兼容 | 无法接入 CS2 风格运行状态、任务图和可观测性消费者 |
| 已完成 | 真实 IDA Preprocessor/validator smoke | `hw.dll` / `hw.so` 双平台分析均由 Preprocessor 成功产出并通过 runtime validator |
| P2 | Redis scheduler/reporter、API、SSE、dashboard 缺失 | 无持久队列、恢复、heartbeat 和远程只读监控 |
| P2 | 缺少 Windows self-hosted IDA workflow | CI 无法证明真实 IDA 分析链可工作 |

`idalib-mcp` lifecycle、database binding、identity validation、IDB lock、健康检查、一次恢复预算、owned shutdown、
Preprocessor contract 和 runtime input/output validation 已补齐；本地真实 IDA smoke 于 2026-08-10 完成。
尚未完成的是把同一 smoke 固化为 Windows self-hosted CI。

## 1. Production 分析内容（首个 finder 已建立）

`configs/svencoop-10257.yaml` 的 engine module 已注册：

```yaml
skills:
  - name: find-R_RenderView
    expected_output:
      - R_RenderView.{platform}.yaml
symbols:
  - name: R_RenderView
    category: func
```

对应实现：

- `ida_preprocessor_scripts/find-R_RenderView.py`；
- `.claude/skills/find-R_RenderView/SKILL.md`；
- `.claude/skills/create-preprocessor-scripts/` 及 A/B/C/D/E/F/H/I/L/M references。

Finder 通过 `xref_strings: ["R_RenderView: NULL worldmodel"]` 定位 `hw.dll` / `hw.so` 中的普通函数，
artifact 使用 `func_name` 身份字段。

`agent_runner.run_skill()` 强制要求 `.claude/skills/<skill>/SKILL.md` 存在，因而一旦 production config
加入无法由前置阶段生成的 skill，Agent fallback 会直接失败。

Repository contract 已改为验证该 production finder，而不是锁定空配置：

- `configs/cstrike-10120.yaml:1-21`
- `configs/svencoop-10257.yaml:1-21`
- `tests/test_repository_contract.py` 的 `test_sven_engine_registers_r_renderview_production_finder`
- `agent_runner.py:67-84`

### 后续目标

- 将已通过的 Windows/Linux 真实 IDA smoke 固化到受控 self-hosted workflow；
- 继续按同一 contract 增加 production symbols；
- 保持单一 skill-specific Preprocessor 优先，LLM 显式 opt-in，Agent 仅作有界 fallback。

## 2. CLI 与环境变量契约

### GoldSrc 对齐状态（2026-08-09）

本轮已完成通用 CLI/环境变量契约对齐，并作出以下明确边界：

- 使用 `GSVIBE_*` namespace，不接受 `OPENAI_*` 或 `CS2VIBE_*` alias；
- 不保留旧 `-config` 或 Analyzer `all-platform` alias；
- `-plan-only` 和 preview 分支已删除，内部 DAG builder 只服务真实执行；
- generic `-vcall_finder` 排除；
- `-ida_args` 已随 owned IDA MCP lifecycle 恢复；`-rename` 仍延期；
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
| IDA 参数 | `-ida_args` | 已对齐 |
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
- `-skip_pp` 会跳过单一 Preprocessor，直接进入 Agent；
- CS2 scheduler 的 `-configyaml` 与逗号 platform 可以复用，但 Reporter 环境变量仍不能直接传给 GoldSrc。

### 已落实规则

- 统一外部语义，不保留旧 GoldSrc CLI alias；
- 环境变量固定使用 `GSVIBE_*`，字段语义与 CS2 对齐；
- Plan preview 删除，真实执行继续使用统一 plan builder；
- 所有可预期配置、参数、Agent 和 preprocessor 错误应统一转为明确诊断和非零退出。

## 3. Config schema 与 DAG 契约（已对齐）

### Symbol 与 artifact schema

GoldSrc config 现在与 CS2 一样只接受：

```yaml
- name: Example
  category: func
  alias:
    - Example::Alias
```

`category` 是唯一分类字段，严格拒绝 `type/kind`。分类集合为
`func/gv/vfunc/vtable/patch/structmember/struct`；`structmember` 必须引用同 module 已声明的 parent
`struct`。

Artifact 严格拒绝通用 `name/type/kind`，按 category 使用 `func_name`、`gv_name`、`patch_name`、
`vtable_class` 或 `struct_name/member_name`。与 CS2 loader 一致，payload identity 不强制等于 config
symbol `name`。

### Artifact path

Output、optional output、skip-if-exists 和 symbol artifact 仍只允许 module-local `.yaml` 文件名。Input
允许 `../engine/Foo.{platform}.yaml` 形式的 sibling-module 引用；解析后必须仍位于同一个 game-version
root。绝对路径、反斜杠与 root escape 继续拒绝。

### DAG 和 plan schema

Producer/input key 已规范化为 game-root 相对 artifact path。跨 module producer/consumer 会建立真实
artifact edge，并参与重复 producer、缺失 input 与 cycle 检测。Snapshot formal paths 也使用规范化 owner
path，因此 `../engine/X.yaml` 在 snapshot 中仍表示为 `engine/X.yaml`。

GoldSrc 仍未移植 CS2 Reporter 使用的 stage/job/task stable ID、layer 与 auxiliary nodes；这属于 Reporter
contract 差异，不再是 artifact DAG 缺口。

本次 shared contract 变更同步更新了 planner、runtime artifact map、snapshot/candidate tests 和文档，
analysis output contract 升级为 version 2。

## 4. `idalib-mcp` 生命周期（已补齐）

GoldSrc 现在与 CS2 一样，对每个仍有待执行节点的 module/platform binary 执行以下流程：

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

当前实现边界：

- preflight 会在所有输出已存在时跳过 IDA startup；
- `.id0` 与已占用端口都在启动前 fail closed；
- readiness 同时要求 TCP port 和 MCP `initialize/list_tools` contract 可用；
- session 按规范化 binary path 绑定唯一活动 database，并用 survey 的 SHA-256/MD5/path 与 platform metadata 核对；
- 同一 binary 的所有节点共享一次 recovery restart budget；
- preprocessor context 可读取绑定后的 host、port、database session id 与 ownership metadata；
- identity 未验证时只停止本次 supervisor，不会向未知 endpoint 发送 `qexit`；
- identity 已验证时只对 `auto_started && owned && backend == "worker"` 的 worker 发送定向 `qexit`，随后停止
  supervisor 并等待端口释放；
- `-ida_args` 已恢复，startup、opened metadata retry 和 shutdown timeout 均有明确上限。

出处：

- GoldSrc lifecycle owner：`ida_analyze_bin.py` 中的 `IdaMcpLifecycle`、`start_idalib_mcp()`、
  `verify_opened_binary_via_mcp()` 与 `ensure_mcp_available()`；
- GoldSrc bound session：`ida_mcp_session.py` 中的 `open_ida_mcp_session()`；
- CS2 startup：`D:\CS2_VibeSignatures\ida_analyze_bin.py:2797-2850`
- CS2 binary processing：`D:\CS2_VibeSignatures\ida_analyze_bin.py:3105-3175`
- CS2 shutdown：`D:\CS2_VibeSignatures\ida_analyze_bin.py:1081-1180,3942-3951`

### `ida_mcp_session.py` 版本差异（已补齐）

GoldSrc session adapter 已补齐以下 CS2 语义，同时保留更严格的 `casefold()` path normalization 和 lazy imports：

- `McpDatabaseBinding.should_auto_quit`；
- tool error 的 server error body；
- database selection 的完整 candidate summary 与空白 session id 拒绝；
- supervisor health helper；
- `idb_list` typed error；
- nested `ExceptionGroup` 中 MCP contract error 的解包；
- setup error 与 session body error 的异常边界，避免把业务异常误报为 connection error。
- 同时兼容 MCP SDK 的 `inputSchema` / `input_schema`、`isError` / `is_error` 和
  `structuredContent` / `structured_content` 字段形式。

对应 unit tests 位于 `tests/test_ida_mcp_session.py` 与 `tests/test_analysis_planner.py`。本机 IDA/
`idalib-mcp` 的真实 smoke 已完成；CI 缺口只剩自动化 self-hosted 执行环境。

## 5. Preprocessor 与 Finder/helper 契约（自动化与真实 IDA smoke 均已完成）

GoldSrc 已采用 CS2 的单一 skill-specific Preprocessor 模型，删除 deterministic / LLM 双目录与旧的布尔入口。
Analyzer 当前调用：

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
    llm_model,
    llm_apikey,
    llm_baseurl,
    llm_temperature,
    llm_effort,
    llm_fake_as,
    llm_max_retries,
    symbol_aliases,
)
```

dispatcher 为每次调用绑定目标 binary/database 的 MCP session，严格解析 image base，并进程内缓存
`ida_preprocessor_scripts/<skill>.py::preprocess_skill`。脚本只有显式声明 `llm_config` 参数时才会收到组装后的
LLM runtime config；不再对 `unexpected keyword argument` 删除参数后重试。

返回值统一归一化为：

- `success`；
- `absent_ok`；
- `no_script`；
- `failed`。

pipeline 采用结构化 `PipelineResult` / `PipelineFailure(reason, payload)`，并实现以下终态：

- `success` 必须生成全部 required outputs；Preprocessor 与 Agent 输出使用同一层 YAML、symbol schema 与当前
  IDB 地址校验；
- `absent_ok` 无条件记为 skipped/`preprocess_absent`，即使脚本同时留下 YAML；
- `failed` 留下的 YAML 不删除，但该失败不能凭文件存在在同一次运行中转成成功，required-output skill 必须进入
  Agent fallback；
- `no_script` 进入 Agent fallback；
- optional-only skill 在正常模式下遇到 `failed` / `no_script` 记为 skipped/`optional_output_absent`；使用
  `-skip_pp` 时仍运行 Agent，最终没有 optional output 时使用同一 skipped reason；
- zero-output skill 按 CS2 语义允许执行；
- 运行前 existing-output short circuit 仍只依据 YAML 文件存在，不附加内容校验。

运行时还会拒绝 required/optional input 重叠、缺失 required input 与无效输入工件；MCP 地址校验不可用时由
lifecycle owner 执行一次受预算约束的恢复。dispatcher 不增加独立 wall-clock timeout。

出处：

- GoldSrc dispatcher：`ida_skill_preprocessor.py`
- GoldSrc pipeline：`ida_analyze_bin.py:788-1245`
- GoldSrc tests：`tests/test_ida_skill_preprocessor.py`、`tests/test_analysis_planner.py`
- CS2 reference：`D:\CS2_VibeSignatures\ida_skill_preprocessor.py:24-207`

自动化 contract tests 已覆盖 loader cache、ABI、status normalization、LLM opt-in、session binding、image-base
解析、输入输出验证、optional-only、zero-output、Agent fallback、MCP recovery，以及 CS2-compatible
`preprocess_common_skill` API。共享 runtime 已覆盖 func/vfunc/GV/patch/structmember/vtable、4-byte inherited
slots、A/B xref filters、C/D/E LLM fallback、H ordinal vtable 和合并后的 I/L unique indirect vcall。

2026-08-10 已在真实 IDA/`idalib-mcp` 环境执行：

```powershell
uv run python ida_analyze_bin.py -gamever svencoop-10257 -modules engine `
  -skill find-R_RenderView -platform windows,linux -debug
```

结果为 `Successful: 2 / Failed: 0 / Skipped: 0`。`hw.dll` 产出 `func_va: 0x1d537b0`、
`func_rva: 0x537b0`；`hw.so` 产出 `func_va/func_rva: 0x13ba80`。两份 artifact 均只包含
`func_name/func_va/func_rva/func_size/func_sig`，没有通用 `name/type/kind`，且 `func_sig` 经 MCP
唯一性复核和 runtime 当前 IDB 地址验证。

## 6. History reuse（category-aware 地址重建已完成）

旧 YAML 直接复制路径已禁用。Analyzer 解析/自动选择同 game family 的 `oldgamever`，并把 new-output 到
old-YAML 的映射交给 MCP-bound Preprocessor；共享 helper 会按 func/GV/patch/structmember/vfunc 类别在新
IDB 中重新定位并重算地址与派生字段。`find-R_RenderView` 是首个 production 使用者。

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

- GoldSrc 当前缓解：`ida_analyze_bin.py:1090-1146`
- GoldSrc 移除前基线：`cabdc95:ida_analyze_bin.py:117-141,183-191`
- CS2 function reuse：`D:\CS2_VibeSignatures\ida_analyze_util.py:2839-2969,3238-3274`
- CS2 global reuse：`D:\CS2_VibeSignatures\ida_analyze_util.py:4717`
- CS2 patch reuse：`D:\CS2_VibeSignatures\ida_analyze_util.py:4883-4979`

### 对齐目标

- skill-specific Preprocessor 只复用可证明稳定的 signature/metadata，不复制旧绝对地址；
- 每种 symbol category 通过 MCP 重新定位并重算派生字段；
- 无法重建时由同一个 Preprocessor 可选使用 LLM，最终进入 Agent fallback；
- old-version 自动选择必须限制在相同 GoldSrc game family；
- `download.yaml` 应支持类似 `major_update` 的显式禁用策略；
- 为地址变化但 signature 不变的场景增加回归测试。

## 7. Runtime 输入、输出和失败语义（核心自动化已对齐）

### Required input

GoldSrc 当前在每个 skill 执行前会：

- 重新解析 required/optional input；
- 拒绝同时声明为 required 和 optional 的同一路径；
- 明确报告缺失 required input；
- 记录缺失 optional input；
- 对 `func` / `vfunc` artifact 检查 YAML、`func_va`、segment 和 function-start identity；
- sibling-module input 已支持；仅做 schema/格式校验，不使用当前 IDB 验证另一 binary 的地址。

出处：

- GoldSrc：`ida_analyze_bin.py:1039-1088`
- GoldSrc tests：`tests/test_analysis_planner.py`
- CS2：`D:\CS2_VibeSignatures\ida_analyze_bin.py:3295-3420`
- CS2 input artifact validation：`D:\CS2_VibeSignatures\ida_analyze_bin.py:451-536`

### Output

Preprocessor 与 Agent 成功后均执行同一层 YAML mapping、symbol normalization、地址字段、segment、function-start
和 VA/RVA consistency 校验；失败通过 `PipelineFailure(reason, payload)` 报告。运行前 existing-output short
circuit 仍按已确认的 CS2 语义仅依据文件存在，不读取内容。

### Skip/cache

两边都主要以 output 是否存在作为幂等 skip，并且都没有独立 `--force`。因此“缺少 `--force`”不是当前
GoldSrc 相对 CS2 的差异。共同风险是旧 artifact 可能因 binary/config/skill 变化而失效。

GoldSrc 不再额外执行分析期间的 binary mutation SHA-256 guard，以与 CS2 保持一致；SHA-256 仍用于
opened binary identity 校验。后续若加入 cache key，应至少考虑：

- binary identity；
- config digest；
- analysis-output contract version；
- skill/preprocessor implementation version。

### Fail-fast 与异常边界

GoldSrc 已支持默认 fail-fast、`-skip_error` opt-in continuation、success/fail/skip 计数和结构化 skill reason。
相对 CS2 完整 Reporter 生命周期仍缺少：

- task abort reason；
- pending task finalization；
- reporter finalize/flush/close；
- unexpected exception 对 run 状态的兜底写入。

## 8. Agent runner 能力差异

### GoldSrc 对齐状态（2026-08-09）

本轮已补齐 Agent runner 运行时契约，同时保留 `run_skill(...) -> bool` 公共返回类型：

- `-agent_model` 已贯通；Claude、Codex、OpenCode 使用各自 model flag，拒绝空白/option-like model，OpenCode
  额外强制 `provider/model`；
- Claude 每次 skill run 生成独立 UUID，首次使用 `--session-id`，retry 稳定使用同一 UUID 的 `--resume`；
- OpenCode 从 JSONL stdout 提取首个有效 `sessionID` 并定向 `--session`，未取得时才回退 `--continue`；
- Codex 从 `.claude/agents/sig-finder.md` 注入 `developer_instructions`，prompt 经 stdin 传输；
- Claude、Codex、OpenCode 均有独立 skill-runner policy/config，OpenCode 通过隔离的 `OPENCODE_CONFIG` 加载；
- subprocess stdout/stderr 由独立线程实时 drain；`-debug` 实时转发，timeout 后执行 kill/wait 并保留已捕获输出；
- 支持 `<skill_error>...</skill_error>` 与 cybersecurity block 检测，后者不进入 retry；
- unknown Agent、invalid model、missing skill、missing Agent、return code、timeout、missing output、MCP preflight
  等失败均产生结构化 reason；attempt 失败事件附带截断后的 stdout/stderr 诊断；
- MCP preflight 成功与失败均按 `(agent, server)` 缓存；
- 每次 attempt 的 start/failure/success/final failure 通过 pipeline adapter 写入现有 reporter。

出处：

- GoldSrc：`agent_runner.py`、`ida_analyze_bin.py:1206`、`tests/test_agent_runner.py`
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

当前仍被仓库主动定义为 contract 的差异：

1. runtime 代码禁止包含 `process_reporter_redis`；
2. README/architecture 仍排除 scheduler、service、UI 和 C++ layout；
3. artifact output 必须留在当前 module；只有 input 可使用安全 sibling path；
4. GoldSrc 始终保持 PE32/ELF32、x86 和 4-byte vfunc slot。

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
- 提供受验证的 32-bit primary/ordinal vtable helper，不移植 Source2 专用 RTTI/dispatcher 语义；
- GoldSrc game tag 和 depot 布局；
- 当前 immutable candidate/gamedata guard。

目标应是对齐“外部 contract、生命周期、恢复、可观测性和自动化”，而不是复制 Source2-specific 分析语义。

## 推荐实施顺序

### Phase 1：统一外部 contract

- 兼容 CS2 语义的 CLI 和 `GSVIBE_*` 环境变量（已完成）；
- `category` 为唯一分类字段，严格拒绝 `type/kind`（已完成）；
- module/skill validation 已修复，`plan-only` 已删除；
- 支持 game-root 内安全 sibling-module input（已完成）；
- 定义 versioned execution plan 和 event schema（Reporter 本次延期）；
- 更新 repository-contract tests 和架构文档。

验收标准：同一组 module/platform/skill filter 在直接执行和未来 scheduler 中生成相同 execution graph；不再提供
独立 preview 入口。

### Phase 2：接入 IDA runtime

- 实现 `idalib-mcp` start/readiness/lock/identity/shutdown（已完成）；
- 将 `ida_mcp_session` 接入 analyzer（已完成）；
- 增加 bounded health recovery（已完成）；
- opened binary identity 校验（与 CS2 对齐）；
- 建立真实 IDA smoke test（本地双平台已完成；self-hosted workflow 待完成）。

验收标准：可以对一个已知 GoldSrc PE32/ELF32 binary 启动 MCP、验证打开目标、执行 `py_eval`，并只关闭本次拥有的 worker。

### Phase 3：统一 preprocessor 和 history

- 定义 MCP-bound status contract（已完成自动化对齐）；
- 传递 old YAML map、expected/optional inputs、LLM config 和 symbol aliases（已完成）；
- 将 history reuse 改为 category-aware 地址重建（已完成）；
- 增加 runtime input/output validation（已完成自动化对齐）；
- 建立第一个 production preprocessor 和 skill（已完成：`R_RenderView`）。

验收标准：旧 signature 地址发生变化时，新 YAML 中的 `VA/RVA` 来自新 IDB；无法证明唯一性时进入后续 fallback。

### Phase 4：补齐 Agent 和失败模型

- port CS2 Agent session/model/output/error handling；
- 添加 success/fail/skip summary（已完成）；
- 添加 fail-fast 与 `skip_error`（已完成）；
- 确保所有 terminal task 和 run 都被 finalize；
- 为 Agent、preprocessor、MCP 和 missing artifact 定义稳定 reason（单进程 event 已完成，Reporter contract 待扩展）。

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
- x86、module-local output、安全 sibling input、candidate 和 GoldSrc-specific 安全边界未被 Source2 假设破坏。
