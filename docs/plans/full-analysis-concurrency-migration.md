# Full analysis 有界并发与内存门禁迁移计划

状态：草案，待设计评审与真实 runner 基线采样

日期：2026-09-01（Asia/Singapore）

优先级：P1

GoldSrc 规划基线：`main@0a7033743425202f76ce0606a3cac274bcd5f50a`

CS2 参考树：`D:/CS2_VibeSignatures@6c28ad813a197d93df138edcb9824e6d27f2118c`

关联计划：

- `docs/plans/dynamic-mcp-endpoint-migration.md`；
- `docs/plans/idb-warmup-job-migration.md`；
- `docs/plans/mcp-preflight-failure-retry-migration.md`。

## 1. 计划定位

本计划改进 Release workflow 中以下 full analysis 步骤的墙钟时间：

```text
ida_analyze_bin.py -allgamever -force_all -bindir bin -artifactdir <fresh-root>
```

迁移借鉴 CS2 的 `bounded coordinator + one worker process per work item` 调度结构，但不复制其 bare-IDALib
worker。GoldSrc full analysis 的 Preprocessor 与 Agent fallback 需要 exact verified MCP endpoint，因此每个 worker 仍使用
现有 `IdaMcpLifecycle` 和 owned `idalib-mcp`。

首版 work item 固定为一个 gamever。Coordinator 最多同时运行有限数量的 gamever worker process；每个 worker 内继续按
现有 execution plan 顺序处理 binary lifecycle 与 skills。这样在不重写单 gamever DAG scheduler 的前提下，同时运行多路
互不共享 artifact/IDB 的 `idalib-mcp`。

本计划采用 Level 2/TDD：它改变 full release analysis 的执行时序、进程拓扑、资源上限和失败聚合，属于高回归风险行为变更。

## 2. 当前状态与瓶颈

当前 Release consumer 已经：

1. 下载并验证 producer 输出的 exact warm IDB selection；
2. restore 全部 immutable generations 到当前 checkout 的 `bin/<tag>`；
3. 删除并新建 `$RUNNER_TEMP/rebuilt-bin-artifacts`；
4. 单次执行 `ida_analyze_bin.py -allgamever -force_all`；
5. 运行 `bin_artifact_contract.py`，确保 fresh output 与 Git truth 完全一致。

Analyzer 当前存在三层串行：

- `run_all()` 按 `configs/config.yaml` 顺序逐个 gamever 调用 `_run_single_tag()`；
- `analyze()` 按 `(module, platform)` binary group 逐个创建 `IdaMcpLifecycle`；
- 同一 binary lifecycle 内按拓扑顺序逐个执行 skill。

动态 MCP endpoint 已消除固定 `13337` 的必然冲突，但它不是并行安全的充分条件。当前还缺少：

- bounded process coordinator；
- aggregate memory hard limit 与 launch admission；
- 跨进程 MCP port startup 竞争保护；
- worker 结果合同和并发日志聚合；
- failure/cancel 时的 owned process-tree cleanup；
- 真实 runner 上的多 IDA/Agent 并发容量证据。

## 3. 目标

### 3.1 吞吐目标

1. `-allgamever` 可以同时执行多个 gamever worker。
2. 实际并发 worker 数始终不超过环境变量配置的上限。
3. Coordinator 不在主进程内执行 gamever analysis；一个 work item 对应一个独立 worker process。
4. 单 gamever 内的 binary、skill 和 artifact DAG 顺序首版保持不变。
5. 并发度设为 `1` 时保持当前 tag admission order、分析范围、失败边界和 output contract。

### 3.2 OOM 防护目标

1. 支持环境变量配置 aggregate full-analysis process-tree memory budget。
2. 在接近 budget 前暂停新 worker admission，而不是继续启动直到系统 OOM。
3. 使用 Windows Job Object 对 coordinator、worker、`idalib-mcp`、Preprocessor/Agent 子进程施加 aggregate hard limit。
4. 内存门禁初始化失败时不得静默无保护地进入并发模式。
5. 内存限制触发、admission timeout 与普通 worker failure 使用不同的结构化 reason 和日志。

### 3.3 正确性目标

1. 每个 gamever 只调度一次，且只写 `<artifact-root>/<tag>`。
2. 每个 worker 只打开 `<bindir>/<tag>` 下属于自己的 restored IDB。
3. 继续使用 `database_policy=restored_strict`、`save_on_success=false`。
4. Worker 不 probe READY、不 restore、不 publish、不 prune persisted cache。
5. 所有 worker 成功后才允许执行 artifact contract、snapshot、gamedata 和 release bundle 阶段。
6. 任一 worker 失败、结果缺失或内存门禁失败，full analysis 整体返回非零。

## 4. 非目标

- 不并行 warm IDB producer；
- 不改变 cache identity、generation、selection schema 或 restore 锁协议；
- 不改成 GitHub Actions gamever matrix；
- 不在首版并行单 gamever 内的 platform、binary 或 skill；
- 不重新设计 `analysis_planner` 的 artifact/prerequisite DAG；
- 不允许 worker 将 finder、Preprocessor 或 Agent mutation 保存回 warm generation；
- 不自动探测“最佳并发数”或根据 CPU 数量无限扩张；
- 不把 Actions artifact、worker result 或 runner workspace提升为发布 truth；
- 不通过终止非本 coordinator 启动的进程进行恢复；
- 不引入 `psutil` 等新 dependency；Windows memory control 使用标准库与 `ctypes`。

## 5. 核心架构

### 5.1 目标进程拓扑

```text
release-build.yml
  -> ida_analyze_bin.py -allgamever -force_all
       coordinator process
         -> bounded scheduler
              -> worker process: hl-3248
                   -> dynamic-port idalib-mcp
                   -> optional Agent child processes
              -> worker process: hl-3266
                   -> dynamic-port idalib-mcp
                   -> optional Agent child processes
              -> ... at most N active workers
         -> aggregate worker results
  -> bin_artifact_contract.py
  -> snapshot / gamedata / bundle
```

Coordinator 和 worker 必须是不同 OS process。可以用小型 `ThreadPoolExecutor` 管理 blocking `subprocess.Popen`，但线程只负责
启动、持续读取日志和等待 worker；不得在线程中直接调用 `_run_single_tag()`。

### 5.2 Work item 选择

首版一个 work item 等于一个 canonical gamever tag，理由：

- `artifact-root/<tag>` 天然隔离；
- `bindir/<tag>` 与 restored IDB 天然隔离；
- 不同 tag 没有 execution-plan edge；
- 保留单 tag 内 artifact prerequisite、platform 和 skill 顺序；
- 避免在线程间共享 `AnalysisReporting`、`AnalysisSummary`、preprocessor module cache 和 Agent preflight state；
- 将 active `idalib-mcp` 数量自然限制为 active worker 数。

不得把同一 tag 拆为两个 worker，也不得在一个 work item 中包含多个 tag。Coordinator 在启动前验证 tag list 非空、canonical、
无重复，并保持 `configs/config.yaml` 的声明顺序作为 admission order 和最终汇总顺序。

### 5.3 Worker invocation

Coordinator 使用 `sys.executable` 和 argv list 启动当前仓库的单 tag analyzer，语义等价于：

```text
python ida_analyze_bin.py
  -gamever <tag>
  -oldgamever none
  -force_all
  <all normalized non-secret analysis options>
```

`-oldgamever none` 必须显式传递，防止从 `-allgamever` 切到单 tag 子进程后意外启用历史 artifact fallback。

LLM API key 等 secret 不写入 child argv、日志或 result JSON。Coordinator 为每个 child 构造独立 environment copy；现有
`GSVIBE_LLM_*`、Agent 和 endpoint override 继续通过 invocation-scoped environment/argv contract传递，不修改父进程全局环境。

Coordinator 通过 internal worker marker 告知 child：调度和 aggregate Job memory authority 已由父进程持有。Coordinated child
不得递归创建 batch coordinator或第二套aggregate Job limit；它直接继承父Job。直接运行的`-gamever`/`-node` invocation没有该marker，
仍可独立应用同一组analysis memory limit。

### 5.4 Worker result contract

新增 invocation-scoped result file，由 coordinator 为每个 worker 分配唯一临时路径。Worker 正常退出前以 canonical JSON 原子写入：

```json
{
  "schema_version": 1,
  "tag": "hl-3248",
  "status": "succeeded",
  "exit_code": 0,
  "summary": {
    "successful": 0,
    "failed": 0,
    "skipped": 0
  },
  "failure_reason": null
}
```

要求：

- exact key set、tag、status、integer counts 和 exit code 都必须验证；
- result 不包含 API key、prompt、绝对 persisted path 或完整 child command；
- child exit code 非零、result 缺失、JSON 非 canonical/malformed、tag 不匹配均视为 worker failure；
- coordinator 汇总使用 result contract，不解析人类日志；
- result 文件仅是运行期控制消息，不进入 release bundle 或 cache identity；
- finally 尽力清理 coordinator 自己创建的 result temp，不掩盖原失败。

## 6. 并发配置合同

### 6.1 环境变量

新增：

```text
GSVIBE_ANALYSIS_MAX_CONCURRENCY
GSVIBE_ANALYSIS_MAX_MEMORY_MIB
```

语义：

- `GSVIBE_ANALYSIS_MAX_CONCURRENCY`：一次 analyzer invocation允许同时处于admitted/running状态的analysis worker process最大数量；
  首版只有`-allgamever`能形成多个work items，直接`-gamever`/`-node`的effective concurrency固定为`1`；
- `GSVIBE_ANALYSIS_MAX_MEMORY_MIB`：当前 analyzer invocation拥有的整个process tree的aggregate committed-memory hard budget，
  单位MiB；对full、single-tag和selected-node analysis都可生效，但不包含GitHub runner service、OS和无关进程。

解析规则：

1. concurrency 未设置时默认为 `1`，保持当前串行行为；
2. concurrency 只接受十进制 `1..32`，并取 `min(configured, work_item_count)`；
3. memory 只接受正十进制整数；设置后必须大于 resource-owning analyzer baseline 加一个 conservative work-item reservation；
4. malformed、零、负数、超范围值全部 fail closed，不回退为另一个并发值；
5. effective concurrency 大于 `1` 时 memory 必须显式设置，否则在启动任何 worker 前失败；
6. effective concurrency 等于 `1` 且 memory 未设置时允许兼容旧行为，但日志明确报告 aggregate memory guard disabled；
7. memory 已设置时，即使 concurrency 为 `1` 也启用 hard limit 与观测；
8. 直接`-gamever`/`-node`也解析这两个变量：concurrency ceiling不会凭空产生并发，memory budget由当前analyzer进程负责施加；
9. 由`-allgamever` coordinator启动的single-tag child通过internal marker继承父级resource authority，不递归调度或重复创建Job。

初版不增加同义 CLI flags，避免出现 CLI 与 Environment variable 哪个是 hard ceiling 的歧义。需要本地验证时通过当前进程环境显式设置。

### 6.2 Workflow 配置

Release 的受保护 `win64` Environment 使用非 secret variables 提供这两个值。Workflow 将其映射到 build job environment，
但代码中的安全默认始终是 concurrency `1`。

激活顺序：

1. 合入代码但 Environment 未配置时，production 继续串行；
2. 配置 memory budget，先以 concurrency `1` 记录真实 peak；
3. 配置 concurrency `2` 并完成真实 runner 验收；
4. 只有峰值、API rate limit、IDA license 与 artifact evidence 支持时才提高到 `3` 或更高；
5. 回滚只需把 concurrency 改回 `1`，不改 cache generation 或 release schema。

不得在仓库中写死特定 runner 的生产 memory MiB；数值属于 runner/Environment 运维配置，并需保留 captured-at evidence。

## 7. 内存门禁设计

### 7.1 两层保护

内存控制包含两层，缺一不可：

1. **Soft admission gate**：在启动新 worker 前检查 aggregate Job memory，预测加入一个 worker 后是否超过 hard budget 的
   85%；超过时等待已有 worker 完成或内存回落。
2. **Windows Job Object hard limit**：设置 `JOB_OBJECT_LIMIT_JOB_MEMORY`，确保本 analysis process tree 不能把 runner 整机拖入
   OOM；设置 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`，确保 coordinator 异常退出后 owned descendants 不成为 orphan。

Hard limit 是最后边界，不是正常调度手段。正常运行应由 soft gate 阻止触顶；若仍触发 hard limit，当前 full analysis 必须失败并报告
`memory_limit_exceeded`，不得缩小并发后在同一次 release run 中悄悄重试。

### 7.2 Process-tree coverage

`-allgamever` coordinator创建Job Object、设置budget，并在启动任何worker前把自身加入Job。直接`-gamever`/`-node`
在memory budget已设置时由当前analyzer进程承担相同resource authority。Windows上由resource owner启动的worker、`idalib-mcp`、
Agent、resume child和其他descendants必须继承同一Job；coordinated child只继承父Job，不创建第二套authority。

实现前必须验证 self-hosted GitHub runner 的既有 Job membership允许 nested Job Object。以下任一情况均 fail closed：

- Create/Set/Assign Job Object 失败；
- 无法查询当前 Job memory；
- child 或 grandchild 可以逃离 configured Job；
- configured budget 小于 resource-owner baseline 与一个 work-item reservation之和。

不得捕获异常后打印 warning 并继续并发。

### 7.3 Admission 算法

参考 CS2 的 `MemoryLaunchGate`，GoldSrc 实现使用可测试的 snapshot abstraction：

- soft limit 初始为 hard budget 的 85%；
- initial worker reservation 初始按 4096 MiB 规划，实施前由 serial full-analysis peak evidence确认或调高；
- 根据 `current_job_bytes - baseline_job_bytes` 和 active worker 数更新 observed per-worker reservation，只增不减；
- 新 worker 的 projected usage 超过 soft limit时进入 condition wait；
- worker 结束时释放 active slot并唤醒等待者；
- 相邻 worker launch 至少间隔 5 秒，避免多个 IDA 同时跨过早期低内存阶段；
- coordinator 定期记录 aggregate current/peak memory、active workers、reservation 和 wait reason；
- external cancellation立即结束 admission，依赖 Job Object cleanup owned descendants。

Soft gate 同时受 max concurrency约束。只有 concurrency slot 和 memory slot同时可用时才允许启动 worker。

### 7.4 Host headroom

Job budget只约束本 analysis process tree，不覆盖 OS、runner service 和其他进程。运维配置必须为这些进程保留明确 headroom。

实现时通过 `GlobalMemoryStatusEx` 读取 host available physical memory并纳入 admission diagnostics；若 available memory 小于下一 worker
reservation，则继续等待。该检查是 soft admission 信号，不替代 Job hard limit，也不把整机瞬时状态写入 durable identity。

## 8. Scheduler、失败与取消语义

### 8.1 Lazy bounded admission

Coordinator 不把所有 tag 一次性无界提交。它按 canonical tag order维护 pending queue，并只在 concurrency + memory 两个 gate均通过时
启动下一个 worker。

状态至少包含：

```text
pending -> admitted -> running -> succeeded | failed
pending -> aborted（上游 failure 后停止 admission）
```

### 8.2 `-skip_error` 关闭

保持当前“遇到错误不继续启动后续 tag”的意图，同时避免粗暴杀死正在正常 cleanup 的 owned lifecycle：

1. 第一个 worker failure 设置 stop-admission；
2. 不再启动 pending tags，并将其标记为 aborted；
3. 已经 running 的 worker允许完成 normal lifecycle cleanup；
4. 所有 active worker drain 后 coordinator 返回非零；
5. partial fresh artifacts只用于 failure diagnostics，不进入 staging。

这与串行模式相比最多允许已启动的 `N-1` 个相邻 tag完成，是 bounded concurrency 的明确时序差异，必须写入测试与运行文档。

### 8.3 `-skip_error` 开启

继续调度全部 tag，收集所有 failure，最终只要任一 tag失败仍返回非零，保持现有 aggregate exit contract。

### 8.4 外部取消与异常退出

- Ctrl-C、workflow cancel 或 coordinator 未捕获异常必须停止 admission；
- 正常可处理取消优先请求 worker退出并等待 bounded grace period；
- grace period后只终止 coordinator-owned worker process tree；
- coordinator Job handle关闭时清理所有仍存活 descendants；
- 不扫描或终止系统中名称相同但不属于当前 Job 的 IDA/Agent 进程；
- 退出后验证 owned ports释放、目标 binary无 active `.id0`、result temp完成清理；
- cleanup failure不得把原 analysis failure改报为成功。

## 9. MCP endpoint 与 IDB ownership

### 9.1 Dynamic port startup hardening

现有 `_allocate_local_port()` 使用 bind-to-zero 后释放 socket，再启动 `idalib-mcp`，并发 worker会放大 TOCTOU 窗口。本计划要求在启用
concurrency `>1` 前完成：

1. 新增 runner-local、跨进程 MCP startup lock；路径位于 validated `RUNNER_TEMP`，不复用 persisted cache 的 warm-port lock；
2. 在锁内完成 ephemeral port allocation、`Popen` 和确认 child 已绑定该端口；
3. 端口被其他进程抢占时执行有限次数 re-allocation；
4. 一旦端口由当前 child绑定即可释放 startup lock，不持有到整个 analysis结束；
5. readiness、database identity 和 endpoint-aware Agent preflight继续使用 lifecycle自己的 recovery budget；
6. 超过 bounded attempts后明确失败，不无限重启或连接未知 supervisor。

该 lock只串行短暂的 MCP bind/startup，不串行后续 IDA analysis。

### 9.2 IDB ownership

- Selection restore 在 coordinator 启动前已经完成；worker不得重复 restore。
- 每个 tag最多一个 worker，因此不会有两个 lifecycle打开同一 restored database。
- `existing_database_lock()` 仍在 lifecycle启动前 fail closed。
- Strict database identity mismatch不 invalidate、不 cold rebuild。
- Normal success与失败 cleanup都不保存 selected-node修改回 immutable generation。
- Dynamic endpoint必须从当前 verified `McpRuntime` 注入Preprocessor和Agent，不能从全局默认端口推导。

## 10. Artifact 与 DAG 正确性

1. Workflow 仍在 coordinator 启动前一次性创建 fresh artifact root；worker不得删除或替换该 root。
2. Worker 的唯一可写 artifact subtree为 `<artifact-root>/<tag>`。
3. Coordinator在启动前验证每个 tag的resolved subtree位于artifact root内且彼此不重叠。
4. Single-tag worker仍由`analysis_planner.build_execution_plan()`验证artifact producer collision、required input和prerequisite DAG。
5. 单tag内按现有topological order和binary lifecycle grouping执行，不因并发迁移改变。
6. 不同tag没有artifact edge；未来若引入cross-tag input，本计划的并发资格必须fail closed或升级scheduler contract。
7. 所有worker成功后，workflow继续运行`bin_artifact_contract.py`和`git diff --exit-code -- bin_artifacts`。
8. Contract failure时上传的unverified diagnostics可以包含partial tag outputs，但后续release staging不得运行。

## 11. 日志与可观测性

Coordinator 日志至少记录：

- configured/effective max concurrency；
- hard/soft memory MiB、resource-owner baseline、initial/observed reservation；
- tag queue order、admitted/running/completed/aborted状态；
- worker PID与dynamic endpoint port（不记录secret或完整command）；
- memory wait、concurrency wait、wall time与aggregate peak memory；
- 每个tag的successful/failed/skipped计数；
- stop-admission、memory violation、missing result与cleanup原因；
- 最终canonical-order aggregate summary。

多个 worker 的 stdout/stderr 使用 `stderr=STDOUT` 合并并持续读取，以 `[<tag>]` 前缀写入 parent console。每个 worker 使用独立 reader，
打印使用锁保持单行完整；不得等 worker结束后才一次性读取大日志，也不得让 pipe buffer阻塞 child。

日志不得包含 LLM API key、Environment secret、完整 prompt、persisted root原始值或包含credentials的Agent config。

## 12. 文件级实施范围

预计修改：

| 文件 | 计划改动 |
| --- | --- |
| `ida_analyze_bin.py` | `-allgamever` coordinator接入、单tag worker result、参数/summary wiring |
| 新增 `analysis_batch.py` | work item/result schema、lazy bounded scheduler、subprocess/log/result聚合 |
| 新增 `analysis_memory.py` | Windows Job Object、memory snapshots、soft admission gate、host headroom |
| `ida_analyze_bin.py` 或小型 MCP lock模块 | 跨进程dynamic-port startup lock与bounded re-allocation |
| `.github/workflows/release-build.yml` | 从受保护Environment映射两个full-analysis limits；保留fresh root与后续contract |
| `tests/test_analysis_batch.py` | scheduler、worker result、failure/cancel、argv/env、log aggregation |
| `tests/test_analysis_memory.py` | Job API abstraction、admission、hard/soft limits、invalid config |
| `tests/test_analysis_planner.py` | strict lifecycle、dynamic port并发startup、single-tag worker wiring |
| `tests/fixtures/` | 不启动真实IDA的bounded worker/process-tree fixtures |
| `docs/en/*`、`docs/zh-CN/*` | 最终architecture、CI/CD、requirements、runner配置与诊断 |
| `memory/` | 实施完成后沉淀full analysis并发、OOM信号、回滚和验证经验 |

如果CS2 `warmup_memory.py` 的行为被复用，应迁移为GoldSrc自己的通用analysis模块并重写日志/命名/测试，不直接复制CS2
repository-specific常量与warmup语义。

## 13. TDD 与测试矩阵

### 13.1 配置解析

- 两个变量unset时full与non-full analysis的concurrency为1、memory guard disabled；
- valid boundary values；
- 空白、非数字、零、负数和overflow拒绝；
- concurrency大于work item数量时正确收敛；
- effective concurrency大于1但memory unset时在任何worker启动前失败；
- memory小于baseline+reservation时失败；
- 直接single-tag/selected-node在memory设置时建立自己的process-tree hard limit；
- coordinated child继承父Job且不重复建立memory authority；
- child single-tag path不递归启动coordinator。

### 13.2 Scheduler

- active worker数从不超过N；
- work item只启动一次且admission order稳定；
- concurrency slot和memory slot必须同时满足；
- worker完成后唤醒下一个pending item；
- result按canonical tag order汇总，而不是completion order；
- `skip_error=false`时首个failure停止新admission并drain active workers；
- `skip_error=true`时继续全部work items；
- missing/malformed/mismatched result fail closed；
- stdout持续排空并按tag前缀输出；
- secret不进入argv、result或display command。

### 13.3 Memory

- Job memory hard limit和kill-on-close flags正确；
- resource-owning analyzer在worker/IDA/Agent child启动前加入Job；
- fake snapshots覆盖低压、接近soft limit、恢复、timeout和violation；
- worker reservation只增不减；
- launch ramp interval生效；
- worker finish释放active count并通知waiter；
- Job API初始化/query失败阻断parallel mode；
- host available memory不足时不admit新worker；
- coordinator异常退出fixture不留下descendant；
- memory violation映射为稳定reason，不伪装成普通Agent failure。

### 13.4 MCP 与 lifecycle

- 两个独立process竞争startup时得到不同可用port；
- startup lock只覆盖allocate/bind，不覆盖完整analysis；
- port抢占触发bounded re-allocation；
- bounded attempts耗尽明确失败；
- 每个Agent override连接自己的verified endpoint；
- lifecycle退出后port释放；
- 同binary `.id0` 仍阻止第二个owner；
- strict restored/no-save语义不变。

### 13.5 Artifact 与集成

- 两个fake tag并发写入不同subtree；
- duplicate/escaping/overlapping tag subtree被拒绝；
- `-oldgamever none`传递；
- concurrency 1与旧串行路径产生相同artifact tree和summary；
- failure后partial artifacts不进入staging；
- all success后artifact contract仍是唯一release continuation gate。

Workflow YAML只做parse/schema/action validation和真实run验证；不得新增约束step文案、环境变量文本排版或其他易变YAML内容的单元测试。

## 14. 实施阶段

### 阶段0：基线与容量采样

1. 在production-equivalent runner以concurrency 1执行一次完整release analysis。
2. 记录每个tag的wall time、Job current/peak memory、IDA/Agent descendant coverage和API rate-limit行为。
3. 验证IDA license允许目标并发实例数。
4. 根据证据确认或提高4096 MiB initial reservation；不得为追求并发盲目调低。

### 阶段1：Memory primitive与失败测试

1. 先写`analysis_memory`的fake-API tests。
2. 实现Windows Job Object hard limit、snapshot和host memory probe。
3. 实现soft admission gate与launch ramp。
4. 在独立fixture中验证kill-on-close和descendant inheritance。

该阶段不改变analyzer执行顺序。

### 阶段2：Worker result与bounded coordinator

1. 定义work item/result dataclass和schema validator。
2. 为单tag analyzer增加internal result输出。
3. 实现lazy pending queue、subprocess worker和tag-prefixed log drain。
4. 实现aggregate summary、stop-admission和result temp cleanup。
5. 默认concurrency 1接管`run_all()`，验证兼容性。

### 阶段3：并发MCP startup hardening

1. 新增runner-local跨进程startup lock。
2. 实现allocate/spawn/bind bounded retry。
3. 增加多进程port与wrong-supervisor tests。
4. 真实启动两个strict restored lifecycle，确认endpoint/binary不串线。

在此阶段完成前不得在workflow配置concurrency大于1。

### 阶段4：Release workflow接入

1. 映射受保护Environment variables。
2. 保持fresh artifact root创建、failure diagnostics和artifact contract顺序不变。
3. 先以concurrency 1 + memory budget跑一次真实release verification。
4. 再以concurrency 2运行并保存证据。

### 阶段5：渐进激活与文档

1. 对比串行/并发artifact bytes、selection、source/bin SHA和release bundle verification。
2. 观察至少两次production-equivalent成功运行和一次受控worker failure。
3. 更新双语architecture/CI/requirements、operator runbook和Basic Memory。
4. 证据支持时再调高Environment concurrency；否则保持2或回滚1。

## 15. 验证命令

定向验证：

```text
uv run python -m unittest tests.test_analysis_batch
uv run python -m unittest tests.test_analysis_memory
uv run python -m unittest tests.test_analysis_planner
uv run python -m unittest tests.test_agent_runner tests.test_ida_mcp_session
```

静态验证：

```text
uv run python format_repo_files.py --check
uv run python -c "from pathlib import Path; import yaml; [yaml.safe_load(path.read_text(encoding='utf-8')) for path in Path('.github/workflows').glob('*.yml')]"
git diff --check
```

完成前质量门禁：

```text
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
```

真实 runner 验证不能由mock代替，至少保留：

1. concurrency 1兼容运行；
2. concurrency 2时两个不同tag同时存在verified MCP endpoint；
3. 两个Agent/MCP查询到各自exact binary，不串线；
4. aggregate Job current/peak memory低于configured hard budget；
5. memory pressure时新worker被延迟而不是继续启动；
6. 受控低budget触发明确memory failure且runner未OOM；
7. worker failure停止新admission、active worker正常cleanup；
8. workflow cancel后无owned worker、`idalib-mcp`、Agent、port或`.id0`残留；
9. 并发输出通过`bin_artifact_contract.py`并与tracked Git truth一致；
10. release bundle本地verify继续成功。

无法执行真实IDA、Agent、license、Job inheritance或OOM门禁时，只能声明仓库实现完成，不得声明parallel production activation完成。

## 16. 风险与缓解

### 风险：动态端口TOCTOU导致worker连接错误supervisor

缓解：跨进程startup lock、bind确认、bounded re-allocation和exact database identity verification必须先于parallel activation完成。

### 风险：memory budget只覆盖worker本体，不覆盖Agent descendants

缓解：resource-owning analyzer先加入Job并验证inheritance；真实fixture必须证明`idalib-mcp`和Agent descendants计入Job snapshot。
逃逸即阻断激活。

### 风险：hard limit触发进程异常而不是优雅退出

缓解：85% soft gate、conservative reservation和staggered launch作为正常保护；hard violation始终fail closed并通过新run恢复，不在同run隐式降并发重试。

### 风险：不同tag并发消耗LLM/API quota

缓解：初始concurrency 2，观察provider rate-limit；Agent自身bounded retry保持不变。不得把API失败误判为memory pressure或自动无限重试。

### 风险：并发改变failure时已执行的tag集合

缓解：lazy admission；首个failure停止新启动，只drain已经running的bounded集合；日志和result明确标记aborted tags。

### 风险：日志交错或pipe阻塞隐藏真实故障

缓解：每worker持续drain、stderr合并、单行prefix和print lock；机器结果来自result JSON而非日志解析。

### 风险：artifact或IDB路径意外共享

缓解：work item固定为unique tag、启动前path containment/non-overlap验证、strict `.id0` ownership和最终artifact contract。

### 风险：GitHub runner已位于不兼容Job Object

缓解：阶段0/1先验证nested Job行为；不兼容时保持concurrency 1并重新设计process assignment，不允许关闭memory guard后继续parallel。

## 17. 回滚与兼容性

- 设置`GSVIBE_ANALYSIS_MAX_CONCURRENCY=1`立即恢复串行admission；
- `GSVIBE_ANALYSIS_MAX_MEMORY_MIB`可以在full、single-tag和selected-node串行模式继续保留，提供统一OOM边界；
- 回滚不修改或删除warm IDB generations、READY、selection artifact或release bundle；
- worker result schema是ephemeral internal contract，不进入长期兼容surface；
- 不恢复fixed MCP port；dynamic endpoint和success-only preflight继续保留；
- 失败run重新执行时仍从新的fresh artifact root和exact restored selection开始，不复用partial artifacts；
- 若coordinator本身存在缺陷，可临时恢复旧`run_all()`串行循环，但不得绕过strict restored/no-save与artifact contract。

## 18. 建议提交拆分

| 顺序 | 主题 | 主要内容 | 门禁 |
| --- | --- | --- | --- |
| 1 | Memory primitives | Job Object、snapshots、soft gate、fixtures | `test_analysis_memory` + process-tree evidence |
| 2 | Batch result contract | work item/result、single-tag result输出 | batch unit tests |
| 3 | Bounded coordinator | lazy scheduler、logs、failure/cancel、default1 | batch + planner tests，串行artifact compare |
| 4 | MCP startup safety | cross-process lock、bounded port retry | lifecycle tests + two-real-MCP evidence |
| 5 | Release activation | Environment wiring、concurrency 1/2 runs | workflow parse + real runner evidence |
| 6 | Operations/docs | runbook、双语docs、memory note | docs review + captured evidence |

每个提交遵循`<type>(scope): <summary>`并追加`Co-Authored-By: Codex <codex@openai.com>`。

## 19. 最终验收标准

必须全部满足：

1. `-allgamever`使用bounded coordinator和一个gamever一个worker process。
2. 未配置时effective concurrency为1；配置N时active worker从不超过N。
3. effective concurrency大于1必须配置aggregate memory budget，非法/缺失配置在启动worker前fail closed。
4. Soft gate在projected memory超过阈值时暂停admission；Windows Job hard limit覆盖coordinator及全部owned descendants。
5. 直接`-gamever`/`-node`设置memory budget时，同一hard limit覆盖该analyzer及其`idalib-mcp`/Agent descendants；
   concurrency ceiling保持effective `1`，不会隐式改变单tag DAG。
6. Memory guard不可用时不会静默parallel；hard violation不会造成runner整机OOM或被当作普通业务failure。
7. Worker使用独立dynamic MCP endpoint并绑定exact binary，不连接其他worker或静态13337。
8. Single-tag DAG、artifact ownership、strict restored/no-save、cache selection和generation协议保持不变。
9. `skip_error=false`首个failure停止新admission并drain active workers；`skip_error=true`聚合全部结果；任一failure最终返回非零。
10. External cancel或coordinator异常后无owned worker、IDA、Agent、port、`.id0`或result temp残留。
11. 并发日志可按tag追踪，summary按canonical tag order稳定，secret不进入argv/log/result。
12. Concurrency 1与迁移前full analysis产生byte-equivalent artifact tree；concurrency 2及以上继续通过artifact和release bundle verification。
13. 定向测试、完整质量门禁、真实runner concurrency/memory/cancel/license证据均已如实记录。
14. Production Environment variable从1到2渐进激活，可仅通过回调concurrency到1安全回滚。
15. 双语架构/CI/requirements、operator runbook与Basic Memory已和最终实现同步。
