# Full analysis 有界并发与内存门禁迁移计划

状态：两阶段设计方向已认可；实施细节待评审与真实 runner 基线采样

日期：2026-09-05（Asia/Singapore）；初稿日期：2026-09-01

优先级：P1

GoldSrc 规划基线：`main@9dfbf0e176fe47fd8adcfe91ccb45a8f0b5b9b22`（PR #66 合并后）

CS2 参考树：`D:/CS2_VibeSignatures@6c28ad813a197d93df138edcb9824e6d27f2118c`

关联计划：

- `docs/plans/dynamic-mcp-endpoint-migration.md`；
- `docs/plans/idb-warmup-job-migration.md`；
- `docs/plans/idb-warmup-concurrent-worker-migration.md`；
- `docs/plans/mcp-preflight-failure-retry-migration.md`。

## 1. 计划定位

本计划改进 Release workflow 中以下 full analysis 步骤的墙钟时间：

```text
ida_analyze_bin.py -allgamever -force_all -bindir bin -artifactdir <fresh-root>
```

迁移借鉴 CS2 的 `bounded coordinator + one worker process per work item` 调度结构，但不复制其 bare-IDALib
worker。GoldSrc full analysis 的 Preprocessor 与 Agent fallback 需要 exact verified MCP endpoint，因此每个 worker 仍使用
现有 `IdaMcpLifecycle` 和 owned `idalib-mcp`。

首版采用「binary 级并行 worker + 跨 binary 依赖 skill 及其下游的串行尾队列」。先按完整节点 DAG 分类，再将并行集合按
binary 分组，有界启动独立 worker；同一 worker 内串行执行 skills。所有并行 worker 成功并完成 lifecycle 退出后，才按节点
拓扑顺序执行串行尾队列，全局最多一个 analysis worker。不同 gamever 之间没有 admission 屏障。

同一 binary 的部分 skills 可以在并行阶段执行，余下 skills 在串行阶段重新打开 IDB 后执行。当前 GoldSrc finder 不要求延续
前一阶段的重命名、类型设置等 IDB 修改；跨阶段保留的是 artifact 输出，而不是 IDB mutation。这里的 fresh IDB 指本次 run
从 exact selection 恢复的 neutral warm IDB，不是绕过 warm cache 重新 cold-analyze，也不要求串行阶段再次 restore。

本计划采用 Level 2/TDD：它改变 full release analysis 的执行时序、进程拓扑、资源上限和失败聚合，属于高回归风险行为变更。
本次仅修订设计文档，不代表实现、测试或 production activation 已完成。

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

在上述规划基线使用现有 config parser 和 planner 做只读统计：16 个 gamever 中，10 个有分析节点，总计 13 个 binary job、
262 个节点，当前跨 binary dependency edge 为 0。此统计不是写死的任务数量或测试断言；warmup 的 binary 数量也不能作为
full analysis 的任务数量。PR #66 已并行化 warm producer，本计划仅改 consumer analysis。

动态 MCP endpoint 已消除固定 `13337` 的必然冲突，但它不是并行安全的充分条件。当前还缺少：

- bounded process coordinator；
- aggregate memory hard limit 与 launch admission；
- 跨进程 MCP port startup 竞争保护；
- worker 结果合同和并发日志聚合；
- failure/cancel 时的 owned process-tree cleanup；
- 真实 runner 上的多 IDA/Agent 并发容量证据。

## 3. 目标

### 3.1 吞吐目标

1. Full `-allgamever` 可以同时执行多个 binary worker，包括同一 gamever、同一 module 的不同 platform binary。
2. 实际并发 worker 数始终不超过环境变量配置的上限。
3. Coordinator 不在主进程内执行 analysis；一个 work item 对应单 binary 的有序节点子集及一个独立 worker process。
4. 保留节点 DAG 依赖和 worker 内的串行顺序，不保留无依赖 binary 之间的旧执行屏障。
5. 并发度设为 `1` 时仍使用两阶段分类，但不重叠 workers。当前无跨 binary edge 的配置保持原 tag/binary admission order、
   分析范围和 output contract；有跨 binary edge 时允许独立节点前移、依赖节点后移，不承诺旧全局时序与失败前执行集合。

### 3.2 OOM 防护目标

1. 支持环境变量配置 aggregate full-analysis process-tree memory budget。
2. 在接近 budget 前暂停新 worker admission，而不是继续启动直到系统 OOM。
3. 使用 Windows Job Object 对 coordinator、worker、`idalib-mcp`、Preprocessor/Agent 子进程施加 aggregate hard limit。
4. 内存门禁初始化失败时不得静默无保护地进入并发模式。
5. 内存限制触发、admission timeout 与普通 worker failure 使用不同的结构化 reason 和日志。

### 3.3 正确性目标

1. 所有计划节点不重不漏地分配到两阶段，每个节点只属于一个 work item；节点内部既有 bounded retry 不属于重复调度。
2. 每个 worker 只打开其指定的 restored IDB；同一实际 binary/IDB 不得同时拥有两个 lifecycle。
3. 继续使用 `database_policy=restored_strict`、`save_on_success=false`。
4. Worker 不 probe READY、不 restore、不 publish、不 prune persisted cache。
5. 并行阶段全部成功且 worker/lifecycle 已退出后才允许启动串行阶段；两阶段全部成功后才允许执行 artifact contract、snapshot、
   JSON datasets 和 release bundle 阶段。
6. 任一 worker 失败、结果缺失或内存门禁失败，full analysis 整体返回非零。

## 4. 非目标

- 不修改 PR #66 已实现的 warm IDB producer 并发路径；
- 不改变 cache identity、generation、selection schema 或 restore 锁协议；
- 不改成 GitHub Actions gamever matrix；
- 不并行同一 binary 内的 skills；不实现依赖就绪即动态启动的通用跨 binary 并发 DAG scheduler；
- 不重新设计 `analysis_planner` 的 artifact/prerequisite DAG，只消费完整图做两阶段分类；
- 不保存中间 IDB、不制作 mutation 快照、不保留跨阶段 IDB 内存状态；
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
         -> build complete node DAGs / classify nodes
         -> parallel phase: bounded binary scheduler
              -> worker: (tag, module, windows), parallel nodes
                   -> dynamic-port idalib-mcp
                   -> optional Agent child processes
              -> worker: (tag, module, linux), parallel nodes
                   -> dynamic-port idalib-mcp
                   -> optional Agent child processes
              -> ... at most N active workers
         -> success barrier: all parallel workers and lifecycles exited
         -> serial phase: topological node queue, at most one worker
              -> binary segment -> close -> next binary segment
         -> aggregate worker results
  -> bin_artifact_contract.py
  -> snapshot / JSON datasets / bundle
```

Coordinator 和 worker 必须是不同 OS process。可以用小型 `ThreadPoolExecutor` 管理 blocking `subprocess.Popen`，但线程只负责
启动、持续读取日志和等待 worker；不得在线程中直接调用 `_run_single_tag()`。

### 5.2 节点分类与 work item

Binary identity 为 `(gamever, module, platform, resolved_binary_path)`。物理路径按 Windows 大小写、实际路径和数据库 side-file
归属规范化，blob 使用准备后的实际 binary 路径。启动前拒绝不同逻辑 identity 指向同一 binary/IDB 的别名冲突。
同一 identity 可以跨阶段或在串行尾队列中重复出现，但节点集合必须互斥，生命周期必须依次退出。

Coordinator 在启动任何 analysis worker 前完成以下步骤：

1. 按 `configs/config.yaml` 解析全部 tag，验证列表非空、canonical 且无重复，构建完整的各 tag 节点 DAG；全局节点身份使用
   `(tag, node_id)`，避免跨 tag 重名。
2. 验证 DAG 无环、artifact producer 唯一、节点与实际 binary 映射有效。不能先过滤节点再建图，以免漏掉跨 binary edge。
3. 对每条真实节点依赖边 `source -> target`，若两端 binary identity 不同，将 **target** 加入串行种子。覆盖 required artifact、
   optional input 和 prerequisite 对应的计划边；reporter 的展示性 stage/job order 不作为数据依赖。
4. 沿全部依赖边求串行种子的下游传递闭包，得到 serial nodes；其余为 parallel nodes。仅提供依赖的 source 不必后移。
   验证两集合互斥且并集等于完整计划，且不存在 serial -> parallel 依赖边。
5. Parallel nodes 按 binary 分组，每组保留节点拓扑顺序，形成一个 work item。按 tag 声明顺序及该 tag 原计划中 binary 首次
   出现顺序稳定排列；空组不启动 worker，零节点 tag 仍保留汇总。不同 tag 无完成屏障。
6. Serial nodes 按完整 DAG 的稳定拓扑顺序排成尾队列。只合并连续属于同一 binary 的节点为一个串行 work item；不能为合并
   而跨过其他 binary 的节点或打乱依赖顺序。串行 work item 全局最多运行一个。

Work item 绑定唯一 ID、phase、binary identity 和精确有序 node IDs。并行阶段一个 binary 最多一个 work item；串行阶段同一
binary 可以出现多段。合法节点 DAG 即使收缩为 binary 图后有环，也不拒绝：例如 `A1 -> B1 -> A2` 可通过串行分段重新打开 A。
只拒绝真实节点环或非法路径/输出合同，不要求整个 binary 一次执行完。

当前各 tag 图没有跨 tag 输入合同；本方案不自行发明跨 tag artifact 路径。未来若增加此能力，必须将真实边纳入完整图和同一
分类规则，不能当作无依赖外部文件绕过屏障。当前无跨 binary edge 时，串行队列自然为空。

示例：B2 依赖 A2，C1 依赖 B2，B1 是 B2 的同 binary 前序节点。

```text
并行阶段：worker A 执行 A1 -> A2；worker B 执行 B1
成功屏障：A、B 的输出与结果完整，worker/lifecycle 均退出
串行阶段：重新打开 B 执行 B2 -> 关闭；打开 C 执行 C1 -> 关闭
```

B2 可读取 B1 的 artifact，但不要求 B1 的 IDB mutation 仍存在。进程隔离避免共享 `AnalysisReporting`、`AnalysisSummary`、
Preprocessor module cache 和 Agent preflight state；同 tag 的不同 worker 不独占整个 tag/module 目录。

### 5.3 Worker invocation

Coordinator 使用 `sys.executable` 和 argv list 启动内部 binary worker 入口，传入 invocation-scoped work item 文件及独立 result
路径。最终文件/参数名在实施时确定，不能直接拼接现有公共 CLI 的以下组合：

```text
不能使用：-force_all -modules <module>（当前 force_all 会选择全部 modules）
不能使用：-node <nodes> -force_all（当前公共 CLI 明确互斥）
```

抽取当前 binary group / node 执行逻辑，让内部 worker 精确执行单 binary 的有序节点子集，并对 full-analysis work item 启用
force execution。不得为此改变公共 `-force_all`、`-modules`、`-node` 合同。内部请求明确 `oldgamever=None`；若复用 CLI
解析入口则显式传 `-oldgamever none`，防止单 tag 默认历史 artifact fallback。

Worker 校验请求的 run/work item identity、phase、binary、node IDs 与完整计划一致，只执行其子集，不递归补跑上游。
不能对子集单独重建无上下文 DAG：依赖在完整图上分类，在执行节点时验证 required inputs；有 producer 的 optional input
必须等待 producer 结束，但允许原合同认可的 absent output。无 producer 的输入沿用完整计划的原验证规则。
每个 work item 复用一个 owned lifecycle 执行内部节点，保留既有 bounded recovery；退出不保存 IDB 修改。

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
  "run_id": "analysis-example",
  "work_item_id": "parallel-0001",
  "phase": "parallel",
  "tag": "hl-3248",
  "module": "engine",
  "platform": "windows",
  "binary_relative_path": "hl-3248/engine/hw.dll",
  "node_ids": [],
  "node_results": [],
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

- 上例仅展示字段形状；实际 work item 必须有非空 node IDs，空组不启动 worker。
- 验证 exact key set、run/work item identity、phase、binary identity、精确有序 node IDs、status、非负 integer counts 和 exit code；
  success 要求全部分配节点有符合原节点合同的成功结果，不能用退出码零掩盖 failed/aborted/未执行节点。
- result 不包含 API key、prompt、绝对 persisted path 或完整 child command；
- child exit code 非零、result 缺失、JSON 非 canonical/malformed、identity 或节点集合不匹配均视为 worker failure；
- coordinator 汇总使用 result contract，不解析人类日志；
- 按 `(tag, node_id)` 校验完整覆盖，不跨阶段/segment 重复累计；保留失败/未执行节点明细以解释不完整汇总；
- `node_results` 对每个分配节点记录 node ID、terminal status 与 reason，精确覆盖 `node_ids`，summary 必须与明细一致；
  每个 worker 的 reporter run ID 由 batch run ID 和 work item ID 唯一派生，不让同 tag 不同阶段/segment 覆盖彼此的报告；
- 只有结果验证成功、进程退出且 owned lifecycle 清理完成才能判为 succeeded 并释放屏障；
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
  首版只在 `-allgamever -force_all` 路径启用两阶段 coordinator。并行阶段按 binary work item 数收敛上限，串行阶段最多 `1`；
  非 full 的 `-allgamever`、直接 `-gamever`/`-node` 保留原执行路径，effective concurrency 固定为 `1`；
- `GSVIBE_ANALYSIS_MAX_MEMORY_MIB`：当前 analyzer invocation拥有的整个process tree的aggregate committed-memory hard budget，
  单位MiB；对full、single-tag和selected-node analysis都可生效，但不包含GitHub runner service、OS和无关进程。

解析规则：

1. concurrency 未设置时默认为 `1`，禁止 worker 重叠，但 full 路径仍应用两阶段分类和成功屏障；
2. concurrency 只接受十进制 `1..32`；并行阶段取 `min(configured, parallel_work_item_count)`，空队列 active count 为 `0`，
   串行阶段有任务时固定为 `1`，无任务时为 `0`；不能把两个阶段的 work item 总数作为并发数量；
3. memory 只接受正十进制整数；设置后必须大于 resource-owning analyzer baseline 加一个 conservative work-item reservation；
4. malformed、零、负数、超范围值全部 fail closed，不回退为另一个并发值；
5. effective concurrency 大于 `1` 时 memory 必须显式设置，否则在启动任何 worker 前失败；
6. effective concurrency 等于 `1` 且 memory 未设置时允许兼容旧行为，但日志明确报告 aggregate memory guard disabled；
7. memory 已设置时，即使 concurrency 为 `1` 也启用 hard limit 与观测；
8. 直接`-gamever`/`-node`也解析这两个变量：concurrency ceiling不会凭空产生并发，memory budget由当前analyzer进程负责施加；
9. 两阶段的内部 binary child 通过 internal marker 继承同一父级 resource authority，不递归调度或重复创建 Job。

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
2. **Windows Job Object hard limit**：设置 `JOB_OBJECT_LIMIT_JOB_MEMORY`，限制本 analysis process tree 的聚合 committed memory；
   设置 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`，用于 coordinator 异常退出时回收 owned descendants，覆盖须由真实 fixture 验证。
   此限制不覆盖 OS 或其他 job，不承诺单靠该 budget 就能保证整机不会 OOM。

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

优先评估 PR #66 已有 `warmup_memory.py` 的底层 Job API 与 `MemoryLaunchGate`，使用可测试的 snapshot abstraction；不能直接
沿用 warmup 的 producer authority、环境变量或未经 full-analysis 采样确认的容量估算：

- soft limit 初始为 hard budget 的 85%；
- initial worker reservation 初始按 4096 MiB 规划，实施前由 serial full-analysis peak evidence确认或调高；
- 根据 `current_job_bytes - baseline_job_bytes` 和 active worker 数更新 observed per-worker reservation，只增不减；
- 新 worker 的 projected usage 超过 soft limit时进入 condition wait；
- worker 结束时释放 active slot并唤醒等待者；
- 相邻 worker launch 至少间隔 5 秒，避免多个 IDA 同时跨过早期低内存阶段；
- coordinator 定期记录 aggregate current/peak memory、active workers、reservation 和 wait reason；
- external cancellation立即结束 admission，依赖 Job Object cleanup owned descendants。
- 每次 admission 使用独立有限 deadline；到期报告 memory admission timeout，不无限等待，也不无保护启动。

Soft gate 同时受 max concurrency约束。只有 concurrency slot 和 memory slot同时可用时才允许启动 worker。
同一个 resource owner/controller 覆盖两个阶段，跨屏障不重建 Job 或重置观测到的 reservation；串行段同样经过内存门禁。

### 7.4 Host headroom

Job budget只约束本 analysis process tree，不覆盖 OS、runner service 和其他进程。运维配置必须为这些进程保留明确 headroom。

实现时通过 `GlobalMemoryStatusEx` 读取 host available physical memory并纳入 admission diagnostics；若 available memory 小于下一 worker
reservation，则继续等待。该检查是 soft admission 信号，不替代 Job hard limit，也不把整机瞬时状态写入 durable identity。

## 8. Scheduler、失败与取消语义

### 8.1 Lazy bounded admission

Coordinator 先按第 5.2 节分类完整计划，不把所有 binary work items 一次性无界提交。并行阶段按稳定 binary order 维护 pending
queue，只在 concurrency + memory 两个 gate 均通过时启动下一个 worker；同 tag 的不同 binary 可同时运行，无 tag 完成屏障。

并行队列耗尽不等于阶段成功。必须所有并行 work items 结果成功、进程退出、owned lifecycle 释放后才跨越屏障；result 提前写入
但 worker 尚未退出时不能启动串行段。并行集合为空时，在全量 preflight 成功后视作空成功阶段；串行集合为空时直接最终汇总。
串行队列按节点拓扑顺序逐段启动，前一段退出并清理后才启动下一段，绝不与任何并行 worker 重叠。

每个 work item 必须有有限 worker execution deadline（从实际启动起计），与 memory admission deadline、MCP startup timeout
分离。到期标记 worker timeout，先尝试有界 graceful shutdown，再终止并等待其 owned process tree；不能仅等待外层 Python
或让 drain 无限挂起。具体 timeout 常量由阶段 0 的 binary/Agent 耗时采样确定并记录，不依赖 workflow 的总超时充当 worker 门禁。

状态至少包含：

```text
pending -> admitted -> running -> succeeded | failed
pending -> aborted（上游 failure 后停止 admission）
```

### 8.2 `-skip_error` 关闭

保持当前“遇到错误停止新工作”的意图，同时避免粗暴杀死正在正常 cleanup 的 owned lifecycle：

1. 第一个 worker failure 设置 stop-admission；
2. 不再启动 pending work items；并行阶段失败时整个串行尾队列标记为 aborted；
3. 已经 running 的 worker 允许在有限退出期限内完成 normal lifecycle cleanup，超时按 owned-tree 规则终止；
4. 所有 active worker drain 后 coordinator 返回非零；
5. partial fresh artifacts只用于 failure diagnostics，不进入 staging。

并行阶段失败时最多允许其余已启动的 `N-1` 个 binary work items 完成；串行段失败时不启动后续段。这是明确的执行时序差异，
不是精确复刻旧 tag 级 fail-fast 集合，必须写入测试与运行文档。

### 8.3 `-skip_error` 开启

Full coordinator 中，`-skip_error` 只允许继续调度并行阶段其余 work items 以收集诊断；任一并行失败仍禁止进入串行阶段。
只有整个并行阶段成功才进入尾队列；尾队列任一段失败后停止后续段，不尝试执行可能依赖失败产物的节点。这是 full 路径新增的
严格阶段门禁，优先于「继续全部任务」；非 full 的既有 `-skip_error` 路径不变。任一失败最终非零，release 不启用该选项。

### 8.4 外部取消与异常退出

- Ctrl-C、workflow cancel 或 coordinator 未捕获异常必须停止 admission；
- 正常可处理取消优先请求 worker退出并等待 bounded grace period；
- grace period后只终止 coordinator-owned worker process tree；
- coordinator Job handle关闭时清理所有仍存活 descendants；
- 不扫描或终止系统中名称相同但不属于当前 Job 的 IDA/Agent 进程；
- 退出后验证 owned ports 释放、进程树退出和 result temp 清理；硬终止可能留下磁盘 `.id0`，不能把 Job 回收等同于文件清理。
- 只有确认 owned process tree 已退出后才允许清理其工作区残留；没有启动或无法确认退出时不得删除该 binary 的锁文件，不能清理
  sibling 或 persisted generation。清理失败保留诊断并阻断后续阶段，不在同一次 run 中重新打开受影响 IDB；
- cleanup failure不得把原 analysis failure改报为成功。

## 9. MCP endpoint 与 IDB ownership

### 9.1 Dynamic port startup hardening

现有 `_allocate_local_port()` 使用 bind-to-zero 后释放 socket，再启动 `idalib-mcp`，并发 worker会放大 TOCTOU 窗口。本计划要求在启用
concurrency `>1` 前完成：

1. 新增 runner-local、跨进程 MCP startup lock；路径位于 validated `RUNNER_TEMP`，不复用 persisted cache 的 warm-port lock；
2. 在锁内完成 ephemeral port allocation、`Popen` 和确认 child 已绑定该端口；
3. 端口被其他进程抢占时执行有限次数 re-allocation；
4. 一旦端口由当前 child 绑定即可释放 startup lock，不持有到完整 IDA readiness 或整个 analysis 结束；
5. readiness、database identity 和 endpoint-aware Agent preflight继续使用 lifecycle自己的 recovery budget；
6. 超过 bounded attempts后明确失败，不无限重启或连接未知 supervisor。

该 lock 只串行短暂的 MCP bind/startup，不串行后续 IDA analysis。不能仅凭「端口可连接」认定由自己的 child 绑定；仍需确认
ownership 和 exact binary。共享锁路径必须显式传给所有 coordinated children；不能假设不同 runner/job 的 `RUNNER_TEMP` 相同，
也不能假设非协作外部进程会遵守该锁，外部抢占仍走有限重试与身份校验。

### 9.2 IDB ownership

- Selection restore 在 coordinator 启动前已经完成；worker不得重复 restore。
- 同一物理 binary/IDB 同时最多一个 owner；同 tag 或 module 的不同 binary 可以并行。
- `existing_database_lock()` 仍在 lifecycle启动前 fail closed。
- Strict database identity mismatch不 invalidate、不 cold rebuild。
- Normal success与失败 cleanup都不保存 selected-node修改回 immutable generation。
- 同一 binary 可在并行阶段关闭、串行阶段重新打开，也可因串行拓扑顺序多次打开。后一次读取 neutral restored IDB，不要求
  前次重命名、类型或其他 mutation 延续；不新增中间保存、快照或长驻等待生命周期。依赖通过 artifact 合同表达。
- Dynamic endpoint必须从当前 verified `McpRuntime` 注入Preprocessor和Agent，不能从全局默认端口推导。

## 10. Artifact 与 DAG 正确性

1. Workflow 仍在 coordinator 启动前一次性创建 fresh artifact root；worker不得删除或替换该 root。
2. Worker 只可写其节点声明的 required/optional outputs，不独占整个 tag/module 目录，不删除或替换这些共享目录。
3. Coordinator 验证实际 binary/IDB 所有权以及输出路径 containment、大小写归一化和 producer 唯一性；不同节点不能写同一路径。
   同 module 的 Windows/Linux worker 可以共享目录，但正式输出、临时文件和辅助日志必须无冲突；实施前审查 Preprocessor/Agent
   的固定文件名、目录清理和其他副作用，不能仅凭 YAML 的 platform 后缀就认定全部写入安全。
4. 完整计划仍由 `analysis_planner.build_execution_plan()` 验证 producer collision、required input 和 prerequisite DAG，再做分类；
   节点子集执行不隐式重跑 producer，也不因本阶段已有文件而跳过 full-analysis 分配节点。
5. 串行种子及其全部下游后移，保留 required、optional 和 prerequisite 计划边；parallel -> serial 通过成功屏障满足。
6. 跨阶段只保留 fresh root 内 artifacts，不删除重建 root、不重新 restore IDB、不依赖前阶段 IDB mutation。
7. 两阶段所有 worker 成功后，workflow 继续运行 `bin_artifact_contract.py` 和 `git diff --exit-code -- bin_artifacts`。
8. Contract failure时上传的unverified diagnostics可以包含partial tag outputs，但后续release staging不得运行。

## 11. 日志与可观测性

Coordinator 日志至少记录：

- configured/effective max concurrency；
- hard/soft memory MiB、resource-owner baseline、initial/observed reservation；
- phase、完整 binary identity、work item/segment order、节点集合、admitted/running/completed/aborted 状态；
- 跨 binary 串行种子及下游分类原因、屏障等待/成功/失败状态；
- worker PID与dynamic endpoint port（不记录secret或完整command）；
- memory wait、concurrency wait、wall time与aggregate peak memory；
- 每个 binary、phase、tag 的 successful/failed/skipped 计数，零节点 tag 和 aborted 节点单独可见；
- stop-admission、memory violation、missing result与cleanup原因；
- 最终canonical-order aggregate summary。

多个 worker 的 stdout/stderr 使用 `stderr=STDOUT` 合并并持续读取，以 `[<phase>/<tag>/<module>/<platform>/<work-item>]` 前缀
写入 parent console。每个 worker 使用独立 reader，
打印使用锁保持单行完整；不得等 worker结束后才一次性读取大日志，也不得让 pipe buffer阻塞 child。

日志不得包含 LLM API key、Environment secret、完整 prompt、persisted root原始值或包含credentials的Agent config。

## 12. 文件级实施范围

预计修改：

| 文件 | 计划改动 |
| --- | --- |
| `ida_analyze_bin.py` | full 路径 coordinator 接入、精确 binary 节点子集执行、内部 worker 入口与 summary wiring |
| 新增 `analysis_batch.py` | 完整图分类/下游闭包、binary 分组、串行分段、成功屏障、work item/result、日志聚合 |
| `warmup_memory.py` / 拟新增 `analysis_memory.py` | 评估复用 Job 底层能力，analysis resource owner、soft gate、host headroom |
| `ida_analyze_bin.py` 或小型 MCP lock模块 | 跨进程dynamic-port startup lock与bounded re-allocation |
| `.github/workflows/release-build.yml` | 从受保护Environment映射两个full-analysis limits；保留fresh root与后续contract |
| `tests/test_analysis_batch.py` | 节点分类、闭包/分段/屏障、scheduler、worker result、failure/cancel、argv/env、logs |
| `tests/test_analysis_memory.py` | Job API abstraction、admission、hard/soft limits、invalid config |
| `tests/test_analysis_planner.py` | 完整 DAG 与节点子集执行、strict lifecycle、重新打开 IDB、dynamic port startup |
| `tests/run_test_suite.py` | 将新增测试文件登记到既有分组，不新增约束文档或 workflow 文本的测试 |
| `tests/fixtures/` | 不启动真实IDA的bounded worker/process-tree fixtures |
| `docs/en/*`、`docs/zh-CN/*` | 最终architecture、CI/CD、requirements、runner配置与诊断 |
| `memory/` | 实施完成后沉淀full analysis并发、OOM信号、回滚和验证经验 |

优先复用本仓库 PR #66 的底层 memory primitives，而不是复制 CS2 实现或再维护一套近似 Windows API。若需抽取共享模块，
实施前明确范围与兼容验证，不改变 warm producer 的 authority、变量、identity 和锁语义；analysis 使用自己的配置和诊断。

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
- binary worker path 不递归启动 coordinator；非 full 的公共入口不意外启用两阶段调度；
- 空 parallel/serial 队列、串行段数多但 parallel binary 数少时，effective concurrency 正确。

### 13.2 Scheduler

- 并行阶段 active worker 数不超过 N，串行阶段不超过 1，两个阶段绝不重叠；
- work item只启动一次且admission order稳定；
- concurrency slot和memory slot必须同时满足；
- worker完成后唤醒下一个pending item；
- result 按稳定 work item order 汇总到 binary/tag/global，节点跨阶段不重复累计，零节点 tag 保留汇总；
- `skip_error=false`时首个failure停止新admission并drain active workers；
- `skip_error=true` 继续并行阶段诊断但任何并行失败仍阻断串行阶段；串行失败停止剩余串行段；
- missing/malformed/mismatched result fail closed；
- stdout 持续排空并按 phase/binary/work item 前缀输出；
- secret不进入argv、result或display command。

节点分类与屏障必须另覆盖：

- 无跨 binary edge 时全部节点进入按 binary 分组的并行集合，serial 为空；
- required/optional 跨 binary edge 的 target 进入串行种子，source 不被无条件后移；
- 同 binary 与跨 binary 的多层下游闭包均后移，绝无 serial -> parallel edge；
- 分类互斥且覆盖所有计划节点，真实节点环在启动前失败；
- `A1 -> B1 -> A2` 按合法节点拓扑执行，不能因 binary 收缩图有环而拒绝；
- 串行只合并连续同 binary 节点，非连续 binary 再出现时创建新 segment；
- 并行集合为空、串行集合为空、所有 tag 均零节点的边界；
- worker 结果先写入但进程/lifecycle 尚未退出时，屏障仍不开放；
- 失败、缺失结果、cleanup failure、取消、timeout 任一发生都不能跨成功屏障；
- worker 只执行其精确节点集合且 force execution，不扩展到整个 tag/module，不递归补跑上游。

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
- 两阶段复用同一 controller，串行段同样受门禁约束；admission timeout 和 worker timeout 均有界。

### 13.4 MCP 与 lifecycle

- 两个独立process竞争startup时得到不同可用port；
- startup lock只覆盖allocate/bind，不覆盖完整analysis；
- port抢占触发bounded re-allocation；
- bounded attempts耗尽明确失败；
- 每个Agent override连接自己的verified endpoint；
- lifecycle退出后port释放；
- 同binary `.id0` 仍阻止第二个owner；
- strict restored/no-save语义不变。
- 同一 binary 并行阶段退出后，串行阶段重新打开，不保存或恢复前一阶段 IDB mutation；
- 同 tag/module 不同 platform 的两个 MCP 查询绑定各自 binary，无静态端口回退；
- 硬终止后只有确认 owned tree 退出才能清理工作区 stale `.id0`，不能触碰 sibling 或 cache generation。

### 13.5 Artifact 与集成

- 同 tag/module 的两个 fake binary 并发写不同输出，共享目录不被删除，临时文件互不覆盖；
- binary/IDB 别名冲突、逃逸路径、输出 producer 冲突被拒绝；
- 内部请求明确 `oldgamever=None`，若走 CLI 则传 `-oldgamever none`；
- 并行节点输出跨屏障保留，串行节点可读；required 缺失失败，optional absent 遵循既有合同；
- concurrency 1与旧串行路径产生相同artifact tree和summary；
- failure后partial artifacts不进入staging；
- all success后artifact contract仍是唯一release continuation gate。
- 含跨 binary edge 的 fixture 在 concurrency 1/2 下得到相同 artifacts；允许两阶段重排，不断言原 tag 执行时序。

Workflow YAML只做parse/schema/action validation和真实run验证；不得新增约束step文案、环境变量文本排版或其他易变YAML内容的单元测试。

## 14. 实施阶段

### 阶段0：基线与容量采样

1. 在production-equivalent runner以concurrency 1执行一次完整release analysis。
2. 记录每个 binary 及 tag 的 wall time、Job current/peak memory、IDA/Agent descendant coverage 和 API rate-limit 行为。
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
2. 先写完整图分类、串行种子下游闭包、binary 分组与串行分段的测试，再实现纯计划转换。
3. 抽取内部 binary 节点子集执行与 result 输出，不改变公共 `-node`/`-force_all` 合同。
4. 实现 lazy pending queue、subprocess worker、phase/binary-prefixed log drain 和严格成功屏障。
5. 实现节点覆盖校验、aggregate summary、stop-admission、bounded timeout/cancel 和 result temp cleanup。
6. 默认 concurrency 1 接管 full `run_all()` 路径，验证无依赖配置兼容与跨 binary 依赖 fixture 两阶段语义。

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
4. 再以 concurrency 2、`publish_release=false` 运行并保存证据，先验收同 tag 不同 binary 同时运行与资源边界。

### 阶段5：渐进激活与文档

1. 对比串行/并发artifact bytes、selection、source/bin SHA和release bundle verification。
2. 观察至少两次production-equivalent成功运行和一次受控worker failure。
3. 更新双语architecture/CI/requirements、operator runbook和Basic Memory。
4. 以受控 finder fixture 验证串行尾队列、成功屏障和重新打开 neutral IDB；生产当前无跨 binary edge 不能替代此证据。
5. 证据支持时再调高Environment concurrency；否则保持2或回滚1。

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
2. concurrency 2 时两个不同 binary 同时存在 verified MCP endpoint，至少覆盖同 tag/module 的不同 platform；
3. 两个Agent/MCP查询到各自exact binary，不串线；
4. aggregate Job current/peak memory低于configured hard budget；
5. memory pressure时新worker被延迟而不是继续启动；
6. 受控低budget触发明确memory failure且runner未OOM；
7. worker failure停止新admission、active worker正常cleanup；
8. workflow cancel 后 owned worker、`idalib-mcp`、Agent 与 port 均回收，stale `.id0` 在确认退出后按 ownership 清理；
9. 并发输出通过`bin_artifact_contract.py`并与tracked Git truth一致；
10. release bundle本地verify继续成功；
11. 受控跨 binary fixture 证明并行成功并退出后才执行串行段，失败时串行段零启动；
12. 同一 binary 跨阶段重新打开，neutral IDB mutation 不延续也能依靠 artifacts 正确执行。

无法执行真实IDA、Agent、license、Job inheritance或OOM门禁时，只能声明仓库实现完成，不得声明parallel production activation完成。

## 16. 风险与缓解

### 风险：动态端口TOCTOU导致worker连接错误supervisor

缓解：跨进程startup lock、bind确认、bounded re-allocation和exact database identity verification必须先于parallel activation完成。

### 风险：memory budget只覆盖worker本体，不覆盖Agent descendants

缓解：resource-owning analyzer先加入Job并验证inheritance；真实fixture必须证明`idalib-mcp`和Agent descendants计入Job snapshot。
逃逸即阻断激活。

### 风险：hard limit触发进程异常而不是优雅退出

缓解：85% soft gate、conservative reservation和staggered launch作为正常保护；hard violation始终fail closed并通过新run恢复，不在同run隐式降并发重试。

### 风险：不同 binary 并发消耗 LLM/API quota

缓解：初始concurrency 2，观察provider rate-limit；Agent自身bounded retry保持不变。不得把API失败误判为memory pressure或自动无限重试。

### 风险：两阶段重排改变 failure 前已执行的节点集合

缓解：lazy admission；首个 failure 停止新启动，只 drain 已运行的 bounded 集合；日志和 result 明确标记 phase、aborted nodes，
不承诺旧 tag 级失败集合。`-skip_error` 不允许绕过成功屏障。

### 风险：日志交错或pipe阻塞隐藏真实故障

缓解：每worker持续drain、stderr合并、单行prefix和print lock；机器结果来自result JSON而非日志解析。

### 风险：artifact或IDB路径意外共享

缓解：实际 binary/IDB identity 去重、精确节点输出 ownership、path containment、共享 module 目录副作用审查、strict `.id0`
与最终 artifact contract。不能再用「不同 tag 子树互不重叠」作为唯一隔离依据。

### 风险：遗漏串行下游或把 IDB mutation 当作跨阶段依赖

缓解：在完整节点 DAG 上分类并计算全部下游闭包，验证 serial -> parallel edge 不存在；跨阶段仅保留 artifacts。若某 finder
实际依赖未声明的前序 IDB 修改，修正该 finder 的自包含初始化或显式 artifact 合同，不为整个批次增加 IDB mutation 保存机制。

### 风险：GitHub runner已位于不兼容Job Object

缓解：阶段0/1先验证nested Job行为；不兼容时保持concurrency 1并重新设计process assignment，不允许关闭memory guard后继续parallel。

## 17. 回滚与兼容性

- 设置 `GSVIBE_ANALYSIS_MAX_CONCURRENCY=1` 后新 invocation 不再重叠 analysis workers；仍使用两阶段分类与成功屏障，
  不表示恢复旧 tag 调度算法，也不改变已经运行中的 invocation；
- `GSVIBE_ANALYSIS_MAX_MEMORY_MIB`可以在full、single-tag和selected-node串行模式继续保留，提供统一OOM边界；
- 回滚不修改或删除warm IDB generations、READY、selection artifact或release bundle；
- worker result schema是ephemeral internal contract，不进入长期兼容surface；
- 不恢复fixed MCP port；dynamic endpoint和success-only preflight继续保留；
- 失败run重新执行时仍从新的fresh artifact root和exact restored selection开始，不复用partial artifacts；
- 若 coordinator 本身存在缺陷，可通过代码回滚恢复旧串行实现，但须先核验目标配置的依赖顺序是否受旧实现支持；不能仅因旧路径
  是串行就认定它支持任意跨 binary DAG。不得绕过 strict restored/no-save 与 artifact contract。

## 18. 建议提交拆分

| 顺序 | 主题 | 主要内容 | 门禁 |
| --- | --- | --- | --- |
| 1 | Memory primitives | Job Object、snapshots、soft gate、fixtures | `test_analysis_memory` + process-tree evidence |
| 2 | Binary work contract | 精确节点子集执行、phase/binary/work item/result | batch + planner unit tests |
| 3 | Two-phase coordinator | 串行闭包、binary 分组、拓扑分段、成功屏障、logs、failure/cancel、default1 | 分类/屏障测试，串行 artifact compare |
| 4 | MCP startup safety | cross-process lock、bounded port retry | lifecycle tests + two-real-MCP evidence |
| 5 | Release activation | Environment wiring、concurrency 1/2 runs | workflow parse + real runner evidence |
| 6 | Operations/docs | runbook、双语docs、memory note | docs review + captured evidence |

每个提交遵循`<type>(scope): <summary>`并追加`Co-Authored-By: Codex <codex@openai.com>`。

## 19. 最终验收标准

必须全部满足：

1. `-allgamever -force_all` 使用完整节点 DAG 分类：跨 binary edge 的 target 及其全部下游进入串行集合，其余按 binary 分组。
2. 每个 work item 是单 binary 的精确有序节点子集和独立 worker process；同 binary 内 skills 串行。并行阶段 active workers
   不超过 N，串行阶段不超过 1；默认 concurrency 为 1，无 tag 完成屏障。
3. effective concurrency大于1必须配置aggregate memory budget，非法/缺失配置在启动worker前fail closed。
4. Soft gate在projected memory超过阈值时暂停admission；Windows Job hard limit覆盖coordinator及全部owned descendants。
5. 直接`-gamever`/`-node`设置memory budget时，同一hard limit覆盖该analyzer及其`idalib-mcp`/Agent descendants；
   concurrency ceiling保持effective `1`，不会隐式改变单tag DAG。
6. Memory guard 不可用时不会静默 parallel；hard violation 明确失败，不当作普通业务 failure；真实容量验收覆盖 host headroom，
   不把 Job budget 误称为整机 OOM 保证。
7. Worker使用独立dynamic MCP endpoint并绑定exact binary，不连接其他worker或静态13337。
8. 保留完整节点依赖和精确输出 ownership；strict restored/no-save、cache selection 和 generation 协议不变。允许同 binary 跨
   阶段或串行分段重新打开，不保存前一阶段 IDB mutation，跨阶段依赖只通过 artifacts 满足。
9. 并行阶段所有 work items 结果完整成功且进程/lifecycle 已退出后，才允许启动串行阶段；任何失败都不能跨屏障。尾队列按节点
   拓扑顺序执行，只合并连续同 binary 节点；合法节点 DAG 的 binary 收缩图有环不构成拒绝理由。
10. `skip_error=false` 首个失败停止新 admission 并 drain active workers；`skip_error=true` 仅允许继续并行诊断，不绕过屏障，
    串行失败仍停止后续段；任一 failure 最终非零。取消/异常后 owned tree 和 ports 回收，磁盘残留仅在确认退出后按 ownership 清理。
11. 日志按 phase/binary/work item 追踪，summary 按稳定顺序汇总，所有计划节点不重不漏，零节点 tag 可见；secret 不进入 argv/log/result。
12. 当前无跨 binary edge 配置的 concurrency 1 与迁移前 full analysis 产生 byte-equivalent artifact tree；含跨 binary fixture
    在 concurrency 1/2 下也得到相同输出。并发输出继续通过 artifact 和 release bundle verification。
13. 定向测试、完整质量门禁、真实runner concurrency/memory/cancel/license证据均已如实记录。
14. Production Environment variable 从 1 到 2 渐进激活；改回 1 后新 invocation 关闭 worker 重叠，仍保留两阶段语义。
15. 双语架构/CI/requirements、operator runbook与Basic Memory已和最终实现同步。
