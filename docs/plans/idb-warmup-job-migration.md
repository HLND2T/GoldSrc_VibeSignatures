# IDB warmup 独立 Job 与原子缓存移植计划

状态：仓库实现与本地验证已完成；production runner evidence 待外部环境验证

日期：2026-08-28（Asia/Singapore）

优先级：P0

GoldSrc 规划基线：`main@21c9044037f17c892a71ff5b96ec1c770d392370`

CS2 参考树：`D:/CS2_VibeSignatures@12ea634c08613f7ef687ecdf7c9519c850ceb46a`

CS2 直接修复提交：`243f4509e7e9b6122487caf715c45e3cd1ef67de` `fix(cache): harden atomic JSON replacement on Windows`

关联计划：`docs/plans/architecture-followup-migration.md` 第 6 节

Warm-only 契约更新（2026-08-28）：`cache_mode` 只作为 plan/selection 中固定为 `warm` 的证据字段保留；
workflow、planner 与 Analyzer 不再暴露 mode switch，producer 失败会阻塞 consumer。下文关于 cold rollback、
warm/cold route 与 `-cache_mode` 的内容是原设计记录，已被当前实现取代。

## 1. 计划定位

本计划把 GoldSrc 的 IDB cache producer 从 analysis consumer 中拆出，迁移为独立、可复用、全局串行的
`warmup-idb` job，并把 CS2 参考树已经验证的以下能力迁移到 GoldSrc：

1. Windows canonical JSON 原子替换重试与 UUID 临时文件；
2. immutable generation + exact selection consumer contract；
3. producer 与 consumer 使用不同、干净 workspace；
4. producer 通过 GitHub Actions concurrency 和 persisted-root file lock 双重串行；
5. consumer 不读取可变 `READY.json`，只恢复 producer 输出的 exact generation；
6. cache miss、cache hit、失败、取消和 cold rollback 都有明确的 fail-closed 语义。

本计划条件性替代 `architecture-followup-migration.md` 第 6.4、6.5 节的“producer/consumer 初版必须同 job”决策。
替代条件不是文档声明，而是第 5 节的共享存储、ACL、跨 runner 可见性与原子 rename 证据全部完成。
第 6.1-6.3 节关于 neutral baseline、identity、immutable generation、strict consumer 的正确性边界继续有效。

### 1.1 如何理解 CS2 参考提交

`12ea634c...` 是 merge commit。相对第一父提交，它只修改：

- `idb_cache.py`；
- `release_workflow_lib/hashing.py`；
- `tests/test_atomic_json_write.py`；
- `tests/test_idb_cache.py`；
- `tests/run_test_suite.py`。

该 diff 只加固 Windows JSON replacement 和相同 READY 不重写。CS2 的 reusable `warmup-idb.yml`、
`preflight -> warmup -> build` DAG、immutable generation outputs 与 exact restore 是该 commit tree 中此前已经存在的架构，
不是本次 merge diff 新增内容。

因此本计划定义的“1:1 移植”是行为和协议对齐，不是源码同步、整提交 cherry-pick 或同名文件覆盖。
GoldSrc 的多 tag/platform、`bin` submodule、blob 解密、manifest schema 和 PR bound plan 必须保留。

## 2. 当前故障与根因

### 2.1 已观察到的真实运行

- Release run `33083848020` 在 cache miss 后进入 analysis。Warm worker 在当前 workspace 构建并留下 IDB，
  因而 analysis 偶然能看到数据库；随后失败于独立的 `find-build_number` Agent fallback 问题。
- Release run `33089310503` 的 warm step 对所有 game version 报 cache hit，但 analysis 立即失败：
  `Strict restored IDA database is missing for bin\hl-3248\engine\hw.decrypt.dll`。
- 第二次运行证明 `idb_cache_release.py warm` 的 cache hit 只验证 persisted generation，没有把 generation restore 到
  `bin/<tag>`；当前 workflow 却直接执行 `ida_analyze_bin.py -cache_mode warm`。

### 2.2 当前错误数据流

```text
release build workspace
  -> idb_cache_release.py warm
       hit  -> verify persisted generation only
       miss -> worker builds workspace IDB and publishes generation
  -> ida_analyze_bin.py -cache_mode warm
       hit path  -> workspace 没有 IDB，strict failure
       miss path -> 偶然复用 worker 留下的 workspace IDB
```

cache miss 的 workspace 副作用掩盖了缺少 restore 的流程错误。任何正确迁移都必须让 hit 和 miss 走完全相同的
consumer 边界：producer 只发布 immutable generation，consumer 只按 exact selection restore。

### 2.3 当前并发缺口

- Release workflow concurrency 按 release version 分组；不同 version 仍可同时写同一 tag cache。
- PR self-hosted workflow 使用另一组 concurrency authority，可能与 release producer 重叠。
- `warm_gamever()` 的 per-tag lock 只保护 `probe -> warm/publish -> verify -> prune`。
- `restore_gamever()` 与 `restore_cache_selection()` 不持有同一个 tag lock，可能与 prune 竞争。
- file lock 默认等待 120 秒，而 warm worker 最长允许 3600 秒；第二个 writer 可能过早失败。
- `write_canonical_json()` 使用 PID 临时名和单次 `os.replace`，Windows sharing violation 会直接失败。
- 直接调用底层 `idb_cache.py publish/prune/restore` 可以绕过 release orchestration 的 tag lock。

## 3. 目标

### 3.1 功能目标

1. 新增独立 reusable `warmup-idb` workflow/job，producer 与 analysis consumer 不共享 workspace 副作用。
2. Release 和需要 warm cache 的 source PR 使用同一个 producer concurrency authority。
3. Producer 为当前 run 生成 canonical `cache-selection.json` 与独立 SHA-256 evidence。
4. Selection 聚合覆盖当前执行计划要求的全部 `(tag, platform)` groups。
5. Consumer 在 fresh checkout/materialization 后验证 selection、restore exact generations，再运行 strict warm analysis。
6. Cache hit 和 miss 对 consumer 完全等价。
7. Cold mode 保留为显式 rollback 路径，不读取 persisted IDB cache。
8. 保留 Release analyzer 的 `-debug -process_reporter console` diagnostics。

### 3.2 并发目标

1. 官方 workflow 同一时刻最多一个 persisted IDB cache producer。
2. 同 tag 的 Python writer 即使绕过 GitHub 调度层也必须由共享 tag lock 串行。
3. Restore、verify 与 prune 对 exact generation 的生命周期不存在 delete/read race。
4. 多个 consumer 可以并发只读 immutable generations，并各自在自己的 workspace 修改 restored IDB。
5. Writer 失败或被取消时不得让 reader 选择 `.incoming-*` 或半写 READY。

### 3.3 可观测性目标

日志至少记录：

- producer scope、source SHA、bin gitlink；
- cache hit/miss；
- tag/platform、cache key、generation、manifest SHA-256；
- selection SHA-256；
- lock wait、warm、publish、verify、restore wall time；
- cleanup 结果；
- 失败阶段与结构化 reason。

不得记录 `PERSISTED_WORKSPACE` secret 的原始值、Steam/LLM/Agent 凭据或其他敏感绝对路径。

## 4. 非目标

- 不解决 `find-build_number` preprocessor/Agent fallback 或缺失 Skill；该问题会在 cache 流程修复后单独暴露和处理。
- 不把项目 finder、Preprocessor、Agent rename/comment/patch 后的 IDB 写回 cache。
- 不把 GitHub Actions artifact 当 IDB payload transport；artifact 只传递 selection/evidence。
- 不把 `READY.json` 升级为 truth source；它仍只是 probe 优化指针。
- 不把 CS2 的单 `GAMEVER`、普通 `bin` 目录或 `.i64`-only 模型复制到 GoldSrc。
- 不在初版引入 tag/platform matrix warmup；先用单 producer job 换取清晰的全局串行语义。
- 不在 strict warm consumer 中增加 inline cold fallback。
- 不顺便改变 snapshot、gamedata、release manifest 或 generated-output PR 的内容合同。

## 5. 激活前置条件与信任边界

拆 job 前必须取得并保存以下真实环境证据：

1. 所有 eligible Windows self-hosted runners 的 `PERSISTED_WORKSPACE` canonical path 指向同一受控存储。
2. Producer 在 runner A 发布的 generation 能由 runner B 读取并通过完整 manifest/inventory 验证。
3. 共享存储支持同一目录内 atomic rename，且不跨 volume/materialization boundary。
4. Runner account 对 persisted root 使用同一 ACL authority；其他账号没有非审计写权限。
5. persisted root 与 checkout、`bin` submodule 相互 disjoint，路径祖先无 symlink/reparse point。
6. Windows byte-range lock 在实际共享存储上具备跨 runner 互斥语义；测试必须使用两个独立进程/runner，而不是同进程线程。
7. `python`、`idalib-mcp`、`IDADIR` 属于同一 pinned IDA installation，动态 kernel identity 一致。
8. `win64` Environment 只向受信任的 producer/consumer job 注入 secrets。
9. Fork/untrusted PR 不能进入 reusable warmup 或 IDA consumer job。

任何条件不满足时保持组合 job 或显式 cold mode，不得仅因为 workflow YAML 已合入就启用 split-job warm path。

## 6. 目标 DAG

### 6.1 Release

```text
preflight
  -> resolve exact source_sha / mode / cache_mode
  -> warmup-idb (cache_mode=warm only)
       fresh checkout exact source_sha
       materialize exact bin + accepted-bin overlay
       prepare/publish/verify immutable generations
       upload cache-selection.json + cache-selection.sha256
  -> build
       fresh checkout exact source_sha
       materialize exact bin + accepted-bin overlay again
       download + verify exact selection
       restore exact generations to bin/<tag>
       ida_analyze_bin.py -allgamever -cache_mode warm -debug -process_reporter console
       candidate/gamedata/stage/output PR
```

`build.needs` 必须包含 `preflight` 与 `warmup-idb`。Warm mode 只有 producer 成功才允许 build；producer failure/cancel
必须使 build 跳过或失败，不能在 build 内重新 warm。

### 6.2 Source PR

```text
plan
  -> hosted plan artifact + plan SHA
  -> warmup-idb (只有 cache_mode=warm 且存在 analysis_nodes)
       fresh merge checkout
       download + verify bound plan
       warm only selected tag/platform groups
       upload exact cache selection
  -> analyze-self-hosted
       fresh merge checkout
       download + verify bound plan and selection
       restore exact generations
       selected-node strict warm analysis
  -> pr-validate
```

Hosted-only、no-op、fork-blocked 和 explicit cold routes 不调用 warmup job。`pr-validate` 固定终态 job 名称不变。

### 6.3 Cold rollback

```text
preflight/plan binds cache_mode=cold
  -> skip warmup-idb
  -> consumer validated clean
  -> ida_analyze_bin.py -cache_mode cold
```

Consumer job 的条件必须显式允许“cold + warmup skipped”，同时拒绝“warm + warmup skipped/failed”。

## 7. Reusable warmup workflow 合同

新增 `.github/workflows/warmup-idb.yml`，支持 `workflow_call`，初版不提供普通公开 `workflow_dispatch`；需要人工 warm
时由受保护 release/maintenance workflow 显式调用，避免绕过 source/plan binding。

### 7.1 Inputs

至少包括：

- `source_sha`：40 位 exact commit SHA；
- `scope`：`release-all` 或 `bound-plan`；
- `plan_artifact_name`：`bound-plan` scope 必填；
- `plan_sha256`：`bound-plan` scope 必填；
- `cache_mode`：初版只接受 `warm`；
- `selection_artifact_name`：由 caller 使用 run ID/attempt 构造，防止同 run 名称冲突。

Secrets 使用 `secrets: inherit`，但 workflow 只读取受保护 Environment 中的：

- `PERSISTED_WORKSPACE`；
- checkout 私有 `bin` submodule 所需 token；
- release accepted-bin materialization 所需的现有受保护凭据。

不得向 neutral warm worker 注入 LLM 或 Agent secrets。

### 7.2 Outputs

至少输出：

- `selection_artifact_name`；
- `selection_sha256`；
- `selection_schema_version`；
- `source_sha`。

多 tag/platform 不使用 CS2 的单一 `generation/cache_key` scalar outputs；exact generations 全部保存在 canonical selection。

### 7.3 Job 边界

Warmup job 固定：

- `environment: win64`；
- `runs-on: [self-hosted, windows, x64]`；
- `timeout-minutes` 覆盖全量 cache miss 最坏墙钟时间；
- job-level global producer concurrency；
- `cancel-in-progress: false`。

步骤顺序：

1. 验证 repository allowlist、source SHA、scope 与 artifact inputs；
2. checkout exact source SHA，`fetch-depth: 0`；
3. restore/sync/update exact `bin` submodule；
4. release scope 以共享 helper materialize accepted bin；PR scope 按 bound plan materialize selected workspace；
5. `uv sync --locked`；
6. 动态解析 IDA Python/`idalib-mcp`/kernel identity；
7. prepare exact selection，miss 时 warm/publish，hit 时 verify；
8. 再次 verify selection 与每个 exact generation；
9. 写 canonical selection 和 ASCII SHA-256 evidence；
10. upload selection artifact；
11. `if: always()` 清理本 job workspace 中 IDB、locks、临时 identity/observed files 与 submodule analysis state。

只有步骤 7-9 全部成功后才允许设置 job outputs。

## 8. Release cache selection 合同

### 8.1 Top-level schema

Release selection 使用独立 schema，避免破坏现有 PR `CACHE_SELECTION_SCHEMA_VERSION = 1` 的 canonical bytes：

```json
{
  "schema_version": 1,
  "cache_mode": "warm",
  "source_sha": "<40-hex>",
  "bin_commit": "<40-hex>",
  "entries": []
}
```

`entries` 按 `(tag, platform)` UTF-8 byte order 排序，每项固定为：

```json
{
  "tag": "hl-3248",
  "platform": "windows",
  "cache_key": "<64-hex>",
  "generation": "<immutable-generation-name>",
  "manifest_sha256": "<64-hex>",
  "binaries": [
    {
      "module": "engine",
      "platform": "windows",
      "path": "engine/hw.decrypt.dll",
      "size": 0,
      "sha256": "<64-hex>"
    }
  ]
}
```

`source_sha` 绑定 producer checkout；`bin_commit` 绑定 source tree 的 `bin` gitlink。Binary list 与 generation manifest 中的
full identity 再绑定实际 accepted overlay、decrypted binary、IDA runtime、loader、worker digest 与 normalized args。

### 8.2 Consumer validation

Consumer 必须在删除任何本地 database 前完成：

1. selection SHA-256 与独立 evidence 匹配；
2. canonical JSON bytes、schema 和 exact key set 匹配；
3. `source_sha` 等于当前 checkout HEAD；
4. `bin_commit` 等于当前 source tree 的 `bin` gitlink；
5. selection entries 完整覆盖当前 release configs 声明的全部 binary groups，无重复或额外 group；
6. 当前 workspace binary identities 与 entry 完全一致；
7. 当前 pinned IDA runtime 重新构建的 expected cache identity 与 generation manifest identity 完全一致；
8. `verify_selection()` 验证 exact `generation + cache_key + manifest_sha256`。

验证过程不得读取 READY 重新选择 generation。READY 在 producer 完成后即使被另一 run 改写，也不得改变当前 consumer。

### 8.3 共享实现

把以下通用 primitive 从 PR-specific `idb_cache_workflow.py` 抽取到内部共享模块，或在不改变现有 PR schema bytes 的前提下
提供等价 helper：

- canonical selection entry validate/build；
- exact generation selection 构造；
- selection file SHA evidence 读写与校验；
- expected group coverage 与 binary identity 校验；
- exact selection restore。

PR selection schema 1 的字段、排序和 canonical bytes 不得因 refactor 改变。Release wrapper 只增加 source/bin binding，
不能复制一份后续会漂移的 generation validation 实现。

## 9. Consumer restore 与 strict analysis

### 9.1 Fresh materialization

Warmup 与 consumer 都必须独立完成：

1. checkout 相同 `source_sha`；
2. sync/update source tree 声明的 exact `bin` gitlink；
3. 对已验证 `$GITHUB_WORKSPACE/bin` 执行 deterministic clean；
4. release scope 按同一 helper/rules overlay `PERSISTED_WORKSPACE/bin/<tag>`，继续排除 IDB 与 lock side files；
5. 重新生成/复用与 selection identity 一致的 decrypted binary。

不能复制两段独立 PowerShell robocopy 逻辑。应把 accepted-bin materialization 收敛到受测试 CLI/helper，producer 与 consumer
调用同一入口。Helper 必须固定 include/exclude、path containment、reparse-point、source/bin binding 和日志规则。

### 9.2 Restore 顺序

```text
validated clean/materialization
  -> verify exact selection
  -> acquire tag lock
  -> restore exact generation
  -> re-verify workspace inventory
  -> strict analysis
  -> final validated clean
```

禁止 restore 后、analysis 前执行 `git clean -ffdx`。Final cleanup 必须 `if: always()`，并只作用于经过 root containment 验证的
当前 checkout `bin` submodule。

### 9.3 Strict mode

- Warm consumer 固定 `database_policy=restored_strict`、`save_on_success=false`。
- Missing/corrupt/mismatched IDB 使当前 consumer 失败。
- Consumer 不调用 warm worker，不发布新 generation，不更新 READY。
- Retry 通过新的 producer run 或相同 immutable selection 的重新 restore 完成。
- Analyzer 保留 `-debug -process_reporter console`，但 diagnostics 不改变 cache correctness contract。

## 10. 并发与锁设计

### 10.1 GitHub Actions authority

初版所有官方 cache producer 使用同一个 job-level group：

```text
idb-warmup-${repository}
```

group 不包含 release version、PR number、source SHA、tag 或 run ID。Release 与 source PR reusable warmup 必须生成完全相同的
group string，`cancel-in-progress: false`，从调度层保证一个 repository 同时只有一个 producer。

现有 release top-level per-version concurrency 保留，它保护 release lifecycle；不能把它误认为 IDB producer authority。

### 10.2 Persisted tag lock

`<PERSISTED_WORKSPACE>/idb-cache/.locks/<tag>.lock` 继续保护：

```text
probe -> optional warm/publish -> verify -> selection entry -> prune
```

修改 lock helper：

- 错误消息使用通用 lock description，不再把 tag lock 超时称为 MCP port lock；
- tag lock timeout 必须不小于 warm worker timeout加发布/校验余量；
- timeout、wait interval 与 lock description 显式传入；
- 进程退出依赖 OS 释放 lock，不删除 lock 文件作为“解锁”；
- 增加跨进程竞争测试。

### 10.3 Restore 与 prune

`restore_cache_selection()` 和 release exact restore 必须取得同一个 tag lock，并在锁内执行 exact verify + restore。
Producer prune 继续位于 tag lock 内。这样 restore 已选择 generation 后不会被另一 producer 删除。

底层 immutable reader 可以并发 verify，但凡涉及以下操作都必须经过 high-level lock authority：

- publish generation；
- 更新/rebuild READY；
- prune；
- restore；
- retired-tag maintenance。

底层函数保持可测试的 lock-agnostic primitive；所有公开 CLI/orchestrator 必须显式取得 lock，不能提供容易误用的无锁写命令。

### 10.4 IDA worker lock

当前 neutral warm worker使用固定 MCP port，因此继续使用全局 `ida-mcp-port.lock`。Global producer job 已消除官方 producer 之间的
端口竞争，file lock 作为直接 CLI/异常调度的防御层。Consumer analyzer 使用动态 endpoint，不共享 warm worker 的固定 port。

### 10.5 Accepted-bin authority

Release warmup 和 build 都会读取 `PERSISTED_WORKSPACE/bin/<tag>`；promotion 可能更新同一目录。必须复用或新增稳定排序的
per-tag accepted-bin lock：

- materialize 在 read/snapshot 临界区持锁；
- promotion 在目录切换临界区持同一锁；
- 多 tag 按 canonical tag order 逐个取得，禁止反序嵌套；
- materialize 释放锁前验证复制 inventory，consumer 后续再由 cache binary identity校验。

## 11. Windows 原子 JSON 加固

按 CS2 `12ea634c...` 的行为移植 `release_workflow_lib.hashing.write_canonical_json()`：

1. 每次调用使用 UUID 临时文件，不使用仅 PID 命名；
2. 临时文件与目标位于同一目录；
3. 先写 canonical bytes，再 `os.replace`；
4. Windows `winerror in {5, 32}` 时 bounded retry；
5. 退避采用 `0.05, 0.1, 0.2, 0.4, 0.8, 1.6` 秒并加入 bounded jitter；
6. replace 失败后若目标已经等于 expected canonical bytes，视为并发 writer 已成功；
7. 不可重试错误立即上抛；
8. 成功与失败都尽力清理本调用自己的临时文件，不掩盖原异常；
9. 不改变 GoldSrc 当前 canonical JSON 编码、`allow_nan=False`、UTF-8/LF 与 `str | Path` API。

在 `idb_cache.py` 增加 GoldSrc 版 `_write_ready(tag_root, selection)`：现有 READY bytes 与 expected canonical bytes 相同时不替换；
内容不同才调用 hardened writer。`publish_generation()` 与 `probe_generation()` 的 READY 修复路径统一使用该 helper。

由于 `write_canonical_json()` 是共享 helper，promotion、staging、gamedata 等调用者会同时获得 Windows retry。实施时必须核对
这些调用者不依赖旧 PID 临时文件名或单次 replace 失败语义。

## 12. 文件级实施范围

| 文件 | 计划改动 |
| --- | --- |
| `release_workflow_lib/hashing.py` | 移植 UUID temp、Windows retry、same-payload success 与 cleanup |
| `idb_cache.py` | 增加 `_write_ready` 幂等写入；保持 immutable generation protocol |
| `idb_warm_worker.py` | 泛化 lock diagnostics/timeout；保留固定 warm port lock |
| `idb_cache_workflow.py` | 保持 PR schema 1；改用共享 selection primitive；restore 加 tag lock |
| `idb_cache_release.py` | 从 `warm/restore` 扩展为 release selection prepare/verify/exact restore，禁止 consumer re-probe READY |
| `release_workflow.py` / `release_workflow_lib/*` | 收敛 accepted-bin materialization 与 per-tag authority，避免 YAML 重复 robocopy |
| `.github/workflows/warmup-idb.yml` | 新 reusable producer workflow、global concurrency、selection artifact |
| `.github/workflows/release-build.yml` | `preflight -> warmup-idb -> build`；build 下载/验证/restore selection；保留 cold route与debug flags |
| `.github/workflows/gamesymbol-pr-validation.yml` | warm producer 拆 job；consumer 只 restore；共用 producer concurrency authority |
| `tests/test_atomic_json_write.py` | 新增 JSON replace retry/cleanup/UUID/并发行为测试 |
| `tests/test_idb_cache.py` | READY 幂等、release selection、exact restore、锁竞争与 failure cleanup |
| `tests/test_release_workflow*.py` | 只测试 Python materialization/selection行为，不锁定 YAML 文本 |
| `tests/run_test_suite.py` | 注册新增 Python unit module |
| `docs/en/*`、`docs/zh-CN/*` | 更新 architecture、analysis、CI/CD、requirements、IDB operations 与 release runbook |
| `memory/` | 实施完成后更新 warm IDB 架构、触发信号、恢复和验证经验 |

若共享 selection primitive 需要新模块，命名应表达 cache selection contract，不得把 PR plan 或 release version 语义塞入
`idb_cache.py` 的 immutable generation core。

## 13. 实施阶段

### 阶段 0：冻结基线与失败测试

1. 保存两次失败 run 的日志和 cache hit/miss 证据。
2. 为 cache hit 后 workspace 无 IDB 的当前行为补 Python regression test。
3. 为 concurrent canonical JSON writer、WinError 5/32 与 READY no-op 写失败测试。
4. 为 restore-vs-prune 与 tag-lock timeout 写跨进程失败测试。
5. 记录当前 PR selection canonical bytes fixture，防止 refactor 改变 schema 1。

### 阶段 1：移植 `12ea` 原子 JSON 加固

1. 实施 hardened `write_canonical_json()`。
2. 实施 `_write_ready()` 幂等路径。
3. 运行 atomic JSON 与 IDB cache unit tests。
4. 核对共享 JSON writer 其他调用者。

该阶段可独立合入，不改变 workflow DAG。

### 阶段 2：共享 exact selection primitive

1. 抽取 entry/build/validate/SHA/restore primitive。
2. 保持现有 PR selection schema 1 byte-stable。
3. 新增 release selection schema 1 与完整 coverage validation。
4. `idb_cache_release.py prepare` 输出 selection + SHA；`verify/restore` 消费 exact selection。
5. 删除或弃用会在 consumer phase重新 probe READY 的 release restore 路径。

### 阶段 3：并发 authority 与 materialization

1. 泛化 file lock helper 和 timeout。
2. restore/prune/public CLI 接入 tag lock。
3. accepted-bin materialization/promotion 接入 per-tag lock。
4. 将 producer 与 consumer 使用的 bin overlay 收敛到同一 helper。
5. 完成真实共享存储跨 runner lock/rename evidence；未完成则停止在此阶段，不拆 job。

### 阶段 4：新增 reusable warmup job

1. 新增 `warmup-idb.yml`。
2. 实现 release-all 与 bound-plan scopes。
3. 配置 global producer concurrency。
4. producer 生成、验证、上传 selection artifact。
5. producer cleanup 使用 `if: always()`。

### 阶段 5：迁移 Release consumer

1. `preflight` 输出并绑定 `cache_mode`。
2. Release 调用 reusable warmup。
3. Build 使用 fresh checkout/materialization，下载 selection。
4. Build verify/restore exact generations 后 strict analysis。
5. 删除 build 内 inline `idb_cache_release.py warm`。
6. 保留 `-debug -process_reporter console`。
7. 验证 cold route 和 warm producer failure route。

### 阶段 6：迁移 PR producer

1. `plan` 向 reusable warmup 传递 bound plan artifact和SHA。
2. 只有 warm + selected analysis route 调用 producer。
3. `analyze-self-hosted` 下载 exact selection，只做 verify/restore/analyze。
4. PR 与 Release 使用相同 global producer concurrency group。
5. `pr-validate` 汇总语义和 required check 名称不变。

### 阶段 7：真实 runner 激活

按以下顺序保留 run evidence：

1. explicit cold；
2. split-job warm cache miss；
3. 同 identity cache hit，且 consumer 位于另一 runner；
4. READY 在 producer/consumer 间改变但 exact restore 仍成功；
5. 两个不同 release version 同时触发，第二个 warm producer排队；
6. Source PR 与 Release 同时请求 warmup，仍只有一个 producer；
7. producer cancel/timeout 后无半写 generation 被选择；
8. corrupt generation/selection fail-closed；
9. build failure 后 workspace cleanup 和 persisted generation完整。

证据不完整前不得删除 cold rollback，也不得把 split warm path 宣称为 production-ready。

## 14. 测试策略

本迁移采用 Level 2/TDD。

### 14.1 Atomic JSON

- UUID 临时路径唯一；
- 同进程多线程写相同/不同 payload；
- Windows error 5/32 retry；
- retry 期间目标已等于 expected bytes；
- retry exhausted；
- 非 retryable error；
- 成功/失败临时文件 cleanup；
- canonical bytes/API 与旧实现兼容。

### 14.2 Cache core

- incoming 完整验证后才发布；
- generation rename 后、READY 前崩溃可由 probe 恢复；
- 相同 READY 不写，不同 READY 才写；
- exact selection 不受 READY 改写影响；
- manifest/binary/database tamper fail-closed；
- decrypted blob path 与 `.i64/.idb` full file set；
- restore 前后 binary/runtime identity；
- restore 失败清理已复制 database；
- prune 不删除持锁 restore 正在消费的 generation。

### 14.3 Selection

- release selection canonical ordering与SHA evidence；
- source SHA/bin gitlink mismatch；
- missing/duplicate/extra tag-platform group；
- binary identity/runtime/manifest mismatch；
- cache hit/miss 产生等价 selection；
- PR schema 1 canonical bytes保持不变；
- release consumer never probes READY。

### 14.4 Concurrency

- 两个进程竞争同 tag lock；
- 等待时间覆盖长 warm；
- timeout 不写 READY；
- restore 与 prune 串行；
- direct CLI 不能绕过 high-level lock；
- accepted-bin materialize 与 promotion 使用同一 authority；
- 进程崩溃后 OS lock 释放，lock 文件存在不等于 lock held。

### 14.5 Workflow 与真实环境

Workflow YAML 只做解析、schema/action validation 和真实 run 验证，不新增约束 YAML 文本、step 文案或易变配置内容的单元测试。

真实环境必须覆盖第 13.7 节全部场景。测试结果记录 run URL、runner identity、source/bin SHA、selection SHA、generation、
cache key、manifest hash 与时间戳。

## 15. 验证命令

定向验证：

```text
uv run python -m unittest tests.test_atomic_json_write
uv run python -m unittest tests.test_idb_cache
uv run python -m unittest tests.test_release_workflow tests.test_release_workflow_guards
```

静态验证：

```text
uv run python -c "from pathlib import Path; import yaml; [yaml.safe_load(path.read_text(encoding='utf-8')) for path in Path('.github/workflows').glob('*.yml')]"
uv run python format_repo_files.py --check
git diff --check
```

若环境已安装 `actionlint`，额外运行全部 workflow validation；未安装时必须明确记录，不能虚构通过。

完成前质量门禁：

```text
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
```

关键真实 runner 验收无法执行时，只能声明仓库实现完成，不得声明 production activation 完成。

## 16. 迁移、回滚与兼容性

### 16.1 向前兼容

- Existing immutable generations 保持 schema/路径不变，可以直接被新 exact selection引用。
- READY 保持相同 schema，仅写入实现更可靠且相同内容不替换。
- PR selection schema 1 不变。
- Release selection 是新增 schema，不复用旧的 implicit READY probe。
- Cache key identity 不因 workflow 拆 job 而改变。

### 16.2 Rollout

1. 先合入原子 JSON/READY 加固。
2. 再合入 selection/lock/materialization core，但 workflow 继续同 job。
3. 在非生产或受保护测试 repository 启用 split-job warm path。
4. 完成跨 runner evidence 后切 production warm route。
5. 保留 cold route至少一个完整 release 周期。

### 16.3 Rollback

- Workflow 回滚到显式 cold mode，不回滚 immutable generation schema。
- 不恢复“warm miss 后直接消费 workspace side effect”的旧行为。
- 不删除已发布 generations；按 retention policy等待确认无 in-flight selection 后再 prune。
- Split-job producer失败时不允许 build 改为 implicit warm/cold；由新 run 重新调度。
- 若 hardened JSON writer 出现兼容问题，可回滚 writer实现，但必须保留 UUID temp 或通过修复提交恢复，不得依赖清理共享 PID temp。

## 17. 风险与权衡

### 17.1 全局 producer 降低吞吐

所有 PR/Release warm producer 串行，cache miss 时可能形成队列。初版优先正确性；只有收集真实等待时间、形成按 tag canonical
matrix outputs并证明 fixed-port隔离后，才另立计划拆成 per-tag concurrency。

### 17.2 Actions artifact 可用性

Selection artifact 下载失败会阻断 consumer。它很小且可重建，但当前 run 不允许重新 probe READY；恢复方式是 retry producer
或重新运行 workflow。这是 exact binding 换来的有意 fail-closed 行为。

### 17.3 Shared storage 语义不可靠

若跨 runner byte-range lock 或 rename 不可靠，GitHub global producer group仍能串行官方 writers，但不能约束人工/旁路 CLI。
因此 direct write CLI必须进入相同 high-level authority，运维 runbook必须禁止无锁写入。

### 17.4 Restore 持锁延长 producer等待

Restore 在 tag lock 内复制并校验完整 database，producer可能等待。IDB generation immutable，未来可通过 generation pin/refcount
减少锁范围；初版先消除 prune/delete race。

### 17.5 Shared JSON helper 影响范围大

`write_canonical_json()` 有多个非 IDB 调用者。Windows retry 提高可靠性，但实现错误会影响 release staging/promotion。
必须先独立合入并运行完整 suite，不能和 workflow 拆分压在同一不可定位的大提交中。

### 17.6 后续 analyzer failure

IDB warmup 修复只保证 analysis 拿到正确 neutral database。`find-build_number` 等业务节点仍可能失败；验收必须区分
“cache producer/restore 成功”与“完整 release build 成功”。

## 18. 建议提交/PR 拆分

| 顺序 | 主题 | 主要内容 | 门禁 |
| --- | --- | --- | --- |
| 1 | Atomic JSON | `12ea` 行为移植、READY幂等、unit tests | atomic JSON + IDB tests + full suite |
| 2 | Selection core | shared primitives、release selection、exact restore | IDB/selection tests，PR schema fixture |
| 3 | Lock/materialization | lock timeout、restore/prune authority、accepted-bin helper | 跨进程 tests + release helper tests |
| 4 | Reusable warmup | 新 workflow、artifact/output、global producer group | YAML/action validation + test repo miss/hit |
| 5 | Release consumer | Release DAG、fresh restore、cold rollback | 两次 release miss/hit + different runner |
| 6 | PR consumer | PR producer拆分、统一 authority、stable final gate | PR warm/cold/no-op/fork routes |
| 7 | Production activation | governance、runbook、evidence | 第 13.7 节完整证据 |

每个提交遵循 `<type>(scope): <summary>`，并追加 `Co-Authored-By: Codex <codex@openai.com>`。

## 19. 最终验收标准

必须全部满足：

1. `warmup-idb` 是独立 reusable job；Release/PR consumer 中没有 inline warm/publish。
2. Release 与 PR 官方 producer 使用同一 global concurrency authority。
3. Cache miss 与 hit 都由 fresh consumer restore exact selection，不依赖 producer workspace IDB。
4. Consumer 不读取 READY 决定 generation。
5. Selection canonical bytes和SHA绑定source SHA、bin gitlink、完整group coverage与exact generation manifest。
6. Restore、prune、publish、READY update和accepted-bin切换处于明确lock authority。
7. Windows JSON transient sharing violation可bounded recovery，temp唯一且无泄漏。
8. Incomplete incoming、损坏 READY、损坏 generation、producer failure/cancel都fail-closed。
9. Warm strict consumer不inline fallback、不保存finder修改回cache。
10. Explicit cold route可以在不读取IDB persisted root的情况下完成同一分析范围。
11. PR selection schema 1与现有canonical bytes兼容。
12. Workflow保留fork/self-hosted/environment/secrets trust boundary。
13. 定向测试、仓库质量门禁和真实runner miss/hit/concurrency/cancel证据全部完成。
14. 运维文档、双语用户文档和Basic Memory架构说明与最终实现同步。
15. Cache恢复成功和完整业务分析成功分别报告，不用IDB验收掩盖后续Skill失败。
