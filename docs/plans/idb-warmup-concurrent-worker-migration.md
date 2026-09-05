# GoldSrc warm IDB 并发 worker 对齐 CS2 移植计划

状态：仓库实现完成；生产激活前仍需执行阶段 5 的跨 runner SMB3 与聚合 Job 证据

日期：2026-09-04

评审修订：2026-09-05（运行时契约收敛为 CS2 的同一 Python executable + IDA kernel version；删除完整 runtime 观测与 loader/plugin 摘要绑定；补齐 auto_wait 失败语义及聚合 Job 的跨 group 生命周期；明确接受版本探针无独立 deadline / 专属 kill-wait 回收）

优先级：P1（吞吐；有意简化运行时 identity，保留 immutable generation / exact selection / 锁 authority）

GoldSrc 基线：`main@21c9044037f17c892a71ff5b96ec1c770d392370`（与 `idb-warmup-job-migration.md` 相同）

CS2 参考树：`D:/CS2_VibeSignatures@12ea634c08613f7ef687ecdf7c9519c850ceb46a`

前置计划：`docs/plans/idb-warmup-job-migration.md`（其 17.1 节明确把「per-tag concurrency」列为"另立计划"，本计划即该后续）

---

## 0. 移植意图（声明）

本计划把 GoldSrc 的 warm IDB **worker 并发模型**对齐 CS2，目标是与 CS2 保持一致的三个能力：

1. **裸 idalib，无端口**：把现有 `idb_warm_worker.py` 原地改造成唯一 warm worker 入口，从 idalib-mcp（`IdaMcpLifecycle` + 固定 `DEFAULT_PORT` + MCP `py_eval` 观察运行时）迁移为**裸 idalib**（`idapro.open_database` / `ida_auto.auto_wait` / `ida_loader.save_database` / `idapro.close_database`），不再占用任何 MCP 端口；worker 必须由 workflow 已解析并验证的 IDA Python 启动。
2. **`--max-concurrency`**：新增并发上限参数与环境变量 `IDB_WARMUP_MAX_CONCURRENCY`（缺省 `2`），约束同一 producer 调用内可同时运行的 worker 进程数。
3. **二进制级并发**：把「一个 worker 进程串行 warm 整个 (tag, platform) 组的所有二进制」改为「**每个二进制一个独立 worker 子进程**，经 `ThreadPoolExecutor` 并行调度」。

**动机**：当前 GoldSrc 用 idalib-mcp + 全局固定 `warm_port_lock`，同一时刻只能有一个 warm worker（[idb_cache.py:742](idb_cache.py#L742)），组内二进制在单个进程内串行（[idb_warm_worker.py:194](idb_warm_worker.py#L194)）。cache miss 时（release-all 一次要 warm 几十个二进制）吞吐被串成一条线；CS2 已验证裸 idalib 无端口可让多个 worker 并行。本计划在不改变 immutable generation / selection / 锁 authority 的正确性契约前提下，把 warm 段并发化以缩短 cache-miss 墙钟时间。

**边界**：并发改造仅作用于 **producer（warm）侧**；共享 cache identity builder、validator 与 release/PR consumer 的缓存 CLI 调用同步适配简化后的运行时字段。consumer 的 `IdaMcpLifecycle`（动态端口、`restored_strict`、`save_on_success=False`）与 exact restore 语义保持不动。官方 producer 实例级「全局单飞」由 `idb-warmup-${repository}` Actions concurrency group 保证；所有 producer high-level prepare（含官方与 direct mutating CLI）还共同持有 repository-wide producer-only SMB lock，使旁路调用不能与官方 producer 重叠。并发发生在**单个 producer 调用、单个 (tag, platform) 组内部**，不引入跨 group / 跨 tag 的并行（那是既有计划 17.1 的另一话题）。`tag_lock` 继续作为跨 runner persisted-storage correctness lock，但不再覆盖耗时的 workspace warm。

**已确认的运行时取舍**：采用 CS2 的同一 Python executable + IDA kernel version 契约，不保留 loader/plugin 摘要、安装目录绑定或逐 worker 的完整 runtime 观测。新 cache identity 的 `ida_runtime` 仅包含 `kernel_version`。同版本下替换 loader/plugin 不自动触发 miss，是接受的边界，不再为此增加防御或测试。此决策不删除二进制 identity、worker contract hash，也不改变 GoldSrc 的多 tag/platform 分组与 immutable generation 模型。

---

## 1. 现状分析

### 1.1 当前 warm 数据流（GoldSrc）

```text
preflight/probe -> prepare_selection_entries (idb_cache_selection.py)
  -> 对每个 (tag, platform) group：
       with tag_lock(tag):
         probe_generation (READY 命中则跳过 warm)
         miss -> warm_and_publish (idb_cache.py:711)
                  -> with warm_port_lock(...):          # 全局固定 MCP 端口锁 (idb_cache.py:742)
                       subprocess.run(idb_warm_worker.py run   # 单 worker 进程 (idb_cache.py:748)
                         -> run_worker (idb_warm_worker.py:181)
                              for binary in identity["binaries"]:   # 串行 (idb_warm_worker.py:194)
                                IdaMcpLifecycle(binary, DEFAULT_HOST, DEFAULT_PORT, ...)  # idalib-mcp 固定端口
                                _observed_runtime(binary, ...)      # MCP py_eval 观察运行时
                                validate_database_file_set(binary)
                  -> publish_generation
```

### 1.2 当前并发缺口（要消除的）

- **固定端口争用**：每个 warm worker 都经 `IdaMcpLifecycle` 打开 idalib-mcp 固定端口，所以只能串行；`warm_port_lock` 是全局唯一锁（[idb_cache_locks.py:105](idb_cache_locks.py#L105)）。
- **组内串行**：`run_worker` 的 `for binary in identity["binaries"]` 逐个 warm，一个二进制完成才开始下一个（[idb_warm_worker.py:194](idb_warm_worker.py#L194)）。
- **运行时观察依赖 MCP**：当前 `_observed_runtime` 通过 `open_ida_mcp_session(...)` + `py_eval` 读取 kernel/processor/bitness/file_type（[idb_warm_worker.py:131-169](idb_warm_worker.py#L131-L169)）。本迁移删除这条完整观测链，仅保留独立版本探针，不再把四字段观测移植到裸 worker。

### 1.3 要保留（不改的）

- immutable generation 发布/校验/恢复/保留协议与 `payload`（binary 副本 + `.i64/.idb` + 侧文件全集）；相关函数只适配 4.2 的 runtime identity 读写边界，不重做存储模型。
- `tag_lock` 的跨 runner authority 保留：producer 的 probe、re-probe/publish/verify/selection/prune 与 consumer 的 exact verify/restore 继续使用同一个 SMB3 byte-range lock；仅把 workspace warm 移到锁外，缩短临界区。
- release / PR 的 `cache_selection.json` + SHA-256 evidence contract；consumer 不探 READY。
- 二进制路径、platform、size、SHA-256 与现有支持格式检查；不再把 processor/bitness/file_type 或 loader/plugin 摘要作为新 runtime identity 字段。旧完整字段仅用于历史 manifest 读取，见 4.2。

---

## 2. 目标

### 2.1 功能目标

1. 将现有 `idb_warm_worker.py` 原地改造为唯一的裸 idalib 单二进制 warm worker（对齐 CS2 `warmup_idb_worker.py`），一个 worker 进程只打开、自动分析、保存、关闭**一个**数据库；不再新建或并存第二个 worker executable。
2. 单个 (tag, platform) group 内，多个二进制由 `ThreadPoolExecutor` 并发 warm，并发度由 `--max-concurrency` / `IDB_WARMUP_MAX_CONCURRENCY`（缺省 2）控制。
3. 版本探针读取 IDA kernel version，并与 `identity["ida_runtime"]["kernel_version"]` 比对；所有 warm worker 使用同一 executable。worker 成功退出且数据库文件集有效后方可 publish，不再生成或聚合 observed-runtime JSON。
4. 任一 worker 失败 / 超时 → 先确认该 worker 进程已退出，再只清理该二进制自己的完整数据库文件集（含 stale `.id0`）；整个组失败，不 publish 半成品 generation。
5. 去掉 `warm_port_lock`（裸 idalib 无端口）；官方 producer 由 GHA concurrency group 串行，所有官方/direct producer 再共同进入 producer-only SMB lock；`tag_lock` 只覆盖短时 persisted-storage 临界区，不覆盖 worker warm。
6. workflow 解析一个 canonical IDA Python executable；版本探针与所有 warm 子进程必须使用该同一 executable，禁止回退到 producer 的 `sys.executable`。

### 2.2 并发目标

1. 一个 producer 调用内，同一 (tag, platform) 组的二进制并发 warm（`max_concurrency`）。
2. 跨 (tag, platform) group 仍串行；每个 miss group 的耗时 warm 在 `tag_lock` 外执行，不引入跨 tag 并行。
3. 并发 worker 写各自独立的数据库文件集，不共享可变状态、无端口争用。
4. 并发度受内存约束：支持 `IDB_WARMUP_MAX_MEMORY_MIB` 聚合门控（对齐 CS2 `warmup_memory.py`），未设置时退化为每 worker 进程自身内存上限（沿用 `_apply_memory_limit`）。
5. producer/consumer 可以位于不同 runner；共享 coordination 依赖 `PERSISTED_WORKSPACE` 的 SMB3 server-side byte-range lock，而非 runner-local 状态。

### 2.3 可观测性目标

每条并发 warm 记录：

- binary path、module、（group 的）tag/platform；
- worker 进程 start/end、退出码、wall 时间；producer 记录绑定的 IDA Python executable 与探针 kernel version；
- max_concurrency、已 warm / 已跳过 / 失败计数；
- producer-only lock wait、首次 tag-lock wait、publish 前 re-acquire wait，以及 re-probe hit/miss；
- 总体 group warm + publish wall 时间。

不得记录 `PERSISTED_WORKSPACE` secret 原始值或凭据。

---

## 3. 非目标

- 不把 consumer 分析侧的 `IdaMcpLifecycle`（动态端口、restore-strict）改为裸 idalib。
- 不引入跨 (tag, platform) group 的并行 warm（per-tag concurrency / matrix），仍由既有计划另行处理。
- 不重做 immutable generation 的分组粒度与寻址模型；本次仅有意收敛 runtime identity、冻结 producer IDA args 并缩减 worker contract 文件清单（见 4.2、4.5、9.1）。
- 不改变 `.i64/.idb` 主数据库后缀支持、payload inventory、restore 顺序或 strict consumer fail-closed 语义。
- 不把 CS2 的「单 GAMEVER、普通 bin、`.i64`-only」模型复制到 GoldSrc（多 tag/platform、bin submodule、blob 解密、PR bound plan 全部保留）。

---

## 4. 目标架构

```text
prepare producer（官方 producer 先经 Actions concurrency）
  -> with producer_lock(timeout=None):                  # 所有官方/direct producer 共用
     配置 producer_memory（进程级 owner；首次 miss 才创建/绑定唯一聚合 Job）
     对每个 (tag, platform) group：
       with tag_lock(tag, timeout=None):                 # SMB3，短临界区
         selection = probe_generation(identity)
         hit -> verify / build selection entry / prune -> 下一 group

       miss -> warm_group(identity, producer_memory)     # 不持 tag_lock；只借用 owner
                 -> validate_ida_python_executable(ida_python_executable)
                 -> [ida_python_executable, idb_warm_worker.py, --print-ida-version] == expected kernel
                 -> 启用聚合预算时：复用进程 controller，重新采样 baseline，建立本组 gate
                 -> 对 identity["binaries"] 的每个 binary：
                      memory admission（启用时；独立有限期限，先于数据库清理）
                      _prepare_database_files_for_warm(binary)
                        # 启动前发现任一 .id0 时 fail closed；不删除可能活动的 IDA lock
                      构造独立 worker 命令
                      _run_one_worker([ida_python_executable, idb_warm_worker.py, run, -binary, <path>, ...])
                 -> ThreadPoolExecutor(max_workers=max_concurrency)
                      as_completed:
                        worker 返回 0 且 validate_database_file_set(binary) 通过
                        else -> 确认进程已退出
                             -> _invalidate_failed_worker_database(binary)（含 stale .id0，只清自己）
                             -> 记失败；不取消 sibling
                 -> 等待全部 worker；任一失败则 group 失败，不 publish
                 -> 全部 worker 已退出且 reservation 归零后丢弃本组 gate，不关闭 controller

       with tag_lock(tag, timeout=None):                 # 重新取得跨-runner短锁
         selection = probe_generation(identity)          # publish 前必须 re-probe
         if selection is None:
           selection = publish_generation(...)
         verify / build selection entry / prune
     完成 selection/evidence 或报告失败，释放 producer lock
  -> CLI 正常退出；聚合 Job handle 留到进程退出由 OS 回收，不在 group/prepare finally 中关闭
```

### 4.1 唯一的裸 idalib worker（原地改造 `idb_warm_worker.py`）

不新建 `goldsrc_warm_worker.py` 或其它第二入口。现有 `idb_warm_worker.py` 原地移除 `IdaMcpLifecycle` / `ida_mcp_session` 依赖，成为 identity builder、contract hash 与实际 subprocess 共同引用的唯一 worker。每个二进制一个进程：

```python
if idapro.open_database(binary_path, run_auto_analysis=True) != 0:
    raise IdaDatabasePathError("Unable to open warm database")
try:
    if not ida_auto.auto_wait():
        raise IdaDatabasePathError("Warm auto-analysis did not complete")
    if not ida_loader.save_database(None, 0):
        raise IdaDatabasePathError("Unable to save warm database")
except Exception as warm_error:
    try:
        idapro.close_database()
    except Exception as close_error:
        raise warm_error from close_error
    raise
else:
    idapro.close_database()
```

**自动分析完成是成功前提**：`auto_wait()` 返回 `False`（包括取消）与抛异常都走 worker failure，不能因为没有异常、磁盘已有主库或保存本可成功而继续。False 路径不调用 `save_database`，仍关闭已经打开的数据库；worker CLI 捕获并报告自动分析失败，非零退出，不报告 warm 成功。关闭本身也失败时保留自动分析失败根因并附加关闭错误，不用关闭错误覆盖根因。producer 确认该 worker 退出后按 4.3.1 只失效它的数据库文件集；sibling 继续，整个组不 publish。仅 `auto_wait()` 成功、保存成功且关闭成功的路径允许返回 0。

worker 仅在执行 `run` 或 `--print-ida-version` 的函数内先 `import idapro` 初始化 idalib，再导入所需的 `idaapi` / `ida_auto` / `ida_loader`；不得照搬 CS2 的模块顶层 IDA imports。保留旧实现内 `IdaDatabasePathError` / `validate_plain_file`、二进制支持格式检查与启动前 `existing_database_lock` 保护；worker 直接以路径为参数（不再传完整 identity JSON），由此只能碰它自己的那一个二进制，降低误伤面。失败后的 stale-lock 清理由已确认该 worker 退出的 producer 执行，worker 不承担 timeout 后清理 authority。

**无 IDA 导入边界**：删除 `probe_runtime_contract`、loader/plugin 文件摘要 helper 与驱动对它们的导入。驱动直接使用已解析的 kernel version 构建最小 runtime identity，无需读取 IDA 安装目录。模块顶层及其传递导入不得加载 `idapro` 或 IDA Python API；不安装 `idapro` 的编排解释器仍可导入驱动、构建 identity、执行 cache verify/restore 与 CLI 参数解析。真实数据库操作与版本探针才进入延迟导入的执行函数，且只能由显式绑定的 IDA Python 启动。此约束不改变 consumer 原有 MCP 分析进程的运行时要求。

`idb_warm_worker.py` 提供且只提供两个受支持入口：

- `--print-ida-version`：在完成 `idapro` 初始化后输出 `idaapi.get_kernel_version()`；
- `run -binary ...`：warm 一个二进制，以退出码报告成功或失败，不提供 observed-runtime 输出参数。

`idb_cache_release.py`、`idb_cache_workflow.py` 构建 identity 时引用的 worker、`warm_group` 实际启动的 worker，以及 `warm_worker_contract_sha256` 接受的 worker，必须全部 resolve 到仓库 canonical `idb_warm_worker.py`。

#### 4.1.1 IDA Python executable 绑定

- `warmup-idb.yml` 的 runtime 解析步骤把 PATH 上的 IDA Python 解析为 canonical absolute path，并以该 executable 运行 `idb_warm_worker.py --print-ida-version`；成功后写入 `IDA_PYTHON_EXE` 与 `IDA_KERNEL_VERSION`。
- release/PR 的 `prepare` CLI 新增必填 `--ida-python`，依次透传到 `prepare_selection_entries` 与 `warm_group`。direct `idb_cache.py warm` 同样必填，不允许隐式使用 `sys.executable`。
- `warm_group` 在启动任何 worker 前要求该路径 `resolve(strict=True)` 为普通文件，并再次用同一 executable 执行版本探针；结果必须等于 identity 的 `kernel_version`。
- producer orchestrator 仍可由 `uv run python` 启动，但它只负责编排；所有会 `import idapro` 的进程始终由 `ida_python_executable` 启动。
- producer 不再要求或解析 `idalib-mcp` executable；consumer 的 `IdaMcpLifecycle` 解析与动态端口流程保持不变。

**已接受的探针边界（用户确认，对齐 CS2）**：workflow 首次版本探针与 `warm_group` 内再次探针均同步调用，等待返回后检查非零退出码、空版本和版本不匹配；不设置探针独立 deadline，不新增探针专属 kill/wait、watchdog 或自动重试，也不把 worker/admission timeout 套到探针上。初始化挂起时依赖外部取消或人工终止，不提供内部超时恢复或显式回收保证。此取舍不再作为实现阻塞项，不在后续评审中以缺少探针 deadline 为由追加防御。它只适用于 `--print-ida-version`；实际 warm worker 仍严格执行 4.3 的运行 timeout、kill → wait → 失败清理，聚合 Job 的既有进程退出语义也不变。

### 4.2 运行时契约收敛（已确认：对齐 CS2）

新 identity 固定采用 `"ida_runtime": {"kernel_version": "<已解析的 IDA 版本>"}`。保留 GoldSrc 的 `ida_runtime` 外层名称，不为对齐 CS2 另行重命名为 `ida_version`。版本必须是非空、trimmed string；producer 在 worker 启动前用绑定的 executable 验证版本，consumer 使用自身已解析的 kernel version 重建相同形状的预期 identity。Python executable 路径只用于本次 producer 的启动绑定，不参与 cache key，不要求不同 runner 使用相同绝对路径。

- 删除 MCP `_observed_runtime` 及其 JSON 交换链，不移植本地四字段观测、逐 worker 版本回传或组级 runtime 聚合。成功条件是版本探针匹配、每个 worker 正常退出且数据库文件集有效。
- 新 runtime 不包含 `processor`、`bitness`、`file_type`、`loader_name`、`loader_module_sha256`、`plugins`；不绑定安装目录、不重新读取 loader/plugin 摘要。同版本下的 loader/plugin 变化不自动失效，这是用户接受的边界。
- 二进制的 platform、size、SHA-256 与 `inspect_binary` 的支持格式约束仍保留；它们属于输入验证，不再额外观测打开后的 IDA processor/bitness/file-type。
- release/PR cache 驱动删除仅服务摘要计算的 `ida_root` 参数及 `-ida-root` CLI；prepare/verify/restore 的 workflow 调用同步调整。`IDADIR` 若由 IDA/MCP 运行环境使用仍可保留，但不作为 cache identity 输入，也不做跨安装一致性校验。

**旧 generation 的最小读取兼容**：`CACHE_SCHEMA_VERSION` 保持 `1`，仅在 runtime validator 中区分两种精确形状：新的 `{kernel_version}` 与旧的完整七字段集合。新 builder、warm/publish 只接受最小形状；通用 manifest verify、exact restore、prune 继续按原规则验证旧完整形状，计算 cache key/manifest digest 时保留原始字段，不投影、不补默认值、不改写旧文件。旧完整字段不再触发安装目录读取。新旧 identity 自然得到不同 cache key；高层 consumer 仍要求与本次预期 identity 完全相同，不把 legacy generation 转换成新 identity 复用。这里保留的是旧缓存可读性，不是继续维持 loader/plugin 运行时绑定。

### 4.3 并发调度与失败语义

- 将现有 `warm_and_publish` 拆为纯 workspace 操作 `warm_group` 与既有 `publish_generation`；`warm_group` 接收必填 `ida_python_executable` 与 `max_concurrency`（缺省取 `IDB_WARMUP_MAX_CONCURRENCY` 或 `2`），在不持 `tag_lock` 时创建 `ThreadPoolExecutor`。
- 每个 worker 由 `_run_one_worker` 使用 `subprocess.Popen` 启动；正常路径等待进程退出，timeout 路径执行 `kill()` 后必须 `wait()` 完成，只有确认该 PID 已终止后才进入失败失效。`worker_timeout_seconds` 缺省 `30 * 60`（对齐 CS2 `DEFAULT_WORKER_TIMEOUT_SECONDS`），可经 `--worker-timeout-seconds` 覆盖；该值只约束 worker，不再参与任何 lock timeout 计算。删除旧的 producer `--timeout-seconds`，避免它继续同时表达 worker 与 lock 两种语义。
- 任一 worker 失败/超时：producer 调用 `_invalidate_failed_worker_database(binary)`，只删除该 binary 的完整数据库文件集，累计失败；不取消 pending/running sibling，等待全部 futures 完成，成功 sibling 的有效数据库保留。只要有一失败，整个组返回失败且不 publish（对齐 CS2）。
- 初次 `probe_generation` 命中时直接在同一短 `tag_lock` 内 verify/build-entry/prune，hit 不走并发路径；miss 的 `warm_group` 成功后必须重新取得 `tag_lock` 并 re-probe。若旁路 writer 已发布相同 identity，则复用已验证 generation；否则才 publish 当前 workspace 产物。

#### 4.3.1 两阶段数据库清理 authority

启动前清理和失败后失效必须是两个独立 helper，不以 `allow_stale_lock` 一类布尔开关复用同一入口：

1. `_prepare_database_files_for_warm(binary)`：在启动 worker 前调用。若 `existing_database_lock(binary)` 返回任何 `.id0`，视为可能存在活动 IDA 进程并 fail closed，不删除 lock；仅在无 lock 时清理旧数据库与 side files。
2. `_invalidate_failed_worker_database(binary)`：仅允许由持有该 worker ownership、且已经确认其进程退出的 producer 调用。它不使用 `existing_database_lock` 阻止删除，而是删除 `database_cleanup_paths(binary)` 返回的完整集合。

`ida_database_paths.py` 新增唯一的 `database_cleanup_paths(binary)`，以稳定去重顺序返回 `database_paths(binary) + database_lock_paths(binary)`，覆盖 `.i64/.idb`、全部 side files，以及 `<binary>.id0` / packed-database `.id0`。删除前仍执行 workspace containment、plain-file 与 reparse-point 校验。

删除规则对齐 CS2 的 bounded retry，并收紧为只重试 Windows transient sharing violations：`FileNotFoundError` 视为成功；`winerror in {5, 32}` 最多尝试 3 次、间隔 1 秒；其它错误立即记录为不可重试。重试耗尽后返回残留路径与错误，group 保持失败且不得 publish。最终异常必须保留原始 worker failure/timeout，并附加 cleanup-incomplete 详情，不能用清理异常覆盖根因。

### 4.4 锁调整

- **删除** `warm_port_lock`（[idb_cache_locks.py:105](idb_cache_locks.py#L105)、[idb_cache.py:742](idb_cache.py#L742)）——裸 idalib 不再有端口争用。
- **Actions producer authority**：`warmup-idb.yml` 继续使用 repository-wide `idb-warmup-${repository}` + `cancel-in-progress: false`，跨 runner 串行所有官方 producer。
- **producer-only SMB lock**：新增 `<PERSISTED_WORKSPACE>/idb-cache/.locks/producer.lock`。release/PR high-level prepare 与 direct mutating warm CLI 都在整个 producer 调用期间持有它；consumer 不取得该锁，因此长时间 warm 不阻塞 restore。它是 Actions authority 对旁路调用的共享存储防御层。
- **缩短 `tag_lock`**：首次 probe（hit 时连同 verify/build-entry/prune）使用一次短锁；miss 时释放锁，在 workspace 完成 `warm_group`；成功后重新取得同一 tag lock，执行 re-probe → optional publish → verify/build-entry → prune。consumer 继续在同一 tag lock 内执行 exact verify → restore。
- **取消等待预算**：删除 `TAG_LOCK_PUBLISH_MARGIN_SECONDS`、`DEFAULT_TAG_LOCK_TIMEOUT_SECONDS` 与 `tag_lock_timeout_seconds(warm_timeout)`。官方 high-level `tag_lock` / producer-only lock 使用 `timeout_seconds=None`，以 non-blocking byte-range lock + polling 等待到取得或进程被取消；不从 worker 数、并发度或 timeout 推导 lock deadline。外层 GHA job `timeout-minutes` / cancellation 是运行时上限。
- **跨 runner 前提已确认**：`PERSISTED_WORKSPACE` 指向所有 eligible runners 共享的 SMB3 文件夹，byte-range lock 由 SMB server 跨机器协调；lock 文件存在不代表持锁，authority 仍是打开 handle 上的 byte-range lock。

#### 4.4.1 无限等待仅适用于真实锁竞争

`timeout_seconds=None` 只取消 contention 的等待期限，不允许沿用当前 `except OSError: sleep/retry` 的全错误重试。锁适配层必须区分“同一 byte range 已被占用”和存储/权限/handle 故障：

- Windows 只将明确的 `ERROR_LOCK_VIOLATION` 作为可轮询的竞争错误；不能仅凭含混的 `errno.EACCES` 推断竞争。若 `msvcrt.locking` 无法保留原始 Windows 错误码，改用能保留原始错误的 non-blocking `LockFileEx` / `UnlockFileEx` 配对，仍锁定同一文件的 offset 0、长度 1，保持与既有 runner 的 byte-range authority 一致。
- POSIX 仅对 non-blocking `flock` 的明确 would-block 错误重试。锁文件打开/初始化失败、权限拒绝、失效 handle、SMB 断连、I/O 错误及其他未知错误立即 fail closed；不得对同一失效 handle 无限轮询，也不得无锁继续 probe/publish/prune/restore。
- 报错保留操作阶段、原始错误类型与错误码及异常链，但对 persisted 路径和凭据脱敏。未取得锁也必须关闭 handle；不得用后续关闭错误覆盖原始 acquisition failure。
- official 与 direct CLI 使用相同分类。真实竞争仍可无限等到取得或被取消；direct CLI 的存储故障无需等待不存在的 GHA timeout。

### 4.5 `normalized_ida_args` 处理（决策：已确认）

现状 identity 携带 `normalized_ida_args` 并传给 `IdaMcpLifecycle`（[idb_cache.py:214-218](idb_cache.py#L214-L218)）；裸 idalib 的 `open_database` 不接受 IDA 命令行参数。

**已确认方案**：warm 路径**不应用** `-ida-arg`；consumer 分析侧（restore-strict `IdaMcpLifecycle`，动态端口）仍可通过自己的分析参数应用。为保持 schema-1 与旧 generation 可读，本迁移**不删除** `normalized_ida_args`，而是把它冻结为兼容保留字段：

- `CACHE_SCHEMA_VERSION` 保持 `1`，`CACHE_IDENTITY_KEYS`、manifest canonical bytes 与通用 `validate_cache_identity` 继续包含 `normalized_ida_args`。通用 validator 仍接受历史 canonical string list，使旧 schema-1 manifest 可以继续 verify、restore 与 prune。
- 新的 `build_cache_identity` 不再接收 producer IDA args，固定写入 `"normalized_ida_args": []`；release/PR prepare 与 direct warm 删除 producer `-ida-arg` 参数，避免静默 no-op。consumer 的 `-ida_args` 保持独立，不通过 cache prepare 透传。
- `warm_group` 在 worker 启动边界额外要求 `identity["normalized_ida_args"] == []`，非空则在启动 worker 前 fail closed；`_validate_manifest` 不施加此“必须为空”约束，以保留 legacy read/prune compatibility。
- 本迁移不 bump `CACHE_SCHEMA_VERSION` 或 `warmup_contract_version`。裸 worker及 contract 清单变化会改变 `warm_worker_sha256`，足以产生预期的一次全量 miss；旧 generation 仍是合法 schema-1 对象，只是不再匹配新 identity。

### 4.6 内存 admission：可满足预算、有限等待与 ownership

聚合内存功能启用时采用 CS2 的 `WindowsJobMemoryController` / `MemoryLaunchGate`，但不直接照搬其 admission timeout 与 worker timeout 共用的调用方式：

1. **启动前校验预算**：沿用命名常量 `DEFAULT_SOFT_LIMIT_RATIO = 0.85` 与 `DEFAULT_INITIAL_WORKER_RESERVATION_BYTES = 4096 * MIB`。每个 miss group 按 4.6.1 取得同一进程 controller 与该组的新 baseline 后，在任何数据库清理或 worker 启动前要求 `baseline_job_bytes + initial_worker_reservation_bytes <= floor(budget_bytes * soft_limit_ratio)`；不满足立即报配置错误，说明预算、baseline、reservation 与 soft limit。不得降低 reservation 或绕过 gate 强行启动。4096 MiB 总预算即使 baseline 为零也必须立即拒绝，而不是等待。
2. **独立有限期限**：新增内部命名常量 `DEFAULT_MEMORY_ADMISSION_TIMEOUT_SECONDS = 300`，作为 `memory_admission_timeout_seconds` 的默认值，经 prepare 调用链传至 `warm_group` / `_run_one_worker`，最终显式传入 `wait_for_launch`；参数必须为有限正数，不接受 `None`。初版不新增 CLI/环境变量，入口使用该默认值，测试可注入较短期限。期限从任务开始等待 admission 时以 monotonic clock 计算，不含 executor 排队时间，不复用或消耗 `worker_timeout_seconds`，不影响任何 lock deadline。成功 `Popen` 后才开始单独的 worker 运行超时计时。
3. **顺序与清理权限**：每个 task 先取得 admission，再执行 `_prepare_database_files_for_warm`，最后 `Popen`。admission 超时或采样失败时没有 worker ownership，不启动进程、不清理该 binary 的任何数据库或 `.id0`；累计组失败，不取消 sibling，等待全部 futures 完成后禁止 publish。初始化预算失败则在创建 futures 前直接失败。gate 通过但启动前校验或 `Popen` 失败也不得调用 failed-worker invalidation；只有实际启动且确认退出的 worker 才拥有该清理权限。
4. **reservation 配对释放**：只有成功取得 admission 才在 `finally` 调用一次 `worker_finished()`；覆盖启动前校验失败、`Popen` 失败、正常退出和 kill/wait 完成等路径。仍存活的 worker 不得提前释放 reservation；admission 未成功不得减少计数。持续压力的每次等待都受上述有限期限约束。
5. **未启用时**：跳过 controller 与 admission，继续沿用 per-worker 内存上限。日志明确区分配置不可满足、admission timeout、采样错误和已启动 worker 的运行失败，避免混淆清理 authority。

#### 4.6.1 聚合 Job 生命周期：进程级 controller，group 级 gate

CS2 controller 把编排进程自身加入带 `KILL_ON_JOB_CLOSE` 的 Job，不能作为 `warm_group` 局部可关闭资源使用。本迁移保留这一进程树模型，不改成逐 worker 手动加入 Job；ownership 明确如下：

1. **唯一 owner 与延迟初始化**：`warmup_memory.py` 持有进程级 `producer_memory` owner，release/PR high-level prepare 与 direct warm 使用同一入口并透传给 `warm_group`。首次 miss 的版本探针退出后、任何 futures/数据库清理/worker 启动前，才创建 controller 并把当前 producer PID 加入聚合 Job。每个 PID 最多创建并成功绑定一个本迁移的聚合 Job；已有 runner 外层 Job 不由本模块管理。后续 group 只复用 controller，不重复 `AssignProcessToJobObject`，全 hit 的新 producer 进程不创建 Job。
2. **baseline 与 gate 按 group 更新**：进入下一 miss group 前，上组全部 worker 必须已 wait/reap 且 reservation 归零；本组版本探针也已退出。随后从同一 controller 重新采样当前 baseline，重新执行 4.6 的预算判定，再创建新的 `MemoryLaunchGate`。不复用前组的 active count、观测峰值或 launch 时间，也不把前组 worker 内存固化为下一组 baseline。group 结束只丢弃 gate，不关闭或替换 controller；仍有未确认退出的 worker 时不得重置 gate 或推进下一 group。
3. **handle 留到进程退出**：controller 成功绑定后由进程级 owner 强引用持有不可继承的 Job handle，禁止在 group/prepare 的 `finally`、context manager、析构或 `atexit` 中关闭它。正常路径先等待 workers、完成 publish/selection/evidence、释放锁并返回 CLI 结果，再由 OS 在进程退出时回收 handle。producer 异常终止时依靠 Job 回收仍在运行的子进程；这不等于数据库文件已清理，不承诺硬终止后的 workspace 清理成功，也不放宽启动前 `.id0` 检查。
4. **初始化失败的清理边界**：成功绑定当前 PID 之前的建 Job/设 limit/assign 失败只关闭已创建且未绑定的有效 handle，并保留原始错误；成功绑定后须先登记进程 owner，再进行 baseline 采样和预算判定。后续采样失败或预算不可满足时不得为“回滚”关闭这个 handle；报告失败、释放 producer lock、正常退出，当前 group 尚未清理数据库或启动 worker。异常路径同样不得意外终止 producer，导致根因日志或退出码丢失。
5. **适用范围与重复调用**：聚合预算从首次绑定持续覆盖 producer、其后代及后续 publish/selection 阶段，不能宣称只限制 warm 或在 prepare 返回时解除限制。同一 PID 再次调用 prepare 只能复用相同预算；请求变更或关闭已绑定预算时明确拒绝，需新进程执行，不增加动态重配或 detach 机制。真实 Job 测试必须放在隔离子进程中，不能把测试主进程加入该 Job。

---

## 5. 文件级实施范围

| 文件 | 计划改动 |
| --- | --- |
| `idb_warm_worker.py`（原地改造；唯一 worker executable） | 移植 CS2 裸 idalib 生命周期，并按 4.1 检查 `auto_wait()` 返回值：False/异常不保存，关闭后非零退出；提供 `--print-ida-version` 与单二进制 `run -binary ...`；仅在执行函数内先 import `idapro`；删除完整 runtime probe/输出链；保留二进制支持格式与启动前 lock / plain-file / 后缀校验；timeout 后清理由 producer 负责 |
| `ida_database_paths.py` | 新增 canonical `database_cleanup_paths()`，稳定合并 `database_paths()` 与 `database_lock_paths()`，作为失败后删除主库、side files 与 stale `.id0` 的唯一文件集合同 |
| `idb_cache.py` | 将 `warm_and_publish` 拆为锁外 `warm_group` 与既有 `publish_generation`；ThreadPoolExecutor + 每二进制一 worker，检查退出码与数据库文件集，不聚合 runtime JSON；用 `Popen` 明确 timeout kill/wait；拆分启动前 lock-preserving cleanup 与退出后 failed-worker invalidation，实现 WinError 5/32 bounded retry；显式绑定 `ida_python_executable` 并校验探针 kernel version；去掉 `warm_port_lock`；`warm` 删除旧 `--timeout-seconds`，增加必填 `--ida-python`、`--max-concurrency` / `--worker-timeout-seconds`；high-level tag lock 无内部 deadline；新 runtime 仅含 kernel version，旧完整 runtime 按 4.2 保留读取兼容；保留 schema-1 `normalized_ida_args`，新 identity 固定为空且 warm/publish 拒绝非空；收敛 `WARM_WORKER_CONTRACT_FILES` |
| `idb_cache_locks.py` | 删除 `warm_port_lock_path`、warm-derived tag-lock timeout 常量/helper；`exclusive_file_lock` / `tag_lock` 支持 `timeout_seconds=None`，但仅重试明确 contention；按 4.4.1 保留原始平台错误、必要时替换 Windows 锁适配，其他错误立即退出并关闭 handle；新增 repository-wide `producer_lock_path` / `producer_lock`，路径位于 SMB3 persisted lock root |
| `idb_cache_selection.py` | `prepare_selection_entries` 删除混合语义的 `timeout_seconds`，增加并透传必填 `ida_python_executable`、`max_concurrency` / `worker_timeout_seconds`；改为 short locked probe → unlocked warm → short locked re-probe/optional-publish/verify/build-entry/prune；consumer exact verify/restore 继续使用同一 tag lock并以 `timeout_seconds=None` 等待 |
| `idb_cache_release.py` / `idb_cache_workflow.py` | high-level `prepare` 全程共同持有 producer-only SMB lock；删除旧 `-timeout-seconds`，增加必填 `--ida-python`、`--max-concurrency` / `--worker-timeout-seconds` 并透传，删除 producer `-ida-arg`；共享 identity builder 固定引用 canonical worker、写空 `normalized_ida_args` 与仅含 kernel version 的 runtime；删除 `probe_runtime_contract` 导入、摘要计算与 cache prepare/verify/restore 的 `ida_root` / `-ida-root` 参数 |
| `warmup_memory.py`（新建，从 CS2 移植） | 进程级 `producer_memory` owner 延迟创建并复用唯一 `WindowsJobMemoryController`；按 group 重新采样 baseline、校验预算、创建 `MemoryLaunchGate`；独立有限 admission timeout 与 reservation 配对释放；已绑定 handle 留到进程退出，不在 group/prepare 清理时关闭；未启用时用 per-worker 限制 |
| `.github/workflows/warmup-idb.yml` | canonicalize IDA Python，以该 executable 调用 `idb_warm_worker.py --print-ida-version`，保存 `IDA_PYTHON_EXE` 并作为 `--ida-python` 传给 release/PR `prepare`；注入并发/内存配置；删除 producer 对 `idalib-mcp` 与 `warm_port_lock` 的依赖 |
| `.github/workflows/warmup-idb.yml` / `release-build.yml` / `gamesymbol-pr-validation.yml` | 同步删除 cache prepare/verify/restore 调用中的 `-ida-root`，保留 `-kernel-version`；consumer 原有 IDA/MCP 运行环境与版本解析链保持不变 |
| `tests/test_warmup_concurrency.py`（新建） | 并发 worker 退出码与数据库文件集校验、失败/超时只清自身、terminate/wait-before-cleanup、stale `.id0`、WinError 5/32 retry、成功 sibling 保留、`--max-concurrency` 生效、内存 gate（参见测试策略） |
| `tests/test_idb_cache.py` / 既有相关单测 | 更新 contract-file / 单二进制 worker 接口 / 锁变化；覆盖锁外 warm、locked re-probe、producer-only lock、restore/prune 互斥与无 warm-derived timeout；验证 canonical worker 与 IDA Python 显式绑定；新 runtime 仅含 kernel version，版本变化导致 key 变化；旧完整 runtime、非空 args 的 schema-1 manifest 仍可 verify/restore/prune，新 identity args 固定为空 |
| `docs/en/*`、`docs/zh-CN/*` | 更新 IDB operations / CI-CD / requirements 中 warm 并发说明 |
| `memory/` | 记录并发 warm 触发信号、根因、正确做法、验证方式与适用范围 |

内存门控的编排配套改动：`idb_cache_release.py` / `idb_cache_workflow.py` → `prepare_selection_entries` → `warm_group` 透传进程级 `producer_memory` owner；`warm_group` 为每组向该 owner 获取 gate，再把 gate 与 4.6 的内部 `memory_admission_timeout_seconds` 传给 `_run_one_worker`。direct warm 采用相同 owner 入口与默认期限，所有调用方都不拥有 controller 的关闭权限。清理时序与无 ownership 失败分支在 `idb_cache.py` 实现，不放进 worker；无需增加 workflow 参数。

### 5.1 测试文件登记

按 `tests/run_test_suite.py` 现有分组约定，把新增 `test_warmup_concurrency.py` 登记到 `unit`（或 `redis-integration`/`ida-integration` 视运行时依赖），并在 `GROUP_FILES` 白名单登记。

---

## 6. 实施阶段（Level 2 / TDD）

### 阶段 0：冻结基线 + 失败测试

1. 保存一次 release-all cache miss 的 warm wall 时间与二进制数量（作为吞吐基线）。
2. 为「单组多二进制串行 warm」的当前行为补回归断言。
3. 为「`warm_port_lock` 存在导致只能单 worker」补当前行为测试。
4. 固化旧 schema-1（含完整七字段 runtime 与非空 `normalized_ida_args`）generation fixture，覆盖 manifest verify、exact restore 与 prune retention，防止迁移后失读。

### 阶段 1：裸 idalib 单二进制 worker

1. 原地改造唯一入口 `idb_warm_worker.py`，移除 MCP 依赖、静态 loader/plugin probe 与 observed-runtime JSON；IDA imports 延迟到两个执行入口，驱动导入与 identity 构建不初始化 IDA；保留二进制输入检查，不增加打开后的四字段观测；不创建第二个 worker 文件。
2. 增加 `ida_python_executable` 校验与 `--print-ida-version` 同步探针；按 4.1.1 的已接受边界不增加探针 deadline 或专属 kill/wait；`warm_group` 明确用该 executable 启动 worker，禁止 `sys.executable` fallback。
3. 收敛 contract hash：只接受 canonical `idb_warm_worker.py`，按固定顺序哈希 `WARM_WORKER_CONTRACT_FILES`，删除 alternate-name 单文件 fallback。
4. 按 4.2 将新 runtime 收敛为 kernel version，validator 保留旧完整 runtime 读取；保留 schema-1 `normalized_ida_args` 字段，新 identity 固定为空，warm/publish 拒绝旧完整 runtime 或非空 args，manifest verify/restore/prune 保留 legacy compatibility；不 bump schema/contract version。
5. 单二进制 smoke：用同一 IDA Python 完成匹配 identity 的版本探针与 warm；worker 返回 0，数据库保存后 `validate_database_file_set` 通过。
6. 补齐 `auto_wait()` False/异常的失败路径：不保存、关闭已打开数据库、非零退出；即使文件集看似有效也不能 publish。定向测试先覆盖 False 后再实现分支，不只测抛异常。

### 阶段 2：并发调度 + 产物校验

1. 将 `warm_and_publish` 拆为锁外 `warm_group` 与 locked `publish_generation`：ThreadPoolExecutor + 每二进制一进程，校验退出码与数据库文件集；仅全部成功才进入 publish。
2. `_run_one_worker` 使用 `Popen` 固化 timeout 的 kill → wait → invalidate 顺序；未确认 worker 退出时禁止删除其 `.id0`。
3. 在 `ida_database_paths.py` 增加完整 cleanup path contract；在 producer 拆分启动前 lock-preserving cleanup 与失败后 stale-lock invalidation，WinError 5/32 最多重试 3 次、间隔 1 秒。
4. 去掉 `warm_port_lock`；`warm` 子命令删除旧 `--timeout-seconds`，增加 `--max-concurrency` / `--worker-timeout-seconds`。
5. 失败/超时只清理该二进制，不取消 sibling；等待全部 futures 完成并保留成功 sibling 的有效数据库。cleanup incomplete 保留原始失败并附加残留详情；组级 fail-closed、不 publish；hit 路径不并发。
6. 重构 producer group 流程为 short locked probe → unlocked warm → short locked re-probe/optional-publish/verify/build-entry/prune；re-probe 命中时复用已发布 generation。
7. 新增 repository-wide producer-only SMB lock，所有官方/direct producer high-level prepare 共用；删除 warm-derived tag-lock timeout 计算，官方 producer/consumer lock acquisition 使用 `timeout_seconds=None`，仅 contention 可无限等待；按 4.4.1 对权限、SMB、handle 等非竞争错误立即报错，保留根因并关闭 handle。外层 job timeout/cancellation 仍可终止正常竞争等待。

### 阶段 3：参数与 workflow 透传

1. `prepare_selection_entries` / release / PR `prepare` 删除旧 `timeout_seconds` / `-timeout-seconds`，透传必填 `--ida-python` 与独立 `worker_timeout_seconds` / `--worker-timeout-seconds`、并发参数，并删除 producer `-ida-arg`；consumer `-ida_args` 参数链保持独立。
2. `warmup-idb.yml` 保存经 `idb_warm_worker.py --print-ida-version` 验证的 `IDA_PYTHON_EXE`，传给两个 `prepare` 入口，并注入 `IDB_WARMUP_MAX_CONCURRENCY` / `IDB_WARMUP_MAX_MEMORY_MIB`。
3. release/PR cache prepare/verify/restore 的共享 identity 构建统一使用最小 runtime，移除 `ida_root` 参数链；producer 与 consumer workflows 删除对应 `-ida-root` 实参，不改 consumer MCP 分析环境。

### 阶段 4：内存门控 + 文档

1. 按 4.6 / 4.6.1 移植 `warmup_memory.py`：先落实进程级唯一 controller、首次 miss 延迟初始化与 handle 留到进程退出，再落实 group 级 baseline/gate 和每组预算校验；显式传入独立的 300 秒 admission 期限，保持 admission → 启动前清理 → Popen、无 ownership 不清理及 reservation 配对释放。覆盖成功绑定前后不同的初始化失败清理边界。未启用则每 worker 进程用现有内存上限。
2. 更新 bilingual 文档与 memory。

### 阶段 5：真实 runner 证据

1. 同 identity cache miss：`max_concurrency=2` 下组 wall 时间显著低于串行。
2. 4 二进制组：并发 vs 串行吞吐对比。
3. 并发 + 失败：其中一个 worker 失败时只清理该 binary；其余 worker 继续完成且成功数据库保持有效；整个组 fail-closed，不 publish generation。
4. timeout 后确认目标 worker 已退出，stale `.id0` 与 side files 被 bounded retry 清理；其它 worker 与数据库不受影响。
5. `IDB_WARMUP_MAX_MEMORY_MIB` 生效；额外记录不可满足预算立即失败、持续压力触发有限 admission timeout 的证据，确认未启动 binary 的数据库文件不被删除。
6. 不同 runner 上让 producer B 长时间执行 `warm_group`，同时 consumer A restore 已选 generation：consumer 不等待整段 warm；producer B publish/prune 与 consumer exact verify/restore 仍由 SMB3 tag lock 串行。
7. 真实 Windows 隔离 producer 子进程启用聚合预算，连续完成至少两个 miss group：记录同一 PID/controller、每组 baseline/gate、worker membership 与退出状态；两个组均能结束并进入 publish，最终 selection/evidence 写完后 CLI 正常退出。另用受控子进程覆盖绑定后预算/采样失败与 producer 异常退出，确认日志/退出码可见、失败不启动 worker，以及异常退出后其任务子进程被回收；不把硬退出视为数据库已清理。

---

## 7. 测试策略

### 7.1 并发 warm

- 多二进制并发时全部 worker 成功退出且数据库文件集有效才允许 publish；退出码为 0 但主库缺失或文件集非法仍走失败失效路径。
- worker API fixture 显式令 `auto_wait()` 返回 False，且预设 `save_database` 本可返回 True：断言 save 未调用、close 恰好调用一次、CLI 非零退出并报告自动分析失败。再覆盖 auto_wait 抛异常、关闭同时失败时保留原始分析错误，以及 True → save → close 的成功顺序。
- 将 auto_wait 失败接入 producer 并发场景：即使该 binary 已有看似有效的主库，仍须等目标进程退出后只清它自己的文件集；成功 sibling 保留，组不 publish。
- 任一 worker 失败 → 只清理该二进制的完整数据库文件集，不取消 pending/running sibling；全部 futures 完成后整个组 fail-closed，不 publish。
- 启动前发现任一 `.id0` → 视为可能活动的 lock，拒绝删除且不启动对应 worker。
- worker 超时 → 断言 `kill()` 和 `wait()` 先完成，之后才删除该 binary 的 `.i64/.idb`、side files 与 stale `.id0`；其他 worker 继续完成，成功 sibling 数据库保持有效。
- 删除遇到 WinError 5/32 时前两次失败、第三次成功；重试耗尽时报告残留路径，保留原始 timeout/worker failure，并继续阻止 publish。
- failure invalidation 只能删除失败 binary 的 `database_cleanup_paths()`，不得触碰成功 sibling；reparse/non-plain target 继续 fail closed。
- `--max-concurrency=1` 时行为退化为串行（与现有一致）。
- 并发 worker 写各自独立文件，无相互覆盖/锁冲突。

### 7.2 版本绑定与输入验证

- 新 identity 的 runtime 只有 `kernel_version`；producer 与 consumer 对同一版本和二进制构建相同 identity，kernel version 变化导致 cache key 变化。
- 当 producer 的 `sys.executable` 与 `IDA_PYTHON_EXE` 不同时，版本探针和 warm subprocess 均只使用后者。
- `--ida-python` 缺失、路径不存在、不是普通文件、无法 import `idapro`，或探针 kernel 与 identity 不一致时，在启动并发任务前 fail closed。
- 探针仅覆盖正常返回、非零退出、空版本与版本不匹配的行为；不增加探针挂起 deadline/kill-wait/重试测试，不为已接受的无内部恢复边界增加防御实现。实际 warm worker 的 timeout、wait-before-cleanup 与失败隔离测试继续保留；不对计划文本增加断言。
- identity builder、实际 subprocess 与 contract hash 引用同一 canonical `idb_warm_worker.py`；替代文件名被拒绝，修改 contract 清单中的任一文件都会改变 digest。
- 在独立子进程中阻止 `idapro` 与 IDA Python API imports（不能复用已缓存模块），仍可导入 worker 与 release/PR 驱动、执行 CLI 参数解析、对 fixture 构建最小 identity 和执行 cache verify/restore；仅进入真实 worker 执行入口才要求 IDA。测试验证运行行为，不断言源码 import 文本。
- 保留二进制支持格式、platform、size、SHA-256 的输入验证测试；删除旧完整 runtime 观测测试，不新增 loader/plugin 变化、安装目录绑定或 IDA file-type 名称分类测试。

### 7.3 Cache identity 向前兼容

- 新 `build_cache_identity` 始终生成 `"normalized_ida_args": []`；producer CLI 不再接受 `-ida-arg`，consumer 的 `-ida_args` 不进入 cache identity。
- `warm_group` 对非空 `normalized_ida_args` fail closed，且在启动 worker 前失败。
- 新 builder 与 warm/publish 只接受最小 runtime；通用读取 validator 仅接受新最小形状或旧完整七字段形状，拒绝不完整的混合字段集合。
- 旧 schema-1、完整 runtime 与非空 `normalized_ida_args` 的 manifest 仍可通过 `_validate_manifest` / `verify_selection` 和 exact legacy restore；原始 cache key/manifest digest 不变，不投影、补字段或读取本机 loader/plugin。
- prune 能解析旧 schema-1 generation，并继续按 READY、keep-latest 与 minimum-age 规则处理，不能把旧 generation 永久跳过。
- 新旧 identity 因 runtime 形状、`warm_worker_sha256`（以及历史非空 args 与新空值的差异）得到不同 cache key；迁移只产生预期 miss，高层 consumer 不把旧完整 runtime generation 当作新 identity 命中。

### 7.4 锁

- 删除 `warm_port_lock` 后，`warm` 不再需要该锁路径。
- `tag_lock` 只覆盖首次 probe/hit finalize、re-probe/publish/verify/build-entry/prune，以及 consumer exact verify/restore；barrier 断言 `warm_group` 执行期间 tag lock 已释放。
- miss warm 完成后必须在 tag lock 内 re-probe；模拟另一 writer 已发布相同 identity 时复用现有 generation，不重复 publish。
- repository-wide producer-only SMB lock 串行 official high-level prepare 与 direct mutating CLI，但 consumer 不取得该锁。
- `exclusive_file_lock(timeout_seconds=None)` 可等待超过旧的 `DEFAULT_TAG_LOCK_TIMEOUT_SECONDS` 后正常取得；worker timeout 参数不传入任何 lock helper，旧 margin/derivation symbol 均删除。
- producer CLI 删除旧 `-timeout-seconds` / `--timeout-seconds`；只有 `--worker-timeout-seconds` 保留且仅传入 worker runner。
- 跨进程 tag lock 竞争测试继续覆盖 publish/prune 与 exact restore 的互斥；真实 runner 再覆盖 SMB3 跨机器 byte-range lock。
- lock 文件存在但 handle 未持 byte-range lock时不得视为占用；进程退出/取消后由 SMB handle 释放 authority。
- fake clock / 锁适配器覆盖 `timeout_seconds=None` 下重复 contention 后成功取得；注入权限拒绝、SMB 断连、失效 handle 与未知 I/O 错误时立即失败、不 sleep/retry、不执行受锁保护操作，且 handle 关闭、原始错误链与错误码保留、敏感路径脱敏。
- Windows 若切换锁适配器，增加与旧 `msvcrt.locking` 持锁进程双向竞争的测试，证明仍对同一文件 offset 0、长度 1 互斥；不能仅凭 mock 认定跨 API / SMB authority 一致。

### 7.5 Workflow 与真实环境

- YAML 只做解析/schema/action validation，不约束 step 文案或易变配置。
- 真实 runner 覆盖阶段 5 的 miss / 失败 / 并发 / 内存场景，记录 run URL、runner identity、binary 数、wall 时间、generation / cache key。

### 7.6 内存 admission 与 Job 生命周期

- 用 fixture snapshot 验证首个 worker 预算判定：4096 MiB 总预算、baseline 为零时立即拒绝；soft-limit 边界相等时允许，少一个字节时拒绝；拒绝发生在创建 futures、清理数据库及启动 worker 之前。
- fake monotonic clock 覆盖内存恢复后获准与持续压力下 admission timeout；默认期限由独立常量提供，调整 worker timeout 不改变 admission 或 lock 等待语义，不用真实等待 300 秒。
- admission 超时/采样错误不启动进程、不删除该 binary 的主库、side files 或 `.id0`，整个组仍失败/no-publish；已启动 sibling 继续完成且有效数据库保留。
- 成功 admission 后的启动前校验失败、`Popen` 失败、正常退出、kill/wait 完成均恰好释放一次 reservation；未获准不释放、未确认进程退出不提前释放。启动前失败不得误入 `_invalidate_failed_worker_database`。
- 聚合功能未启用时不进入 gate，per-worker 内存上限仍生效。所有用例验证实现行为，不给计划文档内容增加文本约束测试。
- fake Job API 覆盖同一 producer 两个连续 miss group：create/set-limit/assign 仅一次，同一 controller 被复用，group/prepare 返回均不调用已绑定 handle 的 close。每组独立采样 baseline、创建 gate；前组峰值/launch 时间不污染后组，前组 worker 未退出或 reservation 未归零时拒绝建立下一 gate。
- 全 hit 的新 producer 不创建 controller；同一 PID 再次 prepare 以相同预算复用，变更/关闭已绑定预算被拒绝且不重复 assign。consumer 不建立 producer Job。
- 初始化错误注入覆盖 create 失败时不关闭无效 handle、set-limit/assign 失败时关闭已创建未绑定的 handle；绑定成功后的 snapshot 失败或预算不足时保留 owner/handle、不清理当前组数据库、不启动 worker、正常返回非零结果并释放 producer lock，关闭错误不得覆盖原始初始化错误。
- 真实 Job 测试放在专用 Windows 子进程：验证连续两组后父 producer 仍存活并写出 selection/evidence、正常退出码正确、worker 归属同一聚合 Job；受控终止该 producer 后验证其仍存活的 worker 被回收。不得用关闭真实 Job handle 的方式清理测试主进程，也不得仅凭 mock 认定跨 group 生命周期正确。

---

## 8. 验证命令

```text
uv run python -m unittest tests.test_warmup_concurrency
uv run python -m unittest tests.test_idb_cache
uv run python -m unittest tests.test_release_workflow tests.test_release_workflow_guards
uv run python -c "from pathlib import Path; import yaml; [yaml.safe_load(path.read_text(encoding='utf-8')) for path in Path('.github/workflows').glob('*.yml')]"
uv run python format_repo_files.py --check
git diff --check
```

完成前质量门禁：

```text
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
```

真实 runner 吞吐验收（阶段 5）无法执行时，只能声明仓库实现完成，不得声明吞吐收益已验证。

---

## 9. 风险与权衡

### 9.1 cache key 变化（有意，已确认）

`warm_worker_contract_sha256`（[idb_cache.py:288](idb_cache.py#L288)）继续参与 cache identity，覆盖 worker 生命周期与数据库文件集合规则的代码变化。本次只把运行时身份简化为 IDA kernel version，不把 GoldSrc 整个 cache key 复制成 CS2 的结构，也不声称 key 覆盖所有可能影响产物的环境差异。loader/plugin 摘要与安装目录明确不在新契约内。

**本迁移导致一次全量 miss（已接受）**：runtime 从完整七字段收敛为仅 kernel version，迁移到裸 idalib 并收敛 contract 文件也会改变 `warm_worker_sha256`，首次 run 为全量 warm。`normalized_ida_args` 字段继续保留；新 identity 固定为空列表，历史非空值也会与新 key 自然分离。既有 generations 按 4.2 保留原始 identity 与 digest，仍可 verify、exact restore、prune，但不匹配新 identity；不原地升级或重写旧 generation。

**失效策略：方案 A（收敛清单）+ 方案 B（显式版本号）双保险**，替代现有「11 文件全量内容寻址」：

- **A（收敛）**：把 `WARM_WORKER_CONTRACT_FILES`（[idb_cache.py:49-61](idb_cache.py#L49-L61)）缩减到 worker 实际执行或直接依赖的最小集合：

  `binary_format.py`（二进制解读）、`ida_database_paths.py`（数据库/侧文件集合）、`idb_warm_worker.py`（唯一的裸 idalib 打开→保存实现）。

  `warm_worker_contract_sha256` 必须拒绝任何不 resolve 到仓库 canonical `idb_warm_worker.py` 的入口，不再为 alternate worker name 退化为单文件哈希。release/PR identity builder 与 subprocess 也固定引用该 canonical 路径。

  并**移出** `ida_analyze_bin.py`、`idb_cache_selection.py`、`idb_cache_workflow.py`、`idb_cache_locks.py`、`release_workflow_lib/errors.py`、`release_workflow_lib/hashing.py` → 裸 worker 不再导入 `ida_analyze_bin.py`，这些文件的变化不再触发 miss。

- **B（兜底）**：保留显式 `warmup_contract_version`（[idb_cache.py:211-213](idb_cache.py#L211-L213)）作为未来「无法由 contract 文件摘要表达的语义大改」时手动强制失效的开关；本迁移不 bump。未来 bump 前必须先让 identity/manifest validator 支持旧 version 只读，否则会再次造成旧 generation 无法 verify/prune。

**净效果**：自动失效覆盖二进制 identity、IDA kernel version、上述 3 个 contract 文件摘要与显式 `warmup_contract_version` 等保留的 key 输入；清单外编排改动不因文件内容变化自动触发 miss。同版本下替换 loader/plugin 或改变安装目录不自动失效，这是有意接受的契约边界，不再追加摘要绑定或防御测试。

### 9.2 `normalized_ida_args` 语义变化（已确认）

裸 idalib 不接 IDA 命令行参数。已确认（见 4.5）：warm 不再应用 producer `-ida-arg`，该 CLI 参数删除；consumer 的 restore-strict 分析仍可通过独立 `-ida_args` 使用动态端口，不受影响。schema-1 的 `normalized_ida_args` 字段不删除，新 identity 固定写空列表，warm/publish 拒绝非空；旧 manifest 继续接受历史 canonical list，以保持 verify/restore/prune compatibility。

### 9.3 timeout 与 stale `.id0`

硬 timeout 无法依赖 worker 的 `idapro.close_database()` 关闭路径；进程被终止时可能留下 `.id0`，而把“存在 `.id0`”一律视为活动锁会使失败清理永久卡住。本迁移以 authority 分层解决：启动前仍把 `.id0` 当成可能活动锁并拒绝删除；只有 producer 拥有该 worker 且已经完成 kill/wait、确认进程退出后，才把其 `.id0` 作为 stale artifact 删除。完整路径合同集中在 `ida_database_paths.database_cleanup_paths()`，Windows sharing violation 使用 3 次、1 秒间隔的 bounded retry。任何残留都记录具体路径并保持组失败/no-publish，不影响成功 sibling。

### 9.4 跨 runner 锁与无等待预算

`PERSISTED_WORKSPACE` 已确认指向所有 eligible runners 共享的 SMB3 文件夹，byte-range lock 由 SMB server 跨机器协调，因此 producer 与 consumer 不要求落在同一 runner。官方 producer 仍由 Actions concurrency 排队；所有 producer另持 producer-only SMB lock以覆盖 direct mutating CLI。`tag_lock` 仅包围 persisted probe/publish/prune 与 exact restore短临界区，长时间 `warm_group` 在锁外运行，并在 publish 前 locked re-probe。lock acquisition 不再从 worker timeout推导 deadline，而以 `timeout_seconds=None` 等待，由外层 GHA job timeout/cancellation 提供运行上限。

风险从“合法 warm 超过计算预算”转为“共享存储 lock 语义漂移”。无限等待仅适用于明确 contention；权限、连接、handle 与未知 I/O 错误按 4.4.1 立即失败，不能依赖 GHA timeout 掩盖永久故障。真实 runner 验收必须用两个不同 runner/process 对同一 UNC target、同一 tag lock byte range证明互斥，并验证 producer warm 与 consumer restore 可并发、publish/prune 与 restore 仍串行。若 SMB authority 证据失效，必须停止 production activation，不得退化为无锁 online prune。

**版本探针挂起风险（已接受）**：`warm_group` 内的再次探针发生在持有 repository-wide producer lock 期间。探针若不返回，当前 producer 会继续占用该锁，直到外部取消或人工终止；direct CLI 不承诺存在 GHA timeout 兜底。接受这一可用性边界，不增加探针内部 deadline、专属 kill/wait 或通过提前释放 producer lock 绕过问题；实际 warm worker 的有限运行时间与退出后清理 authority 保持不变，见 4.1.1、4.3。

### 9.5 内存放大

并发 IDA 进程内存叠加，是并发吞吐的最大代价。初版用 `IDB_WARMUP_MAX_CONCURRENCY` 保守起调（默认 2），并建议设 `IDB_WARMUP_MAX_MEMORY_MIB`；未设时至少保证每 worker 进程自身仍有内存上限（沿用 `_apply_memory_limit`，其默认 8192 MiB）。

聚合预算并非任意正数都可用：必须满足 4.6 的 baseline + 4096 MiB reservation 与 85% soft limit 约束；否则立即拒绝。运行中压力恢复最多等待独立的 300 秒 admission 期限，不降低安全预留来追求吞吐；失败不赋予未启动 worker 的数据库清理权限。该保守策略可能在短期内存压力下让整个组失败，但不会无限持有 producer lock 却没有 worker 推进。

聚合 Job 是进程级限制，不是可在 group 末尾释放的资源：controller 跨组复用，gate/baseline 按组更新，handle 留到 producer 进程退出。预算也覆盖后续 publish/selection 的编排内存，这一点需要纳入 runner 配额；不通过中途关闭带 `KILL_ON_JOB_CLOSE` 的 handle 或重复建立嵌套 Job 来模拟 group 级限制。绑定后的初始化失败也必须正常报告并退出，见 4.6.1。

### 9.6 consumer 分析与恢复语义不变

consumer 仍用 restore-strict + `IdaMcpLifecycle`（动态端口、save_on_success=False），exact selection 与无冷启动 fallback 的语义不变。共享 cache identity builder 与缓存 CLI 调用适配仅含 kernel version 的 runtime；不再要求 loader/plugin 身份一致，但二进制 identity 和选定 generation 的字节校验继续保留。

### 9.7 与既有 `idb-warmup-job-migration.md` 的叠加

既有计划把 producer 拆成独立 job 并全局串行（正确性优先）。本计划在其之上把 warm 段并发化（吞吐）。两者范围不冲突；但既有计划 10.4「继续使用全局 `ida-mcp-port.lock`」一节需**由本计划替换**为「裸 idalib 无端口，删除 `warm_port_lock`」。合并顺序：先合既有计划（全局串行 + 拆 job），再合本计划（并发 worker）。

---

## 10. 最终验收标准

1. `idb_warm_worker.py` 是唯一 warm worker executable，为裸 idalib、无端口；identity builder、contract hash 与实际 subprocess 全部引用同一 canonical 文件，alternate name 被拒绝。
2. workflow 解析并验证 canonical `IDA_PYTHON_EXE`；版本探针与所有 warm subprocess 只使用该 executable，不回退到 producer 的 `sys.executable`，producer 不再依赖 `idalib-mcp`。版本探针按 4.1.1 同步调用，无独立 deadline 或专属 kill/wait；接受挂起时依赖外部取消/人工终止及其 producer lock 占用风险，不以此阻塞验收。实际 warm worker 的 timeout/kill-wait/失败清理不变。IDA imports 仅发生在执行入口，不安装 idapro 的编排解释器仍能导入驱动、构建最小 identity 与执行 cache verify/restore。
3. `warm_port_lock` 删除，`warm` 不再持有 MCP 端口锁。
4. 单个 (tag, platform) group 内多个二进制并发 warm，并发度由 `--max-concurrency` / `IDB_WARMUP_MAX_CONCURRENCY`（缺省 2）控制。
5. 并发 worker 各自独立数据库文件集，无相互覆盖；`auto_wait()` False/异常不保存，关闭后非零退出，不得因磁盘已有主库而报成功；任一失败只清理自身，不取消 sibling，等待全部 futures 完成并保留成功 sibling；组级 fail-closed，不发布半成品 generation。
6. 启动前 `.id0` 继续作为可能活动锁而 fail closed；失败/timeout 后只有在目标 worker 已完成 kill/wait、确认退出后，producer 才删除该 binary 的完整 `database_cleanup_paths()`（含 stale `.id0`），WinError 5/32 bounded retry；cleanup incomplete 保留根因和残留路径并阻止 publish。
7. 新 `ida_runtime` 仅含 `kernel_version`；探针版本必须匹配，所有 worker 使用同一 executable，成功退出且数据库文件集有效后才 publish。删除 `probe_runtime_contract`、observed-runtime JSON 与逐 worker runtime 聚合；不要求 loader/plugin 摘要、安装目录绑定或打开后的四字段观测，保留二进制输入格式与身份检查。
8. schema-1 保留最小读取兼容：新 identity 使用最小 runtime 与空 `normalized_ida_args`，warm/publish 拒绝旧完整 runtime 或非空 args；旧完整 runtime、非空 args 的 manifest 仍可按原始字段与 digest verify/restore/prune，不转换为新 identity 复用；本迁移不 bump schema 或 contract version。
9. 官方 producer 由 repository-wide Actions concurrency 排队，所有官方/direct producer 共用 producer-only SMB lock；consumer 不取得 producer lock。
10. `tag_lock` 只覆盖 short locked probe/finalize 与 consumer exact verify/restore；`warm_group` 在锁外运行，publish 前必须 locked re-probe。删除所有 warm-derived lock timeout，仅明确 contention 无限等待并受外层取消约束；非竞争错误立即 fail closed、关闭 handle 并保留脱敏根因，official/direct CLI 均有覆盖。
11. 两个不同 runner/process 对同一 SMB3 tag lock 的真实证据证明 publish/prune 与 restore 互斥，同时 consumer restore 不被另一 producer 的长时间 warm 阻塞。
12. immutable generation 发布/恢复协议、payload、release/PR exact selection evidence 与 strict consumer 分析语义保持不变；producer/consumer 的共享 identity builder 与 cache CLI 同步采用简化 runtime。明确接受同版本 loader/plugin 变化不触发自动 miss。
13. `IDB_WARMUP_MAX_MEMORY_MIB` 使用首次 miss 延迟初始化的进程级唯一 controller，跨 group 不重复 assign、不提前关闭已绑定 handle；每组重新采样 baseline、建立 gate，并在清理/启动前拒绝不可满足的预算。admission 使用独立有限期限，reservation 成对释放；失败不启动或清理对应 binary。绑定后初始化失败仍保留 owner 并正常报告/退出。真实 Windows 隔离子进程证明连续两个 miss group、最终 selection/evidence 和正常退出均可完成，异常退出可回收任务子进程；未设置聚合预算时每 worker 仍有进程级内存上限。
14. 定向测试、仓库质量门禁、真实 runner 并发/失败/内存证据全部完成。
15. 双语文档与 memory 与最终实现同步。

---

## 11. 实施记录（2026-09-05）

- 已完成唯一裸 idalib worker、显式 IDA Python 绑定、kernel-only 新 identity 与 legacy schema-1 读取兼容。
- 已完成 per-binary `ThreadPoolExecutor`、worker timeout 的 kill → wait → owned cleanup、stale `.id0` 与 WinError 5/32 bounded retry。
- 已完成 producer-only SMB lock、锁外 warm、locked re-probe/publish，以及仅明确 contention 可无限等待的 LockFileEx 适配。
- 已完成进程级 `ProducerMemoryOwner`、跨 group controller 复用、group 级 baseline/gate 与独立有限 admission deadline。
- 已完成 release/PR CLI 与 workflow 透传、双语文档、Basic Memory 和新增/迁移测试。
- 本机真实 IDA 9.3 smoke：单 worker 生成并验证 `client.dll.i64`；同内容 2-binary 组串行 `49.234s`、并发 `24.640s`，本机 wall-time speedup `2.00x`。
- 本地完整门禁：unit 486 项通过；repository-contract 14 项通过；all 504 项通过、4 项因 Redis 未运行/真实 IDA integration 未 opt-in 而跳过。另行执行的真实裸 idalib smoke 已覆盖 IDA integration 核心路径。
- 尚未在本会话内取得两个独立 runner 对同一 SMB3 persisted root 的互斥证据，也未启用真实 `IDB_WARMUP_MAX_MEMORY_MIB` 完成隔离 producer 子进程的连续双 miss group / 异常退出回收证据；这些仍是 production activation gate，不由仓库单测替代。
