# GoldSrc 分析内存门禁 POSIX（cgroup v2）移植计划

状态：仓库实现完成；Linux runner 上的 Tier 1 需运维侧确认 `Delegate=yes`

日期：2026-09-22

优先级：P1（Linux 自托管 runner 上的并行分析被 Windows 专有实现阻断）

GoldSrc 基线：`main@65e75bf`

## 0. 移植意图（声明）

aggregate 内存门禁此前只有一个实现：Windows Job Object。Linux 上它直接抛出
`OSError("Windows Job Objects require Windows")`，使 `GSVIBE_ANALYSIS_MAX_MEMORY_MIB` 一旦配置就让分析在
0 秒内失败。用户在 Windows 与 Linux 两种自托管 runner 上都运行本仓库，因此 Linux 必须执行同一门禁，而不是
降为二等公民。本次移植保留既有所有权/准入/失败语义，只替换执行机制，并按宿主能力分层。

## 1. 现状分析（移植前）

- 全链路唯一的、没有 POSIX 分支的平台门是 `warmup_memory.py:101-106` `_Kernel32JobApi.__init__`。其余平台相
  关代码都已具备回退：`idb_cache_locks.py`/`mcp_startup.py` 用 `fcntl`，`analysis_memory.py:148-170`
  `PosixMeminfoProbe` 读 `/proc/meminfo`，`analysis_batch.py:531-562` 用 `/proc` 走进程树 kill，
  `idb_warm_worker.py:23-27` 用 `RLIMIT_AS`。
- `analysis_memory.py:248,261` 使用默认 `controller_factory`，因此 `AnalysisMemoryAuthority.__init__` 的急切
  构造会命中上述抛出；`ida_analyze_bin.py:2796` 又在 `_run_single_tag` 中无条件调用且丢弃返回值——单节点运行
  为一个从不读取的 Windows 内核对象付出代价。门禁真正被消费的地方只有 full-analysis batch
  （`ida_analyze_bin.py:3190-3192` → `analysis_batch.py:739-741,845`）与 warm producer（`idb_cache.py:948-986`）。
- Windows 子进程继承父 Job（`GSVIBE_ANALYSIS_COORDINATED_CHILD`，`ida_analyze_bin.py:3241`），因此批量子进程
  跳过自身 authority（`analysis_memory.py:312-314`）。降级层没有任何可继承物，这是 4.3 需要额外管线的根因。

## 2. 目标

1. Linux 上提供真正的 aggregate 硬上限（cgroup v2），语义对齐 Windows Job。
2. 拿不到 cgroup 委派时**降级**而非失败：每个 worker 有硬上限，聚合按准入预算有界。
3. Windows 行为、急切构造契约、既有测试保持不变。
4. 运维可以从日志判断当前用了哪一层，并知道 Tier 1 的前置条件。

## 3. 非目标

- 不改变缓存身份、generation、selection、锁 authority、release schema。
- 不改 workflow YAML：三处设置这些变量的 job 都是 `[self-hosted, windows, x64]`；接入 Linux 分析 runner 属独立
  基础设施决策。
- 不改 `idb_warm_worker.py`：它在 `WARM_WORKER_CONTRACT_FILES`（`idb_cache.py:54-58`）内并被哈希进每个
  cache identity（`idb_cache.py:286-296`），任何改动都会失效所有已发布的 warm generation。

## 4. 目标架构

### 4.1 分层

| Tier | 条件 | 保证 |
| --- | --- | --- |
| `windows-job` | Windows | aggregate 硬上限（不变） |
| `cgroup-v2` | Linux 且有可用 cgroup | aggregate 硬上限 + 整组 OOM kill |
| `reservation-only` | Linux 无可用 cgroup | 每 worker 硬上限；聚合按 `并发数 x 预留` 有界 |

### 4.2 Tier 1：cgroup v2 两步都不做

主机级测量（Ubuntu 24.04 / kernel 7.0 / systemd 255 / unified）给出了决定性事实：

- 自身 `cgroup.subtree_control` 列了 controller 的 cgroup **不能再接收进程**。给仍持有进程的 cgroup 写
  `+memory` 返回 `EBUSY`；全机 11 个设了 `subtree_control` 的非 root cgroup 进程数全为 0，唯一两者兼有的是 root。
- 在**已经**把 `memory` 放进 `subtree_control` 的父级下 `mkdir` 子目录，子目录会立即出现真实的 `memory.max`
  （只读验证：`user@1000.service` 的子级 `app.slice` / `session.slice` 均带 `memory.max=max`）。

因此实现只在候选父级下创建一个新目录并写其中的文件，**全程不写 `subtree_control`**。候选顺序为「当前 cgroup 的
父级」优先，其次「当前 cgroup 自身」；逐候选执行：校验目标存在 → 认领子目录（复用固定名 `gsvibe-memory`，占用时
改用 `<name>.<pid>`）→ 能力探测（`memory.max`/`memory.current`/`cgroup.procs` 必须存在）→ 先清 `memory.max`
为 `max` → `memory.oom.group=1` → `memory.swap.max=0`（best effort）→ 迁移 pid → 校验 `memory.current + 余量`
小于预算 → 写入预算。任一步失败则回迁 pid、必要时删除自建目录，并退回 Tier 2。

### 4.3 Tier 2：每 worker 硬上限

分析侧子进程此前没有任何每进程限额。协调者是线程化的，不能用 `preexec_fn`；沿用本文件既有的环境变量传播模式
（`_BATCH_WORKER_ENV_OPTIONS`，`ida_analyze_bin.py:2870-2882,3242-3245`）：降级时协调者注入
`GSVIBE_ANALYSIS_WORKER_VAS_LIMIT_MIB`，子进程在 `_batch_worker_main` 入口自施加。两种机制：

- `RLIMIT_AS` 安全网（默认 8192 MiB，可用 `GSVIBE_ANALYSIS_WORKER_VAS_LIMIT_MIB` 调整；**不**从预留量推导，
  否则运维下调预留量会静默收紧地址空间上限并误杀 IDA）。
- 常驻内存看门狗：读 `/proc/<pid>/stat`（ppid 与 rss 同一次读取）得到进程树 RSS，超过预留量即 SIGKILL 整棵树。

warm 侧由协调者在 `idb_cache._run_one_worker` 内施加（该文件可改，而 worker 文件不可改），且仅在
`reservation-only` 层启用，避免在「根本没配置预算」时引入新的击杀判据。

### 4.4 语义界限（必须如实文档化）

Tier 2 是**准入预算，不是聚合上限**：`RLIMIT_AS` 限制地址空间、`memory.max` 计charged 内存，两者不是同一量，
且上限必须对 IDA 留足余量，因此 `并发数 x C` 可能超过 budget。日志与文档均明说这一点。

## 5. 文件级实施范围

| 文件 | 变更 |
| --- | --- |
| `posix_memory.py`（新增） | Tier 1 controller 与候选梯子、Tier 2 controller 与 `/proc` RSS 探针、常驻看门狗、`apply_address_space_limit`、`build_posix_memory_controller` |
| `warmup_memory.py` | `MemoryController` 协议 + `MemoryControllerCapabilities`、`WindowsJobMemoryController.capabilities`、平台选择 `default_memory_controller`、owner 的 `capabilities`/`reservation_bytes`、warm 预留量环境变量、`cap=` 诊断 |
| `analysis_memory.py` | 默认工厂改平台选择、VAS 限额配置面与 `enforce_worker_memory_limits`、authority 的 `capabilities`、分层诊断 |
| `idb_cache.py` | 按层决定 per-worker 标志与看门狗 |
| `ida_analyze_bin.py` | 协调者注入 + 子进程自施加 |
| `tests/test_posix_memory.py`（新增）+ `tests/run_test_suite.py` | 假 cgroupfs 的纯逻辑测试，注册进 `unit` 组 |
| `tests/test_analysis_memory.py` / `tests/test_warmup_concurrency.py` | 新配置项与分层回归测试；`_run_one_worker` 调用点补两个必填 kwarg |

## 6. 实施阶段

1. **Spike（先做，唯一可能推翻方案的一步）**：在本机只读 + 独立子进程验证 `mkdir` 即得 `memory.max`、活限额与
   `oom_group_kill`、回迁与 `rmdir`、以及全程未触碰 `subtree_control`。
2. `posix_memory.py` + `warmup_memory.py` 的类型与工厂，先落假 cgroupfs 测试。
3. 分析侧默认工厂切换，复现并修复原失败命令。
4. 降级层管线：`idb_cache.py`、`ida_analyze_bin.py`（`analysis_batch.py` 无需改动，改由 worker 自施加）。
5. 文档（en/zh-CN）与 memory 笔记。

## 7. 测试策略

纯逻辑，`unit` 组，全部针对**假 cgroupfs 根**（`tempfile` + 显式 `process_cgroup_path`，绝不触碰真实
cgroupfs——CI 跑在 `ubuntu-latest`）：

- Tier 1：预置带接口文件的子目录 → 断言 `cap=cgroup-v2`、`memory.max` 被改写、`cgroup.procs` 写入 pid、
  `snapshot()` 读 `memory.current`。
- 梯子与降级：缺接口文件的候选（`init.scope` 形态）被拒且父级候选胜出；目录缺失/是文件、写失败、预算低于当前
  占用 → 断言回迁与 Tier 2 原因非空。
- 解析：v1/hybrid、空、多行 `0::`、相对路径全部抛错。
- Tier 2：构造 `/proc/<pid>/stat` 链断言 RSS 求和与无关进程排除；不可读根返回 0 而非抛错。
- 看门狗：在阈值上与阈值下分别断言击杀与不击杀；`RLIMIT_AS` 在子进程内验证（避免污染测试进程）。
- 分层回归（warm）：`capabilities` 为 `aggregate_hard_cap=True` → `--disable-memory-limit`；为
  `reservation-only` → 保留 `-memory-limit-mib 8192`；为 `None`（既有注入式假 controller）→ 行为与今日一致。

既有契约测试必须**原样通过**：`test_analysis_memory.py:112-138`（急切构造与 gate 恒等）与 `:276-292`
（先解析后建 Job）。

## 8. 验证命令

```bash
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b
uv run python format_repo_files.py --check
```

复现并确认修复（原命令，Linux）：

```bash
GSVIBE_ANALYSIS_MAX_MEMORY_MIB=16384 uv run python ida_analyze_bin.py -gamever hl-10210 \
  -bindir /tmp/gsvibe-test -artifactdir /tmp/gsvibe-test/artifacts \
  -node engine:linux:find-R_StudioCheckBBox -debug
```

期望：打印 `cap=cgroup-v2` 与 cgroup 路径，`Summary: Successful: 1`，产出与
`bin_artifacts/hl-10210/engine/R_StudioCheckBBox.linux.yaml` 逐字节一致。降级层验证：从无可委派 cgroup 的位置
运行，期望 `cap=reservation-only`，且 `/proc/<worker-pid>/limits` 的 `Max address space` 等于配置值。

## 9. 风险与权衡

- **systemd 是否总会在委派的服务 unit 上落地 controllers 尚无保证**：`user@.service`（`Delegate=yes`）呈现
  `subtree_control=[cpu memory pids]` 且自身无进程，但 `systemd-udevd.service` 同为 `Delegate=yes` 却
  `subtree_control` 为空、进程在 `udev/` 子组。若 runner unit 与后者相同，Tier 1 需要把步骤包进
  `systemd-run --user --scope -p Delegate=yes`（基础设施改动）。梯子算法两种情况都会正确降级，文档不得过度承诺。
- 当前 Linux runner（`actions.runner.HLND2T.service`）是 `Delegate=no` 且 cgroup 归 root，因此**今天会走
  Tier 2**；Tier 1 需要运维加 `Delegate=yes`。
- **Tier 2 是准入预算而非聚合上限**（见 4.4）。
- 急切构造在 Linux 上新增副作用：每次单节点运行都会把自己迁进受限额 cgroup。这与 Windows 一致；预算过小时
  第 8 步会降级而非直接杀进程，随后由既有的结构化错误报出。
- 看门狗采样有延迟，快速分配可能越过阈值后才被击杀；宽松的 `RLIMIT_AS` 安全网负责兜住最坏情况。
- 运行结束后残留空的 `gsvibe-memory` 目录是预期行为（进程无法删除自身所在 cgroup），固定名会被下次复用。
- 分析子进程的自施加位于所有平台共用的批量启动路径上；Windows 上必须保持 no-op（未注入环境变量即返回）。

## 10. 最终验收标准

1. Linux 上配置 `GSVIBE_ANALYSIS_MAX_MEMORY_MIB` 后，原失败命令成功并打印所选层。
2. Tier 1 环境下 cgroup 的 `memory.max` 等于预算，健康运行后 `memory.events` 的 `oom_group_kill` 为 0。
3. Tier 2 环境下 worker 的地址空间上限等于配置值，且日志明确说明聚合上限不可用。
4. 未配置预算时 `GSVIBE_ANALYSIS_MAX_CONCURRENCY>1` 仍 fail closed
   （`validate_limits_for_effective_concurrency`，`analysis_memory.py:104`）。
5. `unit` 与 `repository-contract` 全绿，包含未改动的急切构造契约测试。
6. Windows 行为不变：`windows-job` 层、`--disable-memory-limit` 的既有语义与测试全部保留。

## 11. 实施记录（2026-09-22）

- Spike 全部通过：`mkdir` 即得 `memory.max`；128 MiB 限额下子进程被 SIGKILL，`memory.events` 显示
  `oom_group_kill 1`，父 shell 存活；回迁与 `rmdir` 成功；`subtree_control` 全程未变。
- `unit` 组 1030 项通过（5 项既有 Windows-only skip），新增 `tests/test_posix_memory.py` 等 38 项。
- 端到端：`-node engine:linux:find-R_StudioCheckBBox` 打印 `cap=cgroup-v2` 并成功；LLM 节点
  `find-R_StudioCheckBBox-decompiles` 产出与已提交的 `R_CullBox.linux.yaml` 逐字节一致。
- 降级层实测：`enforce_worker_memory_limits` 在配置时确实设置 `RLIMIT_AS`、未配置时 no-op；看门狗在 314 MiB
  超过 64 MiB 上限时以 SIGKILL 终止目标进程（exit 137）。
- 未完成（需运维）：给 Linux runner unit 加 `Delegate=yes` 以启用 Tier 1；以及为 Linux 分析 runner 接入 workflow
  （本次范围内明确不做）。

### PR #206 审查修正

- 进程树采样逐 PID 容错，并按父子关系返回后代优先的击杀顺序，避免看门狗先终止自身而遗留 IDA 子进程。
- 直接单 tag / selected-node 入口也安装降级限制；进程级 authority 确保连续多个 tag 只安装一次。
- 非降级 batch worker 清除继承的 VAS 参数，Windows 限制入口保持 no-op。
- 回归覆盖缺失 / 无效 stat、PID 回绕、Linux 自身看门狗的真实子进程退出、直接入口与分层环境传播。
- 修正后验证：WSL2 `tests/run_test_suite.py all -b` 共 1080 项，`OK (skipped=8)`；包含 Redis 集成与 repository
  contract。Windows 内存 / batch / warmup 定向测试 153 项，`OK (skipped=3)`；格式检查通过。
- 本轮未执行真实 IDA 分析或真实 cgroup 限额验证；Linux 进程清理使用独立 Python 子进程验证。
- CI 续修：真实子进程回归测试读取 `/proc/<pid>/stat` 时，进程可能在 open 后被回收并返回 `ESRCH`。
  将 `ProcessLookupError` 与 `FileNotFoundError` 一同视为已退出，保留其他读取错误的失败行为。
