[返回 CI/CD](ci-cd.md) | [English](../en/idb-cache-operations.md)

# IDB cache 运维

## 激活检查表

在专用 Windows runner、受保护 `win64` Environment、checkout 外 persisted root、ACL owner、支持 atomic
rename 的 storage 与 `IDADIR` 全部核验前，不要启用或触发官方 analysis。官方 analysis 始终是 strict warm
consumer，不存在 cold 绕行路径。确认带 `idapro` 的 `python` 与 `idalib-mcp` 解析到同一 installation；CI 会动态
读取其 kernel version。Persisted root 不得包含 checkout，也不得位于 checkout 内；路径与 root 均不得经过 link 或
reparse point。

把 producer 拆成独立 job 还需要额外的跨 runner 证据：所有 eligible runner 的 `PERSISTED_WORKSPACE` 指向同一受控
storage；runner A 发布的 generation 能在 runner B 通过验证；该 storage 支持同目录 atomic rename；所有 runner
account 共用同一 ACL authority；Windows byte-range lock 在该 storage 上对两个独立进程具备互斥语义。任一条不满足就
保持 analysis workflow 禁用——合入 workflow YAML 不等于激活。

按顺序保存证据：一次发布 generation 的 split-job warm miss；一次 consumer 位于另一 runner 的 warm hit；一次 READY
在 producer 与 consumer 之间被改写但 exact restore 仍成功的 run；两个 release version 同时
触发且第二个 producer 排队；source PR 与 release 同时请求 warmup 但仍只有一个 producer；producer 被取消或超时后
没有任何半写 generation 被选择；corrupt generation/selection fail-closed；build 失败后 workspace cleanup 完成且
persisted generation 完整。证据记录 run URL/attempt、runner identity、source/bin SHA、plan/selection SHA-256、
cache key、generation、manifest hash 与 wall time。

## 日常操作

Warm production 在 reusable `warmup-idb` job 中执行。所有官方 producer——release 与 source PR——共用同一个 job-level
concurrency group `idb-warmup-<owner>/<repo>`，且 `cancel-in-progress: false`，因此调度层保证同一 repository 同时
只有一个 persisted IDB cache writer。Producer 内部，每个 tag 的 `probe -> warm/publish -> verify -> selection ->
prune` 都在 `<PERSISTED_WORKSPACE>/idb-cache/.locks/<tag>.lock` 内执行；consumer 在 `verify -> restore` 期间持有同一
把锁，因此并发 prune 无法删除已被选中的 generation。锁由打开的 handle 持有，锁文件存在不代表锁被持有。

Miss 会发布新的 immutable generation；hit 必须先验证 exact generation 再进入 selection。Hit 与 miss 产生逐字节相同
的 selection entry。`cache-selection.json` 是 evidence 与 selection transport，不是 IDB payload transport。Consumer
会把其 SHA-256 与 producer job output 复核、从自身 checkout 与 pinned runtime 重新推导 expected identity、不读取
READY 即恢复 exact entry，并运行 strict no-save analysis。Final workspace clean 删除 restored/modified database，
但不删除 generation。

release-all producer 的 accepted-bin materialization 统一走
`uv run python release_workflow.py materialize-accepted-bin --repo-root <checkout> --persisted-root <root> --all-gamevers`。
它持有 `<PERSISTED_WORKSPACE>/accepted-bin/locks/<gamever>.lock`，只复制 binary/side file（排除分析 YAML、IDA
database 与 BinSync state），并在释放锁前逐字节校验。Legacy YAML 清理使用
`cleanup-legacy-accepted-yaml --cutover-id <id>`：先验证 binary-only materialization，再在
`accepted-bin/legacy-yaml-backups/` 创建 exact inventory 备份，最后才在锁内删除 YAML。不要手工复制或删除 accepted
目录树。

只能在同一 runner authority 下运行 `uv run python idb_cache.py prune -persisted-root <root> -tag <tag>`。
`idb_cache.py` 的每个写命令（`probe`、`warm`、`publish`、`restore`、`prune`）都会自行取得 tag lock，因此直接调用
CLI 也无法绕过 authority；只有只读的 `verify` 无锁。Prune 保留 READY 和最新三个 valid generation，遵守 minimum
age，并且只访问该 tag。Retired tag 需要 offline maintenance window：停止新 IDA job、取得 tag authority、把 exact
tag directory 移到可恢复 operator trash，记录 inventory 与 reason，并在 in-flight retention window 结束后再删除。

## 故障处理

不得原地修复 corrupt generation。保留 selection 与日志，启动新的 warm producer run，并在确认没有 in-flight
selection 引用后隔离损坏 generation。Strict consumer 失败绝不 inline fallback。
损坏的 READY pointer 只能通过 probe 已验证 immutable generation 重建。

Producer 失败、producer 被取消、selection artifact 无法下载，都会阻塞 consumer。这是 exact binding 换来的有意
fail-closed 行为：恢复方式是重新调度 run，绝不是 consumer 侧重新 probe。IDB cache 恢复成功与完整业务分析成功必须
分别报告——恢复正常不能掩盖后续 analysis 或 Skill 失败。
