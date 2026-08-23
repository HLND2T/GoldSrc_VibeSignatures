[返回 CI/CD](ci-cd.md) | [English](../en/idb-cache-operations.md)

# IDB cache 运维

## 激活检查表

在专用 `gsvibe-ida` Windows runner、受保护 `win64` Environment、checkout 外 persisted root、ACL owner、支持
atomic rename 的 storage、`IDADIR` 与 expected kernel version 全部核验前，保持
`GSVIBE_IDB_CACHE_MODE=cold`。Persisted root 不得包含 checkout，也不得位于 checkout 内；路径与 root 均不得经过
link 或 reparse point。

分别保存一次 explicit cold run、一次发布 generation 的 warm miss，以及同一 plan 和 binary/runtime identity 的
后续 warm hit。证据记录 run URL/attempt、source/bin SHA、plan/selection SHA-256、cache key、generation、manifest
hash 与 wall time。完成这些证据后才能设置 `GSVIBE_IDB_CACHE_MODE=warm`。

## 日常操作

Warm preparation 有界且单并发。Miss 可以发布新的 immutable generation；hit 必须先验证 exact generation 再进入
selection。`cache-selection.json` 只作为 evidence 上传，不是 cache transport。Consumer 会重新核对其 SHA-256 与
pinned runtime identity，不读取 READY 即恢复 exact entry，并运行 strict no-save analysis。Final workspace clean
删除 restored/modified database，但不删除 generation。

只能在同一 runner authority 下运行 `uv run python idb_cache.py prune -persisted-root <root> -tag <tag>`。Prune 保留
READY 和最新三个 valid generation，遵守 minimum age，并且只访问该 tag。Retired tag 需要 offline maintenance
window：停止新 IDA job、取得 tag authority、把 exact tag directory 移到可恢复 operator trash，记录 inventory 与
reason，并在 in-flight retention window 结束后再删除。

## 故障处理

不得原地修复 corrupt generation。保留 selection 与日志，让后续 plan 显式切到 cold 或启动新的 warm producer
run，并在确认没有 in-flight selection 引用后隔离损坏 generation。Strict consumer 失败绝不 inline fallback。
损坏的 READY pointer 只能通过 probe 已验证 immutable generation 重建。
