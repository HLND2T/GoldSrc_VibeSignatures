# Release 运维

只有 dispatch 显式请求 activation 且 repository variable `GSVIBE_RELEASE_PHASE2_ENABLED=true` 时，Phase 2 才可能
取得 production authority。Branch/ruleset、merge-commit-only 与 up-to-date policy、protected tag、`release`
Environment、GitHub App identity/permissions、专用 `gsvibe-release` runner 的 protected-repository evidence 未完成前，
不得启用。

`republish` 还要求独立的 `GSVIBE_RELEASE_REPUBLISH_ENABLED=true`；protected test repository 中缺失/损坏资产演练
完成前保持关闭。

## 状态与 truth source

Private chain 为 `BUILDING -> HEAD_BOUND -> PR_CREATED -> READY -> PROMOTION_STARTED -> PROMOTED ->
PROMOTION_COMPLETE`。每个 marker 都是 immutable canonical JSON，hash 前一 marker，并保持已有 non-null binding。
只有 durable completion record、annotated tag identity、Release ID 与下载资产 inventory 同时成立才表示 release
完成；Actions artifact、draft Release、`READY` 或单独的 `PROMOTED` 都不是 completion。

## 受保护操作

以 exact tag/build 和确认词运行 `release-operations.yml`：

- `retry`：只允许在 `PROMOTION_STARTED` 前执行；关闭已记录 PR、移除其 immutable output branch、记录
  `SUPERSEDED`，然后用相同 content identity 与新 build ID dispatch。
- `resume-promotion`：复用同一 build、PR head、merge commit、tag target 与原 promotion workflow identity。Workflow
  checkout exact verifier revision，并在 tag/asset/completion 边界幂等继续。
- `republish`：只从 durable completion 执行。它按已记录 merge 重建原始 bytes，只替换缺失/损坏的命名资产并
  再次下载验证，绝不改变 tag 或 tracked manifest。
- `abandon`：只允许 pre-promotion；确认词为 `abandon:<tag>:<build-id>`，并要求原因。已记录 PR 必须先完成 remote
  identity verification 才会关闭。
- `repair-index`：只有 repository、branch、PR、head、base、tag、build 与 content identity 全部一致时，才重建
  private `pr-index`/`READY`。确认词为 `repair-index:<pr-number>:<tag>:<build-id>`。
- `cleanup`：要求 `cleanup:<tag>:<build-id>`、`PROMOTION_COMPLETE` 与 matching durable completion。Stage 会 atomic
  rename 到 `cleanup-trash/<tag>/<build-id>`，PR index 一并迁移；真正删除属于独立 retention 操作。
- `reconcile`：只读比较 local marker/completion 与 Git tag、Release，只报告差异，不自动修复。

保留失败 stage、operation log、workflow URL/run/attempt、source/bin/workflow SHA、approval digest、PR/head/merge
identity、tag object/target、Release ID 与 downloaded hash。Protected test repository 的 republish 演练完成前，
production republish 保持 disabled。
