# Release 运维

Release build 是手动 `workflow_dispatch`（`release-build.yml`，`version` + 可选 `source_sha` + `mode`）。生产
authority 由 allowlist 仓库 + `win64` Environment + per-version concurrency 提供，不再依赖
`GSVIBE_RELEASE_PHASE2_ENABLED` 或 GitHub App token。

## 状态与 truth source

Private stage 目录为 `PERSISTED_WORKSPACE/release-staging/<version>/<build_id>/`，内含 canonical `manifest.json`、
`READY`、`PROMOTION_STARTED`、`PROMOTED.json` 与 `PROMOTION_COMPLETE` marker。`pr-index/<pr>.json` 绑定 output PR；
`completed/<version>/<build_id>.json` 是 durable completion record。只有 completion record + tag identity + Release
ID + 下载资产 inventory 同时成立才表示 release 完成。

## 受保护操作

- `abandon`：`abandon-staged-release.yml`（`workflow_dispatch`），只允许 pre-promotion；确认词为
  `ABANDON <version>/<build_id>`，并要求原因。已记录 PR 先完成 remote identity verification 才关闭。
- `cleanup`：`cleanup-completed-release-staging.yml`（`workflow_dispatch` 或每日 cron），只清理有
  `PROMOTION_COMPLETE` 与 matching durable completion 的 stage，atomic rename 到
  `cleanup-trash/<version>/<build_id>`。
- `republish`：`release-build.yml` 的 `mode=republish`，要求 `version` tag 已存在；只重新分析自上次接受 source 以来
  受影响的输出。

保留失败 stage、workflow URL/run/attempt、source/bin SHA、PR/head/merge identity、tag target、Release ID 与
downloaded hash。
