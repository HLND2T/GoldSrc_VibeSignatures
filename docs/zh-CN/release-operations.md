# Release 运维

Release build 是手动 `workflow_dispatch`（`release-build.yml`，`version` + 可选 `source_sha` + `mode`），也可通过
push 一个 `v[0-9]*` 版本 tag 触发（tag 名即 `version`，`source_sha` 取 tag 指向的 commit，`mode` 固定为 `new`）。生产
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

## Generated-output PR 的 base advancement

`main` 前进后，output PR 在以下条件全部成立时仍然有效：

- output head 是单父提交，且该父提交恰好是 manifest `source_sha`；
- 当前 PR base 是该 `source_sha` 的后代；
- `source_sha..head` 只改 allowlist 内 generated outputs（含 `release-manifests/<version>.json`）；
- tracked manifest identity 与 hash 仍然匹配。

verifier 不会把 immutable output head rebase 到新 base。Git 冲突仍由 GitHub mergeability 阻止合并。merge-time
`verify_promotion()` 对 merge first parent 使用同一套 ancestor 规则。只有祖先关系或 direct-parent identity 被破坏时，
才需要 replacement build/PR。
