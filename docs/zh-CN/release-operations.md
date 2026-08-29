# Release 运维

Release build 是手动 `workflow_dispatch`（`release-build.yml`，`version` + 可选 `source_sha` + `mode`）。生产
authority 由 allowlist 仓库 + `win64` Environment + per-version concurrency 提供，不再依赖
`GSVIBE_RELEASE_PHASE2_ENABLED` 或 GitHub App token。

## 凭据与权限边界

- `release-build.yml` 的默认 `${{ github.token }}` 保持只读（`actions: read`、`contents: read`、
  `pull-requests: read`）。Exact source checkout、Git authentication、output branch push 与 PR create 使用 `win64`
  Environment secret `HLND2T_GH_TOKEN`。
- PAT 需要 repository `Contents: Read and write`、`Pull requests: Read and write`、`Metadata: Read`；token owner
  必须是 `OWNER`、`MEMBER` 或 repository `COLLABORATOR`。Workflow `permissions` 不会授予或扩大 PAT scope。
- Output PR validation 不接收 PAT，保持 `contents: read`。Merge-time promotion 使用 `${{ github.token }}`，以
  `contents: write`、`pull-requests: read` 创建 immutable tag 与 GitHub Release。
- `GSVIBE_BIN_TOKEN` 若仍用于 source PR 或 warmup workflow，只承担 private submodule read；它不是 release
  publication credential。

不得把 PAT value 输出、持久化、上传或复制到 log、artifact、manifest、stage、cache 或 Git config diagnostic。
通过 `win64` Environment 轮换或吊销，并在仓库外记录 owner、expiry、SSO authorization 与 rotation owner。

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

## Promotion storage 拓扑

`verify` 与 `promote` job 都声明 `win64` Environment，并运行在 `[self-hosted, windows, x64]` runner；两者通过该
Environment 的 `PERSISTED_WORKSPACE` secret 访问同一个 private `release-staging`。`verify` 使用 PowerShell
`Join-Path` 构造路径，并在 secret 为空时 fail closed。所有 eligible runner 仍必须把该路径映射到同一受控存储；在
production promotion 验收前还应完成一次真实 merge 演练，以证明跨 job 可见性与 Environment protection 行为。
