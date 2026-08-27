[返回 README](../../README_CN.md) | [English](../en/ci-cd.md)

# CI/CD 参考

GitHub Actions 工作流在每次 push 与 pull request 上运行受门禁保护的分析与发布阶段。

## 持续集成

[`.github/workflows/ci.yaml`](../../.github/workflows/ci.yaml) 在 `ubuntu-latest` 与 `windows-latest` 上运行：

1. `uv sync --locked` 安装锁定环境。
2. `uv run python format_repo_files.py --check` 检查格式化。
3. `uv run python tests/run_test_suite.py unit -b --durations 30` 运行快速隔离套件。
4. `uv run python tests/run_test_suite.py repository-contract -b --durations 30` 检查仓库合约。
5. `uv run python tests/run_test_suite.py all -b --durations 30` 运行全部指定测试。

独立的 `redis-integration` job 在 `ubuntu-latest` 上运行，带 `redis:7-alpine` 服务，设置 `GSVIBE_REDIS_URL` 与
`GSVIBE_REDIS_PREFIX`，并运行 `tests/run_test_suite.py redis-integration -b --durations 30`。

`pages` job 安装 Node 24，在 `pages/` 目录运行 `npm ci`、`npm test`、`npm run lint`、`npm run build`、
`npm run verify:gamesymbols`，安装 Chromium，并运行 `npm run test:e2e`。

## Game-symbol Pull Request 验证

`gamesymbol-pr-validation.yml` 通过共享路由合约分类每个非 closed pull request。普通 branch 进入 source
plan/hosted/self-hosted 路径；所有 `gamesymbols/build/` branch（包括 malformed output-like 名称）都进入 output
路径并明确失败，不能回落到 trusted analysis runner。

Branch protection 只依赖终态 `pr-validate` job。Source planning 在默认 checkout 中原地执行 PR merge 版本的 semantic planner，并且只上传 canonical bound `plan.json`；selected-node 执行保持不变。终态 job 使用 `always()` 和 shell 逻辑聚合各路由结果，只在 bound plan 未选择对应执行时接受 skipped，并在不向 fork 授予受保护 self-hosted runner 权限的前提下明确拒绝 fork analysis。内部 planner、hosted 与 self-hosted job 名称都不是 required checks。

hosted 与 self-hosted source validation 都会从不可变 symbol candidate 重建 canonical gamedata manifest，并与
exact `HEAD` Git blob 比较。bound plan 绑定 base/merge gamedata subtree digest；被忽略的工作树文件和宽泛 stage
glob 都不是 validation 输入。

Planner 还会从 repository variable `GSVIBE_IDB_CACHE_MODE` 绑定 `cache_mode`，默认值为 `cold`。Analysis 在
`win64` Environment 下的专用 `[self-hosted, windows, x64]` runner 运行，并受 repository-wide IDA
concurrency group 约束（动态 per-binary MCP endpoint 为 invocation-scoped，不会放宽该 group）。Warm mode 在同一个
job 内完成 clean、probe/miss warmup、exact selection、restore、
analysis 与 final clean。`cache-selection.json` 绑定 plan SHA、merge/bin identity、selected binary、cache key、
generation 和 manifest hash；其 SHA-256 会被复核，Actions artifact 只作为 evidence。Cold mode 不执行任何收到
`PERSISTED_WORKSPACE` 的 step。

Production warm activation 必须满足 [IDB cache 运维手册](idb-cache-operations.md) 中的 host/repository 设置。
Unit 与 workflow-contract test 不能替代专用 runner 上记录的 cold、首次 miss/publication 与后续 hit run。

## Release 构建与发布

[`release-build.yml`](../../.github/workflows/release-build.yml) 是手动 `workflow_dispatch`（`version` 如
`v20260825a` + 可选 `source_sha` + `mode` `new|republish`）。它在 self-hosted `[self-hosted, windows, x64]` runner
上：checkout exact source 与 `bin` submodule → 恢复 accepted bin → 逐 game version warm IDB cache →
`ida_analyze_bin.py -allgamever` 分析全部 game version → 逐 game version build/guard/publish candidate 与 gamedata →
`stage-build` → 创建单个 `github-actions[bot]` generated-output PR（分支 `gamesymbols/build/<version>`）。

- `validate-generated-output-pr.yml` 校验 output PR（bot author + 同仓 + `gamesymbols/build/` 分支）。output head 必须是
  单父提交，且该父提交等于 tracked manifest 的 `source_sha`。当前 PR base 必须是该 `source_sha` 的后代，因此 PR
  创建后 default branch 前进本身不是 stale。changed-path allowlist 按 `source_sha..head` 计算（全部 game version 的
  gamesymbols/metadata/gamedata + `release-manifests/<version>.json`），不把可能已前进的 PR base 上的变化算进 output
  PR。tracked output hash 仍必须匹配。trusted validation tooling 继续来自 PR base；output workspace 检出 exact head。
- `promote-release-after-output-merge.yml` 在合并后校验两父合并、把 accepted bin 事务化交换进 persisted workspace、
  打单个 `version` tag 并发布一个 GitHub Release（资产含全部 game version）。
- `abandon-staged-release.yml` 与 `cleanup-completed-release-staging.yml` 处理生命周期（放弃 staged build、清理
  已完成的 completion record）。

`mode=republish` 要求 `version` tag 已存在，且只重新分析自上次接受 source 以来受影响的输出。发布不再依赖
`GSVIBE_RELEASE_PHASE2_ENABLED` 或 GitHub App token；gate 由 allowlist 仓库 + `win64` Environment + concurrency 提供。

## Pages 部署

[`.github/workflows/deploy-pages.yml`](../../.github/workflows/deploy-pages.yml) 在 `main` 分支 push 触碰到
`pages/**`、`gamesymbols/**` 或工作流本身时触发；一般 config 修改不会重新部署历史 alias：

1. **build**：测试、lint、构建 `pages/dist`，校验当前 game-symbol 字节，并上传 artifact。
2. **archive**：校验 `pages-snapshots` 分支历史是 append-only（只允许新增
   `gamesymbols/<family-build>.<sha256>.json`），合并不可变 game-symbol snapshot archive 并推送。
3. **deploy**：通过 GitHub Pages 部署 `pages/dist`，并按验证 manifest 校验已部署 CDN 的 game-symbol 字节。

GitHub Pages 只托管静态资产，绝不托管 Process API/SSE 服务。

## Analyzer 与 CI 参数参考

从 CI 驱动 analyzer 时，传入与本地运行相同的参数，并显式指定 `-cache_mode cold|warm`——参见
[二进制获取与符号分析](analysis.md#分析配置的符号)。对每个配置 tag 的批量分析使用 `-allgamever`；单 tag 运行
使用 `-gamever`。CI job 若只需知道二进制是否已就位，使用 `copy_depot_bin.py ... -checkonly`。
