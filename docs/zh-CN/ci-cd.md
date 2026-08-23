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

`gamesymbol-pr-validation.yml` 通过共享路由合约分类每个非 closed pull request。source-only 上线阶段中，Python 合约已经识别 generated-output branch 语法，但在 output verifier 原子部署前仍把它留在 source 路由。

Branch protection 只依赖终态 `pr-validate` job。该 job 使用 `always()`，显式读取每个路由 job 的结果，只在 trusted plan 未选择对应执行时接受 skipped，并在不向 fork 授予受保护 self-hosted runner 权限的前提下明确拒绝 fork analysis。内部 planner、hosted 与 self-hosted job 名称都不是 required checks。

## Pages 部署

[`.github/workflows/deploy-pages.yml`](../../.github/workflows/deploy-pages.yml) 在 `main` 分支 push 触碰到
`pages/**`、`gamesymbols/**`、`configs/**` 或工作流本身时触发：

1. **build**：测试、lint、构建 `pages/dist`，校验当前 game-symbol 字节，并上传 artifact。
2. **archive**：校验 `pages-snapshots` 分支历史是 append-only（只允许新增
   `gamesymbols/<family-build>.<sha256>.json`），合并不可变 game-symbol snapshot archive 并推送。
3. **deploy**：通过 GitHub Pages 部署 `pages/dist`，并按验证 manifest 校验已部署 CDN 的 game-symbol 字节。

GitHub Pages 只托管静态资产，绝不托管 Process API/SSE 服务。

## Analyzer 与 CI 参数参考

从 CI 驱动 analyzer 时，传入与本地运行相同的参数——参见
[二进制获取与符号分析](analysis.md#分析配置的符号)。对每个配置 tag 的批量分析使用 `-allgamever`；单 tag 运行
使用 `-gamever`。CI job 若只需知道二进制是否已就位，使用 `copy_depot_bin.py ... -checkonly`。
