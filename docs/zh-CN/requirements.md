[返回 README](../../README_CN.md) | [English](../en/requirements.md)

# 依赖与环境配置

## 必需工具

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. [DepotDownloader](https://github.com/SteamRE/DepotDownloader)，并确保 `depotdownloader.exe` 位于 `PATH` 中
3. 一个受支持的 Agent CLI：Claude Code、Codex 或 OpenCode
4. IDA Pro 9.0+
5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
6. [idalib](https://docs.hex-rays.com/user-guide/idalib)，由 `ida_analyze_bin.py` 使用

克隆仓库后安装 Python 依赖：

```bash
uv sync --locked
```

## 环境变量

将 `.env.example` 复制为 `.env` 作为本地模板。Analyzer 使用 GoldSrc 专属的 `GSVIBE_*` 命名空间；优先级为显式
CLI 参数、环境变量、程序默认值。关键变量：

- `GSVIBE_AGENT` 与 `GSVIBE_AGENT_MODEL` 选择 Agent CLI 与模型。
- `GSVIBE_LLM_MODEL`、`GSVIBE_LLM_APIKEY`、`GSVIBE_LLM_BASEURL`、`GSVIBE_LLM_TEMPERATURE`、
  `GSVIBE_LLM_FAKE_AS`、`GSVIBE_LLM_EFFORT` 配置 LLM-backed 工作流。
- `GSVIBE_PROCESS_REPORTER`（`none`、`console` 或 `redis`）、`GSVIBE_REDIS_URL`、`GSVIBE_REDIS_PREFIX`、
  `GSVIBE_RUN_ID` 配置进程上报。
- `GSVIBE_API_HOST`、`GSVIBE_API_PORT`、`GSVIBE_API_CORS_ORIGINS`、`GSVIBE_API_ALLOW_PRIVATE_NETWORK`、
  `GSVIBE_SSE_BLOCK_MS`、`GSVIBE_SSE_BATCH_SIZE` 配置只读 Process API。
- `GSVIBE_REFERENCE_GAMEVER`（默认 `hl-10210`）选择 `LLM_DECOMPILE` 的 canonical reference 游戏版本。
- `DEPOTDOWNLOADER_STEAM_USERNAME` 与 `DEPOTDOWNLOADER_STEAM_PASSWORD` 在需要 depot 认证时由
  `download_depot.py` 读取。

## IDB cache host 要求

Warm-cache runtime probe 需要 `IDADIR`，以绑定 exact pinned loader module 与 allowlisted plugin。Cache CLI 接收
显式 persisted root；CI 后续只会在受保护的专用 Windows runner job 内将其注入为
`GSVIBE_PERSISTED_WORKSPACE`。该 root 必须位于 checkout 与 `bin/` 之外，不得经过 reparse point，并且所在存储
必须支持同文件系统 atomic rename。

Runner account 需要对 cache root 拥有独占写权限。Cache warming 固定单并发，并用本地 file lock 保护固定 MCP
port。只有所有 consumer 共享同一受控 storage 与 ACL authority 时才能共享 cache；Actions artifact 与
`READY.json` 都不是 cache transport 或 truth source。

为专用 runner 配置 `gsvibe-ida` label，并将其关联到受保护的 `win64` Environment。真实 runner evidence 完成前，
repository variable `GSVIBE_IDB_CACHE_MODE` 保持 `cold`，完成后才切换为 `warm`；
`GSVIBE_IDA_KERNEL_VERSION` 记录 pinned installation 的 expected kernel version。Absolute persisted path 作为
Environment secret `GSVIBE_PERSISTED_WORKSPACE` 保存。Observed runtime 必须与 expected kernel、loader、plugin
identity 一致后才能 publication，因此这些配置值不能伪造成功的 cache generation。

## Release runner 与 GitHub governance 要求

Phase 2 需要专用 `[self-hosted, Windows, X64, gsvibe-release]` runner。其 machine environment 必须让 output
validation、build、promotion 与 recovery job 看到同一个 checkout 外 `GSVIBE_PERSISTED_WORKSPACE`；其中
`release-staging` 子树必须由 runner-account ACL 保护，存储需要支持同文件系统 atomic rename 与 hard link，并且不能
提供给 untrusted job。

创建受保护的 `release` Environment，并配置 `GSVIBE_RELEASE_APP_ID` 与
`GSVIBE_RELEASE_APP_PRIVATE_KEY`。Installation App 只获得 output branch/PR、workflow dispatch、annotated tag、
Release 与 assets 所需的最小 repository permissions。还需配置 `GSVIBE_RELEASE_BOT_LOGIN`，只 require Actions-owned
唯一 `pr-validate`，要求 up-to-date merge commit，禁止 `main` direct/admin-bypass push，保护 release tag，并限制
output branch prefix 只能由 App 写入。所有设置和演练取得 captured-at evidence 前，
`GSVIBE_RELEASE_PHASE2_ENABLED` 保持 false；protected republish 演练完成前，独立的
`GSVIBE_RELEASE_REPUBLISH_ENABLED` 也保持 false。Repository test 不能激活或证明这些外部控制。

## 初始化游戏 binaries

使用 `/init-gamebin` 斜杠命令，先用 `download_depot.py -all` 下载 `download.yaml` 中声明的全部 depot，再用
`copy_depot_bin.py` 把配置的二进制复制到 `bin/<tag>/<module>`。Steam 凭据从 `.env` 读取；缺失时
DepotDownloader 会交互式提示。

## Agent skill-runner 策略

Claude 与 OpenCode 会直接加载仓库内的 skill-runner policy。使用 Codex 前需把
`.codex/skill_runner.config.toml` 复制到 `$CODEX_HOME/skill_runner.config.toml`；runner 会通过
`--profile skill_runner` 选择该配置。

## 故障排查

### `error: could not create 'ida.egg-info': access denied`

在以下目录中以管理员权限运行 `python py-activate-idalib.py`：

```text
C:\Program Files\IDA Professional 9.0\idalib\python
```

### `Could not find idalib64.dll in .........`

为当前 shell 设置 `IDADIR`，或将其添加到系统环境变量：

```batch
set IDADIR=C:\Program Files\IDA Professional 9.0
```
