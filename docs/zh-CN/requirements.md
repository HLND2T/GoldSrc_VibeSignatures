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

Warm-cache runtime probe 要求专用 runner 提供带 `idapro` 的 `python`、`idalib-mcp` 与 `IDADIR`。Python
executable 必须与 `idalib-mcp` 位于同一目录，或拥有包含后者的 `Scripts` 目录。CI 使用该 exact Python
installation 调用 `idaapi.get_kernel_version()`，并通过 `IDADIR` 绑定 pinned loader module 与 allowlisted
plugin。Cache CLI 接收显式 persisted root；CI 后续只会在受保护的专用 Windows runner job 内将其注入为
`PERSISTED_WORKSPACE`。该 root 必须位于 checkout 与 `bin/` 之外，不得经过 reparse point，并且所在存储必须
支持同文件系统 atomic rename。

Runner account 需要对 cache root 拥有独占写权限。Cache warming 在调度层通过 repository-wide `idb-warmup-*`
concurrency group 保证单并发，每个 tag 的 publish/restore/prune 再由
`<PERSISTED_WORKSPACE>/idb-cache/.locks/<tag>.lock` 串行；固定 MCP port 另有独立本地 file lock。Byte-range lock
必须在两个独立 runner 进程间具备互斥语义，而不是仅在同进程线程间生效。只有所有 consumer 共享同一受控 storage
与 ACL authority 时才能共享 cache；Actions artifact 是 evidence/selection transport，`READY.json` 是 probe hint，
都不是 cache transport 或 truth source。

官方 analysis 无条件使用 warm cache，不再读取 `GSVIBE_IDB_CACHE_MODE`。真实 runner 与 storage evidence 完成前，
不要启用或触发这些 workflow。不再需要人工维护 IDA version variable。Absolute persisted path 作为 Environment
secret `PERSISTED_WORKSPACE` 保存。Opened runtime 必须与动态探测得到的 kernel、loader、plugin identity 一致后
才能 publication，因此 PATH 或 installation drift 会 fail closed，不会使用过期配置版本选择 cache。

## Release runner 与 GitHub governance 要求

Release build 与 source analysis 共用 `[self-hosted, windows, x64]` runner。受保护 `win64` Environment 只提供
analysis/runtime secret 与 checkout 外 `PERSISTED_WORKSPACE`；`idb-cache` 和 binary-only accepted cache 子树必须由
runner-account ACL 保护，并支持同文件系统 atomic rename。Build 只有 repository read 权限，没有 PAT、push、tag 或
Release authority。PR routing 必须把 untrusted/fork analysis 挡在该 runner 之外。

Production release dispatch 仅允许 `HLND2T/GoldSrc_VibeSignatures`，并使用 per-version concurrency。为 GitHub-hosted
`publish-release` job 配置独立受保护 `release` Environment；它是唯一获准 `contents: write` 的 job。Branch protection
要求 Actions-owned 唯一 `pr-validate`、禁止 `main` direct/admin-bypass push、保护 release tag，并为该 Environment
配置所需 approval。Release authority 不再包含 GitHub App token、`HLND2T_GH_TOKEN`、generated-output branch 或
merge-time promotion；repository test 无法激活或证明这些外部控制。

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
