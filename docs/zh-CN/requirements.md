[返回 README](../../README_CN.md) | [English](../en/requirements.md)

# 依赖与环境配置

## 必需工具

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. [DepotDownloader](https://github.com/SteamRE/DepotDownloader)，确保 `DepotDownloader` 位于 `PATH` 中（Windows 使用 `.exe`）
3. 一个受支持的 Agent CLI：Claude Code、Codex 或 OpenCode
4. IDA Pro 9.0+
5. [ida-pro-mcp](https://github.com/hzqst/ida-pro-mcp)
6. [idalib](https://docs.hex-rays.com/user-guide/idalib)，由 `ida_analyze_bin.py` 使用

克隆仓库后安装 Python 依赖：

```bash
uv sync --locked
```

## Windows 与 Ubuntu self-hosted runner

IDB 预热、PR 分析和 Release 构建使用 `[self-hosted, cross-platform]`。仅为已准备好的 Windows x64 或
Ubuntu x64 runner 添加 `cross-platform` 标签；两端继续使用受保护的 `win64` Environment secrets 与 variables。
runner 需能访问私有 S3 endpoint 和精确 binary submodule，并具有原生 licensed IDA/Hex-Rays、已激活的
idalib、`IDADIR`、受支持的 Agent CLI 和 `uv`。安装 `zstd` 与 Release 使用的归档工具（`7z`）；
git-cache-proxy URL rewrite 继续由 runner 服务账号预先配置。

在 runner 服务的 PATH 中暴露 IDA 环境的 Python（`python`，Linux 也可使用 `python3`）及 `idalib-mcp`，
与 workflow 依赖 venv 分开。两者必须属于同一环境；Linux Python 符号链接保留其 venv 身份，
entry point 的 shebang 必须指向该环境的解释器。跨平台编排和缓存 action 从 immutable `.ci-tools`
checkout 执行；PR planner 与 candidate compare/build 继续使用 trusted base tooling。

在 WSL 中测试 Windows checkout 时，使用独立 Linux venv：

```bash
UV_PROJECT_ENVIRONMENT="$HOME/.cache/gsvibe-linux-venv" uv run --locked python tests/run_test_suite.py all -b
```

Linux MCP supervisor 使用 owned process group。清理先发送 SIGTERM，最多等待 10 秒，再升级 SIGKILL，
最多等待 5 秒；supervisor 提前退出仍会回收 worker。启动失败、取消和恢复走同一清理路径，残留进程组
或未释放端口会使清理失败；只终止本次启动并持有的进程组。已有 aggregate memory hard cap 需要合适的
cgroup-v2 delegation；未配置时仍报告 `reservation-only` 并使用现有 RLIMIT_AS/watchdog 保护。

关闭 runner 迁移 Issue 前，应记录真实 CI 的 cold warmup、repeat hit、Windows producer → Linux consumer、
PR 分析，以及设置 `publish_release=false` 的两种 Release 模式。本地测试不能证明商业 IDA 分析通过或
GitHub runner 已准备就绪。

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
- `GSVIBE_ANALYSIS_MAX_CONCURRENCY` 限制 full analysis 同时准入的 worker 进程数（十进制 `1..32`，默认 `1`，fail closed）；大于 `1` 时必须同时设置 `GSVIBE_ANALYSIS_MAX_MEMORY_MIB`。
- `GSVIBE_ANALYSIS_MAX_MEMORY_MIB` 设置 analyzer 进程树的 aggregate 内存硬预算，含 85% soft admission gate；同样适用于直接单 tag 与 selected-node 分析。仅在宿主确有富余内存时上调；实际由哪一机制执行见运行输出的 `cap=<tier>` 行。
- `DEPOTDOWNLOADER_STEAM_USERNAME` 与 `DEPOTDOWNLOADER_STEAM_PASSWORD` 在需要 depot 认证时由
  `download_depot.py` 读取。

## 初始化游戏 binaries

使用 `/init-gamebin` 斜杠命令，先用 `download_depot.py -all` 下载 `download.yaml` 中声明的全部 depot，再用
`copy_depot_bin.py` 把配置的二进制复制到 `bin/<tag>/<module>`。Steam 凭据从 `.env` 读取；缺失时
DepotDownloader 会交互式提示。

该命令随后会询问是否执行可选的 IDB 预热。获得同意后，它对每个 tag 运行
`warmup_idb.py -gamever <tag> -python <带 idalib 的解释器>`，在每个配置的二进制旁留下已预热的 IDA 数据库，
后续分析直接还原该数据库而无需重新执行完整 auto-analysis。`IDB_WARMUP_MAX_CONCURRENCY` 限制并发预热
worker 数（默认 `2`），`IDB_WARMUP_MAX_MEMORY_MIB` 启用 aggregate 内存准入。

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
