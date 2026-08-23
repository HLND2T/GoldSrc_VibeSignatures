[Back to README](../../README.md) | [中文](../zh-CN/requirements.md)

# Requirements and environment setup

## Required tools

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. [DepotDownloader](https://github.com/SteamRE/DepotDownloader), with `depotdownloader.exe` available in `PATH`
3. One supported agent CLI: Claude Code, Codex, or OpenCode
4. IDA Pro 9.0+
5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
6. [idalib](https://docs.hex-rays.com/user-guide/idalib), required by `ida_analyze_bin.py`

Install the Python dependencies after cloning the repository:

```bash
uv sync --locked
```

## Environment variables

Copy `.env.example` to `.env` for a local template. The analyzer uses the GoldSrc-specific `GSVIBE_*` namespace; explicit CLI values override environment values, which override program defaults. Key variables:

- `GSVIBE_AGENT` and `GSVIBE_AGENT_MODEL` select the Agent CLI and model.
- `GSVIBE_LLM_MODEL`, `GSVIBE_LLM_APIKEY`, `GSVIBE_LLM_BASEURL`, `GSVIBE_LLM_TEMPERATURE`, `GSVIBE_LLM_FAKE_AS`, and `GSVIBE_LLM_EFFORT` configure LLM-backed workflows.
- `GSVIBE_PROCESS_REPORTER` (`none`, `console`, or `redis`), `GSVIBE_REDIS_URL`, `GSVIBE_REDIS_PREFIX`, and `GSVIBE_RUN_ID` configure process reporting.
- `GSVIBE_API_HOST`, `GSVIBE_API_PORT`, `GSVIBE_API_CORS_ORIGINS`, `GSVIBE_API_ALLOW_PRIVATE_NETWORK`, `GSVIBE_SSE_BLOCK_MS`, and `GSVIBE_SSE_BATCH_SIZE` configure the read-only Process API.
- `GSVIBE_REFERENCE_GAMEVER` (default `hl-10210`) selects the canonical reference game version for `LLM_DECOMPILE`.
- `DEPOTDOWNLOADER_STEAM_USERNAME` and `DEPOTDOWNLOADER_STEAM_PASSWORD` are read by `download_depot.py` when depot authentication is required.

## IDB cache host requirements

The warm-cache runtime probe requires `IDADIR` to identify the exact pinned loader modules and allowlisted plugins. The
cache CLI receives an explicit persisted root; CI later exposes it as `GSVIBE_PERSISTED_WORKSPACE` only inside the
protected dedicated Windows runner job. That root must be outside the checkout and `bin/`, must not traverse a reparse
point, and must reside on storage that supports atomic same-filesystem rename.

The runner account needs exclusive write access to its cache root. Cache warming is single-concurrency and uses a local
file lock for the fixed MCP port. A shared cache is valid only when all consumers use the same controlled storage and
ACL authority; Actions artifacts and `READY.json` are not cache transports or truth sources.

Configure the dedicated runner with the `gsvibe-ida` label and attach it to the protected `win64` Environment. Set the
repository variable `GSVIBE_IDB_CACHE_MODE` to `cold` until real runner evidence is captured, then to `warm`; set
`GSVIBE_IDA_KERNEL_VERSION` to the pinned installation's expected kernel version. Store the absolute persisted path as
the Environment secret `GSVIBE_PERSISTED_WORKSPACE`. The observed runtime must match the expected kernel, loader, and
plugin identity before publication, so these settings cannot manufacture a successful cache generation.
